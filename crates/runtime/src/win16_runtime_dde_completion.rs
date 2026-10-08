//! Typed Win16 DDEML completion and cleanup continuations.

use std::{error::Error, fmt, sync::Arc};

use guest_core::{Registers, memory::Memory};
use win16_abi::{AllocationFlags, Win16DdeRequest};

use super::*;
use crate::win16_runtime::guest_ranges::commit_guest_writes_with_selectors;
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostDdeResult,
    Win16HostDdeValue,
};
use compat_services::win16_dde::error as dde_error;

#[path = "win16_runtime_dde_completion_access.rs"]
mod access;
#[path = "win16_runtime_dde_completion_data.rs"]
mod data;
#[path = "win16_runtime_dde_receipt.rs"]
mod receipt;
#[path = "win16_runtime_dde_completion_state_api.rs"]
mod state_api;

pub(in crate::win16_runtime) use access::DdeCompletionAccess;

/// Resolve a native completion through disjoint owner borrows while its
/// central window frame and continuation remain in place.
pub(in crate::win16_runtime) fn finish_dde_operation(
    access: &mut DdeCompletionAccess<'_>,
    continuation: &mut Win16DdeContinuation,
    result: Win16HostDdeResult,
    _registers: &mut Registers,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<Win16DdeFinish, RuntimeError> {
    match access.finish_dde_operation_inner(continuation, result, memory, host) {
        Ok(finish) => Ok(finish),
        Err(error) => Err(continuation.retain_finish_failure(error)),
    }
}

impl DdeCompletionAccess<'_> {
    fn unregister_guest_callback(&mut self, token: crate::Win16GuestCallbackToken) -> bool {
        self.callback_scheduler.unregister_guest_callback(token)
    }

    fn finish_dde_operation_inner(
        &mut self,
        continuation: &mut Win16DdeContinuation,
        result: Win16HostDdeResult,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16DdeFinish, RuntimeError> {
        continuation.require_cached_normal_source_result(&result)?;
        if let Some(original_error) = continuation.cleanup_error.as_ref() {
            return finish_dde_access_compensation(Arc::clone(original_error), result);
        }
        if result.dde_error != dde_error::NO_ERROR {
            validate_dde_error(result.dde_error)?;
            validate_dde_error_shape(&continuation.request, &result)?;
        }
        super::Win16State::validate_dde_transaction_shape(&continuation, &result)?;
        self.finish_data_transfer_receipt(&continuation, &result)?;
        if !matches!(continuation.purpose, Win16DdeCompletionPurpose::GuestApi) {
            return self.finish_dde_callback_readback(continuation, result, memory, host);
        }

        if result.dde_error != dde_error::NO_ERROR {
            self.commit_failed_transaction_result(&continuation, &result, memory)?;
            self.rollback_failed_dde_request(&continuation, memory)?;
            if let Some(instance) = continuation.instance {
                self.dde.set_last_error(instance, result.dde_error);
            }
            if result.dde_error == dde_error::NOTPROCESSED {
                host.report_diagnostic(&Diagnostic::warning(
                    Kind::CompatibilityGap,
                    "Win16 DDEML host operation reported DMLERR_NOTPROCESSED",
                ));
            }
            let value = if matches!(continuation.request, Win16DdeRequest::Initialize { .. }) {
                u32::from(result.dde_error)
            } else {
                0
            };
            return Ok(Win16DdeFinish::Return {
                value,
                return_kind: continuation.return_kind,
            });
        }

        if matches!(&continuation.request, Win16DdeRequest::AccessData { .. })
            && matches!(&result.value, Win16HostDdeValue::None)
        {
            // DDEML uses a NULL native pointer to report AccessData failure;
            // GetLastError may still be NO_ERROR. No native lease exists, so
            // there is no guest snapshot to allocate or compensate.
            if let Some(instance) = continuation.instance {
                self.dde.set_last_error(instance, dde_error::NO_ERROR);
            }
            return Ok(Win16DdeFinish::Return {
                value: 0,
                return_kind: continuation.return_kind,
            });
        }

        if let (
            Win16DdeRequest::ClientTransaction { .. },
            Win16HostDdeValue::ClientTransaction {
                succeeded: false,
                entered_native,
                ..
            },
        ) = (&continuation.request, &result.value)
        {
            if !*entered_native {
                return Err(invariant(
                    "preflight DDE transaction failed without a DMLERR",
                ));
            }
            // A NULL transaction result is failure even when DdeGetLastError
            // reports NO_ERROR. Native entry distinguishes it from preflight.
            self.commit_failed_transaction_result(&continuation, &result, memory)?;
            if let Some(instance) = continuation.instance {
                self.dde.set_last_error(instance, dde_error::NO_ERROR);
            }
            return Ok(Win16DdeFinish::Return {
                value: 0,
                return_kind: continuation.return_kind,
            });
        }

        if let (
            Win16DdeRequest::AccessData { data, .. },
            Win16HostDdeValue::AccessData { bytes, writable },
        ) = (&continuation.request, &result.value)
        {
            match self.finish_access_data(
                *data,
                bytes.clone(),
                *writable,
                continuation.outputs.access_size.as_ref(),
                memory,
            ) {
                Ok(value) => {
                    if let Some(instance) = continuation.instance {
                        self.dde.set_last_error(instance, dde_error::NO_ERROR);
                    }
                    return Ok(Win16DdeFinish::Return {
                        value,
                        return_kind: continuation.return_kind,
                    });
                }
                Err(original_error) => {
                    let host_data = self.dde.host_data(*data).ok_or_else(|| {
                        invariant("DDE AccessData token disappeared before native compensation")
                    })?;
                    continuation.cleanup_error = Some(Arc::new(original_error));
                    let mut next_continuation = continuation.clone();
                    // Keep the completed operation identity on its current
                    // owner until the same-frame follow-up has actually been
                    // submitted and committed. The new continuation starts
                    // without an operation ID but retains the old source
                    // tombstone and owner/generation history.
                    next_continuation.host_operation = None;
                    next_continuation.started_failure = None;
                    next_continuation.clear_completed_phase_for_followup()?;
                    next_continuation.reserve_source_retirement_record()?;
                    return Ok(Win16DdeFinish::FollowUp {
                        call: Win16HostDdeCall::UnaccessData {
                            data: host_data,
                            copyback: None,
                        },
                        continuation: Some(Box::new(next_continuation)),
                        phase: Win16DdeFollowUpPhase::UnboundPrepared,
                    });
                }
            }
        }

        let value = self.finish_dde_success(&continuation, result, memory)?;
        if let Some(instance) = continuation.instance {
            self.dde.set_last_error(instance, dde_error::NO_ERROR);
        }
        Ok(Win16DdeFinish::Return {
            value,
            return_kind: continuation.return_kind,
        })
    }

    /// Consume native per-operation source tombstones only after the shared
    /// window-frame owner has projected the result and restored its original
    /// CPU context. The caller invokes this immediately before its infallible
    /// exact-frame pop; failed host validation leaves every unconsumed proof
    /// cached on the continuation for retry.
    pub(in crate::win16_runtime) fn consume_dde_source_retirements(
        &mut self,
        continuation: &mut Win16DdeContinuation,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        super::source_lifecycle::consume_source_retirements(continuation, host)
    }

    fn rollback_failed_dde_request(
        &mut self,
        continuation: &Win16DdeContinuation,
        _memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        if let Some(candidate) = continuation.callback_candidate {
            let (_, blocks) = self
                .dde
                .rollback_callback_registration(candidate.route)
                .ok_or_else(|| {
                    invariant("staged DDE callback route disappeared before rollback")
                })?;
            for block in blocks {
                self.free_runtime_dde_block(block.identity)?;
            }
            // rollback_callback_registration owns token retirement. Drain its
            // queue once so an in-flight route is never unregistered twice.
            self.unregister_retired_dde_callbacks()?;
        }
        Ok(())
    }

    fn finish_access_data(
        &mut self,
        guest_data: u32,
        bytes: Vec<u8>,
        writable: bool,
        size_output: Option<&GuestOutputRange>,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        let byte_length = u32::try_from(bytes.len()).map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "DDE AccessData snapshot exceeds DWORD size",
            )
        })?;
        if self.dde.data_is_writable(guest_data) != Some(writable) {
            return Err(invariant(
                "DDE AccessData writable projection disagrees with guest ownership state",
            ));
        }
        let existing = self.dde.access_block(guest_data);
        let refresh_existing_readonly = existing.is_some() && !writable;
        let (block, identity, far, allocation, allocation_writable) = if let Some(existing) =
            existing
        {
            if existing.byte_length != byte_length || (writable && !existing.writable) {
                return Err(invariant(
                    "DDE AccessData changed while a guest snapshot remained locked",
                ));
            }
            (
                existing.block,
                existing.identity,
                existing.far_pointer,
                None,
                existing.writable,
            )
        } else {
            self.reserve_dde_guest_block_retirement()?;
            let allocation = {
                let (heap, _selectors) = self.memory.heap_and_selectors_mut();
                heap.alloc(
                    memory,
                    DDE_CALLBACK_OWNER,
                    byte_length.max(1),
                    AllocationFlags::fixed().with_zero_init(),
                )
            }
            .map_err(crate::runtime_error)?;
            let lock_result = {
                let (heap, selectors) = self.memory.heap_and_selectors_mut();
                heap.lock(allocation, selectors, memory)
            };
            let pointer = match lock_result {
                Ok(pointer) => pointer,
                Err(error) => {
                    self.free_runtime_dde_block_unlocked(allocation)?;
                    return Err(crate::runtime_error(error));
                }
            };
            if !bytes.is_empty() {
                if let Err(error) = self.write_dde_snapshot(memory, pointer.far_value(), &bytes) {
                    let cleanup = self.free_runtime_dde_block(allocation);
                    if let Err(cleanup) = cleanup {
                        return Err(error.with_cleanup(
                            "DDE AccessData snapshot write and local block cleanup both failed",
                            cleanup,
                        ));
                    }
                    return Err(error);
                }
            }
            (
                allocation.raw().0,
                allocation,
                pointer.far_value(),
                Some(allocation),
                writable,
            )
        };
        if refresh_existing_readonly && !bytes.is_empty() {
            self.write_dde_snapshot(memory, far, &bytes)?;
        }
        let returned_far = match self.dde.retain_access_block(
            guest_data,
            block,
            identity,
            far,
            byte_length,
            allocation_writable,
        ) {
            Some(far) => far,
            None => {
                if let Some(allocation) = allocation {
                    self.free_runtime_dde_block(allocation)?;
                }
                return Err(invariant("DDE AccessData snapshot could not be retained"));
            }
        };
        if let Some(size_output) = size_output {
            if let Err(original) = commit_guest_writes_with_selectors(
                self.selectors(),
                memory,
                vec![(size_output.clone(), byte_length.to_le_bytes().to_vec())],
            ) {
                if self.dde.access_block(guest_data).is_none() {
                    return Err(invariant(
                        "DDE AccessData reference disappeared during output rollback",
                    ));
                }
                self.reserve_dde_guest_block_retirement()?;
                if let Some(block) = self.dde.take_access_block(guest_data) {
                    if let Err(cleanup) = self.free_runtime_dde_block(block.identity) {
                        return Err(original.with_cleanup(
                            "DDE AccessData output commit and guest-block rollback both failed",
                            cleanup,
                        ));
                    }
                }
                return Err(original);
            }
        }
        Ok(returned_far)
    }

    fn finish_unaccess(&mut self, guest_data: u32) -> Result<(), RuntimeError> {
        if self.dde.access_block(guest_data).is_none() {
            return Err(invariant(
                "successful DdeUnaccessData has no guest access snapshot",
            ));
        }
        self.reserve_dde_guest_block_retirement()?;
        if let Some(block) = self.dde.take_access_block(guest_data) {
            self.free_runtime_dde_block(block.identity)?;
            if let Some(removed) = self.dde.release_unowned_data(guest_data) {
                if let Some(block) = removed.access_block {
                    self.free_runtime_dde_block(block.identity)?;
                }
            }
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn free_runtime_dde_block(
        &mut self,
        identity: win16_abi::GlobalHandle,
    ) -> Result<(), RuntimeError> {
        let mut locked = self
            .dde_retired_guest_blocks
            .iter()
            .find(|entry| entry.identity == identity)
            .map_or(true, |entry| entry.locked);
        self.free_runtime_dde_block_progress(identity, &mut locked)
    }

    pub(in crate::win16_runtime) fn free_runtime_dde_block_unlocked(
        &mut self,
        identity: win16_abi::GlobalHandle,
    ) -> Result<(), RuntimeError> {
        let mut locked = self
            .dde_retired_guest_blocks
            .iter()
            .find(|entry| entry.identity == identity)
            .map_or(false, |entry| entry.locked);
        self.free_runtime_dde_block_progress(identity, &mut locked)
    }

    pub(in crate::win16_runtime) fn reserve_dde_guest_block_retirement(
        &mut self,
    ) -> Result<(), RuntimeError> {
        self.reserve_dde_guest_block_retirements(1)
    }

    pub(in crate::win16_runtime) fn reserve_dde_guest_block_retirements(
        &mut self,
        count: usize,
    ) -> Result<(), RuntimeError> {
        self.dde_retired_guest_blocks
            .try_reserve(count)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve exact DDE guest-block retirement before releasing its owner",
                    error,
                )
            })
    }

    pub(in crate::win16_runtime) fn queue_removed_dde_guest_blocks(
        &mut self,
        blocks: Vec<crate::win16_dde::Win16DdeAccessBlock>,
    ) -> Result<(), RuntimeError> {
        self.reserve_dde_guest_block_retirements(blocks.len())?;
        for block in blocks {
            if let Some(existing) = self
                .dde_retired_guest_blocks
                .iter()
                .find(|entry| entry.identity == block.identity)
            {
                if !existing.locked {
                    return Err(invariant(
                        "DDE access block retirement queue changed its exact lock state",
                    ));
                }
                continue;
            }
            self.dde_retired_guest_blocks.push(
                crate::win16_dde::Win16DdeRetiredGuestBlock::pending(block.identity, true),
            );
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn drain_dde_guest_block_retirements(
        &mut self,
    ) -> Result<(), RuntimeError> {
        self.retry_dde_guest_block_retirements()?;
        if let Some(entry) = self.dde_retired_guest_blocks.first() {
            let error = RuntimeError::new(
                Kind::HostFailure,
                format!(
                    "DDE guest block remains retained by {} selector aliases, {} page locks, and {} internal pins",
                    entry.selector_aliases, entry.page_locks, entry.internal_pins,
                ),
            );
            return Err(if let Some(cause) = entry.failure.as_ref() {
                error.with_cleanup(
                    "DDE guest block retained its original cleanup cause",
                    super::super::callback_lifo::shared_runtime_error(Arc::clone(cause)),
                )
            } else {
                error
            });
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn retry_dde_guest_block_retirements(
        &mut self,
    ) -> Result<(), RuntimeError> {
        let mut index = 0;
        while index < self.dde_retired_guest_blocks.len() {
            let (identity, mut locked) = {
                let entry = &self.dde_retired_guest_blocks[index];
                (entry.identity, entry.locked)
            };
            self.free_runtime_dde_block_progress(identity, &mut locked)?;
            if self
                .dde_retired_guest_blocks
                .iter()
                .any(|entry| entry.identity == identity)
            {
                index += 1;
            }
        }
        Ok(())
    }

    fn retain_dde_guest_block_failure(
        &mut self,
        identity: win16_abi::GlobalHandle,
        error: RuntimeError,
    ) -> RuntimeError {
        let Some(entry) = self
            .dde_retired_guest_blocks
            .iter_mut()
            .find(|entry| entry.identity == identity)
        else {
            return RuntimeError::with_source(
                Kind::InternalInvariant,
                "DDE guest-block cleanup failed after its exact queue entry disappeared",
                error,
            );
        };
        entry.phase = crate::win16_dde::Win16DdeGuestBlockRetirementPhase::Retained;
        if entry.failure.is_none() {
            let cause = std::sync::Arc::new(error);
            entry.failure = Some(std::sync::Arc::clone(&cause));
            RuntimeError::with_source(
                cause.kind(),
                "DDE guest-block retirement remains pending with its first typed cause",
                cause,
            )
        } else {
            error
        }
    }

    pub(in crate::win16_runtime) fn free_runtime_dde_block_progress(
        &mut self,
        identity: win16_abi::GlobalHandle,
        locked: &mut bool,
    ) -> Result<(), RuntimeError> {
        if let Some(entry) = self
            .dde_retired_guest_blocks
            .iter()
            .find(|entry| entry.identity == identity)
        {
            if entry.locked != *locked {
                return Err(invariant(
                    "DDE guest-block retry changed its recorded lock progress",
                ));
            }
        } else {
            self.reserve_dde_guest_block_retirement()?;
            self.dde_retired_guest_blocks.push(
                crate::win16_dde::Win16DdeRetiredGuestBlock::pending(identity, *locked),
            );
        }
        if *locked {
            let unlock = {
                let (heap, selectors) = self.memory.heap_and_selectors_mut();
                heap.unlock(identity, selectors)
            };
            unlock.map_err(|error| {
                self.retain_dde_guest_block_failure(
                    identity,
                    RuntimeError::with_source(
                        Kind::InternalInvariant,
                        "DDE runtime snapshot block lost its lock",
                        error,
                    ),
                )
            })?;
            *locked = false;
            if let Some(entry) = self
                .dde_retired_guest_blocks
                .iter_mut()
                .find(|entry| entry.identity == identity)
            {
                entry.locked = false;
            }
        }
        // This is the shared selector/global owner seam. DDE keeps the exact
        // allocation generation in its retirement queue and never re-resolves
        // a recycled guest HGLOBAL word for final release.
        match self.memory.free_runtime_global_on_teardown(identity) {
            Ok(super::super::global_memory::GlobalTeardownResult::Freed) => {
                let index = self
                    .dde_retired_guest_blocks
                    .iter()
                    .position(|entry| entry.identity == identity)
                    .ok_or_else(|| {
                        invariant("DDE guest-block queue entry disappeared after release")
                    })?;
                self.dde_retired_guest_blocks.remove(index);
                *locked = false;
                Ok(())
            }
            Ok(super::super::global_memory::GlobalTeardownResult::Retained {
                selector_aliases,
                page_locks,
                internal_pins,
            }) => {
                if let Some(entry) = self
                    .dde_retired_guest_blocks
                    .iter_mut()
                    .find(|entry| entry.identity == identity)
                {
                    entry.phase = crate::win16_dde::Win16DdeGuestBlockRetirementPhase::Retained;
                    entry.selector_aliases = selector_aliases;
                    entry.page_locks = page_locks;
                    entry.internal_pins = internal_pins;
                }
                Ok(())
            }
            Err(error) => Err(self.retain_dde_guest_block_failure(identity, error)),
        }
    }

    pub(in crate::win16_runtime) fn unregister_retired_dde_callbacks(
        &mut self,
    ) -> Result<(), RuntimeError> {
        let count = self.dde.retired_callback_token_count();
        self.dde_retired_callback_tokens
            .try_reserve(count)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "retain retired DDE callback tokens before dequeue",
                    error,
                )
            })?;
        self.dde_retired_callback_tokens.extend(
            self.dde
                .take_retired_callback_tokens()
                .into_iter()
                .map(Win16GuestCallbackToken),
        );
        while let Some(token) = self.dde_retired_callback_tokens.first().copied() {
            if !self.unregister_guest_callback(token) {
                return Err(invariant(
                    "retired DDE callback token was not registered with the guest scheduler",
                ));
            }
            self.dde_retired_callback_tokens.remove(0);
        }
        Ok(())
    }
}

fn finish_dde_access_compensation(
    original_error: Arc<RuntimeError>,
    result: Win16HostDdeResult,
) -> Result<Win16DdeFinish, RuntimeError> {
    let compensation = validate_dde_access_compensation(&result).and_then(|succeeded| {
        if succeeded {
            Ok(())
        } else {
            Err(RuntimeError::new(
                Kind::InternalInvariant,
                format!(
                    "DDE UnaccessData compensation returned FALSE (DMLERR={:#06x})",
                    result.dde_error
                ),
            ))
        }
    });
    match compensation {
        Ok(()) => Err(super::super::callback_lifo::shared_runtime_error(
            original_error,
        )),
        Err(compensation_error) => Err(RuntimeError::with_source(
            Kind::InternalInvariant,
            "DDE AccessData snapshot failure could not be balanced by UnaccessData",
            DdeCleanupFailure {
                original: super::super::callback_lifo::shared_runtime_error(original_error),
                compensation: compensation_error,
            },
        )),
    }
}

fn validate_dde_access_compensation(result: &Win16HostDdeResult) -> Result<bool, RuntimeError> {
    if result.dde_error != dde_error::NO_ERROR {
        validate_dde_error(result.dde_error)?;
    }
    if result.transaction_result.is_some() || result.data_transfer.is_some() {
        return Err(invariant(
            "DDE UnaccessData compensation carried transaction-only payload",
        ));
    }
    match &result.value {
        Win16HostDdeValue::Boolean(true) if result.dde_error == dde_error::NO_ERROR => Ok(true),
        Win16HostDdeValue::Boolean(false) => Ok(false),
        Win16HostDdeValue::Boolean(true) => Err(invariant(
            "DDE UnaccessData compensation returned TRUE with a DMLERR",
        )),
        _ => Err(invariant(
            "DDE UnaccessData compensation returned a non-Boolean result",
        )),
    }
}

#[derive(Debug)]
struct DdeCleanupFailure {
    original: RuntimeError,
    compensation: RuntimeError,
}

impl fmt::Display for DdeCleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "snapshot failure: {}; compensation failure: {}",
            self.original, self.compensation
        )
    }
}

impl Error for DdeCleanupFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.compensation)
    }
}

fn validate_dde_error(error: u16) -> Result<(), RuntimeError> {
    if (0x4000..=0x4011).contains(&error) {
        return Ok(());
    }
    Err(invariant(
        "native DDEML returned an error outside the SDK 3.1 DMLERR range",
    ))
}

fn validate_dde_error_shape(
    request: &Win16DdeRequest,
    result: &Win16HostDdeResult,
) -> Result<(), RuntimeError> {
    use Win16DdeRequest as R;
    use Win16HostDdeValue as V;

    if matches!(request, R::Initialize { .. })
        && !matches!(
            result.dde_error,
            dde_error::DLL_USAGE | dde_error::INVALIDPARAMETER | dde_error::SYS_ERROR
        )
    {
        return Err(invariant(
            "DdeInitialize returned an error outside its SDK-defined result set",
        ));
    }

    let value_is_failure = match request {
        R::Initialize { .. } => matches!(&result.value, V::Instance(None)),
        R::ConnectList { .. } => matches!(&result.value, V::ConversationList(None)),
        R::QueryNextServer { .. } | R::Connect { .. } | R::Reconnect { .. } => {
            matches!(&result.value, V::Conversation(None))
        }
        R::DisconnectList { .. } => matches!(
            &result.value,
            V::DisconnectedList {
                succeeded: false,
                ..
            }
        ),
        R::Disconnect { .. }
        | R::Uninitialize { .. }
        | R::SetUserHandle { .. }
        | R::AbandonTransaction { .. }
        | R::PostAdvise { .. }
        | R::UnaccessData { .. }
        | R::FreeData { .. }
        | R::FreeString { .. }
        | R::KeepString { .. }
        | R::EnableCallback { .. }
        | R::NameService { .. } => matches!(&result.value, V::Boolean(false)),
        R::QueryConversationInfo { .. } => matches!(&result.value, V::None),
        R::ClientTransaction { .. } => matches!(
            &result.value,
            V::ClientTransaction {
                data: None,
                succeeded: false,
                ..
            }
        ),
        R::CreateData { .. } | R::AddData { .. } => matches!(&result.value, V::Data(None)),
        R::GetData { .. } => matches!(&result.value,
            V::GetData { bytes, copied: 0 } if bytes.is_empty()),
        R::AccessData { .. } => matches!(&result.value, V::None),
        R::CreateString { .. } => matches!(result.value, V::String(None)),
        // A failed query still supplies an empty terminated guest string when
        // the caller supplied storage; a size query has no output bytes.
        R::QueryString { output, .. } => matches!(&result.value,
        V::Text { bytes, characters: 0 }
            if if output.far_pointer != 0 && output.capacity != 0 {
                bytes.as_slice() == [0]
            } else {
                bytes.is_empty()
            }),
        R::CompareStrings { .. } | R::GetLastError { .. } => false,
    };
    if !value_is_failure {
        return Err(invariant(
            "native DDEML error result carries a success-shaped or mismatched value",
        ));
    }
    match request {
        R::ClientTransaction { result_output, .. } => {
            let V::ClientTransaction { entered_native, .. } = &result.value else {
                return Err(invariant(
                    "failed DDE transaction has the wrong result value",
                ));
            };
            let should_have_result = *entered_native && *result_output != 0;
            if result.transaction_result.is_some() != should_have_result {
                return Err(invariant(
                    "failed DDE transaction pdwResult does not match native entry and request",
                ));
            }
        }
        _ if result.transaction_result.is_some() => {
            return Err(invariant(
                "failed non-transaction DDE operation carried a transaction result",
            ));
        }
        _ => {}
    }
    Ok(())
}

fn invariant(message: &'static str) -> RuntimeError {
    super::invariant(message)
}
