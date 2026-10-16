//! Runtime-side registry and frame handling for asynchronous guest callbacks.
//!
//! Producers publish callback requests through `win16_callback_mailbox`; the
//! runtime validates each registered FAR-call ABI before building its guest
//! frame. Source owners retain their receipt until that frame restores context
//! and transfers callback buffers to their retained memory owners.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

// A Win16 callback buffer must fit within one 16-bit selector extent.
const MAX_GUEST_CALLBACK_BUFFER: usize = 65_536;

use guest_core::memory::Memory;
use win16_abi::{Access, DescriptorInfo, GlobalHandle, SelectorRef};

use super::{CallbackKind, Win16State};
#[path = "win16_callback_scheduler_registry.rs"]
mod registry;
pub(super) use registry::{
    CallbackRegistrationRetirementProof, CallbackUnregisterOutcome,
};
#[path = "win16_callback_scheduler_entry.rs"]
mod entry;
use super::callback_scheduler_errors::{callback_binding_error, combine_callback_failure};
use super::callback_entry::{
    Win16CallbackEntry, Win16CallbackEntryFrame, Win16GuestCallbackAbi,
};
#[path = "win16_callback_scheduler_lifecycle.rs"]
mod lifecycle;
#[path = "win16_callback_scheduler_buffers.rs"]
mod buffers;
use crate::{
    DiagnosticKind as Kind, RuntimeError, Win16CallbackArgumentData,
    Win16GuestCallbackEvent, Win16GuestCallbackToken, Win16HostMidiNotificationId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Win16GuestCallbackRegistration {
    pub(super) procedure: u32,
    pub(super) procedure_selector: SelectorRef,
    pub(super) procedure_descriptor: DescriptorInfo,
    pub(super) abi: Win16GuestCallbackAbi,
    retirement_requested: bool,
}

pub(super) struct Win16CallbackScheduler {
    next_token: u64,
    registrations: BTreeMap<Win16GuestCallbackToken, Win16GuestCallbackRegistration>,
    quiescent_unregister_waiters: BTreeSet<Win16GuestCallbackToken>,
    retired_callback_proofs: BTreeMap<Win16GuestCallbackToken, Win16GuestCallbackRegistration>,
    active: Vec<Win16AsynchronousCallbackFrame>,
    pending_cleanup: Vec<AsyncPreEntryCleanup>,
    pending_source_retirements: Vec<AsynchronousCallbackRetirement>,
    retained_buffers: Vec<CallbackBuffer>,
}

impl Default for Win16CallbackScheduler {
    fn default() -> Self {
        Self {
            next_token: 1,
            registrations: BTreeMap::new(),
            quiescent_unregister_waiters: BTreeSet::new(),
            retired_callback_proofs: BTreeMap::new(),
            active: Vec::new(),
            pending_cleanup: Vec::new(),
            pending_source_retirements: Vec::new(),
            retained_buffers: Vec::new(),
        }
    }
}

struct Win16AsynchronousCallbackFrame {
    callback_id: super::CallbackFrameId,
    callback_token: Win16GuestCallbackToken,
    registration: Win16GuestCallbackRegistration,
    active_call: Win16CallbackEntryFrame,
    buffers: Vec<CallbackBuffer>,
    phase: AsynchronousCallbackPhase,
    return_failure: Option<Arc<RuntimeError>>,
    source_bound: bool,
    midi_source: Option<Win16HostMidiNotificationId>,
    source_acknowledged: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AsynchronousCallbackPhase {
    Guest,
    ReturnValidation,
    Returned,
    ReturnFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AsynchronousCallbackRetirement {
    pub(super) callback_id: super::CallbackFrameId,
    pub(super) callback_token: Win16GuestCallbackToken,
    pub(super) source_bound: bool,
    pub(super) midi_source: Option<Win16HostMidiNotificationId>,
    pub(super) source_acknowledged: bool,
    pub(super) terminal_cancelled: bool,
}

pub(super) enum AsynchronousCallbackBeginFailure {
    Rejected { error: RuntimeError },
    RollbackRetained {
        callback_id: super::CallbackFrameId,
        callback_token: Win16GuestCallbackToken,
        error: RuntimeError,
    },
}

impl AsynchronousCallbackBeginFailure {
    pub(super) fn into_runtime_error(self) -> RuntimeError {
        match self {
            Self::Rejected { error } | Self::RollbackRetained { error, .. } => error,
        }
    }
}

impl From<RuntimeError> for AsynchronousCallbackBeginFailure {
    fn from(error: RuntimeError) -> Self {
        Self::Rejected { error }
    }
}

impl From<AsynchronousCallbackBeginFailure> for RuntimeError {
    fn from(failure: AsynchronousCallbackBeginFailure) -> Self {
        failure.into_runtime_error()
    }
}

pub(super) enum Win16AsynchronousCallbackArgument {
    Word(u16),
    Dword(u32),
    OwnedBytes { bytes: Vec<u8>, access: Access },
    GuestFarPointer {
        far: u32,
        access: Access,
        bytes: u32,
        selector_generation: Option<u64>,
        allow_null: bool,
    },
}

pub(super) struct Win16AsynchronousCallbackRequest {
    pub(super) callback: Win16GuestCallbackToken,
    pub(super) arguments: Vec<Win16AsynchronousCallbackArgument>,
    pub(super) event: Win16GuestCallbackEvent,
}

impl Win16AsynchronousCallbackRequest {
    fn from_mailbox(mut event: Win16GuestCallbackEvent) -> Result<Self, RuntimeError> {
        let values = std::mem::take(&mut event.arguments);
        let mut arguments = Vec::new();
        arguments.try_reserve_exact(values.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve asynchronous Win16 callback arguments",
                error,
            )
        })?;
        for value in values {
            arguments.push(match value {
                Win16CallbackArgumentData::Word(value) => {
                    Win16AsynchronousCallbackArgument::Word(value)
                }
                Win16CallbackArgumentData::Dword(value) => {
                    Win16AsynchronousCallbackArgument::Dword(value)
                }
                Win16CallbackArgumentData::OwnedBytes { bytes, access } => {
                    Win16AsynchronousCallbackArgument::OwnedBytes { bytes, access }
                }
            });
        }
        Ok(Self { callback: event.callback, arguments, event })
    }
}

struct AsyncPreEntryCleanup {
    callback_id: super::CallbackFrameId,
    callback_token: Win16GuestCallbackToken,
    registration: Win16GuestCallbackRegistration,
    buffers: Vec<CallbackBuffer>,
    primary: Arc<RuntimeError>,
    source_bound: bool,
    phase: AsyncPreEntryCleanupPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AsyncPreEntryCleanupPhase {
    BuffersPending,
    SourceReleasePending,
}

#[derive(Default)]
pub(super) struct CallbackBuffer {
    allocation: Option<GlobalHandle>,
    locked: bool,
    first_failure: Option<Arc<RuntimeError>>,
    retained: Option<super::global_memory::GlobalTeardownResult>,
}

impl CallbackBuffer {
    pub(super) fn owns_guest_allocation(&self) -> bool {
        self.allocation.is_some()
    }
}

impl Win16CallbackScheduler {
    pub(super) fn needs_scheduler_progress(&self) -> bool {
        !self.active.is_empty()
            || !self.pending_cleanup.is_empty()
            || !self.pending_source_retirements.is_empty()
            || !self.retained_buffers.is_empty()
            || !self.quiescent_unregister_waiters.is_empty()
    }

    pub(in crate::win16_runtime) fn unregister_guest_callback(
        &mut self,
        token: Win16GuestCallbackToken,
    ) -> bool {
        self.unregister(token).is_some()
    }

    pub(super) fn code_references(&self) -> Vec<u32> {
        let mut references = Vec::with_capacity(self.registrations.len() + self.active.len() * 2);
        references.extend(self.registrations.values().map(|entry| entry.procedure));
        for frame in &self.active {
            references.extend(frame.active_call.code_references());
            references.push(frame.registration.procedure);
        }
        references.extend(self.pending_cleanup.iter().map(|pending| pending.registration.procedure));
        references
    }

    pub(super) fn has_active_frames(&self) -> bool {
        !self.active.is_empty()
    }

    pub(super) fn native_sources_quiescent(&self) -> bool {
        self.registrations.is_empty() && self.active.is_empty()
            && self.pending_cleanup.is_empty() && self.pending_source_retirements.is_empty()
    }

    pub(super) fn has_pending_cleanup(&self) -> bool {
        !self.pending_cleanup.is_empty()
    }

    /// Return the exact retained pre-entry cleanup at the queue head. The
    /// terminal driver retries this owner before retiring later callback
    /// sources, preserving the scheduler's original cleanup order.
    pub(super) fn next_pre_entry_cleanup(
        &self,
    ) -> Option<(super::CallbackFrameId, bool)> {
        self.pending_cleanup
            .first()
            .map(|pending| (pending.callback_id, pending.source_bound))
    }

    pub(super) fn has_pending_source_retirement(&self) -> bool {
        !self.pending_source_retirements.is_empty()
    }

    pub(super) fn asynchronous_top_source_bound(&self) -> bool {
        self.active.last().is_some_and(|frame| frame.source_bound)
    }

    pub(super) fn asynchronous_top_identity(
        &self,
    ) -> Option<(super::CallbackFrameId, Win16GuestCallbackToken)> {
        self.active.last().map(|frame| (frame.callback_id, frame.callback_token))
    }

    pub(super) fn has_active_midi_frame(&self) -> bool {
        self.active.iter().any(|frame| frame.midi_source.is_some())
    }

    pub(super) fn reserve_source_retirement(&mut self) -> Result<(), RuntimeError> {
        self.pending_source_retirements.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain asynchronous callback source-retirement receipt",
                error,
            )
        })
    }

    pub(super) fn retain_source_retirement(
        &mut self,
        receipt: AsynchronousCallbackRetirement,
    ) {
        self.pending_source_retirements.push(receipt);
    }

    pub(super) fn pending_source_retirements(
        &self,
    ) -> &[AsynchronousCallbackRetirement] {
        &self.pending_source_retirements
    }
}

impl Win16State {
    /// Allocate from the callback-family identity sequence used by the
    /// central v2 scheduler contract. Other families still need its shared
    /// LIFO binding before teardown can cancel them through this owner.
    pub(super) fn reserve_callback_frame_id(
        &mut self,
    ) -> Result<super::CallbackFrameId, RuntimeError> {
        if self.callback_kinds.len() != self.callback_frame_ids.len() {
            return Err(callback_binding_error(
                "Win16 callback kind and identity stacks differ before frame reservation",
            ));
        }
        if self.next_callback_frame_id == 0 {
            return Err(callback_binding_error(
                "Win16 callback-frame identity sequence contains its reserved zero value",
            ));
        }
        self.callback_kinds.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain Win16 callback-kind stack entry",
                error,
            )
        })?;
        self.callback_frame_ids.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain Win16 callback identity stack entry",
                error,
            )
        })?;
        let id = self.next_callback_frame_id;
        self.next_callback_frame_id = id.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 callback-frame identities exhausted",
            )
        })?;
        Ok(super::CallbackFrameId(id))
    }

    pub(super) fn unregister_guest_callback(
        &mut self,
        token: Win16GuestCallbackToken,
    ) -> Option<Win16GuestCallbackRegistration> {
        self.callback_scheduler.unregister(token)
    }

    pub(super) fn unregister_guest_callback_if_quiescent(
        &mut self,
        token: Win16GuestCallbackToken,
    ) -> CallbackUnregisterOutcome {
        self.callback_scheduler.unregister_if_quiescent(token)
    }

    pub(super) fn begin_asynchronous_guest_callback(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        event: Win16GuestCallbackEvent,
    ) -> Result<Option<super::CallbackFrameId>, AsynchronousCallbackBeginFailure> {
        let request = Win16AsynchronousCallbackRequest::from_mailbox(event)?;
        self.begin_asynchronous_guest_callback_request_source(cpu, dos, memory, request, false)
    }

    pub(super) fn begin_asynchronous_guest_callback_request_source(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        request: Win16AsynchronousCallbackRequest,
        source_bound: bool,
    ) -> Result<Option<super::CallbackFrameId>, AsynchronousCallbackBeginFailure> {
        self.begin_asynchronous_guest_callback_request_from_source(
            cpu, dos, memory, request, source_bound, None,
        )
    }

    pub(super) fn begin_asynchronous_guest_callback_midi_source(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        event: Win16GuestCallbackEvent,
        identity: Win16HostMidiNotificationId,
    ) -> Result<Option<super::CallbackFrameId>, AsynchronousCallbackBeginFailure> {
        let request = Win16AsynchronousCallbackRequest::from_mailbox(event)?;
        self.begin_asynchronous_guest_callback_request_from_source(
            cpu, dos, memory, request, true, Some(identity),
        )
    }

    fn begin_asynchronous_guest_callback_request_from_source(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        request: Win16AsynchronousCallbackRequest,
        source_bound: bool,
        midi_source: Option<Win16HostMidiNotificationId>,
    ) -> Result<Option<super::CallbackFrameId>, AsynchronousCallbackBeginFailure> {
        if request.callback != request.event.callback {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "asynchronous callback request token does not match its retained event",
            ).into());
        }
        self.begin_asynchronous_guest_callback_entry_from_source(
            cpu,
            dos,
            memory,
            request.callback,
            Win16CallbackEntry::FarCall { arguments: request.arguments },
            source_bound,
            midi_source,
        )
    }

    pub(in crate::win16_runtime) fn require_asynchronous_callback_top(
        &self,
        callback_id: super::CallbackFrameId,
        callback_token: Win16GuestCallbackToken,
    ) -> Result<(), RuntimeError> {
        if self.require_callback_top(CallbackKind::Asynchronous)? != callback_id
            || !self.callback_scheduler.active.last().is_some_and(|frame| {
                frame.callback_id == callback_id && frame.callback_token == callback_token
            })
        {
            return Err(callback_binding_error(
                "asynchronous callback is not the exact current kind and family top",
            ));
        }
        Ok(())
    }

    fn retire_asynchronous_callback_top(
        &mut self,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        callback_id: super::CallbackFrameId,
        callback_token: Win16GuestCallbackToken,
    ) -> Result<AsynchronousCallbackRetirement, RuntimeError> {
        self.require_asynchronous_callback_top(callback_id, callback_token)?;
        let mut frame = self.callback_scheduler.active.pop().ok_or_else(||
            callback_binding_error("asynchronous callback frame disappeared during retirement"))?;
        if frame.callback_id != callback_id || frame.callback_token != callback_token {
            self.callback_scheduler.active.push(frame);
            return Err(callback_binding_error(
                "asynchronous callback retirement removed a different family frame",
            ));
        }
        if let Err(error) = self.release_guest_callback_entry_owner(
            &mut frame.active_call, dos, memory,
        ) {
            self.callback_scheduler.active.push(frame);
            return Err(error);
        }
        if let Err(error) = self.retire_callback_binding(CallbackKind::Asynchronous, callback_id) {
            self.callback_scheduler.active.push(frame);
            return Err(error);
        }
        Ok(AsynchronousCallbackRetirement {
            callback_id,
            callback_token,
            source_bound: frame.source_bound,
            midi_source: frame.midi_source,
            source_acknowledged: frame.source_acknowledged,
            terminal_cancelled: false,
        })
    }

    fn retain_failed_pre_entry_cleanup(
        &mut self,
        callback_id: super::CallbackFrameId,
        callback_token: Win16GuestCallbackToken,
        registration: Win16GuestCallbackRegistration,
        mut buffers: Vec<CallbackBuffer>,
        source_bound: bool,
        primary: RuntimeError,
    ) -> AsynchronousCallbackBeginFailure {
        match self.release_callback_buffers(&mut buffers) {
            Ok(()) => AsynchronousCallbackBeginFailure::Rejected { error: primary },
            Err(cleanup) => {
                let primary = Arc::new(primary);
                let error = combine_callback_failure(
                    Arc::clone(&primary),
                    cleanup,
                    "asynchronous callback entry failed and temporary-buffer rollback also failed",
                );
                self.callback_scheduler.pending_cleanup.push(AsyncPreEntryCleanup {
                    callback_id,
                    callback_token,
                    registration,
                    buffers,
                    primary,
                    source_bound,
                    phase: AsyncPreEntryCleanupPhase::BuffersPending,
                });
                AsynchronousCallbackBeginFailure::RollbackRetained {
                    callback_id,
                    callback_token,
                    error,
                }
            }
        }
    }

    pub(in crate::win16_runtime) fn retry_asynchronous_pre_entry_cleanup(
        &mut self,
        callback_id: super::CallbackFrameId,
    ) -> Result<Option<AsynchronousCallbackRetirement>, RuntimeError> {
        let Some(index) = self.callback_scheduler.pending_cleanup.iter()
            .position(|pending| pending.callback_id == callback_id) else {
            return Ok(None);
        };
        if self.callback_scheduler.pending_cleanup[index].phase
            == AsyncPreEntryCleanupPhase::BuffersPending
        {
            let mut buffers = {
                let pending = &mut self.callback_scheduler.pending_cleanup[index];
                let _roots = pending.registration.procedure;
                std::mem::take(&mut pending.buffers)
            };
            if let Err(cleanup) = self.release_callback_buffers(&mut buffers) {
                // The retained queue normally owns failed releases. Preserve
                // any local owner too if its preallocated queue was exhausted.
                self.callback_scheduler.pending_cleanup[index].buffers = buffers;
                let pending = &self.callback_scheduler.pending_cleanup[index];
                return Err(combine_callback_failure(
                    Arc::clone(&pending.primary),
                    cleanup,
                    "asynchronous callback rollback still owns a guest buffer",
                ));
            }
        }
        let pending = &self.callback_scheduler.pending_cleanup[index];
        let receipt = AsynchronousCallbackRetirement {
            callback_id: pending.callback_id,
            callback_token: pending.callback_token,
            source_bound: pending.source_bound,
            midi_source: None,
            source_acknowledged: false,
            terminal_cancelled: false,
        };
        if pending.source_bound {
            self.callback_scheduler.pending_cleanup[index].phase =
                AsyncPreEntryCleanupPhase::SourceReleasePending;
        } else {
            self.callback_scheduler.pending_cleanup.remove(index);
            self.callback_scheduler.retire_requested_registration(receipt.callback_token);
        }
        Ok(Some(receipt))
    }

    pub(in crate::win16_runtime) fn complete_asynchronous_pre_entry_source_release(
        &mut self,
        callback_id: super::CallbackFrameId,
        callback_token: Win16GuestCallbackToken,
    ) -> Result<(), RuntimeError> {
        let Some(index) = self.callback_scheduler.pending_cleanup.iter()
            .position(|pending| pending.callback_id == callback_id) else {
            return Err(callback_binding_error(
                "asynchronous callback source-release receipt is no longer retained",
            ));
        };
        let pending = &self.callback_scheduler.pending_cleanup[index];
        if pending.phase != AsyncPreEntryCleanupPhase::SourceReleasePending
            || !pending.source_bound
            || pending.callback_token != callback_token
        {
            return Err(callback_binding_error(
                "asynchronous callback source release does not match its retained receipt",
            ));
        }
        self.callback_scheduler.pending_cleanup.remove(index);
        self.callback_scheduler.retire_requested_registration(callback_token);
        Ok(())
    }

    pub(in crate::win16_runtime) fn complete_asynchronous_source_retirement(
        &mut self,
        callback_id: super::CallbackFrameId,
        callback_token: Win16GuestCallbackToken,
    ) -> Result<(), RuntimeError> {
        let Some(index) = self.callback_scheduler.pending_source_retirements.iter()
            .position(|receipt| receipt.callback_id == callback_id
                && receipt.callback_token == callback_token) else {
            return Err(callback_binding_error(
                "asynchronous callback terminal source receipt was not retained",
            ));
        };
        self.callback_scheduler.pending_source_retirements.remove(index);
        self.callback_scheduler.retire_requested_registration(callback_token);
        Ok(())
    }

    pub(in crate::win16_runtime) fn pending_asynchronous_source_retirements(
        &self,
    ) -> &[AsynchronousCallbackRetirement] {
        self.callback_scheduler.pending_source_retirements()
    }

    pub(super) fn asynchronous_callback_code_references(&self) -> Vec<u32> {
        self.callback_scheduler.code_references()
    }

}
