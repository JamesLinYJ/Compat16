//! Runtime ownership of asynchronous NCBs and Win16 POST continuations.
//!
//! A host completion is copied here before guest writes or callback entry.
//! Its exact identity remains until commit and, for POST, callback CPU restoration.

use guest_core::{memory::Memory, Registers};
use std::sync::Arc;
use win16_abi::SegmentedPointer;

use super::callback_scheduler::{
    AsynchronousCallbackBeginFailure, AsynchronousCallbackRetirement,
    CallbackRegistrationRetirementProof, CallbackUnregisterOutcome,
    Win16AsynchronousCallbackArgument, Win16AsynchronousCallbackRequest,
};
use super::guest_ranges::GuestOutputRange;
use super::netbios_call;
use super::netbios_validation::{self, NetbiosCallValidation};
use super::netbios_wire::{NCB16_BYTES, NRC_PENDING, Ncb16Wire};
use super::{CallbackFrameId, Win16State};
#[path = "win16_netbios_teardown.rs"]
mod teardown;
use teardown::{TeardownProgress, remember_failure, report_retirement_failure_warnings_once};
use teardown::{retained_teardown_error, shared_netbios_error, teardown_handoff_started, teardown_receipt_did_not_regress};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16CallbackArgumentData,
    Win16GuestCallbackEvent, Win16GuestCallbackToken, Win16HostNetbiosId,
    Win16HostNetbiosResult, Win16HostNetbiosTeardownReason, Win16HostNetbiosTeardownReceipt};

const NRC_CANCEL: u8 = 0x26;
const NRC_GOODRET: u8 = 0x00;

#[derive(Default)]
pub(super) struct Win16NetbiosState {
    pending: Vec<PendingNcb>,
}

impl Win16NetbiosState {
    pub(super) fn needs_scheduler_progress(&self) -> bool {
        !self.pending.is_empty()
    }
}

struct PendingNcb {
    host_id: Win16HostNetbiosId,
    guest_ncb: SegmentedPointer,
    ncb: Ncb16Wire,
    ncb_output: GuestOutputRange,
    buffer_output: Option<GuestOutputRange>,
    validation: NetbiosCallValidation,
    post: Option<Win16GuestCallbackToken>,
    completion: Option<Win16HostNetbiosResult>,
    result_written: bool, callback_id: Option<CallbackFrameId>,
    callback_cleanup: bool, callback_acknowledged: bool,
    teardown: Option<Win16HostNetbiosTeardownReceipt>,
    teardown_guest_cleanup: TeardownGuestCleanup, retirement_diagnostics_reported: bool,
    source_cause: Option<Arc<RuntimeError>>, terminal_state_query_error: Option<Arc<RuntimeError>>,
}

#[derive(Clone, Copy)]
enum TeardownGuestCleanup {
    NotNeeded,
    CallbackPending,
    CallbackRetired(CallbackRegistrationRetirementProof),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum NetbiosDispatch {
    Idle,
    Completed,
    CallbackEntered,
}

impl Win16State {
    pub(super) fn submit_netbios_async(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        call: crate::Win16HostNetbiosCall,
        validation: NetbiosCallValidation,
        ncb: Ncb16Wire,
        ncb_output: GuestOutputRange,
        buffer_output: Option<GuestOutputRange>,
        return_to: (u16, u16, u32),
    ) -> Result<(), RuntimeError> {
        if ncb.post.get() != 0 {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "Win16 asynchronous POST calling convention and continuation contract are unverified",
            ));
        }
        self.netbios.pending.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain asynchronous Win16 NetBIOS NCB receipt",
                error,
            )
        })?;
        let post = None;
        let submission = match host.win16_netbios_submit(call) {
            Ok(submission) => submission,
            Err(error) => {
                if let Some(token) = post {
                    self.unregister_guest_callback(token);
                }
                return Err(error);
            }
        };
        if submission.id.0 == 0 && submission.inline_terminal {
            return Err(netbios_invariant(
                "inline terminal NetBIOS submission has no exact native source identity",
            ));
        }
        if submission.id.0 != 0
            && !submission.inline_terminal
            && submission.completion.is_some()
        {
            return Err(netbios_invariant(
                "pending NetBIOS submission supplied an unclassified terminal snapshot",
            ));
        }
        if submission.id.0 == 0 {
            let completed = match submission.completion {
                Some(result) => netbios_validation::validate_result(&validation, &result).and_then(|()| {
                    netbios_call::commit_result_to_guest(
                        self,
                        memory,
                        &ncb_output,
                        buffer_output.as_ref(),
                        ncb,
                        &result,
                    )?;
                    Ok(result)
                }),
                None => Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "immediate NetBIOS submission omitted its terminal result",
                )),
            };
            if let Some(token) = post {
                self.unregister_guest_callback(token);
            }
            let result = completed?;
            registers.set_al(result.function_return);
            return self.complete_kernel_register_return(registers, return_to);
        }
        self.netbios.pending.push(PendingNcb {
            host_id: submission.id,
            guest_ncb: ncb_output.start(),
            ncb,
            ncb_output,
            buffer_output,
            validation,
            post,
            completion: submission.completion.clone(),
            result_written: false,
            callback_id: None,
            callback_cleanup: false,
            callback_acknowledged: false,
            teardown: None,
            teardown_guest_cleanup: if post.is_some() {
                TeardownGuestCleanup::CallbackPending
            } else {
                TeardownGuestCleanup::NotNeeded
            },
            retirement_diagnostics_reported: false, source_cause: None,
            terminal_state_query_error: None,
        });
        if submission.inline_terminal {
            if let Some(result) = submission.completion.as_ref() {
                netbios_validation::validate_result(&validation, result)?;
                let pending = self.netbios.pending.last().ok_or_else(|| {
                    netbios_invariant("inline NetBIOS source row was not retained")
                })?;
                netbios_call::commit_result_to_guest(
                    self,
                    memory,
                    &pending.ncb_output,
                    pending.buffer_output.as_ref(),
                    pending.ncb,
                    result,
                )?;
                self.netbios.pending.last_mut().ok_or_else(|| {
                    netbios_invariant("inline NetBIOS source row disappeared after commit")
                })?.result_written = true;
                registers.set_al(result.function_return);
                // No unverified guest POST continuation is accepted. Keep an
                // inline terminal source reachable until exact ACK succeeds.
                if host.win16_netbios_ack(submission.id)? {
                    self.netbios.pending.pop();
                }
            } else {
                // The provider knows this request already terminated but could
                // not yet build a safe output projection. Retain its exact row
                // and publish only the independent function return in AL.
                registers.set_al(submission.initial.function_return);
            }
        } else {
            // Retain the exact accepted native source before validating any
            // provider-supplied pending image, so malformed output remains
            // reachable by task cleanup.
            validate_pending_submission(&submission.initial, &validation)?;
            let pending = self.netbios.pending.last().ok_or_else(|| {
                netbios_invariant("asynchronous NetBIOS ledger row was not retained")
            })?;
            netbios_call::commit_result_to_guest(
                self,
                memory,
                &pending.ncb_output,
                None,
                pending.ncb,
                &submission.initial,
            )?;
            registers.set_al(submission.initial.function_return);
        }
        self.complete_kernel_register_return(registers, return_to)
    }

    fn advance_netbios_teardown(
        &mut self,
        index: usize,
        reason: Win16HostNetbiosTeardownReason,
        host: &mut impl RuntimeHost,
    ) -> Result<TeardownProgress, RuntimeError> {
        let pending = self.netbios.pending.get(index).ok_or_else(|| {
            netbios_invariant("NetBIOS teardown source row disappeared before receipt")
        })?;
        if pending.callback_id.is_some() {
            return Ok(TeardownProgress::Retained);
        }
        let id = pending.host_id;
        let receipt = host.win16_netbios_teardown(id, reason)?;
        if receipt.id != id || receipt.reason != reason || id.0 == 0 {
            return Err(netbios_invariant(
                "NetBIOS teardown returned a different exact source identity or reason",
            ));
        }
        if !receipt.failure_diagnostics.is_well_formed() {
            return Err(netbios_invariant(
                "NetBIOS teardown returned inconsistent phase error counts",
            ));
        }
        if !teardown_handoff_started(&receipt) {
            return Ok(TeardownProgress::NotAccepted);
        }
        {
            let pending = self.netbios.pending.get_mut(index).ok_or_else(|| {
                netbios_invariant("NetBIOS teardown source row disappeared while caching receipt")
            })?;
            if let Some(previous) = pending.teardown.as_ref() {
                if previous.id != receipt.id || previous.reason != receipt.reason {
                    return Err(netbios_invariant(
                        "NetBIOS teardown changed the exact retained source owner",
                    ));
                }
                if !teardown_receipt_did_not_regress(previous, &receipt) {
                    return Err(netbios_invariant(
                        "NetBIOS teardown discarded native proof or regressed its cached phase",
                    ));
                }
                if let Some(previous_cause) = previous.cause.as_ref()
                    && receipt.cause.as_ref().is_none_or(|cause| {
                        !Arc::ptr_eq(previous_cause, cause)
                    })
                {
                    return Err(netbios_invariant(
                        "NetBIOS teardown discarded or replaced its original typed cause",
                    ));
                }
                if let Some(previous_cleanup) = previous.cleanup_error.as_ref()
                    && receipt.cleanup_error.as_ref().is_none_or(|cleanup| {
                        !Arc::ptr_eq(previous_cleanup, cleanup)
                    })
                {
                    return Err(netbios_invariant(
                        "NetBIOS teardown discarded or replaced a cached native cleanup error",
                    ));
                }
            }
            if pending.source_cause.is_none() {
                pending.source_cause = receipt.cause.as_ref().map(Arc::clone);
            }
            pending.teardown = Some(receipt.clone());
        }
        if !receipt.native_owner_retired() {
            return Ok(TeardownProgress::Retained);
        }

        match self.netbios.pending[index].teardown_guest_cleanup {
            TeardownGuestCleanup::NotNeeded => {
                if self.netbios.pending[index].post.is_some() {
                    return Err(netbios_invariant(
                        "NetBIOS POST source lost its callback-retirement phase",
                    ));
                }
            }
            TeardownGuestCleanup::CallbackPending => {
                let token = self.netbios.pending[index].post.ok_or_else(|| {
                    netbios_invariant(
                        "NetBIOS callback-retirement phase lost its exact POST token",
                    )
                })?;
                let proof = match self.unregister_guest_callback_if_quiescent(token) {
                    CallbackUnregisterOutcome::Unregistered(proof)
                    | CallbackUnregisterOutcome::AlreadyRetired(proof) => proof,
                    CallbackUnregisterOutcome::Retained => {
                        return Ok(TeardownProgress::Retained);
                    }
                };
                self.netbios.pending[index].teardown_guest_cleanup =
                    TeardownGuestCleanup::CallbackRetired(proof);
                if !proof.matches_token(token) {
                    return Err(netbios_invariant(
                        "callback-retirement proof names a different POST registration",
                    ));
                }
            }
            TeardownGuestCleanup::CallbackRetired(proof) => {
                let token = self.netbios.pending[index].post.ok_or_else(|| {
                    netbios_invariant(
                        "cached callback-retirement proof lost its exact POST token",
                    )
                })?;
                if !proof.matches_token(token) {
                    return Err(netbios_invariant(
                        "cached callback-retirement proof names a different POST registration",
                    ));
                }
            }
        }
        let exact_receipt = self.netbios.pending[index].teardown.as_ref()
            .ok_or_else(|| netbios_invariant(
                "retired NetBIOS source lost its exact teardown receipt",
            ))?.clone();
        if !exact_receipt.native_owner_retired() {
            return Err(netbios_invariant(
                "NetBIOS teardown ACK was attempted without native retirement proof",
            ));
        }
        report_retirement_failure_warnings_once(
            &mut self.netbios.pending[index].retirement_diagnostics_reported,
            &exact_receipt,
            host,
        );
        if host.win16_netbios_teardown_ack(&exact_receipt)? {
            self.netbios.pending.remove(index);
            Ok(TeardownProgress::Retired)
        } else {
            Ok(TeardownProgress::Retained)
        }
    }

    pub(in crate::win16_runtime) fn dispatch_pending_netbios_notification(
        &mut self,
        cpu: &mut x86_cpu::Cpu, dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<NetbiosDispatch, RuntimeError> {
        if let Some((index, callback_id)) = self.netbios.pending.iter()
            .enumerate()
            .find_map(|(index, pending)| {
                (pending.callback_cleanup)
                    .then_some(pending.callback_id.map(|id| (index, id)))
                    .flatten()
            })
        {
            let receipt = self.retry_asynchronous_pre_entry_cleanup(callback_id)?
                .ok_or_else(|| netbios_invariant(
                    "NetBIOS callback rollback receipt disappeared before retry",
                ))?;
            if receipt.callback_id != callback_id || !receipt.source_bound {
                return Err(netbios_invariant(
                    "NetBIOS callback rollback returned a different source-bound frame",
                ));
            }
            let pending = self.netbios.pending.get(index).ok_or_else(|| {
                netbios_invariant("NetBIOS callback rollback row disappeared")
            })?;
            if pending.post != Some(receipt.callback_token) {
                return Err(netbios_invariant(
                    "NetBIOS callback rollback receipt does not match its guest POST",
                ));
            }
            let already_acknowledged = pending.callback_acknowledged;
            let host_id = pending.host_id;
            if !already_acknowledged {
                if !host.win16_netbios_ack(host_id)? {
                    return Ok(NetbiosDispatch::Idle);
                }
                self.netbios.pending[index].callback_acknowledged = true;
            }
            self.complete_asynchronous_pre_entry_source_release(
                callback_id,
                receipt.callback_token,
            )?;
            // Unregister may be deferred while the generic frame still owns
            // this token. The scheduler performs final retirement after the
            // exact pre-entry source receipt is complete.
            self.unregister_guest_callback(receipt.callback_token);
            self.netbios.pending.remove(index);
            return Ok(NetbiosDispatch::Completed);
        }

        let mut ready = None;
        let mut pending_index = 0;
        while pending_index < self.netbios.pending.len() {
            if self.netbios.pending[pending_index].callback_id.is_some() {
                pending_index += 1;
                continue;
            }
            if let Some(receipt) = self.netbios.pending[pending_index].teardown.as_ref() {
                let reason = receipt.reason;
                match self.advance_netbios_teardown(pending_index, reason, host)? {
                    TeardownProgress::Retired => return Ok(NetbiosDispatch::Completed),
                    TeardownProgress::Retained => {
                        pending_index += 1;
                        continue;
                    }
                    TeardownProgress::NotAccepted => return Err(netbios_invariant(
                        "host discarded an already accepted NetBIOS teardown request",
                    )),
                }
            }
            if self.netbios.pending[pending_index].completion.is_none() {
                let id = self.netbios.pending[pending_index].host_id;
                match host.win16_netbios_completion(id) {
                    Ok(Some(result)) => {
                        self.netbios.pending[pending_index].completion = Some(result);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        let primary = Arc::new(error);
                        if self.netbios.pending[pending_index].source_cause.is_none() {
                            self.netbios.pending[pending_index].source_cause =
                                Some(Arc::clone(&primary));
                        }
                        let reported = shared_netbios_error(
                            Arc::clone(&primary),
                            "NetBIOS completion could not be delivered through its exact source",
                        );
                        let teardown = match host.win16_netbios_terminal_wake_unavailable() {
                            Ok(true) => self.advance_netbios_teardown(
                                pending_index,
                                Win16HostNetbiosTeardownReason::TerminalWakeUnavailable,
                                host,
                            ),
                            Ok(false) => return Err(reported),
                            Err(query_error) => {
                                let cached = self.netbios.pending[pending_index]
                                    .terminal_state_query_error
                                    .get_or_insert_with(|| Arc::new(query_error));
                                return Err(reported.with_cleanup(
                                    "shared USER wake terminal state could not be verified; NetBIOS source remains retained",
                                    shared_netbios_error(
                                        Arc::clone(cached),
                                        "query shared USER wake terminal state",
                                    ),
                                ));
                            }
                        };
                        return Err(match teardown {
                            Ok(TeardownProgress::Retired) => reported,
                            Ok(TeardownProgress::NotAccepted) => reported,
                            Ok(TeardownProgress::Retained) => reported.with_cleanup(
                                "NetBIOS terminal wake failed and its source remains retained",
                                retained_teardown_error(
                                    &self.netbios.pending[pending_index],
                                ),
                            ),
                            Err(cleanup) => reported.with_cleanup(
                                "NetBIOS terminal wake and native teardown both failed",
                                cleanup,
                            ),
                        });
                    }
                }
            }
            if self.netbios.pending[pending_index].completion.is_some() {
                ready = Some(pending_index);
                break;
            }
            pending_index += 1;
        }
        let Some(index) = ready else {
            return Ok(NetbiosDispatch::Idle);
        };

        let (host_id, post, already_written) = {
            let pending = &self.netbios.pending[index];
            (pending.host_id, pending.post, pending.result_written)
        };
        if !already_written {
            let (ncb, ncb_output, buffer_output, validation, result) = {
                let pending = &self.netbios.pending[index];
                (
                    pending.ncb,
                    pending.ncb_output.try_clone()?,
                    pending.buffer_output.as_ref().map(GuestOutputRange::try_clone).transpose()?,
                    pending.validation,
                    pending.completion.as_ref().ok_or_else(|| {
                        netbios_invariant("ready NetBIOS source has no terminal result")
                    })?.clone(),
                )
            };
            netbios_validation::validate_result(&validation, &result)?;
            netbios_call::commit_result_to_guest(
                self,
                memory,
                &ncb_output,
                buffer_output.as_ref(),
                ncb,
                &result,
            )?;
            self.netbios.pending[index].result_written = true;
        }

        let Some(post) = post else {
            if !host.win16_netbios_ack(host_id)? {
                return Ok(NetbiosDispatch::Idle);
            }
            self.netbios.pending.remove(index);
            return Ok(NetbiosDispatch::Completed);
        };

        let ncb_far = self.netbios.pending[index].guest_ncb.far_value();
        let mut callback_arguments = Vec::new();
        callback_arguments.try_reserve_exact(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain Win16 NetBIOS POST argument",
                error,
            )
        })?;
        callback_arguments.push(Win16AsynchronousCallbackArgument::Dword(ncb_far));
        let mut event_arguments = Vec::new();
        event_arguments.try_reserve_exact(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain Win16 NetBIOS POST event argument",
                error,
            )
        })?;
        event_arguments.push(Win16CallbackArgumentData::Dword(ncb_far));
        let event = Win16GuestCallbackEvent {
            callback: post,
            arguments: event_arguments,
        };
        let request = Win16AsynchronousCallbackRequest {
            callback: post,
            arguments: callback_arguments,
            event,
        };
        match self.begin_asynchronous_guest_callback_request_source(
            cpu,
            dos, memory, request, true,
        ) {
            Ok(Some(callback_id)) => {
                self.netbios.pending[index].callback_id = Some(callback_id);
                Ok(NetbiosDispatch::CallbackEntered)
            }
            Ok(None) => Err(RuntimeError::new(
                Kind::GuestFault,
                "Win16 NetBIOS POST registration was retired before callback entry",
            )),
            Err(AsynchronousCallbackBeginFailure::RollbackRetained {
                callback_id, error, ..
            }) => {
                self.netbios.pending[index].callback_id = Some(callback_id);
                self.netbios.pending[index].callback_cleanup = true;
                Err(error)
            }
            Err(failure) => Err(failure.into_runtime_error()),
        }
    }

    pub(in crate::win16_runtime) fn finish_netbios_callback_retirement(
        &mut self,
        retirement: AsynchronousCallbackRetirement,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let Some(index) = self.netbios.pending.iter().position(|pending| {
            pending.callback_id == Some(retirement.callback_id)
        }) else {
            return Ok(false);
        };
        if self.netbios.pending[index].post != Some(retirement.callback_token)
            || !self.netbios.pending[index].result_written
            || self.netbios.pending[index].callback_cleanup
        {
            return Err(netbios_invariant(
                "asynchronous callback retirement does not match its retained NetBIOS NCB",
            ));
        }
        if !retirement.source_bound {
            return Err(netbios_invariant(
                "NetBIOS POST callback retirement lost its source binding",
            ));
        }
        let host_id = self.netbios.pending[index].host_id;
        if !self.netbios.pending[index].callback_acknowledged {
            if !host.win16_netbios_ack(host_id)? {
                return Err(netbios_invariant(
                    "Windows NetBIOS source did not accept the restored POST callback ACK",
                ));
            }
            self.netbios.pending[index].callback_acknowledged = true;
        }
        // None means normal deferred retirement while the generic callback
        // frame still owns the exact registration. The source receipt stays
        // rooted in `pending` until that frame has completed.
        self.unregister_guest_callback(retirement.callback_token);
        Ok(true)
    }

    pub(in crate::win16_runtime) fn has_exact_netbios_callback_retirement(
        &self,
        retirement: AsynchronousCallbackRetirement,
    ) -> bool {
        self.netbios.pending.iter().any(|pending| {
            pending.callback_id == Some(retirement.callback_id)
                && pending.post == Some(retirement.callback_token)
                && pending.result_written
                && !pending.callback_cleanup
        })
    }

    pub(in crate::win16_runtime) fn complete_netbios_callback_frame(
        &mut self,
        retirement: AsynchronousCallbackRetirement,
    ) -> Result<(), RuntimeError> {
        let Some(index) = self.netbios.pending.iter().position(|pending| {
            pending.callback_id == Some(retirement.callback_id)
                && pending.post == Some(retirement.callback_token)
                && pending.callback_acknowledged
                && pending.result_written
        }) else {
            return Err(netbios_invariant(
                "completed generic callback frame has no exact acknowledged NetBIOS source",
            ));
        };
        if !retirement.source_bound {
            return Err(netbios_invariant(
                "completed NetBIOS callback frame lost its source binding",
            ));
        }
        self.netbios.pending.remove(index);
        Ok(())
    }

    pub(super) fn close_netbios_runtime(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let mut failures = None;
        let mut index = 0;
        while index < self.netbios.pending.len() {
            if self.netbios.pending[index].callback_id.is_some() {
                remember_failure(
                    &mut failures,
                    retained_teardown_error(&self.netbios.pending[index]),
                );
                index += 1;
                continue;
            }
            let id = self.netbios.pending[index].host_id;
            let normal_ack = self.netbios.pending[index].result_written
                && self.netbios.pending[index].post.is_none()
                && self.netbios.pending[index].teardown.is_none();
            if normal_ack {
                let ack_failure = match host.win16_netbios_ack(id) {
                    Ok(true) => {
                        self.netbios.pending.remove(index);
                        continue;
                    }
                    Ok(false) => RuntimeError::new(
                        Kind::HostFailure,
                        "committed NetBIOS result remains retained after its exact guest ACK",
                    ),
                    Err(error) => error.with_context(
                        "retry the exact guest ACK for a committed NetBIOS result",
                    ),
                };
                let ack_cause = Arc::new(ack_failure);
                if self.netbios.pending[index].source_cause.is_none() {
                    self.netbios.pending[index].source_cause = Some(Arc::clone(&ack_cause));
                }
                let explicit_teardown = self.advance_netbios_teardown(
                    index,
                    Win16HostNetbiosTeardownReason::TaskTeardown,
                    host,
                );
                let reported = shared_netbios_error(
                    Arc::clone(&ack_cause),
                    "normal NetBIOS guest ACK failed during explicit task teardown",
                );
                match explicit_teardown {
                    Ok(TeardownProgress::Retired) => {
                        remember_failure(&mut failures, reported.with_context(
                            "native teardown retired the source after the guest ACK failure",
                        ));
                        continue;
                    }
                    Ok(TeardownProgress::Retained) => remember_failure(
                        &mut failures,
                        reported.with_cleanup(
                            "native teardown remains retained after the guest ACK failure",
                            retained_teardown_error(&self.netbios.pending[index]),
                        ),
                    ),
                    Ok(TeardownProgress::NotAccepted) => remember_failure(
                        &mut failures,
                        reported.with_cleanup(
                            "host did not accept explicit NetBIOS task teardown",
                            RuntimeError::new(
                                Kind::HostFailure,
                                format!("NetBIOS request {} remains retained", id.0),
                            ),
                        ),
                    ),
                    Err(cleanup) => remember_failure(
                        &mut failures,
                        reported.with_cleanup(
                            "guest ACK and native NetBIOS teardown both failed",
                            cleanup,
                        ),
                    ),
                }
                index += 1;
                continue;
            }

            let reason = self.netbios.pending[index].teardown.as_ref()
                .map_or(Win16HostNetbiosTeardownReason::TaskTeardown, |receipt| receipt.reason);
            match self.advance_netbios_teardown(index, reason, host) {
                Ok(TeardownProgress::Retired) => continue,
                Ok(TeardownProgress::Retained) => remember_failure(
                    &mut failures,
                    retained_teardown_error(&self.netbios.pending[index]),
                ),
                Ok(TeardownProgress::NotAccepted) => remember_failure(
                    &mut failures,
                    RuntimeError::new(
                        Kind::HostFailure,
                        format!(
                            "host retained NetBIOS request {} without accepting its typed teardown handoff",
                            id.0,
                        ),
                    ),
                ),
                Err(error) => remember_failure(
                    &mut failures,
                    error.with_context("advance the exact native NetBIOS teardown receipt"),
                ),
            }
            index += 1;
        }
        failures.map_or(Ok(()), Err)
    }
}

pub(super) fn cancel_target(
    state: &mut Win16State,
    memory: &Memory,
    host: &mut impl RuntimeHost,
    ncb: &Ncb16Wire,
) -> Result<Win16HostNetbiosResult, RuntimeError> {
    let target_far = ncb.buffer_far_value();
    if target_far == 0 {
        return Ok(netbios_call::result_for_ncb(*ncb, NRC_CANCEL));
    }
    let target = state.selectors.pointer_from_far(target_far).map_err(|error| {
        RuntimeError::with_source(
            Kind::GuestFault,
            "NCBCANCEL names an invalid guest NCB FAR pointer",
            error,
        )
    })?;
    GuestOutputRange::capture(state, memory, target, NCB16_BYTES)?;
    let Some(pending) = state.netbios.pending.iter().find(|pending| {
        pending.guest_ncb == target
    }) else {
        return Ok(netbios_call::result_for_ncb(*ncb, NRC_CANCEL));
    };
    let result = host.win16_netbios_cancel(pending.host_id)?;
    match netbios_validation::classify_result(&result)? {
        netbios_validation::NetbiosResultClass::FunctionOnly(_) => return Ok(result),
        netbios_validation::NetbiosResultClass::Pending => {
            return Err(netbios_invariant(
                "NCBCANCEL returned a pending source instead of a terminal function result",
            ));
        }
        netbios_validation::NetbiosResultClass::NcbCompletion => {}
    }
    // The host result describes its private native NCBCANCEL record, whose
    // non-status fields are not the guest's NCB. Keep the caller's fields and
    // transfer only the documented function/completion status back.
    Ok(netbios_call::result_for_ncb(*ncb, result.function_return))
}

fn validate_pending_submission(
    result: &Win16HostNetbiosResult,
    call: &NetbiosCallValidation,
) -> Result<(), RuntimeError> {
    if result.function_return != NRC_GOODRET
        || result.retcode != NRC_PENDING
        || result.cmd_cplt != NRC_PENDING
        || result.length != call.length
        || result.call_name.is_some()
        || !matches!(result.payload, crate::Win16HostNetbiosOutput::None)
    {
        return Err(netbios_invariant(
            "asynchronous NetBIOS submission returned an invalid pending NCB image",
        ));
    }
    Ok(())
}

fn netbios_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
