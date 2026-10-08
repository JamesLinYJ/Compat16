//! Exact-top terminal source ACK and operation-frame retirement.

use super::*;
use dos_kernel::DosKernel;
use x86_cpu::Cpu;
use guest_core::memory::Memory;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum WindowTerminalRetirementStep {
    WindowFrameRetired,
    DdeFrameRetired,
    BlockedBySource(crate::Win16WindowTerminalSourceTop),
    AllRuntimeFramesRetired,
}

impl Win16State {
    /// Complete the USER half of a POST that really entered the worker but
    /// failed before a normal guest notification result could be delivered.
    /// The WAVE/MIDI/MCI/WINSOCK owner retains its own source and payload;
    /// this method retires only the exact USER source, after exact tombstone
    /// readback and shared-ledger top validation.
    pub(in crate::win16_runtime) fn acknowledge_started_post_failure(
        &mut self,
        failure: &std::sync::Arc<crate::Win16WindowOperationStartedFailure>,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if failure.operation.operation_id.0 == 0
            || failure.worker_generation == 0
            || failure.operation.kind
                != crate::Win16NativeWindowOperationKind::PostGuestNotification
            || !matches!(failure.state,
                crate::Win16NativeWindowOperationState::Active
                    | crate::Win16NativeWindowOperationState::Returned)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "USER POST terminal owner has an invalid producer identity or phase"));
        }
        if self.window_teardown_state != super::super::WindowTeardownState::NativeQuiescent {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "USER POST terminal ACK requires the cached native abort receipt"));
        }
        let receipt = self.window_abort_receipt.as_ref().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "USER POST terminal ACK has no retained abort receipt",
        ))?;
        if receipt.worker_generation != failure.worker_generation
            || receipt.request_id == 0
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "USER POST failure belongs to another abort request or worker generation"));
        }
        let operation = failure.operation.operation_id;
        let callback_count = receipt.cancelled_callbacks.iter().filter(|item| {
            item.operation_id == operation
        }).count();
        let modal_count = receipt.cancelled_modals.iter().filter(|item| {
            item.operation_id == operation.0
        }).count();
        let active_count = receipt.active_operations.iter().filter(|proof| {
            proof.operation_id == operation && proof.kind == failure.operation.kind
        }).count();
        let active_for_id = receipt.active_operations.iter().filter(|proof| {
            proof.operation_id == operation
        }).count();
        if callback_count != 0 || modal_count != 0
            || match failure.state {
                crate::Win16NativeWindowOperationState::Active => {
                    active_count != 1 || active_for_id != 1
                }
                crate::Win16NativeWindowOperationState::Returned => active_for_id != 0,
            }
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "USER POST failure has unconsumed callback/modal sources or a mismatched native phase"));
        }
        let ack = crate::Win16WindowTerminalAck {
            worker_generation: failure.worker_generation,
            operation: failure.operation,
            state: failure.state,
            callbacks: Vec::new(),
            modals: Vec::new(),
        };
        if host.win16_window_terminal_acknowledged(receipt, &ack)? {
            return Ok(());
        }
        let top = host.win16_window_terminal_source_top(receipt)?;
        if top != Some(crate::Win16WindowTerminalSourceTop::User {
            operation,
            kind: failure.operation.kind,
            state: failure.state,
            worker_generation: failure.worker_generation,
        }) {
            return Err(RuntimeError::new(Kind::HostFailure,
                "USER POST failure is not the exact top source in the shared host ledger"));
        }
        host.win16_window_terminal_ack(ack)
    }

    /// Retire at most one operation source. The host source-top query spans
    /// the shared USER/DDE ledger; an ACK is attempted only for that exact top.
    pub(in crate::win16_runtime) fn retire_window_operations_for_teardown(
        &mut self,
        ended: &super::super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<WindowTerminalRetirementStep, RuntimeError> {
        if self.window_teardown_state != super::super::WindowTeardownState::NativeQuiescent {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 operation retirement requires the cached native USER quiescence receipt"));
        }
        if !self.callback_kinds.is_empty()
            || !self.callback_frame_ids.is_empty()
            || !self.window_callbacks.is_empty()
            || !self.window_property_callbacks.is_empty()
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 operation retirement requires the entire shared callback LIFO to be empty"));
        }
        let receipt = self.window_abort_receipt.as_ref().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 terminal source selection has no cached native USER receipt",
        ))?;

        // A prior host call may have retired its exact source and then lost
        // the reply. Retry that same cached proof before asking which source
        // is now on top; the host ACK boundary recognizes exact tombstones.
        let retry_terminal = self.window_operations.last().map(|frame| {
            let dde_proof_cached = match frame.continuation() {
                Some(WindowReturn::Dde(continuation)) =>
                    continuation.operation_retirement_proof().is_some(),
                _ => false,
            };
            (frame.terminal_ack_attempted, dde_proof_cached)
        });
        if let Some((true, dde_proof_cached)) = retry_terminal {
            self.retire_terminal_window_operation_top(ended, cpu, dos, memory, host)?;
            return Ok(if dde_proof_cached {
                WindowTerminalRetirementStep::DdeFrameRetired
            } else {
                WindowTerminalRetirementStep::WindowFrameRetired
            });
        }
        if let Some((false, true)) = retry_terminal {
            self.retire_terminal_window_operation_top(ended, cpu, dos, memory, host)?;
            return Ok(WindowTerminalRetirementStep::DdeFrameRetired);
        }
        let source_top = host.win16_window_terminal_source_top(receipt)?;
        let Some(frame_id) = self.window_operations.last().map(|frame| frame.id) else {
            return match source_top {
                None => Ok(WindowTerminalRetirementStep::AllRuntimeFramesRetired),
                Some(source) => Ok(WindowTerminalRetirementStep::BlockedBySource(source)),
            };
        };
        let frame = self.window_operations.last().filter(|frame| frame.id == frame_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "Win16 terminal operation top changed during source selection"))?;
        let lifecycle = frame.lifecycle;
        let is_dde = matches!(frame.continuation(), Some(WindowReturn::Dde(_)));

        if lifecycle == WindowOperationLifecycle::Returned {
            if frame.source_retired.is_none() {
                return self.retain_operation_failure(frame_id, RuntimeError::new(
                    Kind::HostFailure,
                    "returned USER frame has no exact normal source-retirement proof",
                ));
            }
            if let Some(source @ crate::Win16WindowTerminalSourceTop::User {
                operation,
                kind: crate::Win16NativeWindowOperationKind::PostGuestNotification,
                ..
            }) = source_top
            {
                if frame.host_operation == Some(operation) {
                    return self.retain_operation_failure(frame_id, RuntimeError::new(
                        Kind::HostFailure,
                        "normal USER source-retirement proof conflicts with the exact live POST source",
                    ));
                }
                return Ok(WindowTerminalRetirementStep::BlockedBySource(source));
            }
            let terminal_compensation = matches!(frame.continuation(),
                Some(WindowReturn::CleanupPaint { .. } | WindowReturn::CleanupWindowDc { .. }));
            let caller_returned = frame.completion.as_ref().is_some_and(|completion|
                matches!(completion.journal.phase,
                    super::WindowOperationCompletionPhase::CallerReturned { .. }));
            let caller_aborted = match self.terminal_caller_abort_ready(ended, frame_id, cpu) {
                Ok(ready) => ready,
                Err(error) => return self.retain_operation_failure(frame_id, error),
            };
            if !caller_returned && !terminal_compensation && !caller_aborted {
                return self.retain_operation_failure(frame_id, RuntimeError::new(
                    Kind::HostFailure,
                    "returned USER source has neither a checked caller return, terminal caller-abort proof, nor GDI compensation owner",
                ));
            }
            self.retire_normal_window_operation_top(ended, cpu, dos, memory, host, frame_id)?;
            return Ok(WindowTerminalRetirementStep::WindowFrameRetired);
        }

        if matches!(lifecycle, WindowOperationLifecycle::GuestOnly
            | WindowOperationLifecycle::NeverStarted)
        {
            if let Some(source) = source_top {
                return Ok(WindowTerminalRetirementStep::BlockedBySource(source));
            }
            self.retire_terminal_window_operation_top(ended, cpu, dos, memory, host)?;
            return Ok(WindowTerminalRetirementStep::WindowFrameRetired);
        }

        if is_dde {
            let expected = match frame.continuation() {
                Some(WindowReturn::Dde(continuation)) => continuation.host_operation()
                    .ok_or_else(|| RuntimeError::new(Kind::HostFailure,
                        "DDE operation frame has no exact native operation identity"))?,
                _ => unreachable!(),
            };
            match source_top {
                Some(crate::Win16WindowTerminalSourceTop::Dde { operation })
                    if operation == expected => {}
                Some(source @ crate::Win16WindowTerminalSourceTop::User {
                    kind: crate::Win16NativeWindowOperationKind::PostGuestNotification,
                    ..
                }) => return Ok(WindowTerminalRetirementStep::BlockedBySource(source)),
                Some(source) => return Err(RuntimeError::new(Kind::HostFailure,
                    format!("DDE frame {expected:?} is not shared-ledger top {source:?}"))),
                None => return Err(RuntimeError::new(Kind::HostFailure,
                    "DDE operation frame remains after its shared source ledger became empty")),
            }
            self.retire_terminal_window_operation_top(ended, cpu, dos, memory, host)?;
            return Ok(WindowTerminalRetirementStep::DdeFrameRetired);
        }

        let expected = self.terminal_user_operation_ack(frame, receipt)?.ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant,
                "started USER frame produced no exact source acknowledgement")
        })?;
        match source_top {
            Some(crate::Win16WindowTerminalSourceTop::User {
                operation,
                kind,
                state,
                worker_generation,
            }) if operation == expected.operation.operation_id
                && kind == expected.operation.kind
                && state == expected.state
                && worker_generation == expected.worker_generation => {}
            Some(source @ crate::Win16WindowTerminalSourceTop::User {
                kind: crate::Win16NativeWindowOperationKind::PostGuestNotification,
                ..
            }) => return Ok(WindowTerminalRetirementStep::BlockedBySource(source)),
            Some(source) => return Err(RuntimeError::new(Kind::HostFailure,
                format!("USER frame {:?} is not shared-ledger top {source:?}",
                    expected.operation.operation_id))),
            None => return Err(RuntimeError::new(Kind::HostFailure,
                "started USER operation remains after its shared source ledger became empty")),
        }
        self.retire_terminal_window_operation_top(ended, cpu, dos, memory, host)?;
        Ok(WindowTerminalRetirementStep::WindowFrameRetired)
    }

    /// A projected native result can be terminally abandoned only after the
    /// sealed task boundary. Keep this separate from CallerReturned: no guest
    /// return transfer occurred, and the exact retained CPU owner will be
    /// restored by the terminal cleanup path below.
    fn terminal_caller_abort_ready(
        &self,
        _ended: &super::super::execute::Win16TaskExecutionEnded,
        frame_id: u64,
        cpu: &Cpu,
    ) -> Result<bool, RuntimeError> {
        let candidate = self.window_operations.last().filter(|frame| frame.id == frame_id)
            .is_some_and(|frame| {
                let Some(completion) = frame.completion.as_ref() else { return false; };
                frame.lifecycle == WindowOperationLifecycle::Returned
                    && frame.native_state == Some(crate::Win16NativeWindowOperationState::Returned)
                    && completion.source == super::WindowOperationCompletionSource::NativeUser
                    && matches!(completion.journal.phase,
                        super::WindowOperationCompletionPhase::GuestProjected { .. })
                    && completion.journal.first_cause.is_some()
                    && !matches!(frame.continuation(), Some(
                        WindowReturn::CleanupPaint { .. } | WindowReturn::CleanupWindowDc { .. }))
            });
        if !candidate {
            return Ok(false);
        }

        let frame = self.window_operations.last().filter(|frame| frame.id == frame_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "terminal caller-abort candidate lost its exact top frame"))?;
        let (Some(operation), Some(kind), Some(generation), Some(proof), Some(owner)) = (
            frame.host_operation,
            frame.native_source,
            frame.worker_generation,
            frame.source_retired.as_ref(),
            frame.cpu_call_owner,
        ) else {
            return Err(RuntimeError::new(Kind::HostFailure,
                "terminal caller-abort candidate lost its exact source proof or CPU owner"));
        };
        let wait_continuation = matches!(frame.continuation(), Some(
            WindowReturn::GetMessage { .. }
                | WindowReturn::MessageCall(
                    crate::win16_host_message_calls::Win16MessageCallContinuation::WaitMessage { .. }
                )
        ));
        if operation.0 == 0
            || generation == 0
            || proof.operation.operation_id != operation
            || proof.operation.kind != kind
            || proof.worker_generation != generation
            || proof.state != crate::Win16NativeWindowOperationState::Returned
            || frame.guest_callback_id.is_some_and(|callback| callback.0 == 0)
            || frame.guest_callback_id.is_some() != frame.guest_callback_retired
            || frame.terminal_started_failure.is_some()
            || frame.terminal_ack.is_some()
            || frame.terminal_ack_attempted
            || frame.terminal_source_acknowledged
            || !frame.terminal_retired_callbacks.is_empty()
            || !frame.terminal_modal_responses.is_empty()
            || frame.terminal_modal_error.is_some()
            || frame.pending_modal_work.is_some()
            || frame.pending_work.is_some()
            // Successful wait/modal resumes clear their payload slot but
            // retain the exact operation binding as historical identity.
            || (frame.host_wait.is_some() && frame.host_modal_operation.is_some())
            || frame.host_wait.is_some_and(|wait| wait != operation)
            || frame.host_modal_operation.is_some_and(|modal| modal != operation)
            || (frame.host_wait.is_some()
                && (!wait_continuation || frame.last_work_generation == 0))
            || (frame.host_modal_operation.is_some() && frame.last_modal_work_generation == 0)
            || frame.pending_dde_callback.is_some()
            || (frame.terminal_context_restored && !frame.terminal_resources_retired)
            || (frame.source_retirement_consumed && !frame.terminal_context_restored)
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "terminal caller-abort candidate conflicts with its source, callback, modal, or cleanup phase"));
        }
        let receipt = self.window_abort_receipt.as_ref().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "terminal caller-abort candidate has no cached native USER receipt",
        ))?;
        if receipt.worker_generation != generation
            || receipt.request_id == 0
            || receipt.active_operations.iter().any(|active| active.operation_id == operation)
            || receipt.cancelled_callbacks.iter().any(|callback|
                callback.operation_id == operation)
            || receipt.cancelled_modals.iter().any(|modal|
                modal.operation_id == operation.0)
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "terminal caller-abort candidate conflicts with the exact native USER receipt"));
        }
        if !self.legacy_cpu_frame_is_top(owner) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "terminal caller-abort CPU owner is not the exact legacy CPU LIFO top"));
        }
        self.preflight_legacy_cpu_frame(owner, cpu)?;
        Ok(true)
    }

    fn retire_terminal_window_operation_top(
        &mut self,
        ended: &super::super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let frame = self.window_operations.last().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 terminal operation stack became empty before exact-top retirement",
        ))?;
        let (frame_id, callback_owner_valid, is_dde) = (
            frame.id,
            frame.guest_callback_id.is_some() == frame.guest_callback_retired,
            matches!(frame.continuation(), Some(WindowReturn::Dde(_))),
        );
        if !callback_owner_valid {
            return self.retain_operation_failure(frame_id, RuntimeError::new(
                Kind::HostFailure,
                "Win16 operation callback owner has not completed exact callback LIFO cleanup",
            ));
        }
        if is_dde {
            return self.retire_dde_window_operation_top(ended, cpu, dos, memory, host, frame_id);
        }

        let expected_ack_result = {
            let receipt = self.window_abort_receipt.as_ref().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 terminal operation has no retained native USER receipt",
            ))?;
            let frame = self.window_operations.last().filter(|frame| frame.id == frame_id)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "Win16 exact top operation changed before ACK validation"))?;
            self.terminal_user_operation_ack(frame, receipt)
        };
        let expected_ack = match expected_ack_result {
            Ok(ack) => ack,
            Err(error) => return self.retain_operation_failure(frame_id, error),
        };
        let ack_cache_error = {
            let frame = self.window_operations.last_mut().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 terminal operation disappeared before ACK caching",
            ))?;
            match (&frame.terminal_ack, &expected_ack) {
                (Some(previous), Some(expected)) if previous != expected => {
                    Some(RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 USER terminal ACK identity changed across a retry",
                    ))
                }
                (Some(_), None) => {
                    Some(RuntimeError::new(
                        Kind::InternalInvariant,
                        "guest-only USER operation acquired a native terminal ACK",
                    ))
                }
                (None, Some(expected)) => {
                    frame.terminal_ack = Some(expected.clone());
                    None
                }
                _ => None,
            }
        };
        if let Some(error) = ack_cache_error {
            return self.retain_operation_failure(frame_id, error);
        }

        let resources_retired = self.window_operations.last()
            .is_some_and(|frame| frame.terminal_resources_retired);
        if !resources_retired {
            if let Err(error) = self.retire_terminal_window_operation_resources(frame_id, memory) {
                return self.retain_operation_failure(frame_id, error);
            }
            if let Some(frame) = self.window_operations.last_mut() {
                frame.terminal_resources_retired = true;
            }
        }

        let cpu_owner = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.cpu_call_owner);
        let no_cpu_restore_required = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .is_some_and(|frame| {
                frame.lifecycle == WindowOperationLifecycle::NeverStarted
                    && frame.cpu_call_owner.is_none()
                    && frame.terminal_error.is_some()
                    && frame.host_operation.is_none()
                    && frame.worker_generation.is_none()
                    && frame.native_state.is_none()
                    && frame.terminal_ack.is_none()
                    && frame.terminal_retired_callbacks.is_empty()
                    && frame.pending_dde_callback.is_none()
                    && frame.guest_callback_id.is_none()
            });
        if let Some(owner) = cpu_owner {
            let already_restored = self.window_operations.last()
                .filter(|frame| frame.id == frame_id)
                .is_some_and(|frame| frame.terminal_context_restored);
            if !already_restored {
                if let Err(error) = self.restore_legacy_cpu_frame_after_task_execution_ended(
                    ended, owner, cpu, memory,
                ) {
                    return self.retain_operation_failure(frame_id, error);
                }
            }
            let frame = self.window_operations.last_mut()
                .filter(|frame| frame.id == frame_id)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "exact USER operation changed after terminal CPU restoration"))?;
            if frame.cpu_call_owner != Some(owner) {
                return self.retain_operation_failure(frame_id, RuntimeError::new(
                    Kind::InternalInvariant,
                    "USER operation changed CPU owner during terminal restoration",
                ));
            }
            frame.terminal_context_restored = true;
            for proof in &mut frame.terminal_retired_callbacks {
                proof.owner_context_restored = true;
            }
        }
        if !self.window_operations.last().is_some_and(|frame| {
            frame.id == frame_id && frame.terminal_resources_retired
                && (frame.terminal_context_restored || no_cpu_restore_required)
        }) {
            return self.retain_operation_failure(frame_id, RuntimeError::new(
                Kind::CompatibilityGap,
                "terminal USER frame has no exact CPU owner or never-started proof for task cleanup",
            ));
        }

        let has_pending_dde_callback = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .is_some_and(|frame| frame.pending_dde_callback.is_some());
        if has_pending_dde_callback {
            match self.retire_pending_window_dde_callback_after_abort(frame_id, host) {
                Ok(true) => {}
                Ok(false) => return self.retain_operation_failure(frame_id, RuntimeError::new(
                    Kind::InternalInvariant,
                    "pending DDE callback owner disappeared before its exact abort ACK",
                )),
                Err(error) => return self.retain_operation_failure(frame_id, error),
            }
        }

        let ack = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.terminal_ack.clone());
        if let Some(ack) = ack {
            let receipt = self.window_abort_receipt.as_ref().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 USER ACK readback has no exact cached abort receipt",
            ))?;
            let acknowledged = match host.win16_window_terminal_acknowledged(receipt, &ack) {
                Ok(acknowledged) => acknowledged,
                Err(error) => return self.retain_operation_failure(frame_id, error),
            };
            if !acknowledged {
                if let Some(frame) = self.window_operations.last_mut() {
                    frame.terminal_ack_attempted = true;
                }
                if let Err(error) = host.win16_window_terminal_ack(ack) {
                    return self.retain_operation_failure(frame_id, error);
                }
            }
            // Readback or the ACK call itself proves the same exact tombstone;
            // Cache this ACK before attempting any remaining prior-source
            // retirement, so that a retry cannot acknowledge it twice.
            let frame = self.window_operations.last_mut()
                .expect("exact terminal USER frame remains across host ACK");
            frame.terminal_ack_attempted = true;
            frame.terminal_source_acknowledged = true;
            for proof in &mut frame.terminal_retired_callbacks {
                proof.native_source_acknowledged = true;
            }
        }

        if let Err(error) = self.consume_prior_window_source_retirement(frame_id, host) {
            return self.retain_operation_failure(frame_id, error);
        }

        let cpu_owner = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.cpu_call_owner);
        if let Some(owner) = cpu_owner {
            if let Err(error) = self.release_legacy_cpu_frame(owner, dos, memory) {
                return self.retain_operation_failure(frame_id, error);
            }
            self.window_operations.last_mut()
                .filter(|frame| frame.id == frame_id)
                .expect("exact terminal USER frame remains while releasing its CPU owner")
                .cpu_call_owner = None;
        }

        // The exact host ACK consumes any modal terminal slot. Keep the
        // runtime values and context until this point so a negative ACK can
        // retry without losing the native result.
        let frame = self.window_operations.last_mut()
            .expect("exact terminal USER frame remains until its source ACK");
        frame.terminal_modal_responses.clear();
        frame.pending_modal_work = None;
        frame.pending_work = None;
        frame.host_wait = None;
        frame.host_modal_operation = None;
        let popped = self.window_operations.pop()
            .expect("exact terminal USER frame remains through final LIFO pop");
        debug_assert_eq!(popped.id, frame_id);
        Ok(())
    }

    fn retire_normal_window_operation_top(
        &mut self,
        ended: &super::super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        frame_id: u64,
    ) -> Result<(), RuntimeError> {
        let caller_aborted = match self.terminal_caller_abort_ready(ended, frame_id, cpu) {
            Ok(ready) => ready,
            Err(error) => return self.retain_operation_failure(frame_id, error),
        };
        let owner = match self.window_operations.last().filter(|frame| frame.id == frame_id) {
            Some(frame) => {
                let Some(proof) = frame.source_retired.as_ref() else {
                    return self.retain_operation_failure(frame_id, RuntimeError::new(
                        Kind::HostFailure,
                        "normal USER operation has no retained source-retirement proof",
                    ));
                };
                let (Some(operation), Some(kind), Some(worker_generation)) = (
                    frame.host_operation,
                    frame.native_source,
                    frame.worker_generation,
                ) else {
                    return self.retain_operation_failure(frame_id, RuntimeError::new(
                        Kind::InternalInvariant,
                        "normal USER source proof lost its exact operation identity",
                    ));
                };
                let completion_is_returned = frame.completion.as_ref().is_some_and(|completion| {
                    matches!(completion.journal.phase,
                        super::WindowOperationCompletionPhase::CallerReturned { .. })
                });
                let terminal_compensation = matches!(frame.continuation(),
                    Some(WindowReturn::CleanupPaint { .. } | WindowReturn::CleanupWindowDc { .. }));
                if frame.lifecycle != WindowOperationLifecycle::Returned
                    || frame.native_state != Some(crate::Win16NativeWindowOperationState::Returned)
                    || operation.0 == 0
                    || worker_generation == 0
                    || proof.operation.operation_id != operation
                    || proof.operation.kind != kind
                    || proof.worker_generation != worker_generation
                    || proof.state != crate::Win16NativeWindowOperationState::Returned
                    || frame.terminal_ack.is_some()
                    || frame.terminal_ack_attempted
                    || frame.terminal_source_acknowledged
                    || !frame.terminal_modal_responses.is_empty()
                    || (frame.host_modal_operation.is_some() && !caller_aborted)
                    || (!completion_is_returned && !terminal_compensation && !caller_aborted)
                {
                    return self.retain_operation_failure(frame_id, RuntimeError::new(
                        Kind::HostFailure,
                        "normal USER source-retirement proof changed owner, caller phase, or modal slot",
                    ));
                }
                (proof.clone(), operation, kind, worker_generation)
            }
            None => return Err(RuntimeError::new(Kind::InternalInvariant,
                "normal USER terminal retirement lost its exact top frame")),
        };
        let (proof, operation, kind, worker_generation) = owner;
        let already_consumed = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .is_some_and(|frame| frame.source_retirement_consumed);
        if !already_consumed {
            let readback = match host.win16_window_source_retirement(
                crate::Win16NativeWindowOperationProof {
                    operation_id: operation,
                    kind,
                },
                worker_generation,
            ) {
                Ok(readback) => readback,
                Err(error) => return self.retain_operation_failure(frame_id, error),
            };
            if !readback.is_some_and(|readback| *readback == *proof) {
                return self.retain_operation_failure(frame_id, RuntimeError::new(
                    Kind::HostFailure,
                    "host normal USER source tombstone differs from the exact retained frame proof",
                ));
            }
        }

        let resources_retired = self.window_operations.last()
            .is_some_and(|frame| frame.id == frame_id && frame.terminal_resources_retired);
        if !resources_retired {
            if let Err(error) = self.retire_terminal_window_operation_resources(frame_id, memory) {
                return self.retain_operation_failure(frame_id, error);
            }
            if let Some(frame) = self.window_operations.last_mut().filter(|frame| frame.id == frame_id) {
                frame.terminal_resources_retired = true;
            }
        }

        let caller_returned = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.completion.as_ref())
            .is_some_and(|completion| matches!(completion.journal.phase,
                super::WindowOperationCompletionPhase::CallerReturned { .. }));
        if !caller_returned {
            let owner = self.window_operations.last()
                .filter(|frame| frame.id == frame_id)
                .and_then(|frame| frame.cpu_call_owner)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "terminal USER retirement has no full CPU call owner"))?;
            let already_restored = self.window_operations.last()
                .filter(|frame| frame.id == frame_id)
                .is_some_and(|frame| frame.terminal_context_restored);
            if !already_restored {
                if let Err(error) = self.restore_legacy_cpu_frame_after_task_execution_ended(
                    ended, owner, cpu, memory,
                ) {
                    return self.retain_operation_failure(frame_id, error);
                }
                let frame = self.window_operations.last_mut()
                    .filter(|frame| frame.id == frame_id)
                    .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                        "terminal GDI frame changed after full CPU restoration"))?;
                if frame.cpu_call_owner != Some(owner) {
                    return self.retain_operation_failure(frame_id, RuntimeError::new(
                        Kind::InternalInvariant,
                        "terminal GDI compensation changed CPU owner during restoration",
                    ));
                }
                frame.terminal_context_restored = true;
            }
        }

        if !already_consumed {
            if let Err(error) = host.win16_window_source_retirement_consumed(&proof) {
                return self.retain_operation_failure(frame_id, error);
            }
            let frame = self.window_operations.last_mut()
                .filter(|frame| frame.id == frame_id)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "normal USER frame changed after exact source consumption"))?;
            frame.source_retirement_consumed = true;
        }

        if let Err(error) = self.consume_prior_window_source_retirement(frame_id, host) {
            return self.retain_operation_failure(frame_id, error);
        }

        let cpu_owner = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.cpu_call_owner);
        if let Some(owner) = cpu_owner {
            let release = if caller_returned {
                self.release_legacy_cpu_frame(owner, dos, memory)
            } else {
                self.release_legacy_cpu_frame_after_task_execution_ended(
                    ended, owner, dos, memory,
                )
            };
            if let Err(error) = release {
                return self.retain_operation_failure(frame_id, error);
            }
            self.window_operations.last_mut()
                .filter(|frame| frame.id == frame_id)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "normal USER frame changed while releasing its acknowledged CPU owner"))?
                .cpu_call_owner = None;
        }
        let frame = self.window_operations.last_mut()
            .filter(|frame| frame.id == frame_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "normal USER frame changed before its final completion phase"))?;
        let completion = frame.completion.as_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "normal USER completion journal disappeared before source retirement",
        ))?;
        if caller_returned && !matches!(completion.journal.phase,
            super::WindowOperationCompletionPhase::CallerReturned { .. }) {
            return self.retain_operation_failure(frame_id, RuntimeError::new(
                Kind::InternalInvariant,
                "normal USER completion left CallerReturned before terminal retirement",
            ));
        }
        completion.journal.phase = super::WindowOperationCompletionPhase::SourceRetired;
        self.pop_completed_window_operation(frame_id)
    }


}
