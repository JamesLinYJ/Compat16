//! Exact USER result caching, CPU-bound retry and source retirement.

use super::*;
use dos_kernel::DosKernel;
use x86_cpu::{CallEffectPolicy, CallResumeBoundary, Cpu};

impl Win16State {
    /// Cache the host result on the exact top frame before projection. A host
    /// readback failure leaves that result in place for an exact retry.
    pub(super) fn complete_window_operation(
        &mut self,
        _registers: &mut Registers,
        host: &mut impl RuntimeHost,
        result: Win16WindowResult,
    ) -> Result<(), RuntimeError> {
        let frame_id = self.window_operations.last().map(|frame| frame.id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "native window result has no pending operation"))?;
        if self.window_operations.last().is_some_and(|frame|
            matches!(frame.continuation(), Some(WindowReturn::Dde(_))))
        {
            // DDE completion must arrive with its DDE-owned normal source
            // proof. Do not move the continuation into the USER completion
            // owner or turn an unproven Complete into a retired source.
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "raw DDE Complete bypassed its DDE source-retired carrier"));
        }
        if self.window_operations.last().is_some_and(|frame| frame.completion.is_some()) {
            return self.retain_window_completion_failure(frame_id, RuntimeError::new(
                Kind::InternalInvariant,
                "a second native result attempted to replace the retained USER completion"));
        }

        let mut preflight_error = None;
        {
            let frame = self.window_operations.last_mut().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "USER operation frame disappeared while caching its result"))?;
            let continuation = frame.result.take().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "native window result has no original API continuation"))?;
            let source = if frame.host_operation.is_some() {
                WindowOperationCompletionSource::NativeUser
            } else {
                WindowOperationCompletionSource::GuestCallback {
                    callback_id: frame.guest_callback_id,
                }
            };
            if matches!(source, WindowOperationCompletionSource::NativeUser)
                && (frame.native_source.is_none()
                    || frame.worker_generation.is_none()
                    || frame.lifecycle != WindowOperationLifecycle::Started)
            {
                preflight_error = Some(RuntimeError::new(Kind::InternalInvariant,
                    "native USER completion has an incomplete started-owner identity"));
            }
            if matches!(source, WindowOperationCompletionSource::GuestCallback { .. })
                && (frame.lifecycle != WindowOperationLifecycle::GuestOnly
                    || !frame.guest_callback_retired
                    || frame.guest_callback_id.is_none())
            {
                preflight_error.get_or_insert_with(|| RuntimeError::new(
                    Kind::InternalInvariant,
                    "guest-only USER completion has no exact retired callback owner"));
            }
            let journal = match source {
                WindowOperationCompletionSource::NativeUser =>
                    WindowCompletionJournal::for_native_result(&continuation, &result),
                WindowOperationCompletionSource::GuestCallback { .. } =>
                    WindowCompletionJournal::new(&continuation),
            };
            frame.completion = Some(WindowOperationCompletion {
                continuation,
                result,
                journal,
                source,
            });
            if matches!(source, WindowOperationCompletionSource::NativeUser)
                && preflight_error.is_none()
            {
                frame.lifecycle = WindowOperationLifecycle::Returned;
                frame.native_state = Some(crate::Win16NativeWindowOperationState::Returned);
            }
        }

        if let Some(error) = preflight_error {
            return self.retain_window_completion_failure(frame_id, error);
        }

        if self.window_operations.last().is_some_and(|frame| {
            frame.id == frame_id
                && frame.completion.as_ref().is_some_and(|completion|
                    matches!(completion.source, WindowOperationCompletionSource::NativeUser))
        }) {
            self.retry_window_source_retirement_readback(frame_id, host)?;
        }
        // The caller owns the live Cpu, not the Registers-only USER worker
        // path. Projection and the checked continuation commit run at the
        // nearest real CPU dispatch boundary.
        Ok(())
    }

    /// Re-read only the native owner's bounded normal-return tombstone. None
    /// is a known-live source, so the exact result and frame remain cached.
    fn retry_window_source_retirement_readback(
        &mut self,
        frame_id: u64,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let owner = self.window_operations.last().filter(|frame| frame.id == frame_id)
            .and_then(|frame| Some((
                frame.host_operation?,
                frame.native_source?,
                frame.worker_generation?,
            )))
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "normal USER completion lost its exact native operation identity"))?;
        let (operation_id, kind, worker_generation) = owner;
        let operation = crate::Win16NativeWindowOperationProof { operation_id, kind };
        let proof = match host.win16_window_source_retirement(operation, worker_generation) {
            Ok(Some(proof)) => proof,
            Ok(None) => return self.retain_window_completion_failure(frame_id,
                RuntimeError::new(Kind::HostFailure,
                    "native USER result is cached while its exact source remains live")),
            Err(error) => return self.retain_window_completion_failure(frame_id, error),
        };
        if proof.operation != operation || proof.worker_generation != worker_generation
            || proof.worker_generation == 0
            || proof.state != crate::Win16NativeWindowOperationState::Returned
        {
            return self.retain_window_completion_failure(frame_id, RuntimeError::new(
                Kind::HostFailure,
                "host normal source-retirement readback differs from the exact USER operation"));
        }
        let existing_mismatch = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.source_retired.as_ref())
            .is_some_and(|existing| **existing != *proof);
        if existing_mismatch {
            return self.retain_window_completion_failure(frame_id, RuntimeError::new(
                Kind::HostFailure,
                "host changed the cached USER source-retirement proof"));
        }
        let frame = self.window_operations.last_mut()
            .filter(|frame| frame.id == frame_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "USER operation frame changed during source proof readback"))?;
        if frame.source_retired.is_none() {
            frame.source_retired = Some(proof);
        }
        Ok(())
    }

    fn begin_ready_dc_compensation_on_top(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        frame_id: u64,
    ) -> Result<bool, RuntimeError> {
        let operation = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.completion.as_ref())
            .and_then(|completion| match (
                &completion.continuation,
                &completion.journal.projection,
            ) {
                (WindowReturn::CleanupPaint { .. },
                    WindowProjectionJournal::Api(WindowApiProjectionJournal::CleanupPaint(owner)))
                    if owner.phase == super::operation_frame::CompensationProjectionPhase::Ready =>
                    super::completion_gdi::prepare_dc_compensation_operation(
                        &completion.continuation,
                    ),
                (WindowReturn::CleanupWindowDc { .. },
                    WindowProjectionJournal::Api(WindowApiProjectionJournal::CleanupWindowDc(owner)))
                    if owner.phase == super::operation_frame::CompensationProjectionPhase::Ready =>
                    super::completion_gdi::prepare_dc_compensation_operation(
                        &completion.continuation,
                    ),
                _ => None,
            });
        let Some(operation) = operation else { return Ok(false); };
        let prior_proof = self.window_follow_up_source_proof(frame_id)?;
        self.begin_prepared_window_follow_up_on_top(
            registers, memory, host, frame_id, prior_proof, operation, None,
        )?;
        Ok(true)
    }

    /// Run one retained projection in place. The operation frame and its
    /// continuation are borrowed separately from the sibling USER state.
    pub(super) fn resume_window_completion(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        dos: &mut DosKernel,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let frame_id = self.window_operations.last().map(|frame| frame.id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "USER completion retry has no exact top frame"))?;
        let retry_owner = self.window_operations.last()
            .filter(|frame| frame.id == frame_id && frame.completion.is_none())
            .and_then(|frame| {
                if frame.lifecycle != WindowOperationLifecycle::ReturnedWithError
                    || frame.native_state != Some(crate::Win16NativeWindowOperationState::Returned)
                    || frame.result.is_none()
                {
                    return None;
                }
                let failure = frame.terminal_started_failure.as_ref()?;
                let operation_id = frame.host_operation?;
                let kind = frame.native_source?;
                let worker_generation = frame.worker_generation?;
                (failure.operation.operation_id == operation_id
                    && failure.operation.kind == kind
                    && failure.worker_generation == worker_generation
                    && failure.state == crate::Win16NativeWindowOperationState::Returned)
                    .then_some((operation_id, kind, worker_generation))
            });
        if let Some((operation_id, kind, worker_generation)) = retry_owner {
            let step = host.win16_window_retry_cached_completion(
                crate::Win16NativeWindowOperationProof { operation_id, kind },
                worker_generation,
            )?;
            // This call only binds the already-retired source carrier and
            // retained result to the original exact frame. Projection and
            // checked caller return remain in the phases below.
            self.advance_window_operation(&mut cpu.regs, memory, host, step)?;
        }
        let mut phase = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.completion.as_ref())
            .map(|completion| completion.journal.phase)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "USER completion retry has no retained result and journal"))?;

        if phase == WindowOperationCompletionPhase::SourceRetired {
            return self.pop_completed_window_operation(frame_id);
        }
        if matches!(phase, WindowOperationCompletionPhase::CallerReturned { .. }) {
            return self.retire_window_frame_owner_and_pop(frame_id, dos, memory, host);
        }

        let source = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.completion.as_ref())
            .map(|completion| completion.source);
        match source {
            Some(WindowOperationCompletionSource::NativeUser) =>
                self.retry_window_source_retirement_readback(frame_id, host)?,
            Some(WindowOperationCompletionSource::GuestCallback { .. }) => {}
            None => return self.retain_window_completion_failure(frame_id, RuntimeError::new(
                Kind::InternalInvariant,
                "USER completion has no exact source-family owner")),
        }

        if phase == WindowOperationCompletionPhase::Received
            && source == Some(WindowOperationCompletionSource::NativeUser)
        {
            let dialog_item = self.window_operations.last()
                .filter(|frame| frame.id == frame_id)
                .and_then(|frame| {
                    let completion = frame.completion.as_ref()?;
                    let WindowReturn::DialogItemMessage {
                        dialog, native_dialog, message, w_param, l_param,
                    } = &completion.continuation else { return None; };
                    let Win16WindowResult::UserService(
                        crate::Win16HostUserServiceResult::DialogControl(
                            crate::Win16HostDialogControlResult::Item(Some(child)),
                        ),
                    ) = &completion.result else { return None; };
                    Some((
                        *dialog, *native_dialog, *child, *message, *w_param, *l_param,
                    ))
                });
            if let Some((dialog, native_dialog, child, message, w_param, l_param)) = dialog_item {
                let prior_proof = match self.dialog_item_follow_up_source_proof(frame_id) {
                    Ok(Some(proof)) => proof,
                    Ok(None) => return self.retain_window_completion_failure(frame_id,
                        RuntimeError::new(Kind::InternalInvariant,
                            "dialog-item child result lost its exact follow-up owner")),
                    Err(error) => return self.retain_window_completion_failure(frame_id, error),
                };
                let preparation = match super::super::message_calls::prepare_dialog_item_send_message(
                    self,
                    dialog,
                    native_dialog,
                    Some(child),
                    message,
                    w_param,
                    l_param,
                    memory,
                    host,
                ) {
                    Ok(preparation) => preparation,
                    Err(error) => return self.retain_window_completion_failure(frame_id, error),
                };
                match preparation {
                    super::super::message_calls::SendMessagePreparation::Immediate {
                        value, return_kind,
                    } => {
                        let projected_phase = WindowOperationCompletionPhase::GuestProjected {
                            value,
                            return_kind,
                        };
                        let completion = self.window_operations.last_mut()
                            .filter(|frame| frame.id == frame_id)
                            .and_then(|frame| frame.completion.as_mut())
                            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                                "immediate dialog-item result lost its retained lookup frame"))?;
                        match &mut completion.journal.projection {
                            WindowProjectionJournal::Api(
                                WindowApiProjectionJournal::DialogItemMessage(inner_phase),
                            ) => {
                                *inner_phase = super::operation_frame::DialogItemMessageProjectionPhase::Complete;
                            }
                            _ => return self.retain_window_completion_failure(frame_id,
                                RuntimeError::new(Kind::InternalInvariant,
                                    "immediate dialog-item result lost its lookup projection journal")),
                        }
                        completion.journal.phase = projected_phase;
                        phase = projected_phase;
                    }
                    super::super::message_calls::SendMessagePreparation::Prepared {
                        operation,
                        continuation,
                    } => {
                        return self.begin_prepared_window_follow_up_on_top(
                            &mut cpu.regs,
                            memory,
                            host,
                            frame_id,
                            prior_proof,
                            operation,
                            Some(continuation),
                        );
                    }
                }
            }
        }

        let projected = match phase {
            WindowOperationCompletionPhase::GuestProjected { value, return_kind } => {
                Ok((value, return_kind))
            }
            WindowOperationCompletionPhase::Received => {
                self.project_window_completion(frame_id, memory, host)
            }
            _ => Err(RuntimeError::new(Kind::InternalInvariant,
                "USER completion has an invalid pre-return phase")),
        };
        let (value, return_kind) = match projected {
            Ok(value) => value,
            Err(error) => {
                if self.begin_ready_dc_compensation_on_top(
                    &mut cpu.regs, memory, host, frame_id,
                )? {
                    return Ok(());
                }
                return self.retain_window_completion_failure(frame_id, error);
            }
        };

        let (owner_id, saved, return_to, boundary) = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .map(|frame| {
                let boundary = frame.guest_return_transfer.map_or(
                    CallResumeBoundary::NoGuestExecution,
                    |(_, transfer)| CallResumeBoundary::GuestCallReturn { transfer },
                );
                (frame.cpu_call_owner, frame.saved.clone(), frame.return_to, boundary)
            })
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "USER completion frame changed before checked CPU restoration"))?;
        let Some(owner_id) = owner_id else {
            return self.retain_window_completion_failure(frame_id, RuntimeError::new(
                Kind::InternalInvariant,
                "USER completion has no retained legacy caller owner"));
        };
        let target = super::super::call_return::checked_return_target(
            &saved, return_to, value, return_kind,
        );
        if let Err(error) = self.retain_legacy_cpu_frame_roots(
            owner_id, &target.registers, dos, memory,
        ) {
            return self.retain_window_completion_failure(frame_id, error);
        }
        if let Err(error) = self.return_legacy_cpu_call_frame(
            owner_id, cpu, memory, CallEffectPolicy::PreserveX87, boundary, target,
        ) {
            return self.retain_window_completion_failure(frame_id, error);
        }
        self.retire_far_return(return_to.0, u32::from(return_to.1), saved.ss);
        let completion = self.window_operations.last_mut()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.completion.as_mut())
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "USER completion result disappeared after checked caller transfer"))?;
        completion.journal.phase = WindowOperationCompletionPhase::CallerReturned {
            value, return_kind,
        };
        self.retire_window_frame_owner_and_pop(frame_id, dos, memory, host)
    }

    fn retire_window_frame_owner_and_pop(
        &mut self,
        frame_id: u64,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        self.consume_window_source_and_pop(frame_id, dos, memory, host)
    }

    fn consume_window_source_and_pop(
        &mut self,
        frame_id: u64,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let (proof, already_consumed, source) = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| Some((
                frame.source_retired.as_ref().map(std::sync::Arc::clone),
                frame.source_retirement_consumed,
                frame.completion.as_ref()?.source,
            )))
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "USER completion lost its exact source phase"))?;
        let phase_ready = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.completion.as_ref())
            .is_some_and(|completion| matches!(completion.journal.phase,
                WindowOperationCompletionPhase::CallerReturned { .. }));
        if !phase_ready {
            return self.retain_window_completion_failure(frame_id, RuntimeError::new(
                Kind::InternalInvariant,
                "USER source retirement was requested before checked caller return"));
        }
        self.publish_kernel_diagnostic_effect(frame_id)?;
        if !already_consumed {
            let consume = match source {
                WindowOperationCompletionSource::NativeUser => {
                    let Some(proof) = proof.as_ref() else {
                        return self.retain_window_completion_failure(frame_id,
                            RuntimeError::new(Kind::InternalInvariant,
                                "native USER completion has no exact normal source-retirement proof"));
                    };
                    host.win16_window_source_retirement_consumed(proof)
                }
                WindowOperationCompletionSource::GuestCallback { callback_id } => {
                    let exact_guest_owner = self.window_operations.last()
                        .filter(|frame| frame.id == frame_id)
                        .is_some_and(|frame| callback_id.is_some()
                            && frame.guest_callback_id == callback_id
                            && frame.guest_callback_retired);
                    if exact_guest_owner {
                        Ok(())
                    } else {
                        Err(RuntimeError::new(Kind::InternalInvariant,
                            "guest-only USER completion has no retired exact callback source"))
                    }
                }
            };
            if let Err(error) = consume {
                return self.retain_window_completion_failure(frame_id, error);
            }
            let frame = self.window_operations.last_mut()
                .filter(|frame| frame.id == frame_id)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "operation frame changed before source-retirement completion"))?;
            frame.source_retirement_consumed = true;
        }
        if let Err(error) = self.consume_prior_window_source_retirement(frame_id, host) {
            return self.retain_window_completion_failure(frame_id, error);
        }
        let owner = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .map(|frame| frame.cpu_call_owner)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "USER frame disappeared after native source ACK"))?;
        if let Some(owner) = owner {
            if let Err(error) = self.release_legacy_cpu_frame(owner, dos, memory) {
                return self.retain_window_completion_failure(frame_id, error);
            }
            self.window_operations.last_mut()
                .filter(|frame| frame.id == frame_id)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "USER frame changed while releasing its acknowledged CPU owner"))?
                .cpu_call_owner = None;
        }
        let frame = self.window_operations.last_mut()
            .filter(|frame| frame.id == frame_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "USER frame changed before final source phase"))?;
        frame.completion.as_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "USER completion disappeared before final source phase"))?
            .journal.phase = WindowOperationCompletionPhase::SourceRetired;
        self.pop_completed_window_operation(frame_id)
    }

    pub(super) fn consume_prior_window_source_retirement(
        &mut self,
        frame_id: u64,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let prior = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.prior_source_retirement.as_ref())
            .map(|prior| (std::sync::Arc::clone(&prior.proof), prior.consumed));
        let Some((proof, consumed)) = prior else { return Ok(()); };
        if consumed { return Ok(()); }
        if proof.operation.operation_id.0 == 0
            || proof.worker_generation == 0
            || proof.state != crate::Win16NativeWindowOperationState::Returned
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "prior USER source proof lost its exact retired identity"));
        }
        host.win16_window_source_retirement_consumed(&proof)?;
        let frame = self.window_operations.iter_mut()
            .find(|frame| frame.id == frame_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "outer USER frame disappeared after prior source consumption"))?;
        let prior = frame.prior_source_retirement.as_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "prior source proof disappeared after its exact host consumption",
        ))?;
        if !std::sync::Arc::ptr_eq(&prior.proof, &proof) {
            return Err(RuntimeError::new(Kind::HostFailure,
                "prior source proof changed across exact host consumption"));
        }
        prior.consumed = true;
        Ok(())
    }

    fn publish_kernel_diagnostic_effect(&mut self, frame_id: u64) -> Result<(), RuntimeError> {
        let phase = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.completion.as_ref())
            .and_then(|completion| match &completion.journal.projection {
                WindowProjectionJournal::Api(
                    WindowApiProjectionJournal::KernelDiagnostics(phase),
                ) => Some(*phase),
                _ => None,
            });
        let Some(phase) = phase else { return Ok(()); };
        match phase {
            super::operation_frame::KernelDiagnosticProjectionPhase::EffectReserved => {
                let effect = self.window_operations.last()
                    .filter(|frame| frame.id == frame_id)
                    .and_then(|frame| frame.completion.as_ref())
                    .and_then(|completion| completion.journal.kernel_effect);
                if let Some(effect) = effect {
                    self.pending_kernel_diagnostic_effects.push(effect);
                }
                let completion = self.window_operations.last_mut()
                    .filter(|frame| frame.id == frame_id)
                    .and_then(|frame| frame.completion.as_mut())
                    .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                        "KERNEL diagnostic owner disappeared before its queued phase"))?;
                let WindowProjectionJournal::Api(
                    WindowApiProjectionJournal::KernelDiagnostics(phase),
                ) = &mut completion.journal.projection else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "KERNEL diagnostic phase changed while queuing its cached effect"));
                };
                *phase = super::operation_frame::KernelDiagnosticProjectionPhase::EffectQueued;
                Ok(())
            }
            super::operation_frame::KernelDiagnosticProjectionPhase::EffectQueued => Ok(()),
            super::operation_frame::KernelDiagnosticProjectionPhase::Ready =>
                Err(RuntimeError::new(Kind::InternalInvariant,
                    "KERNEL diagnostic effect reached source ACK before it was reserved")),
        }
    }

    pub(super) fn pop_completed_window_operation(&mut self, frame_id: u64) -> Result<(), RuntimeError> {
        if !self.window_operations.last().is_some_and(|frame| {
            frame.id == frame_id
                && frame.source_retirement_consumed
                && frame.prior_source_retirement.as_ref()
                    .is_none_or(|prior| prior.consumed)
                && (frame.completion.as_ref().is_some_and(|completion|
                    completion.journal.phase == WindowOperationCompletionPhase::SourceRetired)
                    || frame.dde_completion.as_ref().is_some_and(|completion|
                        completion.phase == DdeWindowCompletionPhase::SourceRetired))
        }) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "USER operation cannot leave the LIFO before completion and source phases finish"));
        }
        self.window_operations.pop();
        Ok(())
    }

    pub(super) fn retain_window_completion_failure<T>(
        &mut self,
        frame_id: u64,
        error: RuntimeError,
    ) -> Result<T, RuntimeError> {
        let frame = self.window_operations.last_mut()
            .filter(|frame| frame.id == frame_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "failed USER completion lost its exact top frame"))?;
        let completion = frame.completion.as_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "failed USER completion lost its exact result"))?;
        let error_kind = error.kind();
        let cause = match &completion.journal.first_cause {
            Some(cause) => std::sync::Arc::clone(cause),
            None => {
                let cause = std::sync::Arc::new(error);
                completion.journal.first_cause = Some(std::sync::Arc::clone(&cause));
                cause
            }
        };
        Err(RuntimeError::with_source(
            error_kind,
            "Win16 USER completion remains owned for exact retry",
            cause,
        ))
    }
}
