//! Exact-top continuation and source phases for DDE window completions.

use super::*;
use dos_kernel::DosKernel;
use x86_cpu::{CallEffectPolicy, CallResumeBoundary, Cpu};

impl Win16State {
    /// Retain a DDE-owned native result/proof on the exact top DDE
    /// continuation. The central journal records only projection and return
    /// phases; DDE keeps its own result, proof list, and data leases.
    pub(super) fn retain_dde_window_completion(
        &mut self,
        proof: std::sync::Arc<crate::Win16DdeSourceRetiredProof>,
        result: crate::Win16HostDdeResult,
    ) -> Result<(), RuntimeError> {
        if proof.operation.0 == 0 || proof.owner.0 == 0
            || proof.worker_generation == 0
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "DDE normal source proof has an invalid owner or worker generation"));
        }
        let frame_id = self.window_operations.last().map(|frame| frame.id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "DDE source-retired result has no exact top operation frame"))?;
        {
            let frame = self.window_operations.last_mut()
                .filter(|frame| frame.id == frame_id)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "DDE top operation changed before proof caching"))?;
            if frame.completion.is_some() {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "DDE source retirement arrived while another completion remained active"));
            }
            let continuation = frame.result.as_mut().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "DDE source-retired result lost its exact continuation"))?;
            let WindowReturn::Dde(continuation) = continuation else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "DDE source-retired result does not match the exact top DDE continuation"));
            };
            if continuation.host_operation() != Some(proof.operation) {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "DDE source proof operation differs from the exact continuation owner"));
            }
            // The DDE continuation is the canonical owner of native result,
            // normal source proof, and DDE output leases. The central frame
            // keeps the same continuation in place while it drives phases.
            continuation.cache_normal_source_retirement(
                std::sync::Arc::clone(&proof),
                result.clone(),
            )?;
            if frame.dde_completion.is_none() {
                frame.dde_completion = Some(DdeWindowCompletionJournal {
                    phase: DdeWindowCompletionPhase::SourceProofReceived,
                    value: None,
                    first_cause: None,
                    outcome: None,
                });
            } else {
                let journal = frame.dde_completion.as_mut().ok_or_else(||
                    RuntimeError::new(Kind::InternalInvariant,
                        "DDE completion journal disappeared during source transition"))?;
                match journal.phase {
                    DdeWindowCompletionPhase::FollowUpDispatched
                    | DdeWindowCompletionPhase::CallbackDispatched => {
                        journal.phase = DdeWindowCompletionPhase::SourceProofReceived;
                        journal.value = None;
                        journal.outcome = None;
                    }
                    DdeWindowCompletionPhase::SourceProofReceived => {}
                    _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                        "DDE source proof arrived before its previous owner phase was committed")),
                }
            }
        }
        Ok(())
    }

    /// Run a retained result only at a boundary that owns the live Cpu.
    /// Producers that only hold Registers may cache results and source proofs,
    /// but cannot commit a CPU continuation or return to the guest caller.
    pub(in crate::win16_runtime) fn drive_pending_window_completion(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        dos: &mut DosKernel,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let Some(frame) = self.window_operations.last() else { return Ok(()); };
        if frame.dde_completion.is_some() {
            return self.resume_dde_window_completion(cpu, memory, dos, host);
        }
        if matches!(frame.continuation(), Some(WindowReturn::Dde(_))) {
            return Ok(());
        }
        if frame.completion.is_none() {
            let cached_returned_failure = frame.lifecycle == WindowOperationLifecycle::ReturnedWithError
                && frame.native_state == Some(crate::Win16NativeWindowOperationState::Returned)
                && frame.terminal_started_failure.as_ref().is_some_and(|failure| {
                    frame.host_operation == Some(failure.operation.operation_id)
                        && frame.native_source == Some(failure.operation.kind)
                        && frame.worker_generation == Some(failure.worker_generation)
                        && failure.state == crate::Win16NativeWindowOperationState::Returned
                });
            if !cached_returned_failure {
                return Ok(());
            }
        }
        self.resume_window_completion(cpu, memory, dos, host)
    }

    /// Drive a DDE normal completion without moving its continuation out of
    /// the existing exact top frame. DDE owns its result, source-proof list,
    /// callback state, and data leases; this central journal owns only the
    /// projected Win16 return and CPU/caller phases.
    fn resume_dde_window_completion(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        dos: &mut DosKernel,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let frame_id = self.window_operations.last().map(|frame| frame.id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "DDE completion retry has no exact top operation frame"))?;
        let (mut phase, has_outcome) = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.dde_completion.as_ref())
            .map(|journal| (journal.phase, journal.outcome.is_some()))
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "DDE completion retry has no retained completion journal"))?;

        if phase == DdeWindowCompletionPhase::SourceRetired {
            return self.pop_completed_window_operation(frame_id);
        }
        if matches!(phase, DdeWindowCompletionPhase::CallerReturned { .. }) {
            return self.retire_dde_frame_owner_and_sources(frame_id, dos, memory, host);
        }

        if matches!(phase, DdeWindowCompletionPhase::FollowUpDispatched
            | DdeWindowCompletionPhase::CallbackDispatched)
        {
            return Ok(());
        }

        if !has_outcome && phase == DdeWindowCompletionPhase::SourceProofReceived {
            let outcome = match self.finish_dde_operation_for_top(
                frame_id, &mut cpu.regs, memory, host,
            ) {
                Ok(outcome) => outcome,
                Err(error) => return self.retain_dde_window_completion_failure(frame_id, error),
            };
            let frame = self.window_operations.last_mut().filter(|frame| frame.id == frame_id)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "DDE frame changed while caching its typed finish outcome"))?;
            let journal = frame.dde_completion.as_mut().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "DDE completion journal disappeared before outcome caching"))?;
            if journal.outcome.is_some() {
                return self.retain_dde_window_completion_failure(frame_id,
                    RuntimeError::new(Kind::InternalInvariant,
                        "DDE finish outcome attempted to replace an existing owner"));
            }
            journal.outcome = Some(outcome);
            journal.phase = DdeWindowCompletionPhase::FinishOutcomeReady;
            phase = DdeWindowCompletionPhase::FinishOutcomeReady;
        }

        let outcome_kind = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.dde_completion.as_ref())
            .and_then(|journal| journal.outcome.as_ref())
            .map(|outcome| match outcome {
                super::super::runtime_dde::Win16DdeFinish::Return { .. } => 0,
                super::super::runtime_dde::Win16DdeFinish::FollowUp { .. } => 1,
                super::super::runtime_dde::Win16DdeFinish::ResumeCallback { .. } => 2,
            })
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "DDE finish outcome was not retained on the exact frame"))?;

        if outcome_kind == 1 {
            let step = match self.submit_dde_follow_up_for_top(frame_id, host) {
                Ok(step) => step,
                Err(error) => return self.retain_dde_window_completion_failure(frame_id, error),
            };
            let frame = self.window_operations.last_mut().filter(|frame| frame.id == frame_id)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "DDE top frame changed after follow-up submission"))?;
            frame.dde_completion.as_mut().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "DDE completion journal disappeared after follow-up submission"))?
                .phase = DdeWindowCompletionPhase::FollowUpDispatched;
            return self.advance_window_operation(&mut cpu.regs, memory, host, step);
        }
        if outcome_kind == 2 {
            let (origin, step) = {
                let frame = self.window_operations.last()
                    .filter(|frame| frame.id == frame_id)
                    .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                        "DDE top frame changed before callback dispatch"))?;
                let journal = frame.dde_completion.as_ref().ok_or_else(||
                    RuntimeError::new(Kind::InternalInvariant,
                        "DDE completion journal disappeared before callback dispatch"))?;
                let Some(super::super::runtime_dde::Win16DdeFinish::ResumeCallback {
                    origin, step,
                }) = journal.outcome.as_ref() else {
                    return self.retain_dde_window_completion_failure(frame_id,
                        RuntimeError::new(Kind::InternalInvariant,
                            "DDE callback outcome changed before exact dispatch"));
                };
                (*origin, step.clone())
            };
            let frame = self.window_operations.last_mut().filter(|frame| frame.id == frame_id)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "DDE top frame changed before callback dispatch"))?;
            frame.dde_completion.as_mut().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "DDE completion journal disappeared before callback dispatch"))?
                .phase = DdeWindowCompletionPhase::CallbackDispatched;
            return self.route_dde_callback_step(cpu, dos, memory, host, origin, step);
        }

        if phase == DdeWindowCompletionPhase::FinishOutcomeReady {
            let frame = self.window_operations.last_mut().filter(|frame| frame.id == frame_id)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "DDE frame changed before caching its Win16 return"))?;
            let journal = frame.dde_completion.as_mut().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "DDE completion journal disappeared before return projection"))?;
            let Some(super::super::runtime_dde::Win16DdeFinish::Return {
                value,
                return_kind,
            }) = journal.outcome.as_ref() else {
                return self.retain_dde_window_completion_failure(frame_id,
                    RuntimeError::new(Kind::InternalInvariant,
                        "DDE outcome changed before return projection"));
            };
            journal.value = Some((*value, *return_kind));
            journal.phase = DdeWindowCompletionPhase::GuestProjected {
                value: *value,
                return_kind: *return_kind,
            };
        }

        let cached_return = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.dde_completion.as_ref())
            .and_then(|journal| journal.value)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "DDE completion lost its cached guest return"))?;
        let (value, return_kind) = cached_return;

        if matches!(phase, DdeWindowCompletionPhase::FinishOutcomeReady
            | DdeWindowCompletionPhase::GuestProjected { .. })
        {
            let (owner, saved, return_to, transfer_result) = self.window_operations.last()
                .filter(|frame| frame.id == frame_id)
                .map(|frame| {
                    let operation = frame.continuation().and_then(|continuation| match continuation {
                        WindowReturn::Dde(continuation) => continuation.host_operation(),
                        _ => None,
                    });
                    let callback_transfer = match (operation, frame.continuation()) {
                        (Some(operation), Some(WindowReturn::Dde(continuation))) =>
                            continuation.guest_return_transfer_for_operation(operation)
                                .map(|proof| proof.map(|(_, transfer)| transfer)),
                        _ => Ok(None),
                    };
                    let transfer = callback_transfer.map(|transfer|
                        transfer.or(frame.guest_return_transfer.map(|(_, transfer)| transfer)));
                    (frame.cpu_call_owner, frame.saved.clone(), frame.return_to, transfer)
                })
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "DDE frame changed before checked CPU caller transfer"))?;
            let transfer = match transfer_result {
                Ok(transfer) => transfer,
                Err(error) => return self.retain_dde_window_completion_failure(frame_id, error),
            };
            let boundary = transfer.map_or(CallResumeBoundary::NoGuestExecution, |transfer|
                CallResumeBoundary::GuestCallReturn { transfer });
            let Some(owner) = owner else {
                return self.retain_dde_window_completion_failure(frame_id, RuntimeError::new(
                    Kind::InternalInvariant,
                    "DDE completion has no retained legacy CPU owner"));
            };
            let target = super::super::call_return::checked_return_target(
                &saved, return_to, value, return_kind,
            );
            if let Err(error) = self.retain_legacy_cpu_frame_roots(
                owner, &target.registers, dos, memory,
            ) {
                return self.retain_dde_window_completion_failure(frame_id, error);
            }
            if let Err(error) = self.restore_legacy_cpu_call_frame(
                owner, cpu, memory, CallEffectPolicy::PreserveX87, boundary, target,
            ) {
                return self.retain_dde_window_completion_failure(frame_id, error);
            }
            self.retire_far_return(return_to.0, u32::from(return_to.1), saved.ss);
            let frame = self.window_operations.last_mut().filter(|frame| frame.id == frame_id)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "DDE frame changed after checked CPU caller transfer"))?;
            let journal = frame.dde_completion.as_mut().ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "DDE completion journal disappeared after caller transfer"))?;
            journal.phase = DdeWindowCompletionPhase::CallerReturned { value, return_kind };
        }

        self.retire_dde_frame_owner_and_sources(frame_id, dos, memory, host)
    }

    fn retire_dde_frame_owner_and_sources(
        &mut self,
        frame_id: u64,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let (owner, source_already_consumed) = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .map(|frame| (frame.cpu_call_owner, frame.source_retirement_consumed))
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "DDE frame disappeared before CPU owner retirement"))?;
        if !source_already_consumed {
            if let Err(error) = self.consume_dde_source_retirements_for_top(frame_id, host) {
                return self.retain_dde_window_completion_failure(frame_id, error);
            }
            self.window_operations.last_mut()
                .filter(|frame| frame.id == frame_id)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "DDE frame changed after source ACK"))?
                .source_retirement_consumed = true;
        }
        if let Some(owner) = owner {
            if let Err(error) = self.release_legacy_cpu_frame(owner, dos, memory) {
                return self.retain_dde_window_completion_failure(frame_id, error);
            }
            self.window_operations.last_mut()
                .filter(|frame| frame.id == frame_id)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "DDE frame changed while releasing its acknowledged CPU owner"))?
                .cpu_call_owner = None;
        }
        let frame = self.window_operations.last_mut().filter(|frame| frame.id == frame_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "DDE frame changed after source proof consumption"))?;
        frame.dde_completion.as_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "DDE journal disappeared after source proof consumption"))?
            .phase = DdeWindowCompletionPhase::SourceRetired;
        self.pop_completed_window_operation(frame_id)
    }

    fn finish_dde_operation_for_top(
        &mut self,
        frame_id: u64,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<super::super::runtime_dde::Win16DdeFinish, RuntimeError> {
        let Self {
            window_operations,
            heap,
            selectors,
            selector_backing_leases,
            modules,
            global_handles,
            global_selectors,
            discarded_handles,
            allocated_selector_aliases,
            api_allocated_selectors,
            mapls_selectors,
            mapls_bases,
            module_reap_pending,
            dde,
            dde_callbacks,
            dde_retired_callback_tokens,
            dde_retired_guest_blocks,
            callback_kinds,
            callback_frame_ids,
            callback_scheduler,
            ..
        } = self;
        let frame = window_operations.last_mut().filter(|frame| frame.id == frame_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "DDE finish helper lost the exact top operation frame"))?;
        let continuation = match frame.result.as_mut() {
            Some(WindowReturn::Dde(continuation)) => continuation,
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE finish helper has no exact top DDE continuation")),
        };
        let operation = continuation.host_operation().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "DDE finish helper lost its actual host operation identity"))?;
        let record = continuation.normal_source_retirements().last().ok_or_else(||
            RuntimeError::new(Kind::InternalInvariant,
                "DDE completion has no cached normal source-retirement record"))?;
        if record.proof().operation != operation
            || record.proof().worker_generation == 0
            || !record.proof().has_valid_identity()
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "DDE source proof does not match the exact top continuation"));
        }
        let result = record.result().clone();
        let memory_access = super::super::global_teardown::GlobalMemoryTeardownAccess::from_parts(
            heap,
            selectors,
            selector_backing_leases,
            &mut modules.records,
            global_handles,
            global_selectors,
            discarded_handles,
            allocated_selector_aliases,
            api_allocated_selectors,
            mapls_selectors,
            mapls_bases,
            module_reap_pending,
        );
        let mut access = super::super::runtime_dde::DdeCompletionAccess::from_parts(
            memory_access,
            dde,
            dde_callbacks,
            dde_retired_callback_tokens,
            dde_retired_guest_blocks,
            callback_kinds,
            callback_frame_ids,
            callback_scheduler,
        );
        super::super::runtime_dde::finish_dde_operation(
            &mut access,
            continuation,
            result,
            registers,
            memory,
            host,
        )
    }

    fn submit_dde_follow_up_for_top(
        &mut self,
        frame_id: u64,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16WindowStep, RuntimeError> {
        let frame = self.window_operations.last_mut().filter(|frame| frame.id == frame_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "DDE follow-up lost its exact top operation frame"))?;
        if frame.dde_completion.as_ref().is_none_or(|journal|
            journal.phase != DdeWindowCompletionPhase::FinishOutcomeReady)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE follow-up is not in its exact staged completion phase"));
        }
        let continuation = match frame.result.as_mut() {
            Some(WindowReturn::Dde(continuation)) => continuation,
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE follow-up has no exact top DDE continuation")),
        };
        let journal = frame.dde_completion.as_mut().ok_or_else(||
            RuntimeError::new(Kind::InternalInvariant,
                "DDE follow-up lost its central outcome journal"))?;
        let outcome = journal.outcome.as_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "DDE follow-up lost its owner-bearing finish outcome"))?;
        if !matches!(outcome,
            super::super::runtime_dde::Win16DdeFinish::FollowUp { .. })
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE follow-up phase does not match its exact typed outcome"));
        }
        let carrier = super::super::runtime_dde::submit_dde_follow_up_in_place(
            continuation,
            outcome,
            frame_id,
            host,
        )?;
        Ok(super::super::runtime_dde::follow_up_carrier_step(&carrier))
    }

    fn retain_dde_window_completion_failure(
        &mut self,
        frame_id: u64,
        error: RuntimeError,
    ) -> Result<(), RuntimeError> {
        let frame = self.window_operations.last_mut().filter(|frame| frame.id == frame_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "failed DDE completion lost its exact top frame"))?;
        let journal = frame.dde_completion.as_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "failed DDE completion lost its typed journal"))?;
        let error_kind = error.kind();
        let cause = journal.first_cause.get_or_insert_with(|| std::sync::Arc::new(error));
        Err(RuntimeError::with_source(
            error_kind,
            "Win16 DDE completion remains owned for exact retry",
            std::sync::Arc::clone(cause),
        ))
    }

    /// Consume every cached DDE normal-source proof through the DDE-owned
    /// readback/ACK helper while borrowing the exact top continuation in
    /// place. The Memory V4 and DDE access views are canonical owners; this
    /// constructor intentionally names their required state fields so Root
    /// can method-merge them without adding a second heap/selector ledger.
    fn consume_dde_source_retirements_for_top(
        &mut self,
        frame_id: u64,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let Self {
            window_operations,
            heap,
            selectors,
            selector_backing_leases,
            modules,
            global_handles,
            global_selectors,
            discarded_handles,
            allocated_selector_aliases,
            api_allocated_selectors,
            mapls_selectors,
            mapls_bases,
            module_reap_pending,
            dde,
            dde_callbacks,
            dde_retired_callback_tokens,
            dde_retired_guest_blocks,
            callback_kinds,
            callback_frame_ids,
            callback_scheduler,
            ..
        } = self;
        let frame = window_operations.last_mut().filter(|frame| frame.id == frame_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "DDE source consumption lost the exact top operation frame"))?;
        let Some(WindowReturn::Dde(continuation)) = frame.result.as_mut() else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE source consumption lost the exact in-place DDE continuation"));
        };

        let memory = super::super::global_teardown::GlobalMemoryTeardownAccess::from_parts(
            heap,
            selectors,
            selector_backing_leases,
            &mut modules.records,
            global_handles,
            global_selectors,
            discarded_handles,
            allocated_selector_aliases,
            api_allocated_selectors,
            mapls_selectors,
            mapls_bases,
            module_reap_pending,
        );
        let mut access = super::super::runtime_dde::DdeCompletionAccess::from_parts(
            memory,
            dde,
            dde_callbacks,
            dde_retired_callback_tokens,
            dde_retired_guest_blocks,
            callback_kinds,
            callback_frame_ids,
            callback_scheduler,
        );
        access.consume_dde_source_retirements(continuation, host)
    }

}
