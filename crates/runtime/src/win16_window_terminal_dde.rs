//! Exact terminal retirement of a suspended DDE-backed USER operation.

use super::*;
use dos_kernel::DosKernel;
use guest_core::memory::Memory;
use x86_cpu::Cpu;

impl Win16State {
    pub(in crate::win16_runtime) fn retire_dde_window_operation_top(
        &mut self,
        ended: &super::super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        frame_id: u64,
    ) -> Result<(), RuntimeError> {
        let receipt = self.dde_abort_receipt.clone().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "DDE window operation retirement has no cached native abort receipt",
        ))?;
        let identities = (|| {
            let frame = self.window_operations.last().filter(|frame| frame.id == frame_id)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "DDE terminal retirement lost its exact top operation frame"))?;
            if frame.lifecycle != WindowOperationLifecycle::BeginPending
                || frame.native_source != Some(crate::Win16NativeWindowOperationKind::Dde)
                || frame.host_operation.is_some()
                || frame.worker_generation.is_some()
                || frame.native_state.is_some()
                || frame.terminal_ack.is_some()
                || !frame.terminal_modal_responses.is_empty()
                || frame.pending_modal_work.is_some()
                || frame.pending_work.is_some()
                || frame.host_wait.is_some()
                || frame.host_modal_operation.is_some()
            {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "DDE frame has a USER identity or modal owner outside its DDE continuation"));
            }
            let Some(WindowReturn::Dde(continuation)) = frame.continuation() else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "DDE retirement selected a non-DDE window operation"));
            };
            let operation = continuation.host_operation().ok_or_else(|| RuntimeError::new(
                Kind::HostFailure,
                "DDE continuation has no real native operation identity to retire",
            ))?;
            if operation.0 == 0 {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "DDE continuation has a zero native operation identity"));
            }
            Ok((operation, continuation.guest_instance(),
                continuation.operation_retirement_proof().cloned()))
        })();
        let (expected_operation, expected_guest_instance, cached_proof) = match identities {
            Ok(identities) => identities,
            Err(error) => return self.retain_operation_failure(frame_id, error),
        };
        let cpu_owner = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| frame.cpu_call_owner);
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
                    "exact DDE operation changed after terminal CPU restoration"))?;
            if frame.cpu_call_owner != Some(owner) {
                return self.retain_operation_failure(frame_id, RuntimeError::new(
                    Kind::InternalInvariant,
                    "DDE operation changed CPU owner during terminal restoration",
                ));
            }
            frame.terminal_context_restored = true;
            for callback_proof in &mut frame.terminal_retired_callbacks {
                callback_proof.owner_context_restored = true;
            }
        } else {
            return self.retain_operation_failure(frame_id, RuntimeError::new(
                Kind::CompatibilityGap,
                "DDE terminal frame has no exact CPU owner to restore after task execution ended",
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
        let retirement_result = {
            let (dde, retired_guest_blocks, operations) = (
                &mut self.dde,
                &mut self.dde_retired_guest_blocks,
                &mut self.window_operations,
            );
            match operations.last_mut().filter(|frame| frame.id == frame_id) {
                Some(frame) => match frame.continuation_mut() {
                    Some(WindowReturn::Dde(continuation)) => Ok(
                        super::super::runtime_dde::prepare_dde_window_operation_retirement(
                            dde,
                            continuation,
                            &receipt,
                            host,
                            retired_guest_blocks,
                        ),
                    ),
                    _ => Err(RuntimeError::new(Kind::InternalInvariant,
                        "DDE exact top changed kind before its native source ACK")),
                },
                None => Err(RuntimeError::new(Kind::InternalInvariant,
                    "DDE terminal top changed before its exact receipt was consumed")),
            }
        };
        let retirement = match retirement_result {
            Ok(retirement) => retirement,
            Err(error) => return self.retain_operation_failure(frame_id, error),
        };
        let proof = match retirement {
            crate::Win16DdeOperationRetirement::Released(proof) => proof,
            crate::Win16DdeOperationRetirement::Retained {
                operation,
                proof,
                cause,
            } => {
                let identity_error = if operation.is_some_and(|operation|
                    operation != expected_operation)
                {
                    Some(RuntimeError::new(Kind::InternalInvariant,
                        "retained DDE teardown changed its exact host operation identity"))
                } else if let Some(proof) = &proof {
                    if !proof.matches_receipt(&receipt)
                        || proof.cancellation.operation != expected_operation
                    {
                        Some(RuntimeError::new(Kind::HostFailure,
                            "retained DDE teardown proof differs from its exact cached receipt"))
                    } else {
                        None
                    }
                } else {
                    None
                };
                let retained = match identity_error {
                    Some(error) => RuntimeError::with_source(
                        cause.kind(),
                        "DDE teardown retained its original typed failure and operation identity",
                        std::sync::Arc::clone(&cause),
                    ).with_cleanup(
                        "DDE abort receipt or operation ACK remains retained",
                        error,
                    ),
                    None => RuntimeError::with_source(
                        cause.kind(),
                        "DDE native operation, callback source, or resource retirement remains retained",
                        cause,
                    ),
                };
                return self.retain_operation_failure(frame_id, retained);
            }
        };

        if !proof.matches_receipt(&receipt)
            || proof.cancellation.operation != expected_operation
            || cached_proof.as_ref().is_some_and(|cached| cached != &proof)
        {
            return self.retain_operation_failure(frame_id, RuntimeError::new(
                Kind::HostFailure,
                "released DDE source proof does not match its exact owner, operation, context, and native terminal receipt",
            ));
        }
        // matches_receipt validates all documented terminal outcomes, including
        // a real native result or error that arrived during Abort. Its original
        // cause remains owned by the cached abort receipt; retirement does not
        // turn that API failure into a cancellation or successful API result.
        if proof.cancellation.instance.is_none() && expected_guest_instance.is_some() {
            return self.retain_operation_failure(frame_id, RuntimeError::new(
                Kind::HostFailure,
                "released DDE source proof lost the native instance for its guest owner",
            ));
        }

        let cached_after_release = self.window_operations.last()
            .filter(|frame| frame.id == frame_id)
            .and_then(|frame| match frame.continuation() {
                Some(WindowReturn::Dde(continuation)) => continuation.operation_retirement_proof(),
                _ => None,
            });
        if cached_after_release != Some(&proof) {
            return self.retain_operation_failure(frame_id, RuntimeError::new(
                Kind::HostFailure,
                "released DDE ACK proof was not cached on its exact suspended continuation",
            ));
        }

        if let Some(frame) = self.window_operations.last_mut().filter(|frame| frame.id == frame_id) {
            frame.terminal_resources_retired = true;
        }
        let frame = self.window_operations.last().filter(|frame| frame.id == frame_id)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "DDE terminal frame changed after its native resource proof"))?;
        if !frame.terminal_context_restored || !frame.terminal_resources_retired {
            return self.retain_operation_failure(frame_id, RuntimeError::new(
                Kind::CompatibilityGap,
                "DDE terminal cancellation has no event-safe CPU continuation restore proof",
            ));
        }
        let cpu_owner = frame.cpu_call_owner;
        if let Some(owner) = cpu_owner {
            if let Err(error) = self.release_legacy_cpu_frame(owner, dos, memory) {
                return self.retain_operation_failure(frame_id, error);
            }
            self.window_operations.last_mut()
                .filter(|frame| frame.id == frame_id)
                .expect("exact DDE terminal frame remains while releasing its CPU owner")
                .cpu_call_owner = None;
        }
        let popped = self.window_operations.pop().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "DDE exact-top operation disappeared during terminal retirement",
        ))?;
        if popped.id != frame_id {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "DDE operation LIFO identity changed after its source ACK"));
        }
        Ok(())
    }
}
