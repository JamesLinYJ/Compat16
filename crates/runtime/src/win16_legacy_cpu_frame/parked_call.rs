//! A parked USER wait resumes together with its original ABI caller owner.
use super::*;

impl Win16State {
    /// Return whether the caller ticket was rearmed. A host-resume or owner
    /// release retry must reuse that ticket, without consuming another boundary.
    pub(in crate::win16_runtime) fn restore_legacy_cpu_parked_frame_for_call(
        &mut self,
        parked_id: u64,
        caller_id: u64,
        cpu: &mut x86_cpu::Cpu,
        policy: CallEffectPolicy,
        memory: &Memory,
    ) -> Result<bool, RuntimeError> {
        let mut parked = self.take_legacy_cpu_frame(parked_id)?;
        let result = (|| {
            let index = self
                .legacy_cpu_frames
                .iter()
                .position(|frame| frame.id == caller_id)
                .ok_or_else(|| {
                    RuntimeError::new(
                        DiagnosticKind::InternalInvariant,
                        "parked USER work has no exact enclosing CPU call owner",
                    )
                })?;
            let caller = &self.legacy_cpu_frames[index];
            if caller.restored || caller.saved_registers != parked.saved_registers {
                return Err(RuntimeError::new(
                    DiagnosticKind::GuestFault,
                    "parked USER work does not retain its original caller register image",
                ));
            }
            if parked.restored {
                return Ok(false);
            }
            let (
                Win16LegacyCpuContinuation::Parked(Some(wait), _),
                Win16LegacyCpuContinuation::Call(Some(call)),
            ) = (&parked.continuation, &caller.continuation)
            else {
                return Err(RuntimeError::new(
                    DiagnosticKind::InternalInvariant,
                    "parked USER work cannot rearm its retained CPU call ticket",
                ));
            };
            let parked_binding = Win16LegacyCpuBinding::new(self, memory, &parked.owner);
            let caller_binding = Win16LegacyCpuBinding::new(self, memory, &caller.owner);
            let transfer = cpu
                .prepare_legacy_parked_resume_and_rearm_call(
                    wait,
                    call,
                    policy,
                    &parked_binding,
                    &caller_binding,
                )
                .map_err(|error| {
                    RuntimeError::with_source(
                        DiagnosticKind::GuestFault,
                        "prepare paired USER wait and ABI caller continuation",
                        error,
                    )
                })?;
            let rearmed = cpu
                .commit_legacy_parked_resume_and_rearm_call(
                    transfer,
                    &parked_binding,
                    &caller_binding,
                )
                .map_err(|error| {
                    RuntimeError::with_source(
                        DiagnosticKind::GuestFault,
                        "resume checked USER wait and rearm its exact ABI caller",
                        error,
                    )
                })?;
            // CPU commit cannot mutate either runtime ledger. No allocation,
            // lease release, or fallible operation follows this paired commit.
            self.legacy_cpu_frames[index].continuation =
                Win16LegacyCpuContinuation::Call(Some(rearmed));
            parked.continuation =
                Win16LegacyCpuContinuation::Parked(None, parked.saved_registers.clone());
            parked.restored = true;
            Ok(true)
        })();
        self.legacy_cpu_frames.push(parked);
        result
    }
}
