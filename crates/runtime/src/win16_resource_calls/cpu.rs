//! Checked API/handler CPU ownership, plus exact terminal LIFO cancellation.
use super::*;
use x86_cpu::{CallEffectPolicy, CallResumeBoundary};

impl Win16State {
    pub(super) fn return_resource_caller(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        value: u32,
        kind: Win16ReturnKind,
    ) -> Result<(), RuntimeError> {
        let frame = self
            .resource_callbacks
            .last()
            .expect("resource caller source");
        let (caller, parked, saved, return_to) = (
            frame.caller,
            frame.parked,
            frame.saved.clone(),
            frame.return_to,
        );
        let caller = caller.ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "resource API completion has no exact caller CPU owner",
            )
        })?;
        self.preflight_legacy_cpu_frame(caller, cpu)?;
        if let Some(parked) = parked {
            self.preflight_legacy_cpu_frame(parked, cpu)?;
            self.restore_legacy_cpu_parked_frame_for_call(
                parked,
                caller,
                cpu,
                CallEffectPolicy::PreserveX87,
                memory,
            )?;
            self.release_legacy_cpu_frame(parked, dos, memory)?;
            self.resource_callbacks
                .last_mut()
                .expect("resumed resource API")
                .parked = None;
        }
        let target =
            super::super::call_return::checked_return_target(&saved, return_to, value, kind);
        self.retain_legacy_cpu_frame_roots(caller, &target.registers, dos, memory)?;
        self.return_legacy_cpu_call_frame(
            caller,
            cpu,
            memory,
            CallEffectPolicy::PreserveX87,
            CallResumeBoundary::NoGuestExecution,
            target,
        )?;
        self.retire_far_return(return_to.0, u32::from(return_to.1), saved.ss);
        Ok(())
    }

    pub(super) fn retire_resource_call(
        &mut self,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let id = self.require_callback_top(CallbackKind::Resource)?;
        let frame = self
            .resource_callbacks
            .last()
            .filter(|frame| {
                frame.callback_id == id
                    && frame.phase == ResourceCallPhase::Returned
                    && frame.parked.is_none()
                    && frame.callback.is_none()
            })
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "resource retirement precedes its exact checked API return",
                )
            })?;
        if let Some(caller) = frame.caller {
            self.release_legacy_cpu_frame(caller, dos, memory)?;
            self.resource_callbacks
                .last_mut()
                .expect("returned resource caller")
                .caller = None;
        }
        self.retire_callback_binding(CallbackKind::Resource, id)?;
        self.resource_callbacks
            .pop()
            .expect("resource source retained through retirement");
        Ok(())
    }

    pub(in crate::win16_runtime) fn cancel_resource_callback_for_teardown(
        &mut self,
        ended: &super::super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let id = self.require_callback_top(CallbackKind::Resource)?;
        let frame = self
            .resource_callbacks
            .last_mut()
            .filter(|frame| frame.callback_id == id)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "terminal resource cancellation has no exact source",
                )
            })?;
        frame.terminal = true;
        if let Some(mut call) = frame.callback.clone() {
            let result = self.abort_guest_far_callback_after_task_execution_ended(
                ended,
                CallbackKind::Resource,
                id,
                cpu,
                dos,
                memory,
                &mut call,
            );
            self.resource_callbacks
                .last_mut()
                .expect("terminal resource handler")
                .callback = Some(call);
            result?;
            self.resource_callbacks
                .last_mut()
                .expect("aborted resource handler")
                .callback = None;
        }
        let frame = self
            .resource_callbacks
            .last()
            .expect("terminal resource CPU owners");
        for (parked, owner) in [(true, frame.parked), (false, frame.caller)] {
            if let Some(owner) = owner {
                self.abort_legacy_cpu_frame_after_task_execution_ended(
                    ended, owner, cpu, dos, memory,
                )?;
                let frame = self
                    .resource_callbacks
                    .last_mut()
                    .expect("retained terminal resource source");
                if parked {
                    frame.parked = None;
                } else {
                    frame.caller = None;
                }
            }
        }
        // AllocResource/default-loader blocks and committed resource effects
        // remain owned by the resource/global-heap registries. Cancellation
        // must not free a handler-provided raw HGLOBAL without its identity.
        self.retire_callback_binding(CallbackKind::Resource, id)?;
        self.resource_callbacks
            .pop()
            .expect("terminal resource source survived CPU cleanup");
        Ok(())
    }
}
