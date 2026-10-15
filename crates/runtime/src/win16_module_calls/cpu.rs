//! Checked CPU ownership for loader operations and each DLL entry invocation.
use super::super::far_callback::Win16FarCallbackFrame;
use super::*;
use x86_cpu::{CallEffectPolicy, CallResumeBoundary};

#[derive(Default)]
pub(super) struct ModuleCpuOwners {
    pub caller: Option<u64>,
    pub parked: Option<u64>,
    pub active_call: Option<Win16FarCallbackFrame>,
}

impl Win16State {
    pub(super) fn capture_module_cpu_owners(
        &mut self,
        cpu: &Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        api: bool,
    ) -> Result<(), RuntimeError> {
        if api {
            let caller = self.capture_legacy_cpu_call_frame(cpu, dos, memory)?;
            self.module_callbacks
                .last_mut()
                .expect("published DLL caller owner")
                .cpu
                .caller = Some(caller);
        }
        let parked = self.capture_legacy_cpu_parked_frame(cpu, dos, memory)?;
        self.module_callbacks
            .last_mut()
            .expect("published DLL parked owner")
            .cpu
            .parked = Some(parked);
        Ok(())
    }

    pub(super) fn preflight_module_cpu_owners(&self, cpu: &Cpu) -> Result<(), RuntimeError> {
        let id = self.require_callback_top(CallbackKind::Module)?;
        let frame = self.module_callbacks.last().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "DLL continuation has no exact CPU owner",
            )
        })?;
        if frame.callback_id != id || frame.terminal || !frame.prepared {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DLL continuation cannot execute after terminal cancellation or incomplete preparation",
            ));
        }
        for owner in [frame.cpu.caller, frame.cpu.parked].into_iter().flatten() {
            self.preflight_legacy_cpu_frame(owner, cpu)?;
        }
        Ok(())
    }

    pub(super) fn finish_module_cpu_callback(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let mut call = self
            .module_callbacks
            .last()
            .and_then(|frame| frame.cpu.active_call.clone())
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "DLL callback return has no retained checked FAR owner",
                )
            })?;
        let result = self
            .finish_guest_far_callback_checked(cpu, dos, memory, &mut call)
            .and_then(|value| {
                self.release_guest_far_callback_owner(&mut call, dos, memory)
                    .map(|()| value as u16)
            });
        self.module_callbacks
            .last_mut()
            .expect("checked DLL callback source remains")
            .cpu
            .active_call = Some(call);
        result
    }

    pub(super) fn return_module_cpu_caller(
        &mut self,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        resume: bool,
        value: u32,
        kind: Win16ReturnKind,
    ) -> Result<(), RuntimeError> {
        let frame = self
            .module_callbacks
            .last()
            .expect("prepared DLL completion owner");
        let (parked, caller, saved, return_to) = (
            frame.cpu.parked,
            frame.cpu.caller,
            frame.saved.clone(),
            frame.return_to,
        );
        if resume == caller.is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DLL completion caller ownership differs from its API/resume role",
            ));
        }
        if let Some(parked) = parked {
            if let Some(caller) = caller {
                self.restore_legacy_cpu_parked_frame_for_call(
                    parked,
                    caller,
                    cpu,
                    CallEffectPolicy::PreserveX87,
                    memory,
                )?;
            } else {
                self.restore_legacy_cpu_parked_frame(parked, cpu, dos, memory)?;
            }
            self.release_legacy_cpu_frame(parked, dos, memory)?;
            self.module_callbacks
                .last_mut()
                .expect("resumed DLL owner")
                .cpu
                .parked = None;
        }
        if let Some(caller) = caller {
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
        }
        Ok(())
    }

    pub(super) fn retire_completed_module_call(
        &mut self,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let id = self.require_callback_top(CallbackKind::Module)?;
        let frame = self
            .module_callbacks
            .last()
            .filter(|frame| {
                frame.callback_id == id
                    && frame.phase == ModuleCallPhase::Returned
                    && frame.cpu.parked.is_none()
                    && frame.cpu.active_call.is_none()
            })
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "DLL retirement precedes its checked caller return",
                )
            })?;
        let startup = frame.startup;
        if let Some(caller) = frame.cpu.caller {
            self.release_legacy_cpu_frame(caller, dos, memory)?;
            self.module_callbacks
                .last_mut()
                .expect("returned DLL CPU owner")
                .cpu
                .caller = None;
        }
        self.retire_callback_binding(CallbackKind::Module, id)?;
        self.module_callbacks
            .pop()
            .expect("exact DLL source retained through final retirement");
        // A failed startup must stop at this callback boundary, before the
        // execute loop can poll or enter another queued guest callback.
        if startup { self.check_program_modules() } else { Ok(()) }
    }

    pub(in crate::win16_runtime) fn cancel_module_callback_for_teardown(
        &mut self,
        ended: &super::super::execute::Win16TaskExecutionEnded,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let id = self.require_callback_top(CallbackKind::Module)?;
        let frame = self
            .module_callbacks
            .last_mut()
            .filter(|frame| frame.callback_id == id)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "terminal DLL cancellation has no exact source owner",
                )
            })?;
        frame.terminal = true;
        if let Some(mut call) = frame.cpu.active_call.clone() {
            let result = self.abort_guest_far_callback_after_task_execution_ended(
                ended,
                CallbackKind::Module,
                id,
                cpu,
                dos,
                memory,
                &mut call,
            );
            self.module_callbacks
                .last_mut()
                .expect("terminal DLL callback owner")
                .cpu
                .active_call = Some(call);
            result?;
            self.module_callbacks
                .last_mut()
                .expect("terminal DLL callback owner")
                .cpu
                .active_call = None;
        }
        let owners = &self
            .module_callbacks
            .last()
            .expect("terminal DLL source")
            .cpu;
        for (parked, owner) in [(true, owners.parked), (false, owners.caller)] {
            if let Some(owner) = owner {
                self.abort_legacy_cpu_frame_after_task_execution_ended(
                    ended, owner, cpu, dos, memory,
                )?;
                let owners = &mut self
                    .module_callbacks
                    .last_mut()
                    .expect("terminal DLL source")
                    .cpu;
                if parked {
                    owners.parked = None;
                } else {
                    owners.caller = None;
                }
            }
        }
        let frame = self
            .module_callbacks
            .last()
            .expect("terminal DLL metadata owner");
        let modules: &[u16] = match &frame.action {
            ModuleAction::Discover { created } | ModuleAction::LoadFailure { created, .. } => {
                created
            }
            ModuleAction::Load { created, .. } if frame.phase != ModuleCallPhase::Returned => {
                created
            }
            ModuleAction::Load { .. } => &[],
            ModuleAction::Unload { modules, .. } => modules,
        };
        let modules = copy_module_handles(modules, "retain terminal DLL retirement plan")?;
        if frame.phase != ModuleCallPhase::Returned {
            self.detach_failed_startup_dependencies();
        }
        self.rollback_modules(&modules)?;
        self.module_reap_pending = true;
        self.retire_callback_binding(CallbackKind::Module, id)?;
        self.module_callbacks
            .pop()
            .expect("terminal DLL source retained through cleanup");
        Ok(())
    }
}
