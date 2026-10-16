//! A terminal request owns each DLL-cleanup batch until both its WEP calls
//! and the exact module continuation have returned and retired.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TaskExitModulePhase {
    Pending,
    Running(super::super::CallbackFrameId),
    Returned(super::super::CallbackFrameId),
    Ready,
}

impl Win16ToolhelpTaskExitState {
    pub(in crate::win16_runtime) fn begin_module_cleanup(
        &mut self,
        scope: TaskExitModuleScope,
        callback: super::super::CallbackFrameId,
    ) -> Result<(), RuntimeError> {
        let pending = self.pending.as_mut().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "DLL cleanup has no accepted task-exit request",
            )
        })?;
        if pending.id != scope.termination_id
            || pending.task != scope.task
            || pending.modules != TaskExitModulePhase::Pending
            || pending.outstanding_notifications != 0
            || pending.active_dispatch_callback.is_some()
            || pending.active_drain_callback.is_some()
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DLL cleanup changed its exact task-exit notification owner",
            ));
        }
        pending.modules = TaskExitModulePhase::Running(callback);
        Ok(())
    }

    pub(in crate::win16_runtime) fn validate_module_cleanup_return(
        &self,
        scope: TaskExitModuleScope,
        callback: super::super::CallbackFrameId,
    ) -> Result<(), RuntimeError> {
        let pending = self.pending.ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "DLL cleanup return lost its accepted task-exit request",
            )
        })?;
        if pending.id != scope.termination_id
            || pending.task != scope.task
            || !matches!(pending.modules,
                TaskExitModulePhase::Running(id) | TaskExitModulePhase::Returned(id) if id == callback)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DLL cleanup return belongs to a stale task-exit continuation",
            ));
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn module_cleanup_returned(
        &mut self,
        scope: TaskExitModuleScope,
        callback: super::super::CallbackFrameId,
    ) -> Result<(), RuntimeError> {
        self.validate_module_cleanup_return(scope, callback)?;
        self.pending
            .as_mut()
            .expect("validated task-exit continuation")
            .modules = TaskExitModulePhase::Returned(callback);
        Ok(())
    }
}

impl Win16State {
    pub(super) fn service_task_exit_modules(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        loop {
            let pending = self.toolhelp_task_exit.pending().ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "DLL cleanup lost its accepted task-exit request",
                )
            })?;
            let scope = TaskExitModuleScope {
                termination_id: pending.id,
                task: pending.task,
            };
            match pending.modules {
                TaskExitModulePhase::Pending => {
                    let owner = self.tasks.current().ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "DLL cleanup has no current Win16 task",
                        )
                    })?;
                    if !self.classic_dde_task_exit_quiesced(owner) {
                        return Ok(false);
                    }
                    if !self.begin_task_exit_module_calls(scope, cpu, dos, memory, host)? {
                        self.toolhelp_task_exit
                            .pending
                            .as_mut()
                            .expect("live task-exit request")
                            .modules = TaskExitModulePhase::Ready;
                    }
                }
                TaskExitModulePhase::Running(callback) => {
                    if !self.task_exit_module_call_is_live(scope, callback)? {
                        return Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "running DLL cleanup lost its exact module continuation",
                        ));
                    }
                    return Ok(false);
                }
                TaskExitModulePhase::Returned(callback) => {
                    if self.task_exit_module_call_is_live(scope, callback)? {
                        return Ok(false);
                    }
                    // A WEP may have loaded another DLL. Sweep again only
                    // after the preceding batch's CPU owners have retired.
                    self.toolhelp_task_exit
                        .pending
                        .as_mut()
                        .expect("live task-exit request")
                        .modules = TaskExitModulePhase::Pending;
                }
                TaskExitModulePhase::Ready => {
                    // A later DDE/terminal notification callback may have
                    // loaded another DLL after the last WEP batch retired.
                    if !self.has_pending_task_exit_modules() {
                        return Ok(true);
                    }
                    self.toolhelp_task_exit
                        .pending
                        .as_mut()
                        .expect("live task-exit request")
                        .modules = TaskExitModulePhase::Pending;
                }
            }
        }
    }
}
