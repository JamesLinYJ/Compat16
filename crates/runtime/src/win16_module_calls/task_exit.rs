//! WEP_FREE_DLL callbacks while the terminating task still owns execution.

use super::*;

impl Win16State {
    pub(in crate::win16_runtime) fn has_pending_task_exit_modules(&self) -> bool {
        self.modules
            .records
            .iter()
            .any(|(&handle, record)| eligible(self.modules.main, handle, record))
    }

    pub(in crate::win16_runtime) fn begin_task_exit_module_calls(
        &mut self,
        scope: TaskExitModuleScope,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if !self.has_pending_task_exit_modules() {
            return Ok(false);
        }
        let mut modules = Vec::new();
        modules
            .try_reserve_exact(self.modules.records.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve task-exit DLL cleanup owners",
                    error,
                )
            })?;
        for (&handle, record) in &self.modules.records {
            // A LibMain that requested termination before returning TRUE
            // never became an initialized DLL. Its existing load owner is
            // cancelled by terminal teardown, without an invented WEP call.
            if eligible(self.modules.main, handle, record) {
                modules.push(handle);
            }
        }
        if modules.is_empty() {
            return Ok(false);
        }
        let order = self.module_unload_order(&modules);
        let return_to = (cpu.regs.cs, cpu.regs.ip(), u32::from(cpu.regs.sp()));
        self.publish_module_call(
            cpu,
            ModuleAction::TaskExit { modules, scope },
            VecDeque::new(),
            return_to,
        )?;
        let callback = self
            .module_callbacks
            .last()
            .expect("published task-exit DLL owner")
            .callback_id;
        self.toolhelp_task_exit
            .begin_module_cleanup(scope, callback)?;
        self.capture_module_cpu_owners(cpu, dos, memory, false)?;
        self.prepare_module_unload(order)?;
        self.advance_module_calls(cpu, dos, memory, host)?;
        Ok(true)
    }

    pub(in crate::win16_runtime) fn task_exit_module_call_is_live(
        &self,
        scope: TaskExitModuleScope,
        callback: CallbackFrameId,
    ) -> Result<bool, RuntimeError> {
        let mut matches = self
            .module_callbacks
            .iter()
            .filter(|frame| frame.callback_id == callback);
        let Some(frame) = matches.next() else {
            return Ok(false);
        };
        if matches.next().is_some()
            || frame.terminal
            || !frame.prepared
            || !matches!(&frame.action, ModuleAction::TaskExit { scope: held, .. } if *held == scope)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DLL cleanup source differs from its exact terminal continuation",
            ));
        }
        Ok(true)
    }
}

fn eligible(main: u16, handle: u16, record: &super::super::module_registry::ModuleRecord) -> bool {
    handle != main
        && !record.builtin
        && record.state == ModuleState::Ready
        && !record.wep_called
        && record.external_application.is_none()
        && record
            .definition
            .as_ref()
            .is_some_and(|definition| definition.header.flags & 0x8000 != 0)
}
