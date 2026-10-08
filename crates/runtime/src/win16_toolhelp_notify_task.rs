//! ToolHelp registration lifetime and task-owned cleanup.

use dos_kernel::DosKernel;
use guest_core::memory::Memory;

use super::Win16State;
use crate::RuntimeError;

impl Win16State {
    pub(in crate::win16_runtime) fn toolhelp_notify_register(
        &mut self,
        requested_task: u16,
        callback: u32,
        flags: u16,
        memory: &Memory,
    ) -> Result<u16, RuntimeError> {
        let Some(task) = self.live_toolhelp_notify_task(requested_task)? else {
            return Ok(0);
        };
        self.toolhelp_notify.register(task, callback, flags, &self.selectors, memory)
    }

    pub(in crate::win16_runtime) fn toolhelp_notify_unregister(
        &mut self,
        requested_task: u16,
    ) -> Result<u16, RuntimeError> {
        let Some(task) = self.live_toolhelp_notify_task(requested_task)? else {
            return Ok(0);
        };
        Ok(self.toolhelp_notify.unregister(task))
    }

    fn live_toolhelp_notify_task(&self, requested_task: u16) -> Result<Option<u16>, RuntimeError> {
        let task = if requested_task == 0 {
            self.current_task_handle()?
        } else {
            requested_task
        };
        let owner = self.task_handles.iter().find_map(|(owner, handle)|
            (*handle == task).then_some(*owner));
        let Some(owner) = owner else { return Ok(None); };
        let Ok(info) = self.tasks.info(owner) else { return Ok(None); };
        if matches!(info.state, win16_abi::TaskState::Terminating | win16_abi::TaskState::Exited) {
            return Ok(None);
        }
        Ok(Some(task))
    }

    /// Drop task-scoped ToolHelp registrations only after no guest frame can
    /// reenter them. Private interrupt owners must be released before their
    /// registration identity maps are retired.
    pub(in crate::win16_runtime) fn retire_toolhelp_task_callbacks(
        &mut self,
        task: u16,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        self.retire_toolhelp_interrupt_task_owners(task, cpu, dos, memory)?;
        let retired = self.toolhelp_notify.retire_task(task)?;
        self.interrupt_callbacks.remove(&task);
        self.toolhelp_interrupt_handles.remove(&task);
        let mut failure: Option<RuntimeError> = None;
        for event in retired {
            if let Err(error) = self.discard_toolhelp_notify_event(event) {
                failure = Some(match failure {
                    Some(primary) => primary.with_cleanup(
                        "multiple Win16 ToolHelp task-retirement failures", error),
                    None => error,
                });
            }
        }
        if let Some(error) = failure { Err(error) } else { Ok(()) }
    }

    pub(in crate::win16_runtime) fn clear_toolhelp_callbacks_after_task_end(
        &mut self,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        // Callers unwind guest callback frames before entering this exact
        // terminal cleanup phase; a failed descriptor restore keeps owners
        // retained for a later cleanup retry.
        self.clear_toolhelp_interrupt_retained_owners(cpu, dos, memory)?;
        self.interrupt_callbacks.clear();
        self.toolhelp_interrupt_handles.clear();
        let mut failure: Option<RuntimeError> = None;
        while let Some(event) = self.toolhelp_notify.pop_any_pending() {
            if let Err(error) = self.discard_toolhelp_notify_event(event) {
                failure = Some(match failure {
                    Some(primary) => primary.with_cleanup(
                        "multiple Win16 ToolHelp terminal-cleanup failures", error),
                    None => error,
                });
            }
        }
        self.toolhelp_notify.clear();
        if let Some(error) = failure { Err(error) } else { Ok(()) }
    }

    pub(in crate::win16_runtime) fn toolhelp_notify_code_references(&self) -> impl Iterator<Item = u32> + '_ {
        self.toolhelp_notify.code_references()
    }
}
