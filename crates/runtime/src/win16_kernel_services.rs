//! Dispatch for checked KERNEL, TOOLHELP, and SYSTEM guest-service requests.

use guest_core::{memory::Memory, Registers};
use win16_abi::{
    Access, Win16ApiRequest, Win16KernelMemoryRequest, Win16KernelModuleRequest,
    Win16KernelStringRequest, Win16KernelTaskRequest, Win16SystemRequest,
    Win16ToolhelpRequest,
};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

pub(super) enum Win16KernelServicesResult {
    Return(u32),
    TerminateApp { exit_code: u16 },
}

impl Win16State {
    /// Run one implemented kernel-family request using guest-owned state.
    /// `vm_start_tick` is captured by the runtime before guest execution.
    pub(super) fn dispatch_kernel_services(
        &mut self,
        request: Win16ApiRequest,
        registers: &Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        vm_start_tick: Option<u32>,
    ) -> Result<Win16KernelServicesResult, RuntimeError> {
        let result = match request {
            Win16ApiRequest::KernelMemory(request) => match request {
                Win16KernelMemoryRequest::IsBadReadPointer { pointer, length } => {
                    u32::from(self.kernel_is_bad_memory_pointer(
                        pointer, length, Access::Read, memory,
                    )?)
                }
                Win16KernelMemoryRequest::IsBadWritePointer { pointer, length } => {
                    u32::from(self.kernel_is_bad_memory_pointer(
                        pointer, length, Access::Write, memory,
                    )?)
                }
                Win16KernelMemoryRequest::IsBadCodePointer { pointer } => {
                    u32::from(self.kernel_is_bad_code_pointer(pointer, memory))
                }
                Win16KernelMemoryRequest::IsBadStringPointer { pointer, maximum } => {
                    u32::from(self.kernel_is_bad_string_pointer(pointer, maximum, memory))
                }
                Win16KernelMemoryRequest::IsBadHugeReadPointer { pointer, length } => {
                    u32::from(self.kernel_is_bad_huge_memory_pointer(
                        pointer, length, Access::Read, memory,
                    )?)
                }
                Win16KernelMemoryRequest::IsBadHugeWritePointer { pointer, length } => {
                    u32::from(self.kernel_is_bad_huge_memory_pointer(
                        pointer, length, Access::Write, memory,
                    )?)
                }
            },
            Win16ApiRequest::KernelTask(request) => match request {
                Win16KernelTaskRequest::GetCurrentPDB => self.kernel_get_current_pdb(),
                Win16KernelTaskRequest::GetDOSEnvironment => {
                    self.compat.environment_pointer(&self.selectors, memory)?.far_value()
                }
                Win16KernelTaskRequest::GetNumTasks => u32::from(self.kernel_get_num_tasks()?),
                Win16KernelTaskRequest::GetTaskDS => u32::from(self.kernel_get_task_ds()),
                Win16KernelTaskRequest::IsTask { task } => u32::from(self.kernel_is_task(task)),
                Win16KernelTaskRequest::SetPriority { task, delta } => {
                    self.kernel_set_priority(task, delta)?;
                    0
                }
                Win16KernelTaskRequest::LockCurrentTask { lock } => {
                    u32::from(self.kernel_lock_current_task(lock)?)
                }
                Win16KernelTaskRequest::SetTaskQueue { task, queue } => {
                    u32::from(self.kernel_set_task_queue(task, queue)?)
                }
                Win16KernelTaskRequest::GetTaskQueue { task } => {
                    u32::from(self.kernel_get_task_queue(task)?)
                }
                Win16KernelTaskRequest::OldYield => {
                    self.kernel_old_yield(host)?;
                    0
                }
                Win16KernelTaskRequest::GetTaskQueueDs => {
                    u32::from(self.kernel_task_queue_for_segment(registers.ds)?)
                }
                Win16KernelTaskRequest::GetTaskQueueEs => {
                    u32::from(self.kernel_task_queue_for_segment(registers.es)?)
                }
                Win16KernelTaskRequest::IsTaskLocked => u32::from(self.kernel_is_task_locked()),
                Win16KernelTaskRequest::SetLastError { error } => {
                    self.kernel_set_last_error(error)?;
                    0
                }
                Win16KernelTaskRequest::GetLastError => self.kernel_get_last_error()?,
                Win16KernelTaskRequest::GetVersionEx { version_info } => {
                    u32::from(self.kernel_get_version_ex(version_info, memory)?)
                }
                Win16KernelTaskRequest::DirectedYield { task } => {
                    u32::from(self.kernel_directed_yield(task))
                }
            },
            Win16ApiRequest::KernelModule(request) => match request {
                Win16KernelModuleRequest::GetModuleName { module, output, capacity } => {
                    u32::from(self.kernel_get_module_name(module, output, capacity, memory, host)?)
                }
                Win16KernelModuleRequest::GetExePtr { handle } => {
                    u32::from(self.kernel_get_exe_ptr(handle, host))
                }
                Win16KernelModuleRequest::GetExeVersion => {
                    u32::from(self.kernel_get_exe_version())
                }
                Win16KernelModuleRequest::GetExpWinVer { module } => {
                    self.kernel_get_exp_win_ver(module, host)
                }
            },
            Win16ApiRequest::KernelString(request) => match request {
                Win16KernelStringRequest::Lstrcatn { destination, source, limit } => {
                    self.kernel_lstrcatn(destination, &source, limit, memory)?
                }
                Win16KernelStringRequest::Lstrcpyn { destination, source, limit } => {
                    self.kernel_lstrcpyn(destination, &source, limit, memory)?
                }
            },
            Win16ApiRequest::Toolhelp(request) => match request {
                Win16ToolhelpRequest::SystemHeapInfo { output } => {
                    u32::from(self.toolhelp_system_heap_info(output, memory)?)
                }
                Win16ToolhelpRequest::MemManInfo { output } => {
                    u32::from(self.toolhelp_memman_info(output, memory)?)
                }
                Win16ToolhelpRequest::TaskSetCsip { .. } => {
                    self.toolhelp_task_set_csip_unavailable()
                }
                Win16ToolhelpRequest::TaskSwitch { .. } => {
                    u32::from(self.toolhelp_task_switch_unavailable())
                }
                Win16ToolhelpRequest::NotifyRegister { task, callback, flags } => {
                    u32::from(self.toolhelp_notify_register(task, callback, flags, memory)?)
                }
                Win16ToolhelpRequest::NotifyUnregister { task } => {
                    u32::from(self.toolhelp_notify_unregister(task)?)
                }
                Win16ToolhelpRequest::LocalInfo { output, heap } => {
                    u32::from(self.toolhelp_local_info(output, heap, memory)?)
                }
                Win16ToolhelpRequest::LocalFirst { output, heap } => {
                    u32::from(self.toolhelp_local_first(output, heap, memory)?)
                }
                Win16ToolhelpRequest::LocalNext { output } => {
                    u32::from(self.toolhelp_local_next(output, memory)?)
                }
                Win16ToolhelpRequest::ModuleFirst { output } => {
                    u32::from(self.toolhelp_module_first(output, memory)?)
                }
                Win16ToolhelpRequest::ModuleNext { output } => {
                    u32::from(self.toolhelp_module_next(output, memory)?)
                }
                Win16ToolhelpRequest::ModuleFindName { output, name } => {
                    u32::from(self.toolhelp_module_find_name(output, &name, memory)?)
                }
                Win16ToolhelpRequest::ModuleFindHandle { output, module } => {
                    u32::from(self.toolhelp_module_find_handle(output, module, memory)?)
                }
                Win16ToolhelpRequest::TaskFirst { output } => {
                    u32::from(self.toolhelp_task_first(output, registers, memory)?)
                }
                Win16ToolhelpRequest::TaskNext { output } => {
                    u32::from(self.toolhelp_task_next(output, registers, memory)?)
                }
                Win16ToolhelpRequest::TaskFindHandle { output, task } => {
                    u32::from(self.toolhelp_task_find_handle(output, task, registers, memory)?)
                }
                Win16ToolhelpRequest::TaskGetCSIP { task } => {
                    self.toolhelp_task_get_csip(task, registers)?
                }
                Win16ToolhelpRequest::ClassFirst { output } => {
                    u32::from(self.toolhelp_class_first(output, memory)?)
                }
                Win16ToolhelpRequest::ClassNext { output } => {
                    u32::from(self.toolhelp_class_next(output, memory)?)
                }
                Win16ToolhelpRequest::TimerCount { output } => {
                    let Some(start_tick) = vm_start_tick else {
                        return Ok(Win16KernelServicesResult::Return(0));
                    };
                    u32::from(self.toolhelp_timer_count(output, start_tick, memory, host)?)
                }
                Win16ToolhelpRequest::MemoryRead { selector, offset, output, count } => {
                    self.toolhelp_memory_read(selector, offset, output, count, memory)?
                }
                Win16ToolhelpRequest::MemoryWrite { selector, offset, input, count } => {
                    self.toolhelp_memory_write(selector, offset, input, count, memory)?
                }
                Win16ToolhelpRequest::TerminateApp { task, exit_code } => {
                    if self.toolhelp_terminate_app_target(task)? {
                        return Ok(Win16KernelServicesResult::TerminateApp { exit_code });
                    }
                    0
                }
            },
            Win16ApiRequest::System(request) => match request {
                Win16SystemRequest::GetSystemMSecCount => self.system_msec_count(host)?,
            },
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "kernel-family dispatcher received an unrelated Win16 request")),
        };
        Ok(Win16KernelServicesResult::Return(result))
    }
}
