//! USER hook entrypoints, including checked guest callback continuations.

use super::Win16State;
use crate::{RuntimeError, RuntimeHost};
use dos_kernel::DosKernel;
use guest_core::memory::Memory;
use win16_abi::{Win16ExportDescriptor, Win16UserHooksRequest as Request};
use x86_cpu::Cpu;

impl Win16State {
    pub(super) fn dispatch_user_hooks(
        &mut self,
        request: Request,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        descriptor: &Win16ExportDescriptor,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let value = match request {
            Request::SetWindowsHook {
                hook_type,
                procedure,
            } => self.set_windows_hook(memory, host, hook_type, procedure)?,
            Request::UnhookWindowsHook {
                hook_type,
                procedure,
            } => u32::from(self.unhook_windows_hook(host, hook_type, procedure)?),
            Request::CallMsgFilter { message, code } => {
                return self.begin_call_msg_filter(cpu, dos, memory, message, code, return_to);
            }
            Request::DefHookProc {
                code,
                w_param,
                l_param,
                hook_slot,
            } => {
                return self.begin_def_hook_proc(
                    cpu, dos, memory, host, code, w_param, l_param, hook_slot, return_to,
                );
            }
            Request::SetWindowsHookEx {
                hook_type,
                procedure,
                instance,
                task,
            } => self.set_windows_hook_ex(memory, host, hook_type, procedure, instance, task)?,
            Request::UnhookWindowsHookEx { hook } => {
                u32::from(self.unhook_windows_hook_ex(host, hook)?)
            }
            Request::CallNextHookEx {
                hook,
                code,
                w_param,
                l_param,
            } => {
                return self.begin_call_next_hook_ex(
                    cpu, dos, memory, host, hook, code, w_param, l_param, return_to,
                );
            }
        };
        self.complete_return(
            &mut cpu.regs,
            return_to.0,
            return_to.1,
            return_to.2,
            value,
            descriptor.return_kind,
        )
    }
}
