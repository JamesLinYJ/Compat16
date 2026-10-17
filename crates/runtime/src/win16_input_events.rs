//! Deliver USER.289 and USER.299 through the host input recorder.
//!
//! Both exports return void. The register image stays in the guest registers.
//! `Win16ReturnKind::RegisterContext` would overwrite AX, so the return uses
//! the void policy and leaves every general register unchanged.

use guest_core::memory::Memory;
use win16_abi::Win16ReturnKind;
use x86_cpu::Cpu;

use super::Win16State;
use crate::{RuntimeHost, Win16InjectedKey, Win16InjectedMouse};

impl Win16State {
    pub(super) fn inject_user_input(
        &mut self,
        request: win16_abi::Win16UserInputRequest,
        cpu: &mut Cpu,
        memory: &Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<u8>, crate::RuntimeError> {
        let (return_selector, return_offset, return_sp) = self.far_return(&cpu.regs, memory, 0)?;
        match request {
            win16_abi::Win16UserInputRequest::KeybdEvent {
                virtual_key,
                scan,
                flags,
                extra_info,
            } => host.win16_inject_keyboard(Win16InjectedKey {
                virtual_key,
                scan,
                flags,
                extra_info,
            })?,
            win16_abi::Win16UserInputRequest::MouseEvent {
                flags,
                dx,
                dy,
                buttons,
                extra_info,
            } => host.win16_inject_mouse(Win16InjectedMouse {
                flags,
                dx,
                dy,
                buttons,
                extra_info,
            })?,
        }
        self.complete_return(
            &mut cpu.regs,
            return_selector,
            return_offset,
            return_sp,
            0,
            Win16ReturnKind::Void,
        )
    }
}
