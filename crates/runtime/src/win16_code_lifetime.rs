//! Active architectural FAR return addresses retain their owning guest code.

use x86_cpu::ControlTransfer;
use guest_core::Registers;
use super::Win16State;
use crate::{DiagnosticKind, RuntimeError};

// A resource limit for observation metadata, independent of the guest ABI.
const MAX_OBSERVED_FAR_CALLS: usize = 65_536;

pub(super) struct FarCallResume {
    pub(super) selector: u16,
    offset: u32,
    stack: u16,
    /// SS:SP immediately after CALL wrote the return-address frame.
    frame_sp: u16,
}

impl Win16State {
    pub(super) fn observe_control_transfer(&mut self, transfer: Option<ControlTransfer>,
        before_stack: (u16, u16), registers: &Registers) -> Result<(), RuntimeError> {
        let (stack_selector, frame_sp) = before_stack;
        match transfer {
            Some(ControlTransfer::FarCall { return_selector, return_offset, stack_selector }) => {
                if self.far_returns.len() == MAX_OBSERVED_FAR_CALLS {
                    return Err(RuntimeError::new(DiagnosticKind::ResourceExhausted,
                        "Win16 active FAR call observation limit reached"));
                }
                self.far_returns.push(FarCallResume {
                    selector: return_selector, offset: return_offset,
                    stack: stack_selector, frame_sp: registers.sp(),
                });
            }
            Some(ControlTransfer::FarReturn | ControlTransfer::AdapterReturn) => self.retire_far_return(
                registers.cs, u32::from(registers.ip()), registers.ss),
            Some(ControlTransfer::InterruptReturn) => {
                self.retire_interrupt_return(registers)?;
                // IRET also consumes a PUSHF/CALL FAR chain's return address.
                // Match the actual frame SS:SP before IRET, not just its final
                // destination: recursive calls can share a return CS:IP.
                if let Some(index) = self.far_returns.iter().rposition(|entry|
                    entry.selector == registers.cs && entry.offset == u32::from(registers.ip())
                        && entry.stack == registers.ss && entry.stack == stack_selector
                        && entry.frame_sp == frame_sp) {
                    self.far_returns.truncate(index);
                }
            }
            None => {}
        }
        Ok(())
    }

    pub(super) fn retire_far_return(&mut self, selector: u16, offset: u32, stack: u16) {
        if let Some(index) = self.far_returns.iter().rposition(|entry|
            entry.selector == selector && entry.offset == offset && entry.stack == stack) {
            self.far_returns.truncate(index);
        }
        // A nonlocal guest transfer may not match an observed CALL. Keep such
        // code alive conservatively; arbitrary stack bytes are never guessed
        // to be return addresses and no guest memory is rewritten here.
    }
}
