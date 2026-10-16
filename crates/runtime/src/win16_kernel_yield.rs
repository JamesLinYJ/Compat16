//! KERNEL.Yield shares USER's resumable callback boundary for GUI tasks.

use guest_core::{Registers, Selector, memory::Memory};
use win16_abi::Win16ReturnKind;

use super::{Win16State, windows::WindowReturn};
use crate::win16_host_message_calls::Win16MessageCallContinuation;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16MessageCall, Win16WindowOperation,
};

impl Win16State {
    pub(super) fn begin_kernel_yield(
        &mut self,
        registers: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let Some(task_queue) = self.kernel_yield_queue()? else {
            // KERNEL31 routes tasks without a queue to OldYield. Do not create
            // a guest USER queue just because a background computation yields.
            host.win16_yield_thread()?;
            return self.complete_return(
                registers,
                return_to.0,
                return_to.1,
                return_to.2,
                0,
                Win16ReturnKind::Void,
            );
        };
        // A native PeekMessage can deliver sent messages before returning.
        // Keep the exact caller CPU owner in the ordinary USER operation,
        // allowing its guest callbacks to suspend, nest and resume safely.
        self.begin_window_operation(
            registers,
            memory,
            host,
            Win16WindowOperation::MessageCall(Win16MessageCall::Yield { task_queue }),
            WindowReturn::MessageCall(Win16MessageCallContinuation::Yield),
            return_to,
        )
    }

    pub(super) fn kernel_yield_queue(
        &self,
    ) -> Result<Option<crate::Win16HostTaskQueue>, RuntimeError> {
        let Some(owner) = self.tasks.current() else {
            return Ok(None);
        };
        let Some((_, task, generation, queue)) =
            self.user_task_queue.filter(|entry| entry.0 == owner)
        else {
            return Ok(None);
        };
        if self.task_handles.get(&owner) != Some(&task)
            || !self
                .selectors
                .reference(Selector(task))
                .is_ok_and(|reference| reference.generation() == generation)
        {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "KERNEL.Yield task queue has a stale guest task selector",
            ));
        }
        Ok(Some(queue))
    }
}
