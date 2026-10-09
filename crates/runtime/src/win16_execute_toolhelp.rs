//! ToolHelp notification safe points in the Win16 instruction loop.

use crate::machine::Runtime;
use crate::{DiagnosticKind as Kind, RuntimeError};

impl Runtime {
    /// Scoped module notifications must run before the first LibMain step.
    /// A pending but blocked scoped event is a compatibility boundary, not an
    /// empty queue; allowing guest execution would skip STARTDLL delivery.
    pub(super) fn service_toolhelp_module_entry(&mut self) -> Result<bool, RuntimeError> {
        let Some(state) = self.win16.as_mut() else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 execution state is missing",
            ));
        };
        if state.callback_kinds.last() != Some(&super::super::CallbackKind::Module)
            || !state
                .toolhelp_notify_module_entry_has_pending(self.cpu.regs.cs, self.cpu.regs.ip())?
        {
            return Ok(false);
        }
        if state.dispatch_pending_toolhelp_notify_for_module_entry(
            &mut self.cpu,
            &mut self.dos,
            &mut self.memory,
        )? {
            return Ok(true);
        }
        Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "ToolHelp module-entry scope is blocked by an event that cannot yet be dispatched",
        ))
    }
}

/// Poll the same checked ToolHelp dispatcher for protected 16-bit guests.
/// Receive the live state borrow already held by the instruction loop.
pub(super) fn dispatch_protected_toolhelp_notifications(
    state: &mut crate::win16_runtime::Win16State,
    cpu: &mut x86_cpu::Cpu,
    dos: &mut dos_kernel::DosKernel,
    memory: &mut guest_core::memory::Memory,
    guest_dispatch_allowed: bool,
) -> Result<(), RuntimeError> {
    if protected_toolhelp_dispatch_allowed(state, cpu, guest_dispatch_allowed) {
        state.dispatch_pending_toolhelp_notify(cpu, dos, memory)?;
    }
    Ok(())
}

/// Share the protected callback predicate with readiness scheduling so a
/// produced ToolHelp backlog gets the same immediate drain opportunity.
pub(super) fn protected_toolhelp_dispatch_allowed(
    state: &crate::win16_runtime::Win16State,
    cpu: &x86_cpu::Cpu,
    guest_dispatch_allowed: bool,
) -> bool {
    guest_dispatch_allowed
        && cpu.architectural_execution_mode() == Some(x86_cpu::CpuExecutionMode::Protected)
        && state.callback_kinds.is_empty()
        && !cpu.interrupt_shadow_active()
        && !state.is_service_gate(cpu.regs.cs)
        && !state.is_native_procedure_gate(cpu.regs.cs)
        && !state.is_callback_gate(cpu.regs.cs)
}
