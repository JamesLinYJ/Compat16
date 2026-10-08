//! KERNEL debug and fatal APIs remain guest-task effects, never host exits.

use guest_core::memory::Memory;
use win16_abi::{Win16ReturnKind, Win16KernelDiagnosticRequest};
use x86_cpu::Cpu;

use super::{Win16State, windows::WindowReturn};
use super::toolhelp_notify_exit::Win16ToolhelpRip;
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostDialogOperation, Win16HostUserServiceOperation, Win16WindowOperation,
};

// The Win16 entry points specify no task exit code; 1 is the runtime's
// deterministic failure status and is not derived from FatalExit's display code.
const FATAL_TASK_EXIT_STATUS: u16 = 1;

#[derive(Debug)]
pub(in crate::win16_runtime) enum Win16KernelDiagnosticContinuation {
    FatalAppExit { exit_status: u16 },
}

/// A USER modal result cannot borrow the CPU while guest callbacks run. Queue
/// its guest effect and let the instruction loop apply it after the callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum Win16KernelDiagnosticEffect {
    FinishTask { status: u16 },
    FatalExit { status: u16, rip: Win16ToolhelpRip },
}

impl Win16State {
    pub(in crate::win16_runtime) fn begin_kernel_diagnostic(
        &mut self,
        request: Win16KernelDiagnosticRequest,
        cpu: &mut Cpu,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        match request {
            Win16KernelDiagnosticRequest::OutputDebugString { message } => {
                host.win16_output_debug_string(&message)?;
                self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                    return_to.2, 0, Win16ReturnKind::Void)
            }
            Win16KernelDiagnosticRequest::DebugBreak => {
                self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                    return_to.2, 0, Win16ReturnKind::Void)?;
                // DebugBreak is a guest breakpoint exception. An absent guest
                // vector stays a typed compatibility gap; the host is untouched.
                self.begin_software_interrupt(3, cpu, memory)?;
                Ok(None)
            }
            Win16KernelDiagnosticRequest::FatalAppExit { action, message } => {
                if action != 0 {
                    host.report_diagnostic(&Diagnostic::warning(Kind::InvalidInput,
                        "FatalAppExit fuAction is reserved and must be zero; this invalid call was ignored"));
                    return self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                        return_to.2, 0, Win16ReturnKind::Void);
                }
                host.observe_win16_io(&crate::Win16IoEvent::Dialog {
                    api: "FatalAppExit", caption: &[], text: &message,
                });
                self.begin_window_operation(
                    &mut cpu.regs,
                    memory,
                    host,
                    Win16WindowOperation::UserService(
                        Win16HostUserServiceOperation::Dialog(
                            Win16HostDialogOperation::FatalAppExitMessage { message },
                        ),
                    ),
                    WindowReturn::KernelDiagnostics(
                        Win16KernelDiagnosticContinuation::FatalAppExit {
                            exit_status: FATAL_TASK_EXIT_STATUS,
                        },
                    ),
                    return_to,
                )
            }
            Win16KernelDiagnosticRequest::FatalExit { error_code } => {
                host.report_diagnostic(&Diagnostic::info(Kind::GuestFault,
                    format!("Win16 FatalExit({error_code}) reported a guest fatal error")));
                let rip = Win16ToolhelpRip {
                    instruction_pointer: return_to.1,
                    code_segment: return_to.0,
                    stack_segment: cpu.regs.ss,
                    base_pointer: cpu.regs.bp(),
                    // FatalExit takes a signed INT; ToolHelp exposes its WORD bits.
                    exit_code: u16::from_le_bytes(error_code.to_le_bytes()),
                };
                self.pending_kernel_diagnostic_effects.try_reserve(1).map_err(|error|
                    RuntimeError::with_source(Kind::ResourceExhausted,
                        "queue Win16 FatalExit task termination", error))?;
                self.complete_return(&mut cpu.regs, return_to.0, return_to.1,
                    return_to.2, 0, Win16ReturnKind::Void)?;
                self.pending_kernel_diagnostic_effects.push(
                    Win16KernelDiagnosticEffect::FatalExit {
                        status: FATAL_TASK_EXIT_STATUS,
                        rip,
                    },
                );
                Ok(None)
            }
        }
    }

    pub(in crate::win16_runtime) fn take_kernel_diagnostic_effect(
        &mut self,
    ) -> Option<Win16KernelDiagnosticEffect> {
        self.pending_kernel_diagnostic_effects.pop()
    }

    pub(in crate::win16_runtime) fn drain_kernel_diagnostic_effects(
        &mut self,
        _memory: &mut Memory,
        _host: &mut impl RuntimeHost,
    ) -> Result<Option<u8>, RuntimeError> {
        while let Some(effect) = self.take_kernel_diagnostic_effect() {
            match effect {
                Win16KernelDiagnosticEffect::FinishTask { status } => {
                    self.request_toolhelp_task_termination(status, None)?;
                    return Ok(None);
                }
                Win16KernelDiagnosticEffect::FatalExit { status, rip } => {
                    self.request_toolhelp_task_termination(status, Some(rip))?;
                    return Ok(None);
                }
            }
        }
        Ok(None)
    }
}
