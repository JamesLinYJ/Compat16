//! Runtime-owned KERNEL register exports whose contract is not a stack call.

use dos_kernel::{DosAction, DosKernel};
use formats::NeImportTarget;
use guest_core::{OwnerId, Registers};

use super::{ImportBinding, Win16State};
use crate::{DiagnosticKind as Kind, Runtime, RuntimeError, RuntimeHost, runtime_error};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Win16KernelRegisterService {
    Dos3Call,
    NetbiosCall,
    GetSetKernelDosProc,
}

impl Win16State {
    pub(crate) fn complete_kernel_register_return(
        &mut self,
        registers: &mut Registers,
        return_to: (u16, u16, u32),
    ) -> Result<(), RuntimeError> {
        complete_state_register_return(self, registers, return_to)
    }

    pub(super) fn current_task_owner(&self) -> Result<OwnerId, RuntimeError> {
        self.tasks.current().ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant, "Win16 has no current task owner")
        })
    }

    pub(super) fn kernel_register_service_at(
        &self,
        registers: &Registers,
    ) -> Result<Option<Win16KernelRegisterService>, RuntimeError> {
        if !self.is_service_gate(registers.cs) {
            return Ok(None);
        }
        if registers.ip() & 1 != 0 {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                format!(
                    "Win16 service gate offset 0x{:04X} is not aligned",
                    registers.ip()
                ),
            ));
        }
        let slot = usize::from(registers.ip()) / 2;
        let Some(binding) = self.bindings.get(slot) else {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                format!(
                    "Win16 service gate has no export at offset 0x{:04X}",
                    registers.ip()
                ),
            ));
        };
        let ordinal = match binding {
            ImportBinding::Supported(descriptor)
                if descriptor.module().eq_ignore_ascii_case("KERNEL") =>
            {
                descriptor.ordinal()
            }
            ImportBinding::Unavailable { module, target }
                if module.eq_ignore_ascii_case(b"KERNEL") =>
            {
                match target {
                    NeImportTarget::Ordinal(ordinal) => *ordinal,
                    NeImportTarget::Name(name) => match name.as_slice() {
                        b"DOS3Call" => 102,
                        b"NetBIOSCall" => 103,
                        b"GetSetKernelDOSProc" => 311,
                        _ => return Ok(None),
                    },
                }
            }
            _ => return Ok(None),
        };
        Ok(match ordinal {
            102 => Some(Win16KernelRegisterService::Dos3Call),
            103 => Some(Win16KernelRegisterService::NetbiosCall),
            311 => Some(Win16KernelRegisterService::GetSetKernelDosProc),
            _ => None,
        })
    }
}

/// Dispatch KERNEL.102/.103 without decoding a stack frame or fabricating an
/// interrupt frame. The underlying DOS/NetBIOS ABI is a complete register set.
pub(super) fn dispatch(
    runtime: &mut Runtime,
    service: Win16KernelRegisterService,
    host: &mut impl RuntimeHost,
    child_instruction_limit: u64,
) -> Result<Option<u8>, RuntimeError> {
    match service {
        Win16KernelRegisterService::Dos3Call => {
            dispatch_dos3call(runtime, host, child_instruction_limit)
        }
        Win16KernelRegisterService::NetbiosCall => dispatch_netbioscall(runtime, host),
        Win16KernelRegisterService::GetSetKernelDosProc => Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "KERNEL!GetSetKernelDOSProc ordinal 311 has no verified target calling contract",
        )),
    }
}

fn dispatch_dos3call(
    runtime: &mut Runtime,
    host: &mut impl RuntimeHost,
    child_instruction_limit: u64,
) -> Result<Option<u8>, RuntimeError> {
    let return_to = {
        let state = runtime.win16.as_ref().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "KERNEL DOS3Call lost its Win16 task state",
            )
        })?;
        state.far_return(&runtime.cpu.regs, &runtime.memory, 0)?
    };
    let before = runtime.cpu.regs.clone();
    let instruction = runtime.instructions;
    let owner = runtime
        .win16
        .as_ref()
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "KERNEL DOS3Call lost its Win16 task state",
            )
        })?
        .current_task_owner()?;
    let action = {
        let state = runtime.win16.as_mut().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "KERNEL DOS3Call lost its Win16 task state",
            )
        })?;
        match runtime.cpu.regs.ah() {
            0x0e | 0x19 | 0x25 | 0x35 | 0x3a | 0x3b | 0x47 | 0x68 => {
                super::dos_interrupts::dispatch_int21(
                    state,
                    &mut runtime.dos,
                    &mut runtime.cpu.regs,
                    &mut runtime.memory,
                    host,
                )?
            }
            0x52 => {
                return Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "DOS3Call/AH=52 requires a protected List-of-Lists projection; returning the real-mode pointer would be invalid",
                ));
            }
            _ => {
                if super::dos_interrupts::needs_dos_directory_context(runtime.cpu.regs.ah()) {
                    state.activate_dos_directory_context(host)?;
                }
                let file_cdr_notice =
                    state.capture_file_cdr_notice(&runtime.cpu.regs, &mut runtime.memory, host)?;
                let mut address_space = state
                    .dos_call_address_space(&mut runtime.memory, owner)
                    .map_err(runtime_error)?;
                let action = runtime
                    .dos
                    .interrupt_with_address_space(
                        0x21,
                        &mut runtime.cpu.regs,
                        &mut address_space,
                        host,
                    )
                    .map_err(runtime_error)?;
                drop(address_space);
                state.finish_file_cdr_dos_operation(file_cdr_notice, &runtime.cpu.regs, &action)?;
                action
            }
        }
    };
    match action {
        DosAction::Continue => {
            complete_register_return(runtime, return_to)?;
            host.observe_dos_service(instruction, &before, &runtime.cpu.regs);
            if let Some(state) = runtime.win16.as_mut() {
                state.begin_pending_file_cdr_callback(
                    &mut runtime.cpu,
                    &mut runtime.dos,
                    &mut runtime.memory,
                    host,
                )?;
            }
            Ok(None)
        }
        DosAction::Exit(status) => {
            let exit = {
                let state = runtime.win16.as_mut().ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 task disappeared during DOS3Call exit",
                    )
                })?;
                state.finish_task(&mut runtime.memory, host, u16::from(status))?
            };
            if let Some(status) = exit {
                return Ok(Some(status));
            }
            // DOS3Call is an API gate, not a guest instruction. Return to its
            // checked caller before execute drains the requested ToolHelp exit.
            complete_register_return(runtime, return_to)?;
            Ok(None)
        }
        DosAction::Execute(request) => {
            let target_depth = runtime.process_frames.len();
            match runtime.start_win16_child_process(
                request,
                host,
                instruction,
                before,
                return_to,
            )? {
                Some(code) => {
                    DosKernel::complete_exec_failure(&mut runtime.cpu.regs, code);
                    complete_register_return(runtime, return_to)?;
                    Ok(None)
                }
                None => {
                    runtime.run_dos_child_until_process_depth(
                        host,
                        target_depth,
                        child_instruction_limit,
                    )?;
                    Ok(None)
                }
            }
        }
        DosAction::Unhandled => Err(RuntimeError::new(
            Kind::InternalInvariant,
            "DOS3Call returned an unhandled INT 21h action",
        )),
    }
}

fn dispatch_netbioscall(
    runtime: &mut Runtime,
    host: &mut impl RuntimeHost,
) -> Result<Option<u8>, RuntimeError> {
    let return_to = runtime
        .win16
        .as_ref()
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "KERNEL NetBIOSCall lost its Win16 task state",
            )
        })?
        .far_return(&runtime.cpu.regs, &runtime.memory, 0)?;
    let state = runtime.win16.as_mut().ok_or_else(|| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "KERNEL NetBIOSCall lost its Win16 task state",
        )
    })?;
    super::netbios_call::execute(
        state,
        &mut runtime.cpu.regs,
        &mut runtime.memory,
        host,
        return_to,
    )?;
    Ok(None)
}

pub(super) fn complete_state_register_return(
    state: &mut Win16State,
    registers: &mut Registers,
    return_to: (u16, u16, u32),
) -> Result<(), RuntimeError> {
    let return_sp = match return_to.2 {
        0x1_0000 => 0,
        value => u16::try_from(value).map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 register-call stack return exceeds the 16-bit stack boundary",
            )
        })?,
    };
    state.retire_far_return(return_to.0, u32::from(return_to.1), registers.ss);
    registers.cs = return_to.0;
    registers.set_ip(return_to.1);
    registers.set_sp(return_sp);
    Ok(())
}

fn complete_register_return(
    runtime: &mut Runtime,
    return_to: (u16, u16, u32),
) -> Result<(), RuntimeError> {
    let state = runtime.win16.as_mut().ok_or_else(|| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 task disappeared during a register-call return",
        )
    })?;
    state.complete_kernel_register_return(&mut runtime.cpu.regs, return_to)
}
