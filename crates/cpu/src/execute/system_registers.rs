//! Intel486 control/debug register instructions with explicit mode gaps.

use guest_core::Registers;

use crate::{
    CpuCompatibilityGap, CpuError, CpuExecutionMode,
    memory_access::{AccessKind, CpuBus, LogicalSpan},
    memory_values, read_register,
    system::{
        CR0_PE, CR0_TS, CpuSystem, DR6_WRITABLE_MASK, DR7_GD, DR7_WRITABLE_MASK,
    },
    write_register,
    x86_decode::{
        NormalizedSystemInstruction, SystemOperand, SystemOperation, SystemRegister,
        SystemRegisterDirection, SystemRegisterKind,
    },
};

use super::system::{
    current_privilege_level, execution_mode, general_protection_fault, require_privilege,
};

pub(super) fn execute(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedSystemInstruction,
) -> Result<(), CpuError> {
    match instruction.operation {
        SystemOperation::MoveRegister {
            register,
            direction,
            operand,
        } => execute_move(registers, bus, instruction, register, direction, operand),
        SystemOperation::Clts => {
            require_privileged_context(registers, bus, instruction)?;
            bus.system_mut().cr0 &= !CR0_TS;
            Ok(())
        }
        SystemOperation::Lmsw(operand) => execute_lmsw(registers, bus, instruction, operand),
        SystemOperation::Smsw(operand) => execute_smsw(registers, bus, instruction, operand),
        SystemOperation::UnsupportedTestRegister => {
            require_privileged_context(registers, bus, instruction)?;
            // Intel 273021-001 App. B defines TR3-TR5 as cache test hooks and
            // TR6-TR7 as direct TLB write/lookup hooks. This CPU has neither a
            // cache model nor a TLB (page walks observe guest tables directly),
            // so reporting inert register values would fake those operations.
            Err(compatibility_gap(
                instruction,
                CpuCompatibilityGap::TestRegisters,
            ))
        }
        SystemOperation::InvalidEncoding => Err(invalid_opcode(instruction)),
        _ => Err(invalid_opcode(instruction)),
    }
}

fn execute_move(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedSystemInstruction,
    register: SystemRegister,
    direction: SystemRegisterDirection,
    operand: SystemOperand,
) -> Result<(), CpuError> {
    let SystemOperand::Gpr(gpr) = operand else {
        return Err(invalid_opcode(instruction));
    };
    match register.kind {
        SystemRegisterKind::Control if matches!(register.index, 0 | 2 | 3) => {
            require_privileged_context(registers, bus, instruction)?;
            match direction {
                SystemRegisterDirection::FromSystemRegister => {
                    let value = match register.index {
                        0 => bus.system().cr0,
                        2 => bus.system().cr2,
                        3 => bus.system().cr3,
                        _ => return Err(invalid_opcode(instruction)),
                    };
                    write_register(registers, gpr.index, 4, value);
                    Ok(())
                }
                SystemRegisterDirection::ToSystemRegister => {
                    let value = read_register(registers, gpr.index, 4);
                    write_control_register(bus, instruction, register.index, value)
                }
            }
        }
        SystemRegisterKind::Debug if matches!(register.index, 0..=7) => {
            let mut system = *bus.system();
            if bus.architectural_mode_active() && system.debug.control & DR7_GD != 0 {
                // Intel486 DR7.GD traps a MOV DRx before privilege validation,
                // records BD in DR6, and clears GD for the debug handler.
                system.debug.status |= 1 << 13;
                system.debug.control &= !DR7_GD;
                *bus.system_mut() = system;
                return Err(CpuError::DebugFault {
                    ip: instruction.ip,
                });
            }
            require_privileged_context(registers, bus, instruction)?;
            let index = canonical_debug_register(register.index);
            match direction {
                SystemRegisterDirection::FromSystemRegister => {
                    let value = system
                        .read_debug_register(index)
                        .ok_or_else(|| invalid_opcode(instruction))?;
                    write_register(registers, gpr.index, 4, value);
                    Ok(())
                }
                SystemRegisterDirection::ToSystemRegister => {
                    let value = read_register(registers, gpr.index, 4);
                    let mut next = system;
                    write_debug_register(&mut next, instruction, index, value)?;
                    *bus.system_mut() = next;
                    Ok(())
                }
            }
        }
        // CR1, CR4+, DR8+, and reserved system-register encodings do not exist
        // on the i486 target even though iced-x86 can decode later CPUs.
        _ => Err(invalid_opcode(instruction)),
    }
}

fn write_control_register(
    bus: &mut impl CpuBus,
    instruction: &NormalizedSystemInstruction,
    index: u8,
    value: u32,
) -> Result<(), CpuError> {
    match index {
        0 => {
            let current = *bus.system();
            let mut next = current;
            if current.cr0 & CR0_PE == 0 && value & CR0_PE != 0 {
                if !bus.architectural_mode_active() {
                    return Err(compatibility_gap(
                        instruction,
                        CpuCompatibilityGap::ProtectedModeTransition,
                    ));
                }
            }
            next.write_cr0(value)
                .map_err(|_| general_protection_fault(instruction))?;
            // AM is a modeled control bit; checked operand accesses combine it
            // with EFLAGS.AC and CPL instead of blocking the legal CR0 write.
            // Paging, CR0.WP and the page walker are modeled. Cache controls
            // select no software cache state, while EM/TS/MP feed the CPU's
            // x87/WAIT #NM checks.
            *bus.system_mut() = next;
            Ok(())
        }
        2 => {
            bus.system_mut().write_cr2(value);
            Ok(())
        }
        3 => {
            let mut next = *bus.system();
            next.write_cr3(value)
                .map_err(|_| general_protection_fault(instruction))?;
            *bus.system_mut() = next;
            Ok(())
        }
        _ => Err(invalid_opcode(instruction)),
    }
}

fn write_debug_register(
    system: &mut CpuSystem,
    instruction: &NormalizedSystemInstruction,
    index: u8,
    value: u32,
) -> Result<(), CpuError> {
    let writable_mask = match index {
        6 => DR6_WRITABLE_MASK,
        7 => DR7_WRITABLE_MASK,
        _ => u32::MAX,
    };
    if value & !writable_mask != 0 {
        return Err(compatibility_gap(
            instruction,
            CpuCompatibilityGap::DebugRegisterReservedBits,
        ));
    }
    if index == 7 {
        for breakpoint in 0..4_u32 {
            let enabled = (value >> (breakpoint * 2)) & 0b11 != 0;
            if !enabled {
                continue;
            }
            let access = (value >> (16 + breakpoint * 4)) & 0b11;
            let length = (value >> (18 + breakpoint * 4)) & 0b11;
            if access == 0b10 {
                // I/O breakpoints need a port-bus watchpoint hook, which this
                // CPU/PortIo boundary does not yet provide.
                return Err(compatibility_gap(
                    instruction,
                    CpuCompatibilityGap::DebugExceptionDelivery,
                ));
            }
            if access != 0 && length == 0b10 {
                return Err(compatibility_gap(
                    instruction,
                    CpuCompatibilityGap::DebugRegisterReservedBits,
                ));
            }
        }
    }
    if !system.write_debug_register(index, value) {
        return Err(invalid_opcode(instruction));
    }
    Ok(())
}

fn canonical_debug_register(index: u8) -> u8 {
    match index {
        4 => 6,
        5 => 7,
        _ => index,
    }
}

fn execute_lmsw(
    registers: &Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedSystemInstruction,
    operand: SystemOperand,
) -> Result<(), CpuError> {
    require_privileged_context(registers, bus, instruction)?;
    let source = match operand {
        SystemOperand::Gpr(gpr) if matches!(gpr.width, 2 | 4) => {
            read_register(registers, gpr.index, 2)
        }
        SystemOperand::Memory(address) => {
            let (selector, offset) = address.effective_address(registers);
            memory_values::read_width(
                bus,
                LogicalSpan {
                    register: address.segment_register(),
                    selector,
                    offset,
                    len: 2,
                    address32: address.address32(),
                },
                AccessKind::DataRead,
            )?
        }
        SystemOperand::UnsupportedAddressing => {
            return Err(CpuError::UnsupportedSystemAddressing {
                opcode: instruction.opcode,
                ip: instruction.ip,
            });
        }
        _ => return Err(invalid_opcode(instruction)),
    };
    // The operand read may update CR2 or page-table A/D state. Clone only the
    // latest system snapshot after that read so the commit preserves it.
    let current = *bus.system();
    let mut next = current;
    next.write_cr0((current.cr0 & !0x0f) | (source & 0x0f) | (current.cr0 & CR0_PE))
        .map_err(|_| general_protection_fault(instruction))?;
    if current.cr0 & CR0_PE == 0 && next.cr0 & CR0_PE != 0 {
        if !bus.architectural_mode_active() {
            return Err(compatibility_gap(
                instruction,
                CpuCompatibilityGap::ProtectedModeTransition,
            ));
        }
    }
    // LMSW cannot clear PE; the helper's sticky-PE rule leaves no valid mode
    // change here. Commit only after every read and architectural check passes.
    *bus.system_mut() = next;
    Ok(())
}

fn execute_smsw(
    registers: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedSystemInstruction,
    operand: SystemOperand,
) -> Result<(), CpuError> {
    execution_mode(registers, bus, instruction)?;
    match operand {
        SystemOperand::Gpr(gpr) if matches!(gpr.width, 2 | 4) => {
            // SMSW leaves the upper half of a 32-bit destination undefined;
            // retaining it is one deterministic, architecturally permitted
            // realization of that undefined half.
            write_register(registers, gpr.index, 2, bus.system().cr0 & 0xffff);
            Ok(())
        }
        SystemOperand::Memory(address) => {
            let (selector, offset) = address.effective_address(registers);
            let value = bus.system().cr0 & 0xffff;
            memory_values::write_width(
                bus,
                LogicalSpan {
                    register: address.segment_register(),
                    selector,
                    offset,
                    len: 2,
                    address32: address.address32(),
                },
                AccessKind::DataWrite,
                value,
            )
        }
        SystemOperand::UnsupportedAddressing => Err(CpuError::UnsupportedSystemAddressing {
            opcode: instruction.opcode,
            ip: instruction.ip,
        }),
        _ => Err(invalid_opcode(instruction)),
    }
}

fn require_privileged_context(
    registers: &Registers,
    bus: &impl CpuBus,
    instruction: &NormalizedSystemInstruction,
) -> Result<CpuExecutionMode, CpuError> {
    let mode = execution_mode(registers, bus, instruction)?;
    let cpl = current_privilege_level(mode, bus, instruction)?;
    require_privilege(mode, cpl, instruction)?;
    Ok(mode)
}

fn compatibility_gap(
    instruction: &NormalizedSystemInstruction,
    feature: CpuCompatibilityGap,
) -> CpuError {
    CpuError::CompatibilityGap {
        opcode: instruction.opcode,
        ip: instruction.ip,
        feature,
    }
}

fn invalid_opcode(instruction: &NormalizedSystemInstruction) -> CpuError {
    CpuError::InvalidOpcode {
        opcode: instruction.opcode,
        ip: instruction.ip,
    }
}
