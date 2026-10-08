//! Decoded operand access shared by instruction-family executors.

use guest_core::Registers;

use super::super::memory_access::{
    AccessKind, AccessRequest, CpuBus, DataAlignment, LogicalSpan, PreparedAccess,
};
use super::super::memory_values::{
    read_prepared_width, read_width, write_prepared_width, write_width,
};
use super::super::x86_decode::{NormalizedInstruction, Operand, memory_offset};
use super::super::{CpuError, read_register, read_segment, width_mask, write_register};

pub(super) fn error_at(instruction: &NormalizedInstruction) -> CpuError {
    CpuError::UnsupportedOpcode {
        opcode: instruction.decoded.opcode,
        ip: instruction.decoded.start_ip,
    }
}

pub(super) fn read_operand(
    regs: &Registers,
    bus: &mut impl CpuBus,
    operand: Operand,
    width: u8,
) -> Result<u32, CpuError> {
    Ok(match operand {
        Operand::Gpr(register) => {
            let index = register.index | if register.high8 { 4 } else { 0 };
            read_register(regs, index, width)
        }
        Operand::Segment(segment) => u32::from(read_segment(regs, segment)),
        Operand::Memory(reference) => read_width(
            bus,
            logical_span(regs, reference, usize::from(width))?,
            AccessKind::DataRead,
        )?,
        Operand::Immediate(value) => value as u32 & width_mask(width),
        Operand::NearBranch { target, .. } => target as u32,
        Operand::FarBranch { offset, .. } => offset,
        Operand::SecondImmediate(value) => u32::from(value),
        Operand::Other | Operand::SystemRegister(_) | Operand::FloatRegister(_) => {
            return Err(CpuError::InvalidOpcode {
                opcode: 0,
                ip: regs.eip,
            });
        }
    })
}

pub(super) fn write_operand(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    operand: Operand,
    width: u8,
    value: u32,
) -> Result<(), CpuError> {
    match operand {
        Operand::Gpr(register) => {
            let index = register.index | if register.high8 { 4 } else { 0 };
            write_register(regs, index, width, value);
        }
        Operand::Segment(segment) => {
            super::segment_load::load_data_register(regs, bus, segment, value as u16)?
        }
        Operand::Memory(reference) => {
            write_width(
                bus,
                logical_span(regs, reference, usize::from(width))?,
                AccessKind::DataWrite,
                value,
            )?;
        }
        _ => {
            return Err(CpuError::InvalidOpcode {
                opcode: 0,
                ip: regs.eip,
            });
        }
    }
    Ok(())
}

/// Owns one operand's access plan. RMW instructions prepare this once with
/// DataReadWrite and then use the same plan for their read and final write.
pub(super) struct PreparedOperand {
    operand: Operand,
    width: u8,
    access: Option<PreparedAccess>,
}

pub(super) fn prepare_operand(
    regs: &Registers,
    bus: &mut impl CpuBus,
    operand: Operand,
    width: u8,
    kind: AccessKind,
) -> Result<PreparedOperand, CpuError> {
    let access = match operand {
        Operand::Memory(reference) => {
            if !matches!(width, 1 | 2 | 4) {
                return Err(CpuError::InvalidMemoryAccessPlan {
                    ip: bus.instruction_site().ip,
                });
            }
            Some(bus.prepare(AccessRequest::instruction(
                logical_span(regs, reference, usize::from(width))?,
                kind,
                DataAlignment::Natural(width),
            ))?)
        }
        _ => None,
    };
    Ok(PreparedOperand {
        operand,
        width,
        access,
    })
}

pub(super) fn read_prepared_operand(
    regs: &Registers,
    bus: &mut impl CpuBus,
    prepared: &PreparedOperand,
) -> Result<u32, CpuError> {
    if let Some(access) = prepared.access.as_ref() {
        return read_prepared_width(bus, access, prepared.width);
    }
    read_nonmemory_operand(regs, prepared.operand, prepared.width)
}

pub(super) fn write_prepared_operand(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    prepared: PreparedOperand,
    value: u32,
) -> Result<(), CpuError> {
    if let Some(access) = prepared.access {
        return write_prepared_width(bus, access, prepared.width, value);
    }
    write_nonmemory_operand(regs, bus, prepared.operand, prepared.width, value)
}

fn read_nonmemory_operand(regs: &Registers, operand: Operand, width: u8) -> Result<u32, CpuError> {
    Ok(match operand {
        Operand::Gpr(register) => {
            let index = register.index | if register.high8 { 4 } else { 0 };
            read_register(regs, index, width)
        }
        Operand::Segment(segment) => u32::from(read_segment(regs, segment)),
        Operand::Immediate(value) => value as u32 & width_mask(width),
        Operand::NearBranch { target, .. } => target as u32,
        Operand::FarBranch { offset, .. } => offset,
        Operand::SecondImmediate(value) => u32::from(value),
        Operand::Memory(_) => return Err(CpuError::InvalidMemoryAccessPlan { ip: regs.eip }),
        Operand::Other | Operand::SystemRegister(_) | Operand::FloatRegister(_) => {
            return Err(CpuError::InvalidOpcode {
                opcode: 0,
                ip: regs.eip,
            });
        }
    })
}

fn write_nonmemory_operand(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    operand: Operand,
    width: u8,
    value: u32,
) -> Result<(), CpuError> {
    match operand {
        Operand::Gpr(register) => {
            let index = register.index | if register.high8 { 4 } else { 0 };
            write_register(regs, index, width, value);
        }
        Operand::Segment(segment) => {
            super::segment_load::load_data_register(regs, bus, segment, value as u16)?
        }
        _ => {
            return Err(CpuError::InvalidOpcode {
                opcode: 0,
                ip: regs.eip,
            });
        }
    }
    Ok(())
}

pub(super) fn logical_span(
    regs: &Registers,
    reference: super::super::x86_decode::MemoryOperand,
    len: usize,
) -> Result<LogicalSpan, CpuError> {
    let offset = memory_offset(regs, reference).ok_or_else(|| CpuError::UnsupportedOpcode {
        opcode: 0,
        ip: regs.eip,
    })?;
    Ok(LogicalSpan {
        register: reference.segment,
        selector: read_segment(regs, reference.segment),
        offset,
        len,
        address32: reference.address32,
    })
}

pub(super) fn operand_width(instruction: &NormalizedInstruction, index: usize) -> u8 {
    match instruction.operand(index) {
        Operand::Gpr(register) => register.width,
        Operand::Memory(_) => {
            let size = instruction.memory_width;
            if matches!(size, 1 | 2 | 4) {
                size as u8
            } else {
                instruction.data_width()
            }
        }
        Operand::Segment(_) => 2,
        Operand::NearBranch { width, .. } | Operand::FarBranch { width, .. } => width,
        _ => instruction.data_width(),
    }
}

pub(super) fn branch_target(
    instruction: &NormalizedInstruction,
    index: usize,
) -> Result<u32, CpuError> {
    match instruction.operand(index) {
        Operand::NearBranch { target, .. } => Ok(target as u32),
        _ => Err(error_at(instruction)),
    }
}

pub(super) fn read_immediate(
    instruction: &NormalizedInstruction,
    index: usize,
) -> Result<u32, CpuError> {
    match instruction.operand(index) {
        Operand::Immediate(value) => Ok(value as u32),
        Operand::SecondImmediate(value) => Ok(u32::from(value)),
        _ => Err(error_at(instruction)),
    }
}
