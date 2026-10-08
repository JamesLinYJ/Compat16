//! Data movement and register exchange instruction semantics.

use guest_core::Registers;
use x86_decoder::Mnemonic;

use super::super::memory_access::{AccessKind, CpuBus, DataAlignment};
use super::super::memory_values::read_bytes;
use super::super::x86_decode::{NormalizedInstruction, Operand, memory_offset};
use super::super::{CpuError, read_register, signed_value, write_register};
use super::operand::{
    error_at, logical_span, operand_width, prepare_operand, read_operand, read_prepared_operand,
    write_operand, write_prepared_operand,
};

pub(super) fn execute_mov(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let width = operand_width(instruction, 0);
    let source = read_operand(regs, bus, instruction.operand(1), width)?;
    write_operand(regs, bus, instruction.operand(0), width, source)
}

pub(super) fn execute_mov_extend(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let destination_width = operand_width(instruction, 0);
    let source_width = operand_width(instruction, 1);
    let raw = read_operand(regs, bus, instruction.operand(1), source_width)?;
    let value = if instruction.mnemonic == Mnemonic::Movsx {
        signed_value(raw, source_width) as u32
    } else {
        raw
    };
    write_operand(regs, bus, instruction.operand(0), destination_width, value)
}

pub(super) fn execute_lea(
    regs: &mut Registers,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let destination = match instruction.operand(0) {
        Operand::Gpr(register) => register,
        _ => return Err(error_at(instruction)),
    };
    let reference = match instruction.operand(1) {
        Operand::Memory(reference) => reference,
        _ => return Err(error_at(instruction)),
    };
    let value = memory_offset(regs, reference).ok_or_else(|| error_at(instruction))?;
    let index = destination.index | if destination.high8 { 4 } else { 0 };
    write_register(regs, index, destination.width, value);
    Ok(())
}

pub(super) fn execute_far_load(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let destination = match instruction.operand(0) {
        Operand::Gpr(register) => register,
        _ => return Err(error_at(instruction)),
    };
    let source = match instruction.operand(1) {
        Operand::Memory(reference) => reference,
        _ => return Err(error_at(instruction)),
    };
    let width = destination.width;
    if !matches!(width, 2 | 4) {
        return Err(error_at(instruction));
    }
    let segment_register = match instruction.mnemonic {
        Mnemonic::Les => crate::registers::SegmentRegister::Es,
        Mnemonic::Lds => crate::registers::SegmentRegister::Ds,
        Mnemonic::Lss => crate::registers::SegmentRegister::Ss,
        Mnemonic::Lfs => crate::registers::SegmentRegister::Fs,
        Mnemonic::Lgs => crate::registers::SegmentRegister::Gs,
        _ => return Err(error_at(instruction)),
    };
    let span_len = usize::from(width) + 2;
    let mut bytes = [0_u8; 6];
    read_bytes(
        bus,
        logical_span(regs, source, span_len)?,
        AccessKind::DataRead,
        DataAlignment::Natural(width),
        &mut bytes[..span_len],
    )?;
    let value = if width == 2 {
        u32::from(u16::from_le_bytes([bytes[0], bytes[1]]))
    } else {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    };
    let selector_index = usize::from(width);
    let segment = u16::from_le_bytes([bytes[selector_index], bytes[selector_index + 1]]);
    super::segment_load::load_data_register(regs, bus, segment_register, segment)?;
    write_register(
        regs,
        destination.index | if destination.high8 { 4 } else { 0 },
        width,
        value,
    );
    Ok(())
}

pub(super) fn execute_xchg(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let left_operand = instruction.operand(0);
    let right_operand = instruction.operand(1);
    let width = operand_width(instruction, 0);
    if operand_width(instruction, 1) != width {
        return Err(error_at(instruction));
    }
    match (left_operand, right_operand) {
        (Operand::Memory(reference), Operand::Gpr(register)) => {
            let right_index = register.index | if register.high8 { 4 } else { 0 };
            let right_value = read_register(regs, right_index, width);
            let left_value = super::atomic::update_atomically(
                regs,
                bus,
                reference,
                usize::from(width),
                |bytes| {
                    let old = super::atomic::read_unsigned_le(bytes) as u32;
                    super::atomic::write_unsigned_le(bytes, u64::from(right_value));
                    old
                },
            )?;
            write_register(regs, right_index, width, left_value);
            return Ok(());
        }
        (Operand::Gpr(register), Operand::Memory(reference)) => {
            let left_index = register.index | if register.high8 { 4 } else { 0 };
            let left_value = read_register(regs, left_index, width);
            let right_value = super::atomic::update_atomically(
                regs,
                bus,
                reference,
                usize::from(width),
                |bytes| {
                    let old = super::atomic::read_unsigned_le(bytes) as u32;
                    super::atomic::write_unsigned_le(bytes, u64::from(left_value));
                    old
                },
            )?;
            write_register(regs, left_index, width, right_value);
            return Ok(());
        }
        (Operand::Memory(_), _) | (_, Operand::Memory(_)) => return Err(error_at(instruction)),
        _ => {}
    }
    let left_access = prepare_operand(regs, bus, left_operand, width, AccessKind::DataReadWrite)?;
    let right_access = prepare_operand(regs, bus, right_operand, width, AccessKind::DataReadWrite)?;
    let left = read_prepared_operand(regs, bus, &left_access)?;
    let right = read_prepared_operand(regs, bus, &right_access)?;
    write_prepared_operand(regs, bus, left_access, right)?;
    write_prepared_operand(regs, bus, right_access, left)
}

pub(super) fn execute_bswap(
    regs: &mut Registers,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let register = match instruction.operand(0) {
        Operand::Gpr(register) if register.width == 4 => register,
        _ => return Err(error_at(instruction)),
    };
    let value = read_register(regs, register.index, 4).swap_bytes();
    write_register(regs, register.index, 4, value);
    Ok(())
}
