//! Bit-test, bit-modify, bit-scan, and double-shift instruction semantics.

use guest_core::Registers;
use x86_decoder::Mnemonic;

use super::super::x86_decode::{NormalizedInstruction, Operand, memory_offset};
use super::super::{
    CF, CpuError, OF, PF, SF, ZF, apply_flags, read_segment,
};
use super::super::memory_access::{
    AccessKind, AccessRequest, CpuBus, DataAlignment, LogicalSpan,
};
use super::super::memory_values::{read_prepared_width, write_prepared_width};
use super::operand::{
    error_at, operand_width, prepare_operand, read_operand, read_prepared_operand,
    write_operand, write_prepared_operand,
};

const SZP: u32 = SF | ZF | PF;

pub(super) fn execute_bit(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let width = operand_width(instruction, 0);
    if !matches!(width, 2 | 4) {
        return Err(error_at(instruction));
    }

    // Capture the offset first. For a register-form operation, source and base
    // may name the same register and the source is read before any destination
    // write.
    let offset_operand = instruction.operand(1);
    let offset = read_operand(regs, bus, offset_operand, operand_width(instruction, 1))?;
    let base_operand = instruction.operand(0);
    let bits = u32::from(width) * 8;
    if !matches!(
        instruction.mnemonic,
        Mnemonic::Bt | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc
    ) {
        return Err(error_at(instruction));
    }
    let modifies = instruction.mnemonic != Mnemonic::Bt;
    let (value, bit, memory_access) = match base_operand {
        Operand::Memory(reference) => {
            let base = memory_offset(regs, reference).ok_or_else(|| error_at(instruction))?;
            let (bit, effective_offset) = match offset_operand {
                // Immediate offsets select a bit within the addressed element.
                // Assemblers fold larger bit-string offsets into displacement.
                Operand::Immediate(_) | Operand::SecondImmediate(_) => (offset & (bits - 1), base),
                Operand::Gpr(register) => {
                    let signed = match register.width {
                        2 => (offset as u16 as i16) as i32,
                        4 => offset as i32,
                        _ => return Err(error_at(instruction)),
                    };
                    let element = signed.div_euclid(bits as i32);
                    let bit = signed.rem_euclid(bits as i32) as u32;
                    let byte_delta = element.wrapping_mul(i32::from(width)) as u32;
                    let adjusted = if reference.address32 {
                        base.wrapping_add(byte_delta)
                    } else {
                        u32::from((base as u16).wrapping_add(byte_delta as u16))
                    };
                    (bit, adjusted)
                }
                _ => return Err(error_at(instruction)),
            };
            if modifies && instruction.decoded.instruction.has_lock_prefix() {
                let old_bit = super::atomic::update_span_atomically(
                    bus,
                    LogicalSpan {
                        register: reference.segment,
                        selector: read_segment(regs, reference.segment),
                        offset: effective_offset,
                        len: usize::from(width),
                        address32: reference.address32,
                    },
                    |bytes| {
                        let selected = super::atomic::read_unsigned_le(bytes) as u32;
                        let old_bit = (selected >> bit) & 1;
                        let changed = match instruction.mnemonic {
                            Mnemonic::Bts => selected | (1 << bit),
                            Mnemonic::Btr => selected & !(1 << bit),
                            Mnemonic::Btc => selected ^ (1 << bit),
                            _ => selected,
                        };
                        super::atomic::write_unsigned_le(bytes, u64::from(changed));
                        old_bit
                    },
                )?;
                apply_flags(regs, CF, if old_bit != 0 { CF } else { 0 });
                return Ok(());
            }
            let access = bus.prepare(AccessRequest::instruction(
                LogicalSpan {
                    register: reference.segment,
                    selector: read_segment(regs, reference.segment),
                    offset: effective_offset,
                    len: usize::from(width),
                    address32: reference.address32,
                },
                if modifies { AccessKind::DataReadWrite } else { AccessKind::DataRead },
                DataAlignment::Natural(width),
            ))?;
            let selected = read_prepared_width(bus, &access, width)?;
            (selected, bit, Some(access))
        }
        Operand::Gpr(_) => (
            read_operand(regs, bus, base_operand, width)?,
            offset & (bits - 1),
            None,
        ),
        _ => return Err(error_at(instruction)),
    };

    let old_bit = (value >> bit) & 1;
    let mnemonic = instruction.mnemonic;

    if mnemonic != Mnemonic::Bt {
        let changed = match mnemonic {
            Mnemonic::Bts => value | (1 << bit),
            Mnemonic::Btr => value & !(1 << bit),
            Mnemonic::Btc => value ^ (1 << bit),
            _ => return Err(error_at(instruction)),
        };
        if let Some(access) = memory_access {
            write_prepared_width(bus, access, width, changed)?;
        } else {
            write_operand(regs, bus, base_operand, width, changed)?;
        }
    }

    // Only CF is defined by the BT family; retain the other undefined flags.
    apply_flags(regs, CF, if old_bit != 0 { CF } else { 0 });
    Ok(())
}

pub(super) fn execute_bit_scan(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let width = operand_width(instruction, 1);
    if !matches!(width, 2 | 4) || !matches!(instruction.operand(0), Operand::Gpr(_)) {
        return Err(error_at(instruction));
    }
    let source = read_operand(regs, bus, instruction.operand(1), width)?;
    if source == 0 {
        // Intel leaves DEST undefined here. Preserve it rather than inventing a
        // deterministic value, and preserve the other undefined status flags.
        apply_flags(regs, ZF, ZF);
        return Ok(());
    }

    let bit_index = match instruction.mnemonic {
        Mnemonic::Bsf => source.trailing_zeros(),
        Mnemonic::Bsr => 31 - source.leading_zeros(),
        _ => return Err(error_at(instruction)),
    };
    write_operand(
        regs,
        bus,
        instruction.operand(0),
        width,
        bit_index,
    )?;
    apply_flags(regs, ZF, 0);
    Ok(())
}

pub(super) fn execute_double_shift(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let width = operand_width(instruction, 0);
    if !matches!(width, 2 | 4) || instruction.operand_count != 3 {
        return Err(error_at(instruction));
    }
    let destination_operand = instruction.operand(0);
    let prepared = prepare_operand(regs, bus, destination_operand, width, AccessKind::DataReadWrite)?;
    let destination = read_prepared_operand(regs, bus, &prepared)?;
    let source = read_operand(regs, bus, instruction.operand(1), width)?;
    let count = read_operand(regs, bus, instruction.operand(2), 1)? & 0x1f;
    if count == 0 {
        return Ok(());
    }

    let bits = u32::from(width) * 8;
    if count > bits {
        // Intel leaves the result and status flags undefined above operand size.
        return Ok(());
    }
    let mask = super::super::width_mask(width);
    let count64 = u64::from(count);
    let (result, carry, overflow) = match instruction.mnemonic {
        Mnemonic::Shld => {
            let pair = (u64::from(destination & mask) << bits) | u64::from(source & mask);
            let result = ((pair << count64) >> bits) as u32 & mask;
            let carry = ((pair >> (2 * bits - count)) & 1) != 0;
            let overflow = ((result >> (bits - 1)) & 1) != u32::from(carry);
            (result, carry, overflow)
        }
        Mnemonic::Shrd => {
            let pair = (u64::from(source & mask) << bits) | u64::from(destination & mask);
            let result = ((pair >> count64) as u32) & mask;
            let carry = ((pair >> (count - 1)) & 1) != 0;
            let overflow = ((destination ^ result) >> (bits - 1)) & 1 != 0;
            (result, carry, overflow)
        }
        _ => return Err(error_at(instruction)),
    };

    write_prepared_operand(regs, bus, prepared, result)?;
    let mut flag_mask = CF | SZP;
    let mut flag_values = if carry { CF } else { 0 };
    if count == 1 {
        flag_mask |= OF;
        if overflow {
            flag_values |= OF;
        }
    }
    apply_flags(regs, flag_mask, flag_values);
    super::super::update_szp(regs, result, width);
    Ok(())
}

#[cfg(test)]
#[path = "bit/tests.rs"]
mod tests;
