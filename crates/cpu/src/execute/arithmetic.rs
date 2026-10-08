//! Arithmetic, logical, shifts, and condition-result semantics.

use x86_decoder::Mnemonic;
use guest_core::Registers;

use super::super::{
    alu_compute, apply_flags, condition, execute_multiply, read_register, write_register,
    signed_value, update_szp, width_mask, AluOp, CpuError, CF, OF,
};
use super::super::memory_access::{AccessKind, CpuBus};
use super::super::x86_decode::NormalizedInstruction;
use super::operand::{
    error_at, operand_width, prepare_operand, read_immediate, read_operand,
    read_prepared_operand, write_operand, write_prepared_operand,
};

pub(super) fn execute_alu(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let op = alu_operation(instruction.mnemonic).ok_or_else(|| error_at(instruction))?;
    let width = operand_width(instruction, 0);
    let destination = instruction.operand(0);
    let writes_destination = !matches!(op, AluOp::Cmp | AluOp::Test);
    if writes_destination
        && instruction.decoded.instruction.has_lock_prefix()
    {
        let reference = match destination {
            super::super::x86_decode::Operand::Memory(reference) => reference,
            _ => return Err(error_at(instruction)),
        };
        let right = read_operand(regs, bus, instruction.operand(1), width)?;
        let (_, mask, flags) = super::atomic::update_atomically(
            regs,
            bus,
            reference,
            usize::from(width),
            |bytes| {
                let left = super::atomic::read_unsigned_le(bytes) as u32;
                let (result, mask, flags) = alu_compute(regs, op, left, right, width);
                super::atomic::write_unsigned_le(bytes, u64::from(result));
                (result, mask, flags)
            },
        )?;
        apply_flags(regs, mask, flags);
        return Ok(());
    }
    let prepared = prepare_operand(
        regs,
        bus,
        destination,
        width,
        if writes_destination { AccessKind::DataReadWrite } else { AccessKind::DataRead },
    )?;
    let left = read_prepared_operand(regs, bus, &prepared)?;
    let right = read_operand(regs, bus, instruction.operand(1), width)?;
    let (result, mask, flags) = alu_compute(regs, op, left, right, width);
    if writes_destination {
        write_prepared_operand(regs, bus, prepared, result)?;
    }
    apply_flags(regs, mask, flags);
    Ok(())
}

pub(super) fn alu_operation(mnemonic: Mnemonic) -> Option<AluOp> {
    Some(match mnemonic {
        Mnemonic::Add => AluOp::Add,
        Mnemonic::Or => AluOp::Or,
        Mnemonic::Adc => AluOp::Adc,
        Mnemonic::Sbb => AluOp::Sbb,
        Mnemonic::And => AluOp::And,
        Mnemonic::Sub => AluOp::Sub,
        Mnemonic::Xor => AluOp::Xor,
        Mnemonic::Cmp => AluOp::Cmp,
        Mnemonic::Test => AluOp::Test,
        _ => return None,
    })
}

pub(super) fn execute_inc_dec(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let destination = instruction.operand(0);
    let width = operand_width(instruction, 0);
    if instruction.decoded.instruction.has_lock_prefix() {
        let reference = match destination {
            super::super::x86_decode::Operand::Memory(reference) => reference,
            _ => return Err(error_at(instruction)),
        };
        let op = if instruction.mnemonic == Mnemonic::Inc { AluOp::Add } else { AluOp::Sub };
        let (_, mask, flags) = super::atomic::update_atomically(
            regs,
            bus,
            reference,
            usize::from(width),
            |bytes| {
                let value = super::atomic::read_unsigned_le(bytes) as u32;
                let (result, mask, flags) = alu_compute(regs, op, value, 1, width);
                super::atomic::write_unsigned_le(bytes, u64::from(result));
                (result, mask, flags)
            },
        )?;
        apply_flags(regs, mask & !CF, flags);
        return Ok(());
    }
    let prepared = prepare_operand(regs, bus, destination, width, AccessKind::DataReadWrite)?;
    let value = read_prepared_operand(regs, bus, &prepared)?;
    let op = if instruction.mnemonic == Mnemonic::Inc { AluOp::Add } else { AluOp::Sub };
    let (result, mask, flags) = alu_compute(regs, op, value, 1, width);
    write_prepared_operand(regs, bus, prepared, result)?;
    apply_flags(regs, mask & !CF, flags);
    Ok(())
}

pub(super) fn execute_not_neg(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let destination = instruction.operand(0);
    let width = operand_width(instruction, 0);
    if instruction.decoded.instruction.has_lock_prefix() {
        let reference = match destination {
            super::super::x86_decode::Operand::Memory(reference) => reference,
            _ => return Err(error_at(instruction)),
        };
        if instruction.mnemonic == Mnemonic::Not {
            super::atomic::update_atomically(
                regs,
                bus,
                reference,
                usize::from(width),
                |bytes| {
                    let value = super::atomic::read_unsigned_le(bytes);
                    super::atomic::write_unsigned_le(bytes, !value);
                },
            )?;
        } else {
            let (_, mask, flags) = super::atomic::update_atomically(
                regs,
                bus,
                reference,
                usize::from(width),
                |bytes| {
                    let value = super::atomic::read_unsigned_le(bytes) as u32;
                    let (result, mask, flags) = alu_compute(regs, AluOp::Sub, 0, value, width);
                    super::atomic::write_unsigned_le(bytes, u64::from(result));
                    (result, mask, flags)
                },
            )?;
            apply_flags(regs, mask, flags);
        }
        return Ok(());
    }
    let prepared = prepare_operand(regs, bus, destination, width, AccessKind::DataReadWrite)?;
    let value = read_prepared_operand(regs, bus, &prepared)?;
    if instruction.mnemonic == Mnemonic::Not {
        write_prepared_operand(regs, bus, prepared, !value & width_mask(width))?;
    } else {
        let (result, mask, flags) = alu_compute(regs, AluOp::Sub, 0, value, width);
        write_prepared_operand(regs, bus, prepared, result)?;
        apply_flags(regs, mask, flags);
    }
    Ok(())
}

pub(super) fn execute_mul_div(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let mnemonic = instruction.mnemonic;
    let width = if mnemonic == Mnemonic::Imul && instruction.operand_count > 1 {
        operand_width(instruction, 0)
    } else {
        operand_width(instruction, 0)
    };

    if mnemonic == Mnemonic::Imul && instruction.operand_count > 1 {
        let destination = instruction.operand(0);
        let lhs = signed_value(read_operand(regs, bus, instruction.operand(1), width)?, width);
        let rhs_operand = if instruction.operand_count > 2 {
            instruction.operand(2)
        } else {
            destination
        };
        let rhs = signed_value(read_operand(regs, bus, rhs_operand, width)?, width);
        let product = lhs * rhs;
        let min = -(1_i64 << (u32::from(width) * 8 - 1));
        let max = -min - 1;
        write_operand(regs, bus, destination, width, product as u32 & width_mask(width))?;
        apply_flags(regs, CF | OF, if product < min || product > max { CF | OF } else { 0 });
        return Ok(());
    }

    let operand = read_operand(regs, bus, instruction.operand(0), width)?;
    match mnemonic {
        Mnemonic::Mul => execute_multiply(regs, operand, width, false),
        Mnemonic::Imul => execute_multiply(regs, operand, width, true),
        Mnemonic::Div => crate::execute_divide(regs, operand, width, false)?,
        Mnemonic::Idiv => crate::execute_divide(regs, operand, width, true)?,
        _ => return Err(error_at(instruction)),
    }
    Ok(())
}

pub(super) fn execute_cmpxchg(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let destination = instruction.operand(0);
    let width = operand_width(instruction, 0);
    if instruction.decoded.instruction.has_lock_prefix() {
        let reference = match destination {
            super::super::x86_decode::Operand::Memory(reference) => reference,
            _ => return Err(error_at(instruction)),
        };
        let source = read_operand(regs, bus, instruction.operand(1), width)?;
        let accumulator = read_register(regs, 0, width);
        let (current, equal, mask, flags) = super::atomic::update_atomically(
            regs,
            bus,
            reference,
            usize::from(width),
            |bytes| {
                let current = super::atomic::read_unsigned_le(bytes) as u32;
                let (_, mask, flags) = alu_compute(regs, AluOp::Cmp, accumulator, current, width);
                let equal = accumulator == current;
                super::atomic::write_unsigned_le(
                    bytes,
                    u64::from(if equal { source } else { current }),
                );
                (current, equal, mask, flags)
            },
        )?;
        if !equal {
            write_register(regs, 0, width, current);
        }
        apply_flags(regs, mask, flags);
        return Ok(());
    }
    let prepared = prepare_operand(regs, bus, destination, width, AccessKind::DataReadWrite)?;
    let current = read_prepared_operand(regs, bus, &prepared)?;
    let source = read_operand(regs, bus, instruction.operand(1), width)?;
    let accumulator = read_register(regs, 0, width);
    let (_, mask, flags) = alu_compute(regs, AluOp::Cmp, accumulator, current, width);
    write_prepared_operand(
        regs,
        bus,
        prepared,
        if accumulator == current { source } else { current },
    )?;
    if accumulator != current {
        write_register(regs, 0, width, current);
    }
    apply_flags(regs, mask, flags);
    Ok(())
}

pub(super) fn execute_setcc(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let code = condition_code(instruction.mnemonic).ok_or_else(|| error_at(instruction))?;
    let value = u32::from(condition(regs, code));
    write_operand(
        regs,
        bus,
        instruction.operand(0),
        1,
        value,
    )
}

pub(super) fn execute_shift(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let width = operand_width(instruction, 0);
    let destination = instruction.operand(0);
    let prepared = prepare_operand(regs, bus, destination, width, AccessKind::DataReadWrite)?;
    let value = read_prepared_operand(regs, bus, &prepared)?;
    let count = if instruction.operand_count == 1 {
        1
    } else {
        read_operand(regs, bus, instruction.operand(1), 1)? as u8
    };
    let extension = match instruction.mnemonic {
        Mnemonic::Rol => 0,
        Mnemonic::Ror => 1,
        Mnemonic::Rcl => 2,
        Mnemonic::Rcr => 3,
        Mnemonic::Shl | Mnemonic::Sal => 4,
        Mnemonic::Shr => 5,
        Mnemonic::Sar => 7,
        _ => return Err(error_at(instruction)),
    };
    let (result, mask, flags) = crate::execute_shift(regs, value, width, extension, count);
    if mask != 0 {
        write_prepared_operand(regs, bus, prepared, result)?;
        apply_flags(regs, mask, flags);
    }
    Ok(())
}

pub(super) fn execute_ascii_base(
    regs: &mut Registers,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let base = read_immediate(instruction, 0)? as u8;
    // Intel SDM Vol. 2A, AAD: a zero immediate is valid multiplication;
    // only AAM divides by its immediate and raises #DE for zero.
    if instruction.mnemonic == Mnemonic::Aam && base == 0 {
        return Err(CpuError::DivideError);
    }
    if instruction.mnemonic == Mnemonic::Aam {
        let al = regs.al();
        regs.set_ah(al / base);
        regs.set_al(al % base);
    } else {
        let value = regs.ah().wrapping_mul(base).wrapping_add(regs.al());
        regs.set_ah(0);
        regs.set_al(value);
    }
    update_szp(regs, u32::from(regs.al()), 1);
    Ok(())
}

pub(super) fn condition_code(mnemonic: Mnemonic) -> Option<u8> {
    Some(match mnemonic {
        Mnemonic::Seto => 0,
        Mnemonic::Setno => 1,
        Mnemonic::Setb => 2,
        Mnemonic::Setae => 3,
        Mnemonic::Sete => 4,
        Mnemonic::Setne => 5,
        Mnemonic::Setbe => 6,
        Mnemonic::Seta => 7,
        Mnemonic::Sets => 8,
        Mnemonic::Setns => 9,
        Mnemonic::Setp => 10,
        Mnemonic::Setnp => 11,
        Mnemonic::Setl => 12,
        Mnemonic::Setge => 13,
        Mnemonic::Setle => 14,
        Mnemonic::Setg => 15,
        _ => return None,
    })
}
