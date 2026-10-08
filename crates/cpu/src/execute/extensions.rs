//! Pentium-era integer instruction families and selected 486/P6 extensions.

use guest_core::Registers;
use x86_decoder::{Mnemonic, Register};

use super::super::x86_decode::{NormalizedInstruction, Operand, memory_offset};
use super::super::{
    AluOp, CpuError, ZF, alu_compute, apply_flags, condition, read_segment, write_register,
};
use super::super::memory_access::{
    AccessKind, AccessOrigin, AccessRequest, CpuBus, DataAlignment, LogicalSpan,
};
use super::super::memory_values::read_width;
use super::operand::{
    error_at, operand_width, prepare_operand, read_operand, read_prepared_operand,
    write_operand, write_prepared_operand,
};

pub(super) fn execute_cmov(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let code = cmov_condition_code(instruction.mnemonic).ok_or_else(|| error_at(instruction))?;
    let width = operand_width(instruction, 0);
    if !matches!(width, 2 | 4) || !matches!(instruction.operand(0), Operand::Gpr(_)) {
        return Err(error_at(instruction));
    }

    // CMOVcc performs the source read even when the condition is false. This
    // preserves the architectural memory-fault behavior of the instruction.
    let source = read_operand(regs, bus, instruction.operand(1), width)?;
    if condition(regs, code) {
        write_operand(
            regs,
            bus,
            instruction.operand(0),
            width,
            source,
        )?;
    }
    Ok(())
}

fn cmov_condition_code(mnemonic: Mnemonic) -> Option<u8> {
    Some(match mnemonic {
        Mnemonic::Cmovo => 0,
        Mnemonic::Cmovno => 1,
        Mnemonic::Cmovb => 2,
        Mnemonic::Cmovae => 3,
        Mnemonic::Cmove => 4,
        Mnemonic::Cmovne => 5,
        Mnemonic::Cmovbe => 6,
        Mnemonic::Cmova => 7,
        Mnemonic::Cmovs => 8,
        Mnemonic::Cmovns => 9,
        Mnemonic::Cmovp => 10,
        Mnemonic::Cmovnp => 11,
        Mnemonic::Cmovl => 12,
        Mnemonic::Cmovge => 13,
        Mnemonic::Cmovle => 14,
        Mnemonic::Cmovg => 15,
        _ => return None,
    })
}

pub(super) fn execute_xadd(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let destination = instruction.operand(0);
    let source = instruction.operand(1);
    let width = operand_width(instruction, 0);
    if !matches!(width, 1 | 2 | 4)
        || !matches!(source, Operand::Gpr(_))
        || operand_width(instruction, 1) != width
    {
        return Err(error_at(instruction));
    }

    if instruction.decoded.instruction.has_lock_prefix() {
        let reference = match destination {
            Operand::Memory(reference) => reference,
            _ => return Err(error_at(instruction)),
        };
        let old_source = read_operand(regs, bus, source, width)?;
        let (old_destination, flag_mask, flags) = super::atomic::update_atomically(
            regs,
            bus,
            reference,
            usize::from(width),
            |bytes| {
                let old_destination = super::atomic::read_unsigned_le(bytes) as u32;
                let (sum, mask, flags) =
                    alu_compute(regs, AluOp::Add, old_destination, old_source, width);
                super::atomic::write_unsigned_le(bytes, u64::from(sum));
                (old_destination, mask, flags)
            },
        )?;
        if let Operand::Gpr(register) = source {
            write_register(
                regs,
                register.index | if register.high8 { 4 } else { 0 },
                width,
                old_destination,
            );
        }
        apply_flags(regs, flag_mask, flags);
        return Ok(());
    }

    let prepared = prepare_operand(regs, bus, destination, width, AccessKind::DataReadWrite)?;
    let old_destination = read_prepared_operand(regs, bus, &prepared)?;
    let old_source = read_operand(regs, bus, source, width)?;
    let (sum, flag_mask, flags) = alu_compute(regs, AluOp::Add, old_destination, old_source, width);

    match destination {
        Operand::Memory(_) => {
            // Commit the potentially faulting guest-memory write first. The
            // register source and flags remain intact if address validation
            // fails.
            write_prepared_operand(regs, bus, prepared, sum)?;
            write_operand(regs, bus, source, width, old_destination)?;
        }
        Operand::Gpr(_) => {
            // This ordering also gives XADD reg,reg the architectural doubled
            // result when both operands encode the same register.
            write_operand(regs, bus, source, width, old_destination)?;
            write_prepared_operand(regs, bus, prepared, sum)?;
        }
        _ => return Err(error_at(instruction)),
    }
    apply_flags(regs, flag_mask, flags);
    Ok(())
}

pub(super) fn execute_xlat(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    if instruction.mnemonic != Mnemonic::Xlatb {
        return Err(error_at(instruction));
    }
    let decoded = instruction.decoded.instruction;
    let address32 = decoded.memory_base() == Register::EBX;
    let offset = if address32 {
        regs.ebx.wrapping_add(u32::from(regs.al()))
    } else {
        u32::from(regs.bx().wrapping_add(u16::from(regs.al())))
    };
    let segment = match decoded.memory_segment() {
        Register::ES => crate::registers::SegmentRegister::Es,
        Register::CS => crate::registers::SegmentRegister::Cs,
        Register::SS => crate::registers::SegmentRegister::Ss,
        Register::FS => crate::registers::SegmentRegister::Fs,
        Register::GS => crate::registers::SegmentRegister::Gs,
        Register::DS | Register::None => crate::registers::SegmentRegister::Ds,
        _ => crate::registers::SegmentRegister::Ds,
    };
    let value = read_width(bus, LogicalSpan {
        register: segment,
        selector: read_segment(regs, segment),
        offset,
        len: 1,
        address32,
    }, AccessKind::DataRead)?;
    regs.set_al(value as u8);
    Ok(())
}

pub(super) fn execute_cmpxchg8b(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    instruction: &NormalizedInstruction,
) -> Result<(), CpuError> {
    let reference = match instruction.operand(0) {
        Operand::Memory(reference) => reference,
        _ => return Err(error_at(instruction)),
    };
    if instruction.decoded.instruction.has_lock_prefix() {
        let expected = (u64::from(regs.edx) << 32) | u64::from(regs.eax);
        let replacement = (u64::from(regs.ecx) << 32) | u64::from(regs.ebx);
        let (old_memory, equal) = super::atomic::update_atomically(
            regs,
            bus,
            reference,
            8,
            |bytes| {
                let old_memory = super::atomic::read_unsigned_le(bytes);
                let equal = old_memory == expected;
                super::atomic::write_unsigned_le(
                    bytes,
                    if equal { replacement } else { old_memory },
                );
                (old_memory, equal)
            },
        )?;
        if equal {
            apply_flags(regs, ZF, ZF);
        } else {
            regs.eax = old_memory as u32;
            regs.edx = (old_memory >> 32) as u32;
            apply_flags(regs, ZF, 0);
        }
        return Ok(());
    }
    let base = memory_offset(regs, reference).ok_or_else(|| error_at(instruction))?;
    let segment = read_segment(regs, reference.segment);
    let access = bus.prepare(AccessRequest::Logical {
        span: LogicalSpan {
            register: reference.segment,
            selector: segment,
            offset: base,
            len: 8,
            address32: reference.address32,
        },
        kind: AccessKind::DataReadWrite,
        alignment: DataAlignment::Natural(8),
        origin: AccessOrigin::GuestInstruction,
    })?;
    let mut bytes = [0_u8; 8];
    bus.read_prepared(&access, &mut bytes)?;
    let old_memory = u64::from_le_bytes(bytes);
    let expected = (u64::from(regs.edx) << 32) | u64::from(regs.eax);
    let equal = old_memory == expected;

    // The full 8-byte RMW span is preflighted before reading or changing flags.
    let replacement = if equal {
        (u64::from(regs.ecx) << 32) | u64::from(regs.ebx)
    } else {
        old_memory
    };
    bus.write_prepared(access, &replacement.to_le_bytes())?;

    if equal {
        apply_flags(regs, ZF, ZF);
    } else {
        regs.eax = old_memory as u32;
        regs.edx = (old_memory >> 32) as u32;
        apply_flags(regs, ZF, 0);
    }
    Ok(())
}

#[cfg(test)]
#[path = "extensions/tests.rs"]
mod tests;
