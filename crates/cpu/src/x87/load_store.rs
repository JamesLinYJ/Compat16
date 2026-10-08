use x86_decoder::Mnemonic as M;
use guest_core::Registers;

use crate::memory_access::{CpuBus, DataAlignment};
use crate::x86_decode::{NormalizedInstruction, Operand};
use crate::x87_state::{Ext80, X87State, X87Tag};
use crate::x87_math::{self, X87_IE};
use crate::CpuError;

use super::{
    memory_location, raise_flags, raise_result_flags, read_bytes, read_st, set_c1, write_bytes,
    write_st,
};

#[cfg(test)]
#[path = "load_store_tests.rs"]
mod tests;

pub(super) fn execute(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    state: &mut X87State,
    instruction: &NormalizedInstruction,
) -> Result<bool, CpuError> {
    use M as Mnemonic;
    let mnemonic = instruction.mnemonic;
    let memory_operand = instruction.operands[..usize::from(instruction.operand_count)]
        .iter()
        .find_map(|operand| if let Operand::Memory(mem) = operand { Some(*mem) } else { None });
    match mnemonic {
        Mnemonic::Fld1 | Mnemonic::Fldl2t | Mnemonic::Fldl2e | Mnemonic::Fldpi | Mnemonic::Fldlg2 | Mnemonic::Fldln2 | Mnemonic::Fldz => {
            let value = constant(mnemonic, state.control_word);
            set_c1(state, false);
            super::push(state, value);
            Ok(true)
        }
        Mnemonic::Fxch => {
            let first = instruction.float_register(0);
            let second = instruction.float_register(1);
            let index = second.filter(|value| *value != 0)
                .or_else(|| first.filter(|value| *value != 0))
                .or(second)
                .or(first)
                .unwrap_or(1);
            let Some(top) = read_st(state, 0) else { return Ok(true); };
            let Some(other) = read_st(state, index) else { return Ok(true); };
            set_c1(state, false);
            write_st(state, 0, other);
            write_st(state, index, top);
            Ok(true)
        }
        Mnemonic::Ffree | Mnemonic::Ffreep => {
            let index = instruction.float_register(0).unwrap_or(0);
            let physical = state.physical_register(index);
            state.set_tag(physical, X87Tag::Empty);
            if mnemonic == Mnemonic::Ffreep {
                if index == 0 {
                    super::increment_top(state);
                } else {
                    super::pop(state);
                }
            }
            Ok(true)
        }
        Mnemonic::Fincstp => {
            set_c1(state, false);
            super::increment_top(state);
            Ok(true)
        }
        Mnemonic::Fdecstp => {
            set_c1(state, false);
            super::decrement_top(state);
            Ok(true)
        }
        Mnemonic::Fld => execute_fld(regs, bus, state, instruction, memory_operand),
        Mnemonic::Fst | Mnemonic::Fstp => execute_fst(regs, bus, state, instruction, memory_operand),
        Mnemonic::Fild => execute_fild(regs, bus, state, instruction, memory_operand),
        Mnemonic::Fist | Mnemonic::Fistp | Mnemonic::Fisttp => execute_fist(regs, bus, state, instruction, memory_operand),
        Mnemonic::Fbld => execute_fbld(regs, bus, state, instruction, memory_operand),
        Mnemonic::Fbstp => execute_fbstp(regs, bus, state, instruction, memory_operand),
        _ => Ok(false),
    }
}

fn execute_fld(
    regs: &Registers,
    bus: &mut impl CpuBus,
    state: &mut X87State,
    instruction: &NormalizedInstruction,
    mem: Option<crate::x86_decode::MemoryOperand>,
) -> Result<bool, CpuError> {
    if let Some(mem) = mem {
        let width = instruction.memory_width;
        let location = memory_location(regs, mem, width)?;
        state.data_pointer = location.offset;
        state.data_segment = location.selector;
        let alignment = match width {
            4 => DataAlignment::Natural(4),
            8 | 10 => DataAlignment::Natural(8),
            _ => return Err(unsupported(instruction)),
        };
        let bytes = read_bytes(bus, location, alignment)?;
        let (value, exceptions) = match width {
            4 => {
                let result = x87_math::from_f32_bits(bytes_to_u64(&bytes) as u32);
                (result.value, result.exceptions)
            }
            8 => {
                let result = x87_math::from_f64_bits(bytes_to_u64(&bytes));
                (result.value, result.exceptions)
            }
            // FLD m80 copies the raw value. Unsupported encodings are checked
            // when consumed by arithmetic rather than during the load.
            10 => (Ext80::from_le_bytes(bytes.try_into().unwrap_or([0; 10])), 0),
            _ => return Err(unsupported(instruction)),
        };
        push_loaded_value(state, value, exceptions, super::StackReadKind::Value);
    } else {
        let index = instruction.float_register(0).unwrap_or(0);
        let Some(source) = super::read_st_with_outcome(state, index) else { return Ok(true); };
        push_loaded_value(state, source.value, 0, source.kind);
    }
    Ok(true)
}

fn push_loaded_value(
    state: &mut X87State,
    value: Ext80,
    exceptions: u16,
    source: super::StackReadKind,
) {
    match super::preflight_push(state, source) {
        super::PushPreflight::Available => {}
        super::PushPreflight::MaskedSourceUnderflow => {
            super::commit_masked_source_underflow_push(state, value);
            return;
        }
        super::PushPreflight::MaskedStackOverflow => {
            super::commit_preflight_stack_overflow(state);
            return;
        }
        super::PushPreflight::Suppressed => return,
    }

    let exceptions = x87_math::prioritize_operand_exceptions(&[value], exceptions);
    let denormal = exceptions & x87_math::X87_DE;
    if !raise_flags(state, exceptions & !x87_math::X87_DE) {
        return;
    }

    // FLD m32/m64 signals #D but still pushes the converted operand when #D
    // is unmasked. Other selected classes retain ordinary pre-compute rules.
    if denormal != 0 {
        raise_flags(state, denormal);
    }
    set_c1(state, false);
    let pushed = super::push(state, value);
    debug_assert!(pushed, "preflighted FLD destination must remain available");
}

fn execute_fst(
    regs: &Registers,
    bus: &mut impl CpuBus,
    state: &mut X87State,
    instruction: &NormalizedInstruction,
    mem: Option<crate::x86_decode::MemoryOperand>,
) -> Result<bool, CpuError> {
    let Some(value) = read_st(state, 0) else { return Ok(true); };
    if let Some(mem) = mem {
        let width = instruction.memory_width;
        let location = memory_location(regs, mem, width)?;
        state.data_pointer = location.offset;
        state.data_segment = location.selector;
        let alignment = match width {
            4 => DataAlignment::Natural(4),
            8 | 10 => DataAlignment::Natural(8),
            _ => return Err(unsupported(instruction)),
        };
        let bytes = match width {
            4 => {
                let result = x87_math::to_f32_bits(value, state.control_word);
                if !commit_rounded_store(state, result.exceptions, result.c1) { return Ok(true); }
                (result.bits as u32).to_le_bytes().to_vec()
            }
            8 => {
                let result = x87_math::to_f64_bits(value, state.control_word);
                if !commit_rounded_store(state, result.exceptions, result.c1) { return Ok(true); }
                result.bits.to_le_bytes().to_vec()
            }
            10 => value.to_le_bytes().to_vec(),
            _ => return Err(unsupported(instruction)),
        };
        write_bytes(bus, location, alignment, &bytes)?;
    } else {
        let dest = instruction.float_register(0).unwrap_or(0);
        write_st(state, dest, value);
    }
    if instruction.mnemonic == M::Fstp { super::pop(state); }
    Ok(true)
}

fn execute_fild(
    regs: &Registers,
    bus: &mut impl CpuBus,
    state: &mut X87State,
    instruction: &NormalizedInstruction,
    mem: Option<crate::x86_decode::MemoryOperand>,
) -> Result<bool, CpuError> {
    let mem = mem.ok_or_else(|| unsupported(instruction))?;
    let width = instruction.memory_width;
    if !matches!(width, 2 | 4 | 8) { return Err(unsupported(instruction)); }
    let location = memory_location(regs, mem, width)?;
    state.data_pointer = location.offset;
    state.data_segment = location.selector;
    let bytes = read_bytes(bus, location, DataAlignment::Natural(width as u8))?;
    let result = x87_math::from_i128(i128::from(sign_extend(bytes_to_u64(&bytes), (width * 8) as u32)));
    if raise_flags(state, result.exceptions) {
        set_c1(state, false);
        super::push(state, result.value);
    }
    Ok(true)
}

fn execute_fist(
    regs: &Registers,
    bus: &mut impl CpuBus,
    state: &mut X87State,
    instruction: &NormalizedInstruction,
    mem: Option<crate::x86_decode::MemoryOperand>,
) -> Result<bool, CpuError> {
    let mem = mem.ok_or_else(|| unsupported(instruction))?;
    let width = instruction.memory_width;
    if !matches!(width, 2 | 4 | 8) { return Err(unsupported(instruction)); }
    let location = memory_location(regs, mem, width)?;
    state.data_pointer = location.offset;
    state.data_segment = location.selector;
    let Some(value) = read_st(state, 0) else { return Ok(true); };
    let integer = x87_math::to_i128_for_store(
        value,
        width * 8,
        state.control_word,
        instruction.mnemonic == M::Fisttp,
    );
    if !raise_result_flags(state, integer.exceptions) { return Ok(true); }
    set_c1(state, integer.c1);
    write_bytes(bus, location, DataAlignment::Natural(width as u8), &integer.value.to_le_bytes()[..width])?;
    if matches!(instruction.mnemonic, M::Fistp | M::Fisttp) { super::pop(state); }
    Ok(true)
}

fn execute_fbld(
    regs: &Registers,
    bus: &mut impl CpuBus,
    state: &mut X87State,
    instruction: &NormalizedInstruction,
    mem: Option<crate::x86_decode::MemoryOperand>,
) -> Result<bool, CpuError> {
    let mem = mem.ok_or_else(|| unsupported(instruction))?;
    let location = memory_location(regs, mem, 10)?;
    state.data_pointer = location.offset;
    state.data_segment = location.selector;
    // Intel's FBLD entry specifies #AC when an unaligned reference occurs but
    // does not state the natural modulus for m80bcd; keep only that AC-enabled
    // case typed as a compatibility gap, while preserving the format path
    // whenever the actual #AC gate is closed.
    let bytes = read_bytes(bus, location, DataAlignment::Unspecified)?;
    let packed: [u8; 10] = bytes.try_into().unwrap_or([0; 10]);
    let value = packed_bcd_to_ext80(&packed);
    set_c1(state, false);
    super::push(state, value);
    Ok(true)
}

fn execute_fbstp(
    regs: &Registers,
    bus: &mut impl CpuBus,
    state: &mut X87State,
    instruction: &NormalizedInstruction,
    mem: Option<crate::x86_decode::MemoryOperand>,
) -> Result<bool, CpuError> {
    let mem = mem.ok_or_else(|| unsupported(instruction))?;
    let location = memory_location(regs, mem, 10)?;
    state.data_pointer = location.offset;
    state.data_segment = location.selector;
    let Some(value) = read_st(state, 0) else { return Ok(true); };
    let result = x87_math::to_i128_for_store(value, 64, state.control_word, false);
    let mut flags = result.exceptions;
    let negative = result.value < 0
        || (result.value == 0 && value.sign_exponent & 0x8000 != 0);
    let encoded = encode_packed_bcd_with_sign(result.value, negative);
    if encoded.is_none() {
        // The selected BCD-format #IA suppresses this conversion's new #P;
        // sticky #P already present in status_word remains untouched.
        flags = (flags & !x87_math::X87_PE) | X87_IE;
    }
    if !raise_result_flags(state, flags) { return Ok(true); }
    set_c1(state, result.c1);
    let bytes = encoded.unwrap_or(BCD_INDEFINITE);
    // See FBLD above: packed BCD is an 80-bit operand, not the documented
    // 80-bit extended-real type, so do not borrow its Natural(8) rule.
    write_bytes(bus, location, DataAlignment::Unspecified, &bytes)?;
    super::pop(state);
    Ok(true)
}

fn sign_extend(raw: u64, bits: u32) -> i64 {
    if bits == 64 { raw as i64 } else { ((raw << (64 - bits)) as i64) >> (64 - bits) }
}

fn bytes_to_u64(bytes: &[u8]) -> u64 {
    bytes.iter().enumerate().fold(0_u64, |value, (index, byte)| value | (u64::from(*byte) << (index * 8)))
}

fn commit_rounded_store(state: &mut X87State, exceptions: u16, c1: bool) -> bool {
    if !raise_result_flags(state, exceptions) {
        set_c1(state, false);
        return false;
    }
    set_c1(state, c1);
    true
}

const BCD_INDEFINITE: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 0xc0, 0xff, 0xff];

fn decode_packed_bcd(bytes: &[u8; 10]) -> i128 {
    let mut magnitude = 0_i128;
    let mut multiplier = 1_i128;
    for byte in bytes.iter().take(9) {
        for digit in [byte & 0x0f, byte >> 4] {
            // Intel leaves the result undefined for invalid packed digits;
            // this deterministic decoder does not raise an invented #IA.
            magnitude += i128::from(digit) * multiplier;
            multiplier *= 10;
        }
    }
    if bytes[9] & 0x80 != 0 { -magnitude } else { magnitude }
}

fn packed_bcd_to_ext80(bytes: &[u8; 10]) -> Ext80 {
    let signed = decode_packed_bcd(bytes);
    let mut value = x87_math::from_i128(signed).value;
    if signed == 0 && bytes[9] & 0x80 != 0 {
        value.sign_exponent |= 0x8000;
    }
    value
}

#[cfg(test)]
fn encode_packed_bcd(value: i128) -> Option<[u8; 10]> {
    encode_packed_bcd_with_sign(value, value < 0)
}

fn encode_packed_bcd_with_sign(value: i128, negative: bool) -> Option<[u8; 10]> {
    if value.unsigned_abs() > 999_999_999_999_999_999 {
        return None;
    }
    let mut bytes = [0_u8; 10];
    let mut magnitude = value.unsigned_abs();
    for byte in bytes.iter_mut().take(9) {
        let low = (magnitude % 10) as u8;
        magnitude /= 10;
        let high = (magnitude % 10) as u8;
        magnitude /= 10;
        *byte = (high << 4) | low;
    }
    bytes[9] = if negative { 0x80 } else { 0 };
    Some(bytes)
}

fn constant(mnemonic: M, control_word: u16) -> Ext80 {
    // Intel SDM Vol. 2A, FLD constants: RC applies to the internal constant,
    // PC does not; loading a rounded constant does not raise PE or set C1.
    // Store the lower adjacent significand and the nearest-round direction.
    // The directed endpoints also follow independently from high-precision
    // evaluations of log2(10), log2(e), pi, log10(2), and ln(2).
    let (lower, sign_exponent, nearest_up) = match mnemonic {
        M::Fld1 => return Ext80 { significand: 1 << 63, sign_exponent: 0x3fff },
        M::Fldl2t => (0xd49a_784b_cd1b_8afe, 0x4000, false),
        M::Fldl2e => (0xb8aa_3b29_5c17_f0bb, 0x3fff, true),
        M::Fldpi => (0xc90f_daa2_2168_c234, 0x4000, true),
        M::Fldlg2 => (0x9a20_9a84_fbcf_f798, 0x3ffd, true),
        M::Fldln2 => (0xb172_17f7_d1cf_79ab, 0x3ffe, true),
        _ => return Ext80::default(),
    };
    let increment = match (control_word >> 10) & 3 {
        0 => nearest_up,
        2 => true,
        _ => false,
    };
    Ext80 { significand: lower + u64::from(increment), sign_exponent }
}

fn unsupported(instruction: &NormalizedInstruction) -> CpuError {
    CpuError::UnsupportedOpcode { opcode: instruction.decoded.opcode, ip: instruction.decoded.start_ip }
}
