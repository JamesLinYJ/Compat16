use core::cmp::Ordering;

use x86_decoder::Mnemonic as M;
use guest_core::Registers;

use crate::memory_access::{CpuBus, DataAlignment};
use crate::x86_decode::{NormalizedInstruction, Operand};
use crate::x87_state::{Ext80, X87State, X87Tag, X87_C0, X87_C1, X87_C2, X87_C3};
use crate::x87_math::{self, BinaryOp};
use crate::CpuError;

use super::{
    clear_conditions, commit_register_math_result, memory_location, raise_flags,
    raise_result_flags, read_bytes, read_st, set_c1, set_compare, write_st,
};

pub(super) fn execute(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    state: &mut X87State,
    instruction: &NormalizedInstruction,
) -> Result<bool, CpuError> {
    use M as Mnemonic;
    match instruction.mnemonic {
        Mnemonic::Fcmovb | Mnemonic::Fcmovbe | Mnemonic::Fcmove | Mnemonic::Fcmovnb |
        Mnemonic::Fcmovnbe | Mnemonic::Fcmovne | Mnemonic::Fcmovnu | Mnemonic::Fcmovu => {
            execute_fcmov(regs, state, instruction)
        }
        Mnemonic::Fcom | Mnemonic::Fcomp | Mnemonic::Fcompp | Mnemonic::Fucom | Mnemonic::Fucomp | Mnemonic::Fucompp |
        Mnemonic::Fcomi | Mnemonic::Fcomip | Mnemonic::Fucomi | Mnemonic::Fucomip | Mnemonic::Ficom | Mnemonic::Ficomp => {
            execute_compare(regs, bus, state, instruction)
        }
        Mnemonic::Fadd | Mnemonic::Faddp | Mnemonic::Fiadd | Mnemonic::Fsub | Mnemonic::Fsubp |
        Mnemonic::Fsubr | Mnemonic::Fsubrp | Mnemonic::Fisub | Mnemonic::Fisubr | Mnemonic::Fmul |
        Mnemonic::Fmulp | Mnemonic::Fimul | Mnemonic::Fdiv | Mnemonic::Fdivp | Mnemonic::Fdivr |
        Mnemonic::Fdivrp | Mnemonic::Fidiv | Mnemonic::Fidivr => {
            execute_binary(regs, bus, state, instruction)
        }
        Mnemonic::Fsqrt | Mnemonic::Frndint | Mnemonic::Fscale | Mnemonic::Fxtract |
        Mnemonic::Fabs | Mnemonic::Fchs | Mnemonic::Ftst | Mnemonic::Fxam |
        Mnemonic::Fprem | Mnemonic::Fprem1 => {
            execute_unary_or_scale(state, instruction)
        }
        _ => Ok(false),
    }
}

fn execute_compare(
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
    let right_index = if matches!(mnemonic, Mnemonic::Fcompp | Mnemonic::Fucompp) {
        1
    } else {
        second_register(instruction)
    };
    let Some(left) = read_st(state, 0) else { return Ok(true); };
    let (right, source_flags) = if let Some(mem) = memory_operand {
        let width = instruction.memory_width;
        let integer_memory = matches!(mnemonic, Mnemonic::Ficom | Mnemonic::Ficomp);
        let alignment = source_alignment(width, integer_memory, instruction)?;
        let location = memory_location(regs, mem, width)?;
        state.data_pointer = location.offset;
        state.data_segment = location.selector;
        let bytes = read_bytes(bus, location, alignment)?;
        memory_source(&bytes, integer_memory, instruction)?
    } else {
        let Some(value) = read_st(state, right_index) else { return Ok(true); };
        (value, 0)
    };
    let compared = x87_math::compare_with_input_flags(left, right, source_flags);
    let ordering = compared.ordering;
    let fucom = matches!(mnemonic, Mnemonic::Fucom | Mnemonic::Fucomp | Mnemonic::Fucompp | Mnemonic::Fucomi | Mnemonic::Fucomip);
    let invalid = if fucom { 0 } else if is_nan(left) || is_nan(right) { 1 } else { 0 };
    if !raise_flags(state, compared.exceptions | invalid) { return Ok(true); }
    if matches!(mnemonic, Mnemonic::Fcomi | Mnemonic::Fcomip | Mnemonic::Fucomi | Mnemonic::Fucomip) {
        set_integer_compare_flags(regs, ordering);
    } else {
        set_compare(state, ordering);
    }
    let pops = match mnemonic {
        Mnemonic::Fcomp | Mnemonic::Fucomp | Mnemonic::Fcomip | Mnemonic::Fucomip => 1,
        Mnemonic::Fcompp | Mnemonic::Fucompp => 2,
        _ => 0,
    };
    for _ in 0..pops { super::pop(state); }
    Ok(true)
}

fn execute_fcmov(regs: &Registers, state: &mut X87State, instruction: &NormalizedInstruction) -> Result<bool, CpuError> {
    use M as Mnemonic;
    let condition = match instruction.mnemonic {
        Mnemonic::Fcmovb => regs.eflags & 1 != 0,
        Mnemonic::Fcmovbe => regs.eflags & 0x41 != 0,
        Mnemonic::Fcmove => regs.eflags & (1 << 6) != 0,
        Mnemonic::Fcmovu => regs.eflags & (1 << 2) != 0,
        Mnemonic::Fcmovnb => regs.eflags & 1 == 0,
        Mnemonic::Fcmovnbe => regs.eflags & 0x41 == 0,
        Mnemonic::Fcmovne => regs.eflags & (1 << 6) == 0,
        Mnemonic::Fcmovnu => regs.eflags & (1 << 2) == 0,
        _ => return Ok(false),
    };
    if condition {
        let source = second_register(instruction);
        let Some(value) = read_st(state, source) else { return Ok(true); };
        if read_st(state, 0).is_some() {
            write_st(state, 0, value);
        }
    }
    Ok(true)
}

fn execute_binary(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    state: &mut X87State,
    instruction: &NormalizedInstruction,
) -> Result<bool, CpuError> {
    let mnemonic = instruction.mnemonic;
    let memory_operand = instruction.operands[..usize::from(instruction.operand_count)]
        .iter()
        .find_map(|operand| if let Operand::Memory(mem) = operand { Some(*mem) } else { None });
    let integer_memory = matches!(mnemonic, M::Fiadd | M::Fisub | M::Fisubr | M::Fimul | M::Fidiv | M::Fidivr);
    let (destination, lhs, rhs, input_flags) = if let Some(mem) = memory_operand {
        let width = instruction.memory_width;
        let alignment = source_alignment(width, integer_memory, instruction)?;
        let location = memory_location(regs, mem, width)?;
        state.data_pointer = location.offset;
        state.data_segment = location.selector;
        let bytes = read_bytes(bus, location, alignment)?;
        let (source, flags) = memory_source(&bytes, integer_memory, instruction)?;
        let Some(lhs) = read_st(state, 0) else { return Ok(true); };
        (0, lhs, source, flags)
    } else {
        let (destination, source) = binary_register_indices(instruction);
        let Some(lhs) = read_st(state, destination) else { return Ok(true); };
        let Some(rhs) = read_st(state, source) else { return Ok(true); };
        (destination, lhs, rhs, 0)
    };
    let reversed = matches!(mnemonic, M::Fsubr | M::Fsubrp | M::Fisubr | M::Fdivr | M::Fdivrp | M::Fidivr);
    let (operation, lhs, rhs) = match mnemonic {
        M::Fadd | M::Faddp | M::Fiadd => (BinaryOp::Add, lhs, rhs),
        M::Fsub | M::Fsubp | M::Fsubr | M::Fsubrp | M::Fisub | M::Fisubr => (BinaryOp::Sub, if reversed { rhs } else { lhs }, if reversed { lhs } else { rhs }),
        M::Fmul | M::Fmulp | M::Fimul => (BinaryOp::Mul, lhs, rhs),
        M::Fdiv | M::Fdivp | M::Fdivr | M::Fdivrp | M::Fidiv | M::Fidivr => (BinaryOp::Div, if reversed { rhs } else { lhs }, if reversed { lhs } else { rhs }),
        _ => return Ok(false),
    };
    let result = x87_math::binary_with_input_flags(
        operation,
        lhs,
        rhs,
        state.control_word,
        input_flags,
    );
    if let Some((value, c1)) = commit_register_math_result(state, result) {
        set_c1(state, c1);
        write_st(state, destination, value);
        if matches!(mnemonic, M::Faddp | M::Fsubp | M::Fsubrp | M::Fmulp | M::Fdivp | M::Fdivrp) {
            super::pop(state);
        }
    }
    Ok(true)
}

fn execute_unary_or_scale(
    state: &mut X87State,
    instruction: &NormalizedInstruction,
) -> Result<bool, CpuError> {
    use M as Mnemonic;
    let mnemonic = instruction.mnemonic;

    if matches!(mnemonic, Mnemonic::Fxam) {
        execute_fxam(state);
        return Ok(true);
    }

    if matches!(mnemonic, Mnemonic::Fprem | Mnemonic::Fprem1) {
        return execute_remainder(state, mnemonic == Mnemonic::Fprem1);
    }

    let Some(source) = super::read_st_with_outcome(state, 0) else { return Ok(true); };
    let value = source.value;
    match mnemonic {
        Mnemonic::Fabs | Mnemonic::Fchs => {
            let mut result = value;
            if mnemonic == Mnemonic::Fabs {
                result.sign_exponent &= 0x7fff;
            } else {
                result.sign_exponent ^= 0x8000;
            }
            write_st(state, 0, result);
        }
        Mnemonic::Ftst => {
            let compared = x87_math::compare(value, Ext80::default());
            let invalid = if is_nan(value) { x87_math::X87_IE } else { 0 };
            if raise_flags(state, compared.exceptions | invalid) {
                set_compare(state, compared.ordering);
            }
        }
        Mnemonic::Fsqrt | Mnemonic::Frndint => {
            let result = if mnemonic == Mnemonic::Fsqrt {
                x87_math::sqrt(value, state.control_word)
            } else {
                x87_math::round_integral(value, state.control_word)
            };
            if let Some((value, c1)) = commit_register_math_result(state, result) {
                set_c1(state, c1);
                write_st(state, 0, value);
            }
        }
        Mnemonic::Fscale => {
            let Some(exponent) = read_st(state, 1) else { return Ok(true); };
            let result = x87_math::scale(value, exponent, state.control_word);
            if let Some((value, c1)) = commit_register_math_result(state, result) {
                set_c1(state, c1);
                write_st(state, 0, value);
            }
        }
        Mnemonic::Fxtract => {
            // FXTRACT always needs a new stack slot. A source #IS already
            // selected by read_st wins; otherwise resolve push #IS before the
            // instruction's lower #D or #Z.
            match super::preflight_push(state, source.kind) {
                super::PushPreflight::Available => {}
                super::PushPreflight::MaskedSourceUnderflow => {
                    // The source #IS is already the selected masked response.
                    // FXTRACT writes both result registers as indefinite; do
                    // not let an occupied wrap slot replace C1=0 with overflow.
                    let indefinite = super::indefinite();
                    super::commit_masked_source_underflow_push(state, indefinite);
                    write_st(state, 1, indefinite);
                    return Ok(true);
                }
                super::PushPreflight::MaskedStackOverflow => {
                    super::commit_preflight_stack_overflow(state);
                    return Ok(true);
                }
                super::PushPreflight::Suppressed => return Ok(true),
            }
            let result = x87_math::extract(value);
            if raise_result_flags(state, result.exceptions) {
                // Push first so an unmasked stack overflow cannot partially
                // replace the original ST0 before the instruction faults.
                if super::push(state, result.significand) {
                    write_st(state, 1, result.exponent);
                }
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn execute_fxam(state: &mut X87State) {
    clear_conditions(state);
    let physical = state.physical_register(0);
    if state.tag(physical) == X87Tag::Empty {
        state.status_word |= X87_C3 | X87_C0;
        return;
    }

    let value = state.registers[physical];
    if value.sign_exponent & 0x8000 != 0 {
        state.status_word |= X87_C1;
    }
    let class = x87_math::classify(value);
    state.status_word |= match class {
        x87_math::Classification::Unsupported => 0,
        x87_math::Classification::QuietNaN | x87_math::Classification::SignalingNaN => X87_C0,
        x87_math::Classification::Finite if value.sign_exponent & 0x7fff == 0 => X87_C2 | X87_C3,
        x87_math::Classification::Finite => X87_C2,
        x87_math::Classification::Infinity => X87_C2 | X87_C0,
        x87_math::Classification::Zero => X87_C3,
    };
}

fn execute_remainder(state: &mut X87State, nearest_even: bool) -> Result<bool, CpuError> {
    let Some(dividend) = read_st(state, 0) else { return Ok(true); };
    let Some(divisor) = read_st(state, 1) else { return Ok(true); };
    let result = x87_math::remainder(dividend, divisor, nearest_even);
    if !raise_flags(state, result.exceptions) {
        return Ok(true);
    }
    write_st(state, 0, result.value);
    if result.partial {
        state.status_word &= !X87_C2;
        state.status_word |= X87_C2;
    } else {
        clear_conditions(state);
        if result.quotient_low3 & 0b100 != 0 { state.status_word |= X87_C0; }
        if result.quotient_low3 & 0b001 != 0 { state.status_word |= X87_C1; }
        if result.quotient_low3 & 0b010 != 0 { state.status_word |= X87_C3; }
    }
    Ok(true)
}

fn memory_source(
    bytes: &[u8],
    integer: bool,
    instruction: &NormalizedInstruction,
) -> Result<(Ext80, u16), CpuError> {
    let raw = bytes.iter().take(8).enumerate().fold(0_u64, |value, (index, byte)| value | (u64::from(*byte) << (index * 8)));
    if integer {
        if !matches!(bytes.len(), 2 | 4) { return Err(unsupported(instruction)); }
        let bits = (bytes.len() * 8) as u32;
        let signed = if bits == 64 { raw as i64 } else { ((raw << (64 - bits)) as i64) >> (64 - bits) };
        let result = x87_math::from_i128(i128::from(signed));
        return Ok((result.value, result.exceptions));
    }
    match bytes.len() {
        4 => { let result = x87_math::from_f32_bits(raw as u32); Ok((result.value, result.exceptions)) }
        8 => { let result = x87_math::from_f64_bits(raw); Ok((result.value, result.exceptions)) }
        10 => Ok((Ext80::from_le_bytes(bytes.try_into().unwrap_or([0; 10])), 0)),
        _ => Err(unsupported(instruction)),
    }
}

fn source_alignment(
    width: usize,
    integer: bool,
    instruction: &NormalizedInstruction,
) -> Result<DataAlignment, CpuError> {
    match (integer, width) {
        (true, 2) => Ok(DataAlignment::Natural(2)),
        (true, 4) | (false, 4) => Ok(DataAlignment::Natural(4)),
        (false, 8 | 10) => Ok(DataAlignment::Natural(8)),
        _ => Err(unsupported(instruction)),
    }
}

fn is_nan(value: Ext80) -> bool {
    value.sign_exponent & 0x7fff == 0x7fff && value.significand & 0x7fff_ffff_ffff_ffff != 0
}

fn second_register(instruction: &NormalizedInstruction) -> u8 {
    instruction.float_register(1)
        .or_else(|| instruction.float_register(0))
        .unwrap_or(1)
}

fn binary_register_indices(instruction: &NormalizedInstruction) -> (u8, u8) {
    let destination = instruction.float_register(0).unwrap_or(0);
    let source = instruction.float_register(1).unwrap_or(if destination == 0 { 1 } else { 0 });
    (destination, source)
}

#[cfg(test)]
#[path = "arithmetic_tests.rs"]
mod tests;

fn set_integer_compare_flags(regs: &mut Registers, result: Option<Ordering>) {
    const CF: u32 = 1;
    const PF: u32 = 1 << 2;
    const AF: u32 = 1 << 4;
    const ZF: u32 = 1 << 6;
    const SF: u32 = 1 << 7;
    const OF: u32 = 1 << 11;
    regs.eflags &= !(CF | PF | AF | ZF | SF | OF);
    regs.eflags |= 2;
    match result {
        Some(Ordering::Less) => regs.eflags |= CF,
        Some(Ordering::Equal) => regs.eflags |= ZF,
        Some(Ordering::Greater) => {}
        None => regs.eflags |= CF | PF | ZF,
    }
}

fn unsupported(instruction: &NormalizedInstruction) -> CpuError {
    CpuError::UnsupportedOpcode { opcode: instruction.decoded.opcode, ip: instruction.decoded.start_ip }
}
