//! Intel 387-compatible x87 instruction execution over raw 80-bit values.
//!
//! This module owns the x87 stack, status, memory formats, and instruction
//! effects while routing exact numerical operations through the shared CPU
//! software-float adapter.

mod arithmetic;
mod control;
mod load_store;
#[cfg(test)]
mod tests;

use x86_decoder::Mnemonic;
use guest_core::Registers;

use crate::memory_access::{AccessKind, CpuBus, DataAlignment, LogicalSpan};
use crate::x86_decode::{memory_offset, MemoryOperand, NormalizedInstruction};
use crate::registers::read_segment;
use crate::x87_math::{X87_IE, X87_OE, X87_PE};
use crate::x87_state::{
    Ext80, X87State, X87Tag, X87_C0, X87_C1, X87_C2, X87_C3,
};
use crate::CpuError;

/// Execute an x87 instruction, returning `false` for an instruction owned by
/// the integer or SIMD decoder.
pub(crate) fn execute(
    regs: &mut Registers,
    bus: &mut impl CpuBus,
    state: &mut X87State,
    instruction: &NormalizedInstruction,
) -> Result<bool, CpuError> {
    let mnemonic = instruction.mnemonic;
    if instruction.decoded.x87_opcode.is_none() && mnemonic != Mnemonic::Wait {
        return Ok(false);
    }
    // The three legacy controls are FN forms on this CPU model: they do not
    // wait for pending exceptions before executing as no-ops.
    let non_waiting = matches!(
        mnemonic,
        Mnemonic::Fnclex | Mnemonic::Fninit | Mnemonic::Fnstcw | Mnemonic::Fnstenv |
            Mnemonic::Fnsave | Mnemonic::Fnstsw | Mnemonic::Fndisi |
            Mnemonic::Fneni | Mnemonic::Fnsetpm
    );
    if !non_waiting && state.pending_unmasked_exceptions() != 0 {
        return Err(CpuError::FloatException);
    }
    if crate::x87_transcendental::execute(state, mnemonic) {
        if should_note_pointer(mnemonic) { note_instruction(regs, state, instruction); }
        return Ok(true);
    }

    let handled = match mnemonic {
        Mnemonic::Fadd | Mnemonic::Faddp | Mnemonic::Fiadd |
        Mnemonic::Fsub | Mnemonic::Fsubp | Mnemonic::Fsubr | Mnemonic::Fsubrp | Mnemonic::Fisub | Mnemonic::Fisubr |
        Mnemonic::Fmul | Mnemonic::Fmulp | Mnemonic::Fimul |
        Mnemonic::Fdiv | Mnemonic::Fdivp | Mnemonic::Fdivr | Mnemonic::Fdivrp | Mnemonic::Fidiv | Mnemonic::Fidivr |
        Mnemonic::Fprem | Mnemonic::Fprem1 |
        Mnemonic::Fcom | Mnemonic::Fcomp | Mnemonic::Fcompp | Mnemonic::Fucom | Mnemonic::Fucomp | Mnemonic::Fucompp |
        Mnemonic::Fcomi | Mnemonic::Fcomip | Mnemonic::Fucomi | Mnemonic::Fucomip | Mnemonic::Ficom | Mnemonic::Ficomp |
        Mnemonic::Fcmovb | Mnemonic::Fcmovbe | Mnemonic::Fcmove | Mnemonic::Fcmovnb | Mnemonic::Fcmovnbe | Mnemonic::Fcmovne | Mnemonic::Fcmovnu | Mnemonic::Fcmovu |
        Mnemonic::Fsqrt | Mnemonic::Frndint | Mnemonic::Fscale | Mnemonic::Fxtract |
        Mnemonic::Fabs | Mnemonic::Fchs | Mnemonic::Ftst | Mnemonic::Fxam => {
            arithmetic::execute(regs, bus, state, instruction)?
        }
        Mnemonic::Fld | Mnemonic::Fst | Mnemonic::Fstp | Mnemonic::Fild | Mnemonic::Fist | Mnemonic::Fistp | Mnemonic::Fisttp |
        Mnemonic::Fbld | Mnemonic::Fbstp | Mnemonic::Fld1 | Mnemonic::Fldl2t | Mnemonic::Fldl2e | Mnemonic::Fldpi |
        Mnemonic::Fldlg2 | Mnemonic::Fldln2 | Mnemonic::Fldz | Mnemonic::Fxch | Mnemonic::Ffree | Mnemonic::Ffreep |
        Mnemonic::Fdecstp | Mnemonic::Fincstp => {
            load_store::execute(regs, bus, state, instruction)?
        }
        Mnemonic::Fldcw | Mnemonic::Fnstcw | Mnemonic::Fstcw | Mnemonic::Fldenv | Mnemonic::Fnstenv | Mnemonic::Fstenv |
        Mnemonic::Frstor | Mnemonic::Fnsave | Mnemonic::Fsave | Mnemonic::Fnstsw | Mnemonic::Fstsw |
        Mnemonic::Fnclex | Mnemonic::Fclex | Mnemonic::Fninit | Mnemonic::Finit |
        Mnemonic::Fnop | Mnemonic::Fndisi | Mnemonic::Fneni | Mnemonic::Fnsetpm |
        Mnemonic::Fdisi | Mnemonic::Feni | Mnemonic::Fsetpm | Mnemonic::Wait => {
            control::execute(regs, bus, state, instruction)?
        }
        _ => false,
    };

    if handled && should_note_pointer(mnemonic) {
        note_instruction(regs, state, instruction);
    }
    if handled { Ok(true) } else { Err(CpuError::UnsupportedOpcode { opcode: instruction.decoded.opcode, ip: instruction.decoded.start_ip }) }
}

fn should_note_pointer(mnemonic: Mnemonic) -> bool {
    !matches!(mnemonic,
        Mnemonic::Fninit | Mnemonic::Finit | Mnemonic::Fnsave | Mnemonic::Fsave |
        Mnemonic::Fnstenv | Mnemonic::Fstenv | Mnemonic::Fldenv | Mnemonic::Frstor |
        Mnemonic::Fnclex | Mnemonic::Fclex | Mnemonic::Wait |
        Mnemonic::Fndisi | Mnemonic::Fneni | Mnemonic::Fnsetpm |
        Mnemonic::Fdisi | Mnemonic::Feni | Mnemonic::Fsetpm |
        Mnemonic::Fldcw | Mnemonic::Fnstcw | Mnemonic::Fstcw | Mnemonic::Fnstsw | Mnemonic::Fstsw
    )
}

fn note_instruction(regs: &Registers, state: &mut X87State, instruction: &NormalizedInstruction) {
    state.instruction_pointer = instruction.decoded.start_ip as u32;
    state.instruction_segment = regs.cs;
    // Filled from the decoder's 11-bit escape-opcode/ModRM field.
    state.opcode = instruction.decoded.x87_opcode.unwrap_or(0);
}

/// Record architectural exception bits and report whether all are masked.
pub(crate) fn raise_flags(state: &mut X87State, status_flags: u16) -> bool {
    state.record_exceptions(status_flags, false, None) == 0
}

/// Commit post-computation exceptions, where precision is reported after the
/// rounded destination is produced. An unmasked non-precision exception still
/// suppresses the destination; unmasked PE is deferred to the next waiting
/// instruction while this operation commits its result.
pub(crate) fn raise_result_flags(state: &mut X87State, status_flags: u16) -> bool {
    let precommit = status_flags & !crate::x87_math::X87_PE;
    let pending = state.record_exceptions(precommit, false, None);
    if pending & !crate::x87_math::X87_PE != 0 {
        return false;
    }
    let precision = status_flags & crate::x87_math::X87_PE;
    if precision != 0 {
        state.record_exceptions(precision, false, None);
    }
    true
}

/// Commit a numerically computed register result. x87 reports IE/DE/ZE before
/// producing a result, so an unmasked flag from that group suppresses all
/// destination and stack effects. OE/UE/PE are post-computation: their flags
/// are recorded and the supplied numeric result is committed. The arithmetic
/// adapter provides the exponent-biased result and C1 for unmasked OE/UE.
pub(crate) fn commit_register_math_result(
    state: &mut X87State,
    result: crate::x87_math::MathResult,
) -> Option<(Ext80, bool)> {
    if !commit_register_math_results(state, &[result]) {
        return None;
    }
    Some(register_math_result_value(result))
}

/// Retire post-computation flags for one or more x87 register destinations.
///
/// Multiple-result instructions use this same boundary once for their whole
/// result set, so an unmasked pre-computation exception cannot partially push
/// a stack result. Post-computation O/U/P flags remain pending while the
/// rounded destination values are committed by the caller.
pub(crate) fn commit_register_math_results(
    state: &mut X87State,
    results: &[crate::x87_math::MathResult],
) -> bool {
    const PRECOMPUTE_EXCEPTION_MASK: u16 = 0x0007; // IE, DE, ZE
    const UNDERFLOW_EXCEPTION: u16 = 1 << 4;

    let mut precompute_flags = 0;
    let mut postcompute_flags = 0;
    for result in results {
        precompute_flags |= result.exceptions & PRECOMPUTE_EXCEPTION_MASK;
        postcompute_flags |= result.exceptions & !PRECOMPUTE_EXCEPTION_MASK;
        if let Some(range) = result.range {
            let range_exception = match range.kind {
                crate::x87_math::RegisterRangeKind::Overflow => X87_OE,
                crate::x87_math::RegisterRangeKind::Underflow => UNDERFLOW_EXCEPTION,
            };
            let metadata_flags = range_exception
                | if range.precision_lost { X87_PE } else { 0 };
            debug_assert_eq!(
                result.exceptions & (X87_OE | UNDERFLOW_EXCEPTION | X87_PE),
                metadata_flags,
                "range metadata and x87 exception flags must agree",
            );
            debug_assert_eq!(
                state.control_word & range_exception,
                0,
                "range metadata is only supplied for an unmasked O/U exception",
            );
        }
    }
    let pending = state.record_exceptions(precompute_flags, false, None);
    if pending & precompute_flags != 0 {
        return false;
    }
    state.record_exceptions(postcompute_flags, false, None);
    true
}

pub(crate) fn register_math_result_value(
    result: crate::x87_math::MathResult,
) -> (Ext80, bool) {
    result.range.map_or((result.value, result.c1), |range| {
        (range.biased_value, range.biased_c1)
    })
}

pub(crate) fn raise_stack_fault(state: &mut X87State, overflow: bool) -> bool {
    // Other unmasked exceptions may already be pending from an operation
    // whose result must still commit (notably PE). Only this stack fault's IE
    // mask controls whether the stack operation itself is suppressed.
    state.record_exceptions(X87_IE, true, Some(overflow)) & X87_IE == 0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StackReadKind {
    Value,
    MaskedUnderflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StackReadOutcome {
    pub value: Ext80,
    pub kind: StackReadKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PushPreflight {
    Available,
    /// A masked source #IS already selected this instruction's response.
    /// Do not replace its C1=0 response with a destination #IS overflow.
    MaskedSourceUnderflow,
    MaskedStackOverflow,
    Suppressed,
}

/// Resolve a required push's higher-priority stack fault before the
/// instruction commits its lower-priority input or result flags. When the
/// source already selected masked underflow, retain that class without checking
/// or reporting a second fault for the wrap slot.
pub(crate) fn preflight_push(
    state: &mut X87State,
    source: StackReadKind,
) -> PushPreflight {
    if source == StackReadKind::MaskedUnderflow {
        return PushPreflight::MaskedSourceUnderflow;
    }
    if state.tag(state.physical_register(7)) == X87Tag::Empty {
        PushPreflight::Available
    } else if raise_stack_fault(state, true) {
        PushPreflight::MaskedStackOverflow
    } else {
        PushPreflight::Suppressed
    }
}

/// Commit the masked response after `preflight_push` has already recorded
/// #IS. The new top receives the stack-indefinite value; existing sources stay
/// intact because stack overflow outranks operand and arithmetic exceptions.
pub(crate) fn commit_preflight_stack_overflow(state: &mut X87State) {
    let top = state.top().wrapping_sub(1) & 7;
    debug_assert_ne!(state.tag(usize::from(top)), X87Tag::Empty);
    state.set_top(top);
    state.write_st(0, indefinite());
}

/// Commit a result after a masked source #IS has already selected the response.
/// The source underflow has higher stack-fault priority than a full push slot,
/// so write the instruction's pushed result without reporting a second #IS.
pub(crate) fn commit_masked_source_underflow_push(state: &mut X87State, value: Ext80) {
    let top = state.top().wrapping_sub(1) & 7;
    state.set_top(top);
    state.write_st(0, value);
    state.status_word &= !X87_C1;
}

/// Push a raw value. On a masked stack overflow, x87 writes the indefinite
/// value into the new top slot and records IE/SF/C1.
pub(crate) fn push(state: &mut X87State, value: Ext80) -> bool {
    let top = state.top().wrapping_sub(1) & 7;
    let physical = usize::from(top);
    if state.tag(physical) != X87Tag::Empty {
        if !raise_stack_fault(state, true) {
            return false;
        }
        state.set_top(top);
        state.write_st(0, indefinite());
        true
    } else {
        state.set_top(top);
        state.write_st(0, value);
        true
    }
}

pub(crate) fn pop(state: &mut X87State) -> bool {
    if state.tag(state.physical_register(0)) == X87Tag::Empty && !raise_stack_fault(state, false) {
        return false;
    }
    state.empty_st(0);
    increment_top(state);
    true
}

pub(crate) fn increment_top(state: &mut X87State) {
    state.set_top(state.top().wrapping_add(1) & 7);
}

pub(crate) fn decrement_top(state: &mut X87State) {
    state.set_top(state.top().wrapping_sub(1) & 7);
}

/// Obtain an ST operand, substituting the architectural indefinite value for
/// a masked stack underflow. `None` means an unmasked exception suppressed it.
pub(crate) fn read_st(state: &mut X87State, index: u8) -> Option<Ext80> {
    read_st_with_outcome(state, index).map(|outcome| outcome.value)
}

/// Read an ST operand while preserving whether this call itself selected a
/// masked stack underflow. Sticky IE/SF bits may predate the current instruction
/// and therefore cannot identify this response class.
pub(crate) fn read_st_with_outcome(
    state: &mut X87State,
    index: u8,
) -> Option<StackReadOutcome> {
    if let Some(value) = state.read_st(index) {
        return Some(StackReadOutcome {
            value,
            kind: StackReadKind::Value,
        });
    }
    if raise_stack_fault(state, false) {
        Some(StackReadOutcome {
            value: indefinite(),
            kind: StackReadKind::MaskedUnderflow,
        })
    } else {
        None
    }
}

pub(crate) fn indefinite() -> Ext80 {
    Ext80 { significand: 0xc000_0000_0000_0000, sign_exponent: 0xffff }
}

pub(crate) fn write_st(state: &mut X87State, index: u8, value: Ext80) {
    state.write_st(index, value);
}

pub(crate) fn memory_location(
    regs: &Registers,
    operand: MemoryOperand,
    len: usize,
) -> Result<LogicalSpan, CpuError> {
    let segment = read_segment(regs, operand.segment);
    let offset = memory_offset(regs, operand).ok_or(CpuError::UnsupportedOpcode {
        opcode: 0,
        ip: u32::from(regs.ip()),
    })?;
    Ok(LogicalSpan {
        register: operand.segment,
        selector: segment,
        offset,
        len,
        address32: operand.address32,
    })
}

pub(crate) fn read_bytes(
    bus: &mut impl CpuBus,
    span: LogicalSpan,
    alignment: DataAlignment,
) -> Result<Vec<u8>, CpuError> {
    let mut bytes = vec![0; span.len];
    crate::memory_values::read_bytes(bus, span, AccessKind::DataRead, alignment, &mut bytes)?;
    Ok(bytes)
}

pub(crate) fn write_bytes(
    bus: &mut impl CpuBus,
    span: LogicalSpan,
    alignment: DataAlignment,
    bytes: &[u8],
) -> Result<(), CpuError> {
    crate::memory_values::write_bytes(bus, span, AccessKind::DataWrite, alignment, bytes)
}

pub(crate) fn clear_conditions(state: &mut X87State) {
    state.status_word &= !(X87_C0 | X87_C1 | X87_C2 | X87_C3);
}

/// Set the direction/round-up condition bit without changing the other
/// condition-code bits.
pub(crate) fn set_c1(state: &mut X87State, set: bool) {
    if set {
        state.status_word |= X87_C1;
    } else {
        state.status_word &= !X87_C1;
    }
}

pub(crate) fn set_compare(state: &mut X87State, result: Option<core::cmp::Ordering>) {
    clear_conditions(state);
    match result {
        Some(core::cmp::Ordering::Less) => state.status_word |= X87_C0,
        Some(core::cmp::Ordering::Equal) => state.status_word |= X87_C3,
        Some(core::cmp::Ordering::Greater) => {}
        None => state.status_word |= X87_C0 | X87_C2 | X87_C3,
    }
}
