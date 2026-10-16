//! Bounded x87 arithmetic adapter over LLVM APFloat's portable Rust port.
//!
//! Raw 80-bit storage and instruction effects stay in the CPU crate. This
//! module translates those raw values to APFloat, applies x87 control-word
//! rounding and precision, then returns raw values and architectural flags.

mod convert;
mod extract;
mod remainder;
mod rounding;
mod scale;
mod sqrt;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod jit_tests;

use core::cmp::Ordering;

use rustc_apfloat::ieee::X87DoubleExtended as ApX87;
use rustc_apfloat::{Float, Round, Status};

use crate::x87_state::Ext80;

pub(crate) use convert::{
    from_f32_bits, from_f64_bits, from_i128, from_quad_wide, to_f32_bits, to_f64_bits,
    to_i128_for_store, to_quad,
};
#[cfg(test)]
pub(crate) use convert::to_i128;
pub(crate) use extract::extract;
pub(crate) use remainder::remainder;
pub(crate) use rounding::{
    round_from_control_word, X87_DE, X87_IE, X87_OE, X87_PE, X87_ZE,
};
#[cfg(test)]
use rounding::X87_UE;
pub(crate) use scale::scale;
pub(crate) use sqrt::sqrt;

/// x87's six sticky exception flag positions in the status word.
pub(crate) const X87_EXCEPTION_MASK: u16 = 0x003f;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MathResult {
    pub value: Ext80,
    pub exceptions: u16,
    /// True when rounding increased the magnitude from its toward-zero value.
    pub c1: bool,
    /// Alternate register payload for an unmasked arithmetic range exception.
    /// The ordinary `value` remains the masked-result value.
    pub range: Option<RegisterRangeResult>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegisterRangeKind {
    Overflow,
    Underflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RegisterRangeResult {
    pub kind: RegisterRangeKind,
    pub biased_value: Ext80,
    pub biased_c1: bool,
    pub precision_lost: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CompareResult {
    pub ordering: Option<Ordering>,
    pub exceptions: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExtractResult {
    pub significand: Ext80,
    pub exponent: Ext80,
    pub exceptions: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RemainderResult {
    pub value: Ext80,
    pub exceptions: u16,
    pub c1: bool,
    pub quotient_low3: u8,
    pub partial: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Classification {
    Zero,
    Finite,
    Infinity,
    QuietNaN,
    SignalingNaN,
    Unsupported,
}

/// Classify an 80-bit operand before APFloat canonicalizes pseudo-denormals.
pub(crate) fn classify(value: Ext80) -> Classification {
    let exponent = value.sign_exponent & 0x7fff;
    let integer_bit = value.significand & (1 << 63) != 0;
    if exponent == 0 {
        return if value.significand == 0 {
            Classification::Zero
        } else {
            Classification::Finite
        };
    }
    if exponent == 0x7fff {
        if !integer_bit {
            return Classification::Unsupported;
        }
        if value.significand == 1 << 63 {
            return Classification::Infinity;
        }
        return if value.significand & (1 << 62) != 0 {
            Classification::QuietNaN
        } else {
            Classification::SignalingNaN
        };
    }
    if integer_bit {
        Classification::Finite
    } else {
        Classification::Unsupported
    }
}

fn is_denormal_operand(value: Ext80) -> bool {
    value.sign_exponent & 0x7fff == 0 && value.significand != 0
}

fn decode(value: Ext80) -> Result<(ApX87, u16), u16> {
    if classify(value) == Classification::Unsupported {
        return Err(X87_IE);
    }
    let mut bits = u128::from(value.significand) | (u128::from(value.sign_exponent) << 64);
    // APFloat treats E=0/J=1 as an ordinary normalized value. Preserve the
    // architectural denormal-operand indication while using that canonical value.
    if value.sign_exponent & 0x7fff == 0 && value.significand & (1 << 63) != 0 {
        bits = (bits & !(0x7fff_u128 << 64)) | (1_u128 << 64);
    }
    let flags = if is_denormal_operand(value) {
        X87_DE
    } else {
        0
    };
    Ok((ApX87::from_bits(bits), flags))
}

/// Resolve x87 exception precedence before a consumer records source flags.
/// Invalid and QNaN handling outrank #ZE/#D; #ZE also outranks #D. Range
/// results keep the separate masked-#D plus #O/#U/#P behavior below.
pub(crate) fn prioritize_operand_exceptions(operands: &[Ext80], flags: u16) -> u16 {
    let classes = operands.iter().map(|value| classify(*value));
    let mut has_quiet_nan = false;
    let mut has_invalid_operand = false;
    for class in classes {
        match class {
            Classification::QuietNaN => has_quiet_nan = true,
            Classification::SignalingNaN | Classification::Unsupported => {
                has_invalid_operand = true;
            }
            Classification::Zero | Classification::Finite | Classification::Infinity => {}
        }
    }
    if flags & X87_IE != 0 || has_invalid_operand {
        flags & X87_IE
    } else if has_quiet_nan {
        0
    } else if flags & X87_ZE != 0 {
        flags & X87_ZE
    } else {
        flags
    }
}

/// Encode APFloat's canonical x87 bit layout without a host floating-point cast.
pub(crate) fn from_apfloat(value: ApX87) -> Ext80 {
    let bits = value.to_bits();
    Ext80 {
        significand: bits as u64,
        sign_exponent: (bits >> 64) as u16,
    }
}

pub(crate) fn map_status(status: Status) -> u16 {
    rounding::map_status(status)
}

#[cfg(test)]
pub(crate) fn binary(op: BinaryOp, lhs: Ext80, rhs: Ext80, control_word: u16) -> MathResult {
    binary_with_input_flags(op, lhs, rhs, control_word, 0)
}

/// Compute an ordinary binary operation while deferring source-conversion
/// flags until both raw operands have participated in x87 class selection.
pub(crate) fn binary_with_input_flags(
    op: BinaryOp,
    lhs: Ext80,
    rhs: Ext80,
    control_word: u16,
    source_flags: u16,
) -> MathResult {
    let (left, left_flags) = match decode(lhs) {
        Ok(value) => value,
        Err(flags) => {
            return indefinite_result(prioritize_operand_exceptions(
                &[lhs, rhs],
                source_flags | flags,
            ));
        }
    };
    let (right, right_flags) = match decode(rhs) {
        Ok(value) => value,
        Err(flags) => {
            return indefinite_result(prioritize_operand_exceptions(
                &[lhs, rhs],
                source_flags | left_flags | flags,
            ));
        }
    };
    let input_flags = prioritize_operand_exceptions(
        &[lhs, rhs],
        source_flags | left_flags | right_flags,
    );
    let precision = rounding::precision_bits(control_word);
    let mode = round_from_control_word(control_word);
    let truncated = binary_ap(op, left, right, Round::TowardZero);
    let clipped_to_maximum = truncated.status.contains(Status::INEXACT)
        && is_largest_finite_extended(truncated.value);
    let finite_operands = left.is_finite_non_zero() && right.is_finite_non_zero();
    let overflow_candidate = finite_operands
        && (truncated.status.contains(Status::OVERFLOW)
            || clipped_to_maximum
            || (truncated.value.is_finite_non_zero() && truncated.value.ilogb() == 16_383));
    let underflow_candidate = finite_operands && is_tiny_ap(truncated.value, truncated.status);
    let range = if overflow_candidate && control_word & (1 << 3) == 0 {
        unmasked_binary_range(
            op,
            left,
            right,
            precision,
            mode,
            RegisterRangeKind::Overflow,
        )
    } else if underflow_candidate && control_word & (1 << 4) == 0 {
        unmasked_binary_range(
            op,
            left,
            right,
            precision,
            mode,
            RegisterRangeKind::Underflow,
        )
    } else {
        None
    };

    if precision == 64 && !is_tiny_ap(truncated.value, truncated.status) {
        let rounded = binary_ap(op, left, right, mode);
        let c1 = magnitude_grew(rounded.value, truncated.value);
        let mut flags = input_flags | map_status(rounded.status);
        if clipped_to_maximum {
            let (range_probe, exponent_adjust) =
                scaled_binary_for_large_result(op, left, right, mode);
            let rounds_away = (mode == Round::TowardPositive && !rounded.value.is_negative())
                || (mode == Round::TowardNegative && rounded.value.is_negative());
            if rounds_away || exponent_after_adjust(range_probe.value, exponent_adjust) > 16_383 {
                flags |= X87_OE | X87_PE;
            }
        }
        let mut value = rounded.value;
        if rounded.status.contains(Status::INVALID_OP)
            && !left.is_signaling()
            && !right.is_signaling()
            && value.is_nan()
        {
            value = ApX87::from_bits(raw_bits(indefinite()));
        }
        return MathResult {
            value: from_apfloat(value),
            exceptions: range.map_or(
                prioritize_operand_exceptions(&[lhs, rhs], flags),
                |range| range_exception_flags(input_flags, range),
            ),
            c1,
            range,
        };
    }

    let (calculation, exponent_adjust) = if is_tiny_ap(truncated.value, truncated.status) {
        scaled_binary(op, left, right)
    } else if clipped_to_maximum {
        scaled_binary_for_large_result(op, left, right, Round::TowardZero)
    } else {
        (truncated, 0)
    };
    let mut rounded = rounding::round_extended_bits(
        calculation.value.to_bits(),
        exponent_adjust,
        precision,
        mode,
        calculation.status.contains(Status::INEXACT)
            || (clipped_to_maximum && truncated.status.contains(Status::INEXACT)),
        calculation.status.contains(Status::OVERFLOW),
    );
    let mut flags = input_flags | map_status(calculation.status) | rounded.flags;
    if rounded.value.significand == 0
        && !calculation.status.contains(Status::INEXACT)
        && exact_cancellation(op, left, right)
    {
        rounded.value.sign_exponent = if mode == Round::TowardNegative {
            0x8000
        } else {
            0
        };
    }
    let signaling = left.is_signaling() || right.is_signaling();
    if flags & X87_IE != 0 && !signaling && classify(rounded.value) == Classification::QuietNaN {
        rounded.value = indefinite();
    }
    flags &= X87_EXCEPTION_MASK;
    MathResult {
        value: rounded.value,
        exceptions: range.map_or(
            prioritize_operand_exceptions(&[lhs, rhs], flags),
            |range| range_exception_flags(input_flags, range),
        ),
        c1: rounded.c1,
        range,
    }
}

fn unmasked_binary_range(
    op: BinaryOp,
    lhs: ApX87,
    rhs: ApX87,
    precision: u32,
    mode: Round,
    kind: RegisterRangeKind,
) -> Option<RegisterRangeResult> {
    let (toward_zero, exponent_adjust) = match kind {
        RegisterRangeKind::Overflow => {
            scaled_binary_for_large_result(op, lhs, rhs, Round::TowardZero)
        }
        RegisterRangeKind::Underflow => scaled_binary_with_round(op, lhs, rhs, Round::TowardZero),
    };

    let rounded = if precision == 64 {
        let (in_mode, _) = match kind {
            RegisterRangeKind::Overflow => scaled_binary_for_large_result(op, lhs, rhs, mode),
            RegisterRangeKind::Underflow => scaled_binary_with_round(op, lhs, rhs, mode),
        };
        let mut rounded = rounding::round_unbounded_extended_bits(
            in_mode.value.to_bits(),
            exponent_adjust,
            64,
            Round::TowardZero,
            false,
        );
        rounded.precision_lost = in_mode.status.contains(Status::INEXACT);
        rounded.c1 = magnitude_grew(in_mode.value, toward_zero.value);
        rounded
    } else {
        rounding::round_unbounded_extended_bits(
            toward_zero.value.to_bits(),
            exponent_adjust,
            precision,
            mode,
            toward_zero.status.contains(Status::INEXACT),
        )
    };

    let (kind, exponent_bias) = match kind {
        RegisterRangeKind::Overflow if rounded.exponent > 16_383 => {
            (RegisterRangeKind::Overflow, -24_576)
        }
        RegisterRangeKind::Underflow if rounded.exponent < -16_382 => {
            (RegisterRangeKind::Underflow, 24_576)
        }
        _ => return None,
    };
    Some(RegisterRangeResult {
        kind,
        biased_value: rounding::encode_biased_ext80(rounded, exponent_bias),
        biased_c1: rounded.c1,
        precision_lost: rounded.precision_lost,
    })
}

fn range_exception_flags(input_flags: u16, range: RegisterRangeResult) -> u16 {
    let mut flags = input_flags;
    flags |= match range.kind {
        RegisterRangeKind::Overflow => X87_OE,
        RegisterRangeKind::Underflow => rounding::X87_UE,
    };
    if range.precision_lost {
        flags |= X87_PE;
    }
    flags & X87_EXCEPTION_MASK
}

fn exact_cancellation(op: BinaryOp, lhs: ApX87, rhs: ApX87) -> bool {
    if !lhs.is_finite() || !rhs.is_finite() {
        return false;
    }
    match op {
        BinaryOp::Add => lhs.is_negative() != rhs.is_negative(),
        BinaryOp::Sub => lhs.is_negative() == rhs.is_negative(),
        BinaryOp::Mul | BinaryOp::Div => false,
    }
}

fn binary_ap(
    op: BinaryOp,
    lhs: ApX87,
    rhs: ApX87,
    round: Round,
) -> rustc_apfloat::StatusAnd<ApX87> {
    match op {
        BinaryOp::Add => lhs.add_r(rhs, round),
        BinaryOp::Sub => lhs.sub_r(rhs, round),
        BinaryOp::Mul => lhs.mul_r(rhs, round),
        BinaryOp::Div => lhs.div_r(rhs, round),
    }
}

fn is_tiny_ap(value: ApX87, status: Status) -> bool {
    status.contains(Status::UNDERFLOW) || value.is_denormal()
}

fn scaled_binary(op: BinaryOp, lhs: ApX87, rhs: ApX87) -> (rustc_apfloat::StatusAnd<ApX87>, i32) {
    scaled_binary_with_round(op, lhs, rhs, Round::TowardZero)
}

fn scaled_binary_with_round(
    op: BinaryOp,
    lhs: ApX87,
    rhs: ApX87,
    round: Round,
) -> (rustc_apfloat::StatusAnd<ApX87>, i32) {
    const MIN_EXP: i32 = -16_382;
    const MAX_EXP: i32 = 16_383;
    match op {
        BinaryOp::Add | BinaryOp::Sub => {
            // Any nonzero extended result is at least one minimum subnormal.
            // Scaling by 64 moves that grid above the normal boundary.
            let scaled_lhs = lhs.scalbn_r(64, Round::TowardZero);
            let scaled_rhs = rhs.scalbn_r(64, Round::TowardZero);
            (
                binary_ap(op, scaled_lhs, scaled_rhs, round),
                -64,
            )
        }
        BinaryOp::Mul => {
            let left_exp = lhs.ilogb();
            let right_exp = rhs.ilogb();
            let total = (MIN_EXP - left_exp - right_exp).max(0);
            let left_capacity = MAX_EXP.saturating_sub(left_exp).max(0);
            let left_shift = (total / 2).min(left_capacity);
            let right_shift = total - left_shift;
            let (left_shift, right_shift) = if right_shift > MAX_EXP.saturating_sub(right_exp) {
                let excess = right_shift - MAX_EXP.saturating_sub(right_exp);
                (left_shift + excess, right_shift - excess)
            } else {
                (left_shift, right_shift)
            };
            let scaled_lhs = lhs.scalbn_r(left_shift, Round::TowardZero);
            let scaled_rhs = rhs.scalbn_r(right_shift, Round::TowardZero);
            (
                binary_ap(op, scaled_lhs, scaled_rhs, round),
                -left_shift - right_shift,
            )
        }
        BinaryOp::Div => {
            let left_exp = lhs.ilogb();
            let right_exp = rhs.ilogb();
            let shift = (MIN_EXP + 1 - (left_exp - right_exp)).max(0);
            let scaled_lhs = lhs.scalbn_r(shift, Round::TowardZero);
            (binary_ap(op, scaled_lhs, rhs, round), -shift)
        }
    }
}

fn scaled_binary_for_large_result(
    op: BinaryOp,
    lhs: ApX87,
    rhs: ApX87,
    round: Round,
) -> (rustc_apfloat::StatusAnd<ApX87>, i32) {
    match op {
        BinaryOp::Add | BinaryOp::Sub => {
            let scaled_lhs = lhs.scalbn_r(-1, Round::TowardZero);
            let scaled_rhs = rhs.scalbn_r(-1, Round::TowardZero);
            (binary_ap(op, scaled_lhs, scaled_rhs, round), 1)
        }
        BinaryOp::Mul => {
            let left_exponent = lhs.ilogb();
            let right_exponent = rhs.ilogb();
            let scaled_lhs = lhs.scalbn_r(-left_exponent, Round::TowardZero);
            let scaled_rhs = rhs.scalbn_r(-right_exponent, Round::TowardZero);
            (
                binary_ap(op, scaled_lhs, scaled_rhs, round),
                left_exponent + right_exponent,
            )
        }
        BinaryOp::Div => {
            let left_exponent = lhs.ilogb();
            let right_exponent = rhs.ilogb();
            let scaled_lhs = lhs.scalbn_r(-left_exponent, Round::TowardZero);
            let scaled_rhs = rhs.scalbn_r(-right_exponent, Round::TowardZero);
            (
                binary_ap(op, scaled_lhs, scaled_rhs, round),
                left_exponent - right_exponent,
            )
        }
    }
}

fn is_largest_finite_extended(value: ApX87) -> bool {
    let bits = value.to_bits();
    ((bits >> 64) & 0x7fff) == 0x7ffe && bits as u64 == u64::MAX
}

fn exponent_after_adjust(value: ApX87, exponent_adjust: i32) -> i32 {
    if value.is_infinite() {
        i32::MAX
    } else if value.is_finite_non_zero() {
        value.ilogb().saturating_add(exponent_adjust)
    } else {
        i32::MIN
    }
}

fn magnitude_grew(rounded: ApX87, truncated: ApX87) -> bool {
    !rounded.is_nan() && !truncated.is_nan() && rounded.abs() > truncated.abs()
}

fn raw_bits(value: Ext80) -> u128 {
    u128::from(value.significand) | (u128::from(value.sign_exponent) << 64)
}

pub(crate) fn indefinite() -> Ext80 {
    Ext80 {
        significand: 0xc000_0000_0000_0000,
        sign_exponent: 0xffff,
    }
}

fn indefinite_result(exceptions: u16) -> MathResult {
    MathResult {
        value: indefinite(),
        exceptions,
        c1: false,
        range: None,
    }
}

pub(crate) fn compare(lhs: Ext80, rhs: Ext80) -> CompareResult {
    compare_with_input_flags(lhs, rhs, 0)
}

/// Compare operands after selecting source-conversion and raw operand classes.
pub(crate) fn compare_with_input_flags(lhs: Ext80, rhs: Ext80, source_flags: u16) -> CompareResult {
    let (left, left_flags) = match decode(lhs) {
        Ok(value) => value,
        Err(flags) => {
            return CompareResult {
                ordering: None,
                exceptions: prioritize_operand_exceptions(&[lhs, rhs], source_flags | flags),
            };
        }
    };
    let (right, right_flags) = match decode(rhs) {
        Ok(value) => value,
        Err(flags) => {
            return CompareResult {
                ordering: None,
                exceptions: prioritize_operand_exceptions(
                    &[lhs, rhs],
                    source_flags | left_flags | flags,
                ),
            };
        }
    };
    let mut exceptions = prioritize_operand_exceptions(
        &[lhs, rhs],
        source_flags | left_flags | right_flags,
    );
    if left.is_signaling() || right.is_signaling() {
        exceptions |= X87_IE;
    }
    exceptions = prioritize_operand_exceptions(&[lhs, rhs], exceptions);
    CompareResult {
        ordering: left.partial_cmp(&right),
        exceptions,
    }
}

pub(crate) fn round_integral(value: Ext80, control_word: u16) -> MathResult {
    let (input, flags) = match decode(value) {
        Ok(value) => value,
        Err(flags) => return indefinite_result(flags),
    };
    let truncated = input.round_to_integral(Round::TowardZero);
    let rounded = input.round_to_integral(round_from_control_word(control_word));
    let c1 = magnitude_grew(rounded.value, truncated.value);
    let mut result_flags = flags | map_status(rounded.status);
    let mut result = rounded.value;
    if rounded.status.contains(Status::INVALID_OP) && result.is_nan() && !input.is_signaling() {
        result = ApX87::from_bits(raw_bits(indefinite()));
    }
    result_flags &= X87_EXCEPTION_MASK;
    MathResult {
        value: from_apfloat(result),
        exceptions: result_flags,
        c1,
        range: None,
    }
}
