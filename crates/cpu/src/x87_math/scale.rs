use rustc_apfloat::{Float, Round};

use crate::x87_state::Ext80;

use super::rounding::{round_from_control_word, X87_OE, X87_PE, X87_UE};
use super::{
    decode, from_apfloat, indefinite_result, map_status, magnitude_grew,
    range_exception_flags, MathResult, RegisterRangeKind, RegisterRangeResult, X87_IE,
    X87_EXCEPTION_MASK,
};

pub(crate) fn scale(value: Ext80, exponent: Ext80, control_word: u16) -> MathResult {
    let (input, input_flags) = match decode(value) {
        Ok(value) => value,
        Err(flags) => return indefinite_result(flags),
    };
    let (scale, scale_flags) = match decode(exponent) {
        Ok(value) => value,
        Err(flags) => {
            // Keep both raw operands available until pre-computation
            // precedence is selected: an unsupported ST(1) invalid operand
            // outranks a denormal ST(0), even when #IE is masked.
            return indefinite_result(super::prioritize_operand_exceptions(
                &[value, exponent],
                input_flags | flags,
            ));
        }
    };
    let mut exceptions = input_flags | scale_flags;
    let mode = round_from_control_word(control_word);

    // NaN handling takes precedence over the exponent's numeric class.
    if input.is_nan() || scale.is_nan() {
        if input.is_signaling() || scale.is_signaling() {
            exceptions |= X87_IE;
        }
        let quieted = input.add_r(scale, mode);
        exceptions |= map_status(quieted.status);
        return MathResult {
            value: from_apfloat(quieted.value),
            exceptions: super::prioritize_operand_exceptions(&[value, exponent], exceptions)
                & X87_EXCEPTION_MASK,
            c1: false,
            range: None,
        };
    }

    if scale.is_infinite() {
        if input.is_zero() {
            if scale.is_negative() {
                return MathResult { value: from_apfloat(input), exceptions, c1: false, range: None };
            }
            // 0 * 2^(+infinity) has the architectural invalid result.
            return indefinite_result(exceptions | X87_IE);
        }
        if input.is_infinite() {
            if scale.is_negative() {
                // infinity * 2^(-infinity) is invalid; the negative scale is
                // the zero multiplier in this limiting combination.
                return indefinite_result(exceptions | X87_IE);
            }
            return MathResult { value: from_apfloat(input), exceptions, c1: false, range: None };
        }
        // Intel's FSCALE class table defines finite × 2^(±infinity) directly
        // as signed infinity or signed zero. These are exact class outcomes,
        // not finite-exponent range exceptions and do not use exponent bias.
        let sign = if input.is_negative() { 0x8000 } else { 0 };
        let value = if scale.is_negative() {
            Ext80 {
                significand: 0,
                sign_exponent: sign,
            }
        } else {
            Ext80 {
                significand: 1 << 63,
                sign_exponent: sign | 0x7fff,
            }
        };
        return MathResult {
            value,
            exceptions: exceptions & X87_EXCEPTION_MASK,
            c1: false,
            range: None,
        };
    }

    // Finite exponents leave zero and infinity unchanged. Handling these
    // directly avoids asking scalbn to interpret its special operands.
    if input.is_zero() || input.is_infinite() {
        return MathResult { value: from_apfloat(input), exceptions, c1: false, range: None };
    }

    let scale_amount = if scale.ilogb() > 30 {
        if scale.is_negative() { i32::MIN } else { i32::MAX }
    } else {
        let integer = scale.to_i128_r(32, Round::TowardZero, &mut true);
        integer.value.clamp(i128::from(i32::MIN), i128::from(i32::MAX)) as i32
    };
    let rounded = input.scalbn_r(scale_amount, mode);
    let truncated = input.scalbn_r(scale_amount, Round::TowardZero);
    let back = rounded.scalbn_r(scale_amount.saturating_neg(), Round::TowardZero);
    let inexact = input.is_finite_non_zero() && !back.bitwise_eq(input);
    let exact_overflow = input.is_finite_non_zero()
        && input.ilogb().saturating_add(scale_amount) > 16_383;
    let exact_underflow = input.is_finite_non_zero()
        && input.ilogb().saturating_add(scale_amount) < -16_382;
    if exact_overflow || (rounded.is_infinite() && input.is_finite_non_zero()) {
        exceptions |= X87_OE | X87_PE;
    } else if (rounded.is_zero() || rounded.is_denormal()) && inexact {
        exceptions |= X87_UE | X87_PE;
    } else if inexact {
        exceptions |= X87_PE;
    }
    let c1 = magnitude_grew(rounded, truncated);
    let unbounded = super::rounding::round_unbounded_extended_bits(
        input.to_bits(),
        scale_amount,
        64,
        Round::TowardZero,
        false,
    );
    let range = if exact_overflow && control_word & (1 << 3) == 0 {
        Some(RegisterRangeResult {
            kind: RegisterRangeKind::Overflow,
            biased_value: super::rounding::encode_biased_ext80(unbounded, -24_576),
            biased_c1: false,
            precision_lost: false,
        })
    } else if exact_underflow && control_word & (1 << 4) == 0 {
        Some(RegisterRangeResult {
            kind: RegisterRangeKind::Underflow,
            biased_value: super::rounding::encode_biased_ext80(unbounded, 24_576),
            biased_c1: false,
            precision_lost: false,
        })
    } else {
        None
    };
    MathResult {
        value: from_apfloat(rounded),
        exceptions: range.map_or(exceptions, |range| range_exception_flags(input_flags, range))
            & X87_EXCEPTION_MASK,
        c1,
        range,
    }
}
