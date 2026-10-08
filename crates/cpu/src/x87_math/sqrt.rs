use rustc_apfloat::{Float, Round};

use crate::x87_state::Ext80;

use super::rounding::{X87_IE, X87_PE, precision_bits, round_from_control_word};
use super::{MathResult, decode, from_apfloat, indefinite};

const MIN_EXP: i32 = -16_382;
const EXPONENT_BIAS: i32 = 16_383;

/// Compute x87 square root using a 128-bit integer radicand and exact remainder.
/// This avoids host floating-point behavior and provides guard/sticky data for
/// each x87 rounding mode and precision-control setting.
pub(crate) fn sqrt(value: Ext80, control_word: u16) -> MathResult {
    let (input, mut exceptions) = match decode(value) {
        Ok(value) => value,
        Err(flags) => {
            return MathResult {
                value: indefinite(),
                exceptions: flags,
                c1: false,
                range: None,
            };
        }
    };
    if input.is_nan() {
        let quieted = input.add_r(
            rustc_apfloat::ieee::X87DoubleExtended::ZERO,
            round_from_control_word(control_word),
        );
        exceptions |= super::map_status(quieted.status);
        return MathResult {
            value: from_apfloat(quieted.value),
            exceptions,
            c1: false,
            range: None,
        };
    }
    if input.is_zero() {
        return MathResult {
            value: from_apfloat(input),
            exceptions,
            c1: false,
            range: None,
        };
    }
    if input.is_negative() {
        return MathResult {
            value: indefinite(),
            // An invalid arithmetic result outranks a denormal source flag.
            exceptions: super::prioritize_operand_exceptions(&[value], exceptions | X87_IE),
            c1: false,
            range: None,
        };
    }
    if input.is_infinite() {
        return MathResult {
            value: from_apfloat(input),
            exceptions,
            c1: false,
            range: None,
        };
    }

    let bits = input.to_bits();
    let exponent_field = ((bits >> 64) & 0x7fff) as i32;
    let mut significand = bits as u64;
    let exponent = if exponent_field == 0 {
        let highest = 63 - significand.leading_zeros() as i32;
        significand <<= (63 - highest) as u32;
        MIN_EXP - (63 - highest)
    } else {
        exponent_field - EXPONENT_BIAS
    };
    let odd_exponent = exponent.rem_euclid(2) != 0;
    let radicand = u128::from(significand) << if odd_exponent { 64 } else { 63 };
    let root = integer_sqrt(radicand) as u64;
    let root_wide = u128::from(root);
    let remainder = radicand - root_wide * root_wide;
    let mut result_exponent = exponent.div_euclid(2);
    let precision = precision_bits(control_word);
    let drop = 64 - precision;
    let quotient = u128::from(root) >> drop;
    let discarded = low_bits_nonzero(root, drop) || remainder != 0;
    let half_cmp = compare_remainder_to_half(root, drop, remainder);
    let increment = match round_from_control_word(control_word) {
        Round::NearestTiesToEven => half_cmp.is_gt() || (half_cmp.is_eq() && quotient & 1 != 0),
        Round::TowardPositive => discarded,
        Round::TowardNegative | Round::TowardZero => false,
        Round::NearestTiesToAway => half_cmp.is_ge(),
    };
    let mut rounded = quotient + u128::from(increment);
    let limit = 1_u128 << precision;
    if rounded >= limit {
        rounded >>= 1;
        result_exponent += 1;
    }
    if discarded {
        exceptions |= X87_PE;
    }
    exceptions &= 0x003f;
    MathResult {
        value: Ext80 {
            significand: (rounded << drop) as u64,
            sign_exponent: (result_exponent + EXPONENT_BIAS) as u16,
        },
        exceptions,
        c1: increment,
        range: None,
    }
}

fn integer_sqrt(mut value: u128) -> u128 {
    let mut result = 0_u128;
    let mut bit = 1_u128 << 126;
    while bit > value {
        bit >>= 2;
    }
    while bit != 0 {
        if value >= result + bit {
            value -= result + bit;
            result = (result >> 1) + bit;
        } else {
            result >>= 1;
        }
        bit >>= 2;
    }
    result
}

fn low_bits_nonzero(value: u64, count: u32) -> bool {
    match count {
        0 => false,
        1..=63 => value & ((1_u64 << count) - 1) != 0,
        _ => value != 0,
    }
}

fn compare_remainder_to_half(root: u64, drop: u32, square_remainder: u128) -> core::cmp::Ordering {
    use core::cmp::Ordering;
    if drop == 0 {
        // For integer radicands, sqrt(N) cannot be exactly half-integral.
        // The exact comparison is N - floor(sqrt(N))^2 > floor(sqrt(N)).
        return if square_remainder > u128::from(root) {
            Ordering::Greater
        } else {
            Ordering::Less
        };
    }
    let guard = (root >> (drop - 1)) & 1 != 0;
    if !guard {
        Ordering::Less
    } else if low_bits_nonzero(root, drop - 1) || square_remainder != 0 {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}
