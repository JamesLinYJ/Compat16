use rustc_apfloat::ieee::{Double, Quad, Single, X87DoubleExtended as ApX87};
use rustc_apfloat::{Float, FloatConvert, Round, Status};

use crate::x87_state::Ext80;

use super::X87_EXCEPTION_MASK;
use super::rounding::{self, X87_DE, X87_IE, X87_OE, X87_PE, X87_UE};
use super::{
    decode, from_apfloat, map_status, round_from_control_word, RegisterRangeKind,
    RegisterRangeResult,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BitResult {
    pub bits: u64,
    pub exceptions: u16,
    pub c1: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IntResult {
    pub value: i128,
    pub exceptions: u16,
    pub c1: bool,
}

pub(crate) fn from_f32_bits(bits: u32) -> super::MathResult {
    let source = Single::from_bits(u128::from(bits));
    let mut loses_info = false;
    let converted = source.convert_r(Round::TowardZero, &mut loses_info);
    let denormal = (bits & 0x7f80_0000 == 0) && (bits & 0x007f_ffff != 0);
    super::MathResult {
        value: from_apfloat(converted.value),
        exceptions: (map_status(converted.status) | if denormal { X87_DE } else { 0 })
            & X87_EXCEPTION_MASK,
        c1: false,
        range: None,
    }
}

pub(crate) fn from_f64_bits(bits: u64) -> super::MathResult {
    let source = Double::from_bits(u128::from(bits));
    let mut loses_info = false;
    let converted = source.convert_r(Round::TowardZero, &mut loses_info);
    let denormal = (bits & 0x7ff0_0000_0000_0000 == 0) && (bits & 0x000f_ffff_ffff_ffff != 0);
    super::MathResult {
        value: from_apfloat(converted.value),
        exceptions: (map_status(converted.status) | if denormal { X87_DE } else { 0 })
            & X87_EXCEPTION_MASK,
        c1: false,
        range: None,
    }
}

pub(crate) fn from_i128(value: i128) -> super::MathResult {
    let converted = ApX87::from_i128_r(value, Round::TowardZero);
    super::MathResult {
        value: from_apfloat(converted.value),
        exceptions: map_status(converted.status) & X87_EXCEPTION_MASK,
        c1: false,
        range: None,
    }
}

pub(crate) fn to_f32_bits(value: Ext80, control_word: u16) -> BitResult {
    let (input, flags) = match decode(value) {
        Ok(value) => value,
        Err(flags) => {
            return BitResult {
                bits: 0xffc0_0000,
                exceptions: flags,
                c1: false,
            };
        }
    };
    let mut loses_info = false;
    let truncated: rustc_apfloat::StatusAnd<Single> =
        input.convert_r(Round::TowardZero, &mut loses_info);
    let mut loses_info = false;
    let converted: rustc_apfloat::StatusAnd<Single> =
        input.convert_r(round_from_control_word(control_word), &mut loses_info);
    let mut exceptions = (flags & !X87_DE) | map_status(converted.status);
    let tiny = if input.is_finite_non_zero() {
        let scale = input.ilogb();
        let mut loses_info = false;
        let normalized = input.scalbn(-scale);
        let normalized_rounded: rustc_apfloat::StatusAnd<Single> =
            normalized.convert_r(round_from_control_word(control_word), &mut loses_info);
        !normalized_rounded.value.is_zero()
            && scale.saturating_add(normalized_rounded.value.ilogb()) < -126
    } else {
        false
    };
    // APFloat applies tininess-after-rounding but reports UE only for tiny and
    // inexact results. Intel's unmasked store form also signals exact tiny
    // results, so derive the unbounded rounded exponent before target clamp.
    exceptions &= !X87_UE;
    if tiny && (converted.status.contains(Status::INEXACT) || control_word & (1 << 4) == 0) {
        exceptions |= X87_UE;
    }
    if input.is_finite_non_zero() && input.ilogb() > 127 {
        // APFloat intentionally reports only inexact when directed rounding
        // saturates at the largest finite value. At this point the exact
        // source exponent proves that the unbounded rounded result exceeds
        // the binary32 exponent range.
        exceptions |= X87_OE | X87_PE;
    }
    BitResult {
        bits: converted.value.to_bits() as u64,
        exceptions: exceptions & X87_EXCEPTION_MASK,
        c1: !converted.value.is_nan()
            && !truncated.value.is_nan()
            && converted.value.abs() > truncated.value.abs(),
    }
}

pub(crate) fn to_f64_bits(value: Ext80, control_word: u16) -> BitResult {
    let (input, flags) = match decode(value) {
        Ok(value) => value,
        Err(flags) => {
            return BitResult {
                bits: 0xfff8_0000_0000_0000,
                exceptions: flags,
                c1: false,
            };
        }
    };
    let mut loses_info = false;
    let truncated: rustc_apfloat::StatusAnd<Double> =
        input.convert_r(Round::TowardZero, &mut loses_info);
    let mut loses_info = false;
    let converted: rustc_apfloat::StatusAnd<Double> =
        input.convert_r(round_from_control_word(control_word), &mut loses_info);
    let mut exceptions = (flags & !X87_DE) | map_status(converted.status);
    let tiny = if input.is_finite_non_zero() {
        let scale = input.ilogb();
        let mut loses_info = false;
        let normalized = input.scalbn(-scale);
        let normalized_rounded: rustc_apfloat::StatusAnd<Double> =
            normalized.convert_r(round_from_control_word(control_word), &mut loses_info);
        !normalized_rounded.value.is_zero()
            && scale.saturating_add(normalized_rounded.value.ilogb()) < -1022
    } else {
        false
    };
    // See the binary32 path above. Source Ext80 denormals do not raise DE for
    // FST/FSTP; destination underflow still follows the target format and UM.
    exceptions &= !X87_UE;
    if tiny && (converted.status.contains(Status::INEXACT) || control_word & (1 << 4) == 0) {
        exceptions |= X87_UE;
    }
    if input.is_finite_non_zero() && input.ilogb() > 1023 {
        // See the binary32 path above: directed overflow can saturate without
        // APFloat's Status::OVERFLOW bit, but it still sets x87 OE and PE.
        exceptions |= X87_OE | X87_PE;
    }
    BitResult {
        bits: converted.value.to_bits() as u64,
        exceptions: exceptions & X87_EXCEPTION_MASK,
        c1: !converted.value.is_nan()
            && !truncated.value.is_nan()
            && converted.value.abs() > truncated.value.abs(),
    }
}

/// Convert ST0 to a signed integer. `truncate` implements FISTTP's fixed RC=0.
pub(crate) fn to_i128(value: Ext80, width: usize, control_word: u16, truncate: bool) -> IntResult {
    if !(1..=128).contains(&width) {
        return IntResult {
            value: 0,
            exceptions: X87_IE,
            c1: false,
        };
    }
    let (input, flags) = match decode(value) {
        Ok(value) => value,
        Err(flags) => {
            return IntResult {
                value: min_signed(width),
                exceptions: flags,
                c1: false,
            };
        }
    };
    let round = if truncate {
        Round::TowardZero
    } else {
        round_from_control_word(control_word)
    };
    let toward_zero = input.to_i128_r(width, Round::TowardZero, &mut true);
    let converted = input.to_i128_r(width, round, &mut true);
    let invalid = converted.status.contains(Status::INVALID_OP);
    let result = if invalid {
        min_signed(width)
    } else {
        converted.value
    };
    IntResult {
        value: result,
        exceptions: (flags | map_status(converted.status)) & X87_EXCEPTION_MASK,
        c1: !truncate && !invalid && result.unsigned_abs() > toward_zero.value.unsigned_abs(),
    }
}

/// FIST/FISTP/FISTTP/FBSTP have instruction-specific exception sets without
/// #D. Keep the shared Ext80 classifier for value conversion, then remove its
/// source-class denormal flag at this integer-store instruction boundary.
pub(crate) fn to_i128_for_store(
    value: Ext80,
    width: usize,
    control_word: u16,
    truncate: bool,
) -> IntResult {
    let mut result = to_i128(value, width, control_word, truncate);
    result.exceptions &= !X87_DE;
    result
}

fn min_signed(width: usize) -> i128 {
    if width == 128 {
        i128::MIN
    } else {
        -(1_i128 << (width - 1))
    }
}

/// Widen an x87 value for high-precision transcendental approximations.
pub(crate) fn to_quad(value: Ext80) -> Result<(Quad, u16), u16> {
    let (input, flags) = decode(value)?;
    let mut loses_info = false;
    let converted = input.convert_r(Round::TowardZero, &mut loses_info);
    Ok((converted.value, flags | map_status(converted.status)))
}

/// Round a Quad approximation once into x87 extended precision.
pub(crate) fn from_quad(value: Quad, round: Round) -> (Ext80, u16, bool) {
    let mut loses_info = false;
    let toward_zero = value.convert_r(Round::TowardZero, &mut loses_info);
    let rounded = value.convert_r(round, &mut loses_info);
    let c1 = !rounded.value.is_nan()
        && !toward_zero.value.is_nan()
        && rounded.value.abs() > toward_zero.value.abs();
    (
        from_apfloat(rounded.value),
        map_status(rounded.status) & X87_EXCEPTION_MASK,
        c1,
    )
}

/// Round one Quad approximation with a separately retained binary exponent.
///
/// The internal rustc_apfloat Quad format shares the x87 exponent ceiling and
/// has no out-of-range rounded-result record. This project adapter therefore
/// keeps the Quad significand and exponent adjustment separate until both the
/// masked Ext80 result and any unmasked ±24576-bias register payload exist.
pub(crate) fn from_quad_wide(
    value: Quad,
    exponent_adjust: i32,
    known_inexact: bool,
    control_word: u16,
) -> super::MathResult {
    let round = round_from_control_word(control_word);
    if !value.is_finite_non_zero() {
        let (result, mut exceptions, c1) = from_quad(value, round);
        if known_inexact {
            exceptions |= X87_PE;
        }
        return super::MathResult {
            value: result,
            exceptions: exceptions & X87_EXCEPTION_MASK,
            c1,
            range: None,
        };
    }

    let (rounded, unbounded) = rounding::round_quad_extended_bits(
        value,
        exponent_adjust,
        round,
        known_inexact,
    );
    let mut exceptions = rounded.flags;
    let range = if exceptions & X87_OE != 0 && control_word & (1 << 3) == 0 {
        Some(RegisterRangeResult {
            kind: RegisterRangeKind::Overflow,
            biased_value: rounding::encode_biased_ext80(unbounded, -24_576),
            biased_c1: unbounded.c1,
            precision_lost: unbounded.precision_lost,
        })
    } else if control_word & (1 << 4) == 0
        && unbounded.significand != 0
        && unbounded.exponent < -16_382
    {
        Some(RegisterRangeResult {
            kind: RegisterRangeKind::Underflow,
            biased_value: rounding::encode_biased_ext80(unbounded, 24_576),
            biased_c1: unbounded.c1,
            precision_lost: unbounded.precision_lost,
        })
    } else {
        None
    };
    if let Some(range) = range {
        // The unmasked register form is rounded before exponent biasing. Its
        // precision flag therefore comes from that normal-range result, not
        // from bits discarded only because the masked form became subnormal.
        exceptions = super::range_exception_flags(0, range);
    }
    super::MathResult {
        value: rounded.value,
        exceptions: exceptions & X87_EXCEPTION_MASK,
        c1: rounded.c1,
        range,
    }
}
