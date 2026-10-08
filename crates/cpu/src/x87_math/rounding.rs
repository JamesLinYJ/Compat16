use core::cmp::Ordering;

use rustc_apfloat::{ieee::Quad, Float, Round};

use crate::x87_state::Ext80;

pub(crate) const X87_IE: u16 = 1 << 0;
pub(crate) const X87_DE: u16 = 1 << 1;
pub(crate) const X87_ZE: u16 = 1 << 2;
pub(crate) const X87_OE: u16 = 1 << 3;
pub(crate) const X87_UE: u16 = 1 << 4;
pub(crate) const X87_PE: u16 = 1 << 5;

const MIN_EXP: i32 = -16_382;
const MAX_EXP: i32 = 16_383;
const EXPONENT_BIAS: i32 = 16_383;
const QUAD_FRACTION_BITS: u32 = 112;
const QUAD_SIGNIFICAND_BITS: u32 = QUAD_FRACTION_BITS + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RoundedValue {
    pub value: Ext80,
    pub flags: u16,
    pub c1: bool,
}

/// A precision-controlled significand paired with an unbounded exponent.
/// This is used to form the x87 register result for unmasked range traps before
/// the ordinary Ext80 exponent clamp discards the useful significand.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UnboundedRounded {
    pub significand: u64,
    pub negative: bool,
    pub exponent: i32,
    pub precision_lost: bool,
    pub c1: bool,
}

/// Round a Quad approximation directly to the architectural Ext80 format.
///
/// The exponent adjustment is kept separate from the Quad value so products
/// whose x87 result lies beyond Quad's exponent range can still produce the
/// x87 register-range payload. This adapter is handwritten because
/// rustc_apfloat's conversion API has no extended-exponent intermediate and
/// cannot return both the ordinary subnormal result and the x87 ±24576-bias
/// result from the same 113-bit approximation.
pub(crate) fn round_quad_extended_bits(
    value: Quad,
    exponent_adjust: i32,
    mode: Round,
    extra_inexact: bool,
) -> (RoundedValue, UnboundedRounded) {
    let bits = value.to_bits();
    let negative = bits & (1_u128 << 127) != 0;
    let sign = if negative { 1 << 15 } else { 0 };
    let exponent_field = ((bits >> QUAD_FRACTION_BITS) & 0x7fff) as i32;
    let fraction_mask = (1_u128 << QUAD_FRACTION_BITS) - 1;
    let fraction = bits & fraction_mask;
    if exponent_field == 0x7fff || exponent_field == 0 && fraction == 0 {
        // The format converter handles infinities and NaNs separately. This
        // branch only preserves the zero sign for an exact finite zero.
        let result = Ext80 { significand: 0, sign_exponent: sign };
        return (
            RoundedValue {
                value: result,
                flags: if extra_inexact { X87_PE } else { 0 },
                c1: false,
            },
            UnboundedRounded {
                significand: result.significand,
                negative,
                exponent: MIN_EXP,
                precision_lost: extra_inexact,
                c1: false,
            },
        );
    }

    let (significand, exponent) = if exponent_field == 0 {
        let highest = 127 - fraction.leading_zeros() as i32;
        let shift = (QUAD_FRACTION_BITS as i32 - highest) as u32;
        (
            fraction << shift,
            (1 - EXPONENT_BIAS - shift as i32).saturating_add(exponent_adjust),
        )
    } else {
        (
            (1_u128 << QUAD_FRACTION_BITS) | fraction,
            (exponent_field - EXPONENT_BIAS).saturating_add(exponent_adjust),
        )
    };

    const PRECISION: u32 = 64;
    let precision_drop = QUAD_SIGNIFICAND_BITS - PRECISION;
    let (mut unbounded_significand, mut unbounded_exponent, unbounded_inexact, unbounded_c1) =
        round_quad_significand(significand, exponent, precision_drop, mode, negative, false);
    if unbounded_significand >= (1_u128 << PRECISION) {
        unbounded_significand >>= 1;
        unbounded_exponent = unbounded_exponent.saturating_add(1);
    }
    let unbounded = UnboundedRounded {
        significand: unbounded_significand as u64,
        negative,
        exponent: unbounded_exponent,
        precision_lost: unbounded_inexact || extra_inexact,
        c1: unbounded_c1,
    };

    let subnormal_shift = MIN_EXP.saturating_sub(exponent).max(0) as u32;
    let drop = precision_drop.saturating_add(subnormal_shift);
    let (mut rounded, mut output_exponent, inexact, c1) =
        round_quad_significand(significand, exponent, drop, mode, negative, false);
    let mut flags = if inexact || extra_inexact { X87_PE } else { 0 };
    let output;
    if subnormal_shift != 0 {
        if rounded >= (1_u128 << 63) {
            output = Ext80 {
                significand: 1 << 63,
                sign_exponent: sign | 1,
            };
        } else {
            output = Ext80 {
                significand: rounded as u64,
                sign_exponent: sign,
            };
            if inexact || extra_inexact {
                flags |= X87_UE;
            }
        }
    } else {
        if rounded >= (1_u128 << PRECISION) {
            rounded >>= 1;
            output_exponent = output_exponent.saturating_add(1);
        }
        if output_exponent > MAX_EXP {
            flags |= X87_OE | X87_PE;
            output = if overflow_to_infinity(negative, mode) {
                Ext80 {
                    significand: 1 << 63,
                    sign_exponent: sign | 0x7fff,
                }
            } else {
                Ext80 {
                    significand: u64::MAX,
                    sign_exponent: sign | 0x7ffe,
                }
            };
        } else {
            output = Ext80 {
                significand: rounded as u64,
                sign_exponent: sign | (output_exponent + EXPONENT_BIAS) as u16,
            };
        }
    }

    (
        RoundedValue {
            value: output,
            flags,
            c1,
        },
        unbounded,
    )
}

fn round_quad_significand(
    significand: u128,
    exponent: i32,
    drop: u32,
    mode: Round,
    negative: bool,
    sticky: bool,
) -> (u128, i32, bool, bool) {
    let quotient = if drop >= 128 {
        0
    } else {
        significand >> drop
    };
    let inexact = low_bits_nonzero_u128(significand, drop) || sticky;
    let half = compare_quad_remainder_to_half(significand, drop, sticky);
    let increment = match mode {
        Round::NearestTiesToEven => half.is_gt() || (half.is_eq() && quotient & 1 != 0),
        Round::NearestTiesToAway => half.is_ge(),
        Round::TowardPositive => !negative && inexact,
        Round::TowardNegative => negative && inexact,
        Round::TowardZero => false,
    };
    (quotient + u128::from(increment), exponent, inexact, increment)
}

fn low_bits_nonzero_u128(value: u128, count: u32) -> bool {
    match count {
        0 => false,
        1..=127 => value & ((1_u128 << count) - 1) != 0,
        _ => value != 0,
    }
}

fn compare_quad_remainder_to_half(value: u128, drop: u32, sticky: bool) -> Ordering {
    if drop == 0 || drop > 128 {
        return Ordering::Less;
    }
    let guard = value & (1_u128 << (drop - 1)) != 0;
    if !guard {
        return Ordering::Less;
    }
    if low_bits_nonzero_u128(value, drop - 1) || sticky {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}

pub(crate) fn round_from_control_word(control_word: u16) -> Round {
    match (control_word >> 10) & 3 {
        0 => Round::NearestTiesToEven,
        1 => Round::TowardNegative,
        2 => Round::TowardPositive,
        _ => Round::TowardZero,
    }
}

pub(crate) fn precision_bits(control_word: u16) -> u32 {
    match (control_word >> 8) & 3 {
        0 => 24,
        2 => 53,
        _ => 64,
    }
}

pub(crate) fn map_status(status: rustc_apfloat::Status) -> u16 {
    let mut flags = 0;
    if status.contains(rustc_apfloat::Status::INVALID_OP) {
        flags |= X87_IE;
    }
    if status.contains(rustc_apfloat::Status::DIV_BY_ZERO) {
        flags |= X87_ZE;
    }
    if status.contains(rustc_apfloat::Status::OVERFLOW) {
        flags |= X87_OE;
    }
    if status.contains(rustc_apfloat::Status::UNDERFLOW) {
        flags |= X87_UE;
    }
    if status.contains(rustc_apfloat::Status::INEXACT) {
        flags |= X87_PE;
    }
    flags
}

/// Round an APFloat x87 result that was first computed toward zero at 64 bits.
/// `exponent_adjust` removes exact power-of-two scaling used to keep APFloat's
/// intermediate away from its subnormal boundary.
pub(crate) fn round_extended_bits(
    bits: u128,
    exponent_adjust: i32,
    precision: u32,
    mode: Round,
    sticky: bool,
    ap_overflow: bool,
) -> RoundedValue {
    let sign = bits & (1_u128 << 79) != 0;
    let sign_exponent = ((bits >> 64) & 0xffff) as u16;
    let exponent_field = i32::from(sign_exponent & 0x7fff);
    let mut significand = bits as u64;

    if exponent_field == 0x7fff || (exponent_field == 0 && significand == 0) {
        return RoundedValue {
            value: Ext80 {
                significand,
                sign_exponent,
            },
            flags: if ap_overflow { X87_OE | X87_PE } else { 0 },
            c1: false,
        };
    }

    let exponent = if exponent_field == 0 {
        let highest = 63 - significand.leading_zeros() as i32;
        let normalize_shift = (63 - highest) as u32;
        significand <<= normalize_shift;
        MIN_EXP - normalize_shift as i32
    } else {
        exponent_field - EXPONENT_BIAS
    };
    let exponent = exponent + exponent_adjust;
    let subnormal_shift = (MIN_EXP - exponent).max(0) as u32;
    let precision_drop = 64 - precision;
    let drop = subnormal_shift.saturating_add(precision_drop);

    let quotient = if drop >= 128 {
        0
    } else {
        u128::from(significand) >> drop
    };
    let discarded_bits = low_bits_nonzero(significand, drop);
    let inexact = discarded_bits || sticky;
    let half_cmp = compare_remainder_to_half(significand, drop, sticky);
    let increment = match mode {
        Round::NearestTiesToEven => half_cmp.is_gt() || (half_cmp.is_eq() && quotient & 1 != 0),
        Round::TowardPositive => !sign && inexact,
        Round::TowardNegative => sign && inexact,
        Round::TowardZero | Round::NearestTiesToAway => false,
    };
    let mut rounded = quotient + u128::from(increment);
    let limit = 1_u128 << precision;
    let mut output_exponent = exponent;
    let mut flags = if inexact { X87_PE } else { 0 };
    let output;

    if subnormal_shift != 0 {
        let denormal_significand = rounded << precision_drop;
        if denormal_significand >= (1_u128 << 63) {
            output = Ext80 {
                significand: 1 << 63,
                sign_exponent: (if sign { 1 << 15 } else { 0 }) | 1,
            };
        } else {
            output = Ext80 {
                significand: denormal_significand as u64,
                sign_exponent: if sign { 1 << 15 } else { 0 },
            };
            if inexact {
                flags |= X87_UE;
            }
        }
    } else {
        let max_significand = limit - 1;
        let carry = rounded >= limit;
        if carry {
            rounded >>= 1;
            output_exponent += 1;
        }
        // The exact value can be a little larger than max finite and still
        // round back to max finite. IEEE overflow is raised only when the
        // rounded result with unbounded exponent exceeds the destination
        // range, so do not infer overflow from a discarded tail alone.
        let overflow = ap_overflow || output_exponent > MAX_EXP;
        if overflow {
            flags |= X87_OE | X87_PE;
            if overflow_to_infinity(sign, mode) {
                output = Ext80 {
                    significand: 1 << 63,
                    sign_exponent: (if sign { 1 << 15 } else { 0 }) | 0x7fff,
                };
            } else {
                output = Ext80 {
                    significand: (max_significand << (64 - precision)) as u64,
                    sign_exponent: (if sign { 1 << 15 } else { 0 }) | 0x7ffe,
                };
            }
        } else {
            output = Ext80 {
                significand: (rounded << (64 - precision)) as u64,
                sign_exponent: (if sign { 1 << 15 } else { 0 })
                    | (output_exponent + EXPONENT_BIAS) as u16,
            };
        }
    }

    RoundedValue {
        value: output,
        flags,
        c1: increment,
    }
}

/// Round a normalized significand while retaining its exponent outside the
/// Ext80 range. For PC=64 callers must pass a value already rounded by APFloat
/// in the requested mode, with `sticky=false`; APFloat's status then carries
/// the precision-loss indication. For reduced PC, the APFloat value is first
/// computed toward zero and `sticky` supplies its discarded tail.
pub(crate) fn round_unbounded_extended_bits(
    bits: u128,
    exponent_adjust: i32,
    precision: u32,
    mode: Round,
    sticky: bool,
) -> UnboundedRounded {
    let negative = bits & (1_u128 << 79) != 0;
    let sign_exponent = ((bits >> 64) & 0xffff) as u16;
    let exponent_field = i32::from(sign_exponent & 0x7fff);
    let mut significand = bits as u64;

    let mut exponent = if exponent_field == 0 {
        if significand == 0 {
            return UnboundedRounded {
                significand: 0,
                negative,
                exponent: MIN_EXP,
                precision_lost: sticky,
                c1: false,
            };
        }
        let highest = 63 - significand.leading_zeros() as i32;
        let normalize_shift = (63 - highest) as u32;
        significand <<= normalize_shift;
        MIN_EXP - normalize_shift as i32
    } else {
        exponent_field - EXPONENT_BIAS
    };
    exponent = exponent.saturating_add(exponent_adjust);

    let precision_drop = 64 - precision;
    let quotient = u128::from(significand) >> precision_drop;
    let discarded = low_bits_nonzero(significand, precision_drop);
    let precision_lost = discarded || sticky;
    let half_cmp = compare_remainder_to_half(significand, precision_drop, sticky);
    let increment = match mode {
        Round::NearestTiesToEven => {
            half_cmp.is_gt() || (half_cmp.is_eq() && quotient & 1 != 0)
        }
        Round::TowardPositive => !negative && precision_lost,
        Round::TowardNegative => negative && precision_lost,
        Round::TowardZero | Round::NearestTiesToAway => false,
    };
    let mut rounded = quotient + u128::from(increment);
    let limit = 1_u128 << precision;
    if rounded >= limit {
        rounded >>= 1;
        exponent = exponent.saturating_add(1);
    }

    UnboundedRounded {
        significand: (rounded << precision_drop) as u64,
        negative,
        exponent,
        precision_lost,
        c1: increment,
    }
}

/// Apply an x87 range-exception exponent bias to an unbounded rounded result.
/// Ext80's post-bias massive-range cases become signed infinity or signed zero.
pub(crate) fn encode_biased_ext80(value: UnboundedRounded, exponent_bias: i32) -> Ext80 {
    let sign = if value.negative { 1 << 15 } else { 0 };
    let exponent = value.exponent.saturating_add(exponent_bias);
    if value.significand == 0 || exponent < MIN_EXP {
        return Ext80 {
            significand: 0,
            sign_exponent: sign,
        };
    }
    if exponent > MAX_EXP {
        return Ext80 {
            significand: 1 << 63,
            sign_exponent: sign | 0x7fff,
        };
    }
    Ext80 {
        significand: value.significand,
        sign_exponent: sign | (exponent + EXPONENT_BIAS) as u16,
    }
}

fn low_bits_nonzero(value: u64, count: u32) -> bool {
    match count {
        0 => false,
        1..=63 => value & ((1_u64 << count) - 1) != 0,
        _ => value != 0,
    }
}

fn compare_remainder_to_half(value: u64, drop: u32, sticky: bool) -> core::cmp::Ordering {
    if drop == 0 || drop > 64 {
        return core::cmp::Ordering::Less;
    }
    let guard = (value >> (drop - 1)) & 1 != 0;
    if !guard {
        return core::cmp::Ordering::Less;
    }
    let lower = low_bits_nonzero(value, drop - 1);
    if lower || sticky {
        core::cmp::Ordering::Greater
    } else {
        core::cmp::Ordering::Equal
    }
}

fn overflow_to_infinity(sign: bool, mode: Round) -> bool {
    match mode {
        Round::NearestTiesToEven | Round::NearestTiesToAway => true,
        Round::TowardPositive => !sign,
        Round::TowardNegative => sign,
        Round::TowardZero => false,
    }
}
