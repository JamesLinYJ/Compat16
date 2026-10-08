use rustc_apfloat::ieee::Quad;
use rustc_apfloat::Float;

use crate::x87_state::Ext80;

use super::payne_hanek;

const PI_BITS: u128 = 0x4000_921f_b544_42d1_8469_898c_c517_01b8;
const LN2_BITS: u128 = 0x3ffe_62e4_2fef_a39e_f357_93c7_6730_07e5;

fn pi_value() -> Quad {
    Quad::from_bits(PI_BITS)
}

fn ln2() -> Quad {
    Quad::from_bits(LN2_BITS)
}

fn integer(value: i128) -> Quad {
    Quad::from_i128(value).value
}

pub(crate) fn add(left: Quad, right: Quad) -> Quad {
    (left + right).value
}

pub(crate) fn sub(left: Quad, right: Quad) -> Quad {
    (left - right).value
}

fn mul(left: Quad, right: Quad) -> Quad {
    (left * right).value
}

fn div(left: Quad, right: Quad) -> Quad {
    (left / right).value
}

/// Approximate 2^x-1 on x in [-1,1] with an expm1 Taylor recurrence.
/// The recurrence avoids subtractive cancellation near zero. At |x|<=1,
/// forty terms leave a tail far below Quad's 113-bit significand.
pub(crate) fn exp2m1(x: Quad) -> Quad {
    let z = mul(x, ln2());
    if z.is_zero() {
        return z;
    }
    let mut term = z;
    let mut sum = z;
    for n in 2..=48_i128 {
        term = div(mul(term, z), integer(n));
        let next = add(sum, term);
        if next.bitwise_eq(sum) {
            break;
        }
        sum = next;
    }
    sum
}

/// Compute log2(x) for positive finite x. The mantissa is scaled into
/// [3/4,3/2], keeping the atanh-series argument within 1/5. `exact` is true
/// precisely for powers of two; all other positive finite inputs have an
/// irrational base-2 logarithm.
pub(crate) fn log2_positive(x: Quad) -> (Quad, bool) {
    let mut exponent = x.ilogb();
    let mut mantissa = x.scalbn(-exponent);
    let three_halves = integer(3).scalbn(-1);
    if mantissa > three_halves {
        mantissa = mantissa.scalbn(-1);
        exponent += 1;
    }

    let z = div(sub(mantissa, Quad::from_bits(0x3fff_0000_0000_0000_0000_0000_0000_0000)),
        add(mantissa, Quad::from_bits(0x3fff_0000_0000_0000_0000_0000_0000_0000)));
    let exact = z.is_zero();
    if exact {
        return (integer(i128::from(exponent)), true);
    }

    let z2 = mul(z, z);
    let mut power = z;
    let mut sum = z;
    for k in 1..=80_i128 {
        power = mul(power, z2);
        let term = div(power, integer(2 * k + 1));
        let next = add(sum, term);
        if next.bitwise_eq(sum) {
            break;
        }
        sum = next;
    }
    let log_mantissa = mul(integer(2), sum);
    let fractional = div(log_mantissa, ln2());
    (add(integer(i128::from(exponent)), fractional), false)
}

/// Stable log2(1+x) for -1/2 <= x <= 1/2. Using
/// `u=x/(x+2)` retains tiny x even when `1+x` rounds to one in Quad.
pub(crate) fn log2_one_plus(x: Quad) -> (Quad, bool) {
    if x.is_zero() {
        // Preserve log1p's signed-zero identity; the following multiplication
        // in FYL2XP1 uses this sign for zero/infinity combinations.
        return (if x.is_negative() { -Quad::ZERO } else { Quad::ZERO }, true);
    }
    let u = div(x, add(x, integer(2)));
    let u2 = mul(u, u);
    let mut power = u;
    let mut sum = u;
    for k in 1..=80_i128 {
        power = mul(power, u2);
        let term = div(power, integer(2 * k + 1));
        let next = add(sum, term);
        if next.bitwise_eq(sum) {
            break;
        }
        sum = next;
    }
    (div(mul(integer(2), sum), ln2()), false)
}

/// Return sin(x), cos(x) for a finite x in the architectural range.
/// `magnitude` is the positive raw encoding; the input sign is applied here.
pub(crate) fn sin_cos(magnitude: Ext80, value: Quad, negative: bool) -> (Quad, Quad) {
    let (quadrant, reduced) = if magnitude.sign_exponent & 0x7fff < 0x3fff {
        (0, value)
    } else {
        payne_hanek::reduce(magnitude)
    };
    let (sin_r, cos_r) = sin_cos_small(reduced);
    let (mut sine, cosine) = match quadrant & 3 {
        0 => (sin_r, cos_r),
        1 => (cos_r, -sin_r),
        2 => (-sin_r, -cos_r),
        _ => (-cos_r, sin_r),
    };
    if negative {
        sine = -sine;
    }
    (sine, cosine)
}

pub(crate) fn sin_cos_small(x: Quad) -> (Quad, Quad) {
    let x2 = mul(x, x);
    let mut sin_term = x;
    let mut sine = x;
    let mut cos_term = Quad::from_bits(0x3fff_0000_0000_0000_0000_0000_0000_0000);
    let mut cosine = cos_term;

    for n in 1..=32_i128 {
        let s_denominator = integer((2 * n) * (2 * n + 1));
        sin_term = -div(mul(sin_term, x2), s_denominator);
        let next_sine = add(sine, sin_term);
        let sine_done = next_sine.bitwise_eq(sine);
        sine = next_sine;

        let c_denominator = integer((2 * n - 1) * (2 * n));
        cos_term = -div(mul(cos_term, x2), c_denominator);
        let next_cosine = add(cosine, cos_term);
        let cosine_done = next_cosine.bitwise_eq(cosine);
        cosine = next_cosine;
        if sine_done && cosine_done {
            break;
        }
    }
    (sine, cosine)
}

/// atan(t) for |t|<=1, reducing values above 1/2 around pi/4 before the
/// alternating series. The largest series argument is 1/2, so 112 terms are
/// more than sufficient for Quad precision.
pub(crate) fn atan_unit(t: Quad) -> Quad {
    let half = integer(1).scalbn(-1);
    if t.abs() > half {
        let reduced = div(sub(t, integer(1)), add(t, integer(1)));
        add(div(pi_value(), integer(4)), atan_series(reduced))
    } else {
        atan_series(t)
    }
}

fn atan_series(x: Quad) -> Quad {
    let x2 = mul(x, x);
    let mut power = x;
    let mut sum = x;
    for n in 1..=128_i128 {
        power = mul(power, x2);
        let term = div(power, integer(2 * n + 1));
        let next = if n & 1 == 0 { add(sum, term) } else { sub(sum, term) };
        if next.bitwise_eq(sum) {
            break;
        }
        sum = next;
    }
    sum
}

pub(crate) fn pi() -> Quad {
    pi_value()
}

pub(crate) fn one() -> Quad {
    Quad::from_bits(0x3fff_0000_0000_0000_0000_0000_0000_0000)
}
