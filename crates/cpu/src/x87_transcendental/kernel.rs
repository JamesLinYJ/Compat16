//! Table-assisted binary128 minimax kernels with fused polynomial evaluation.
//!
//! Fits and certified polynomial errors are recorded beside the coefficient
//! data. The actual instruction result also includes reduction, evaluation,
//! and Ext80 rounding error; those are not covered by the polynomial bound.

use rustc_apfloat::{Float, Round, ieee::Quad};

use crate::x87_state::Ext80;

use super::{coefficients, payne_hanek};

const ONE_BITS: u128 = 0x3fff_0000_0000_0000_0000_0000_0000_0000;
const PI_BITS: u128 = 0x4000_921f_b544_42d1_8469_898c_c517_01b8;
const CELL_BITS: i32 = 5; // Centers are spaced by 1/32.
// Binary128 has 113 significand bits. Below these exponents the omitted
// relative correction is <2^-119: cubic for odd functions, quadratic for
// cosine, and quadratic/linear for expm1. Instruction retirement still owns
// the strict directional inequalities when an approximation equals its input.
const ODD_LINEAR_MAX_EXPONENT: i32 = -60;
const EXP_LINEAR_MAX_EXPONENT: i32 = -120;

pub(crate) fn one() -> Quad {
    Quad::from_bits(ONE_BITS)
}

pub(crate) fn pi() -> Quad {
    Quad::from_bits(PI_BITS)
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

fn inverse_ln2() -> Quad {
    Quad::from_bits(coefficients::INV_LN2[0])
}

/// Each software FMA rounds once to binary128, independent of the host FPU.
/// APFloat provides arithmetic but no transcendental functions, so these
/// bounded-domain polynomials and reductions belong to the instruction layer.
fn polynomial<const N: usize>(x: Quad, coefficients: &[u128; N]) -> Quad {
    let mut value = Quad::from_bits(coefficients[N - 1]);
    for &coefficient in coefficients[..N - 1].iter().rev() {
        value = value.mul_add(x, Quad::from_bits(coefficient)).value;
    }
    value
}

/// The caller has already bounded the scaled positive argument to [0,32].
/// Nearest/even cell selection gives a residual distance of at most 1/64.
fn nearest_cell(scaled: Quad) -> usize {
    let mut exact = false;
    scaled
        .to_u128_r(CELL_BITS as usize + 1, Round::NearestTiesToEven, &mut exact)
        .value as usize
}

/// F2XM1: approximate on [-1/4,1/4], then apply expm1(2a)=u*(u+2)
/// twice. FMA performs each reconstruction without subtracting nearly equal
/// values. The linear tiny path differs by less than binary128 guard precision.
pub(crate) fn exp2m1(x: Quad) -> (Quad, i32) {
    if x.is_zero() {
        return (x, 0);
    }
    let exponent = x.abs().ilogb();
    if exponent <= EXP_LINEAR_MAX_EXPONENT {
        // Keep guard bits for the unmasked-underflow biased register result,
        // even when the eventual masked result is an Ext80 subnormal or zero.
        return (
            mul(x.scalbn(-exponent), Quad::from_bits(coefficients::EXP[0])),
            exponent,
        );
    }
    let reduced = x.scalbn(-2);
    let mut value = mul(reduced, polynomial(reduced, &coefficients::EXP));
    for _ in 0..2 {
        value = value.mul_add(value, value.scalbn(1)).value;
    }
    (value, 0)
}

/// Positive finite x is normalized to [1,2). A nearest dyadic center c leaves
/// u=(m-c)/(m+c) with |u|<=1/128. The identity ln(m/c)=2*atanh(u)
/// avoids loss of small residuals, and powers of two keep their exact result.
pub(crate) fn log2_positive(x: Quad) -> (Quad, bool) {
    let exponent = x.ilogb();
    let mantissa = x.scalbn(-exponent);
    let integral = Quad::from_i128(i128::from(exponent)).value;
    if mantissa.bitwise_eq(one()) {
        return (integral, true);
    }
    let index = nearest_cell(sub(mantissa, one()).scalbn(CELL_BITS));
    let center = add(
        one(),
        Quad::from_u128(index as u128).value.scalbn(-CELL_BITS),
    );
    let residual = div(sub(mantissa, center), add(mantissa, center));
    let correction = mul(atanh_small(residual), inverse_ln2().scalbn(1));
    let base = add(integral, Quad::from_bits(coefficients::LOG_CENTERS[index]));
    (add(base, correction), false)
}

/// Return a logarithm significand, separate scale, and exactness. Normalize
/// extremely tiny x before x/ln(2): rounding a subnormal intermediate can
/// discard guard bits that a later multiplication by large y would expose.
/// Outside |x|<=1/128, forming 1+x loses at most about seven guard bits.
pub(crate) fn log2_one_plus(x: Quad) -> (Quad, i32, bool) {
    if x.is_zero() {
        return (x, 0, true);
    }
    let exponent = x.abs().ilogb();
    if exponent <= EXP_LINEAR_MAX_EXPONENT {
        return (mul(x.scalbn(-exponent), inverse_ln2()), exponent, false);
    }
    if x.abs() <= one().scalbn(-7) {
        let residual = div(x, add(x, one().scalbn(1)));
        return (
            mul(atanh_small(residual), inverse_ln2().scalbn(1)),
            0,
            false,
        );
    }
    let (value, exact) = log2_positive(add(one(), x));
    (value, 0, exact)
}

fn atanh_small(x: Quad) -> Quad {
    if x.is_zero() || x.abs().ilogb() <= ODD_LINEAR_MAX_EXPONENT {
        return x;
    }
    mul(x, polynomial(mul(x, x), &coefficients::ATANH))
}

/// Payne-Hanek leaves a remainder in [-pi/4,pi/4]. The direct path is limited
/// to that same interval, so the minimax kernels always use their fitted domain.
pub(crate) fn sin_cos(magnitude: Ext80, value: Quad, negative: bool) -> (Quad, Quad) {
    let (quadrant, reduced) = reduce_angle(magnitude, value);
    let (sin_r, cos_r) = sin_cos_small(reduced);
    let (sine, cosine) = match quadrant {
        0 => (sin_r, cos_r),
        1 => (cos_r, -sin_r),
        2 => (-sin_r, -cos_r),
        _ => (-cos_r, sin_r),
    };
    (if negative { -sine } else { sine }, cosine)
}

fn reduce_angle(magnitude: Ext80, value: Quad) -> (u8, Quad) {
    if value <= pi().scalbn(-2) {
        (0, value)
    } else {
        payne_hanek::reduce(magnitude)
    }
}

pub(crate) fn sin(magnitude: Ext80, value: Quad, negative: bool) -> Quad {
    single_trig(magnitude, value, negative, false)
}

pub(crate) fn cos(magnitude: Ext80, value: Quad) -> Quad {
    single_trig(magnitude, value, false, true)
}

/// A scalar instruction needs only one reduced polynomial. Odd quadrants
/// exchange sine and cosine, while the original reduction and coefficient
/// evaluation order remain identical to the paired instruction path.
fn single_trig(magnitude: Ext80, value: Quad, negative: bool, cosine: bool) -> Quad {
    let (quadrant, reduced) = reduce_angle(magnitude, value);
    let use_cosine = (quadrant & 1 != 0) ^ cosine;
    let tiny = reduced.is_zero() || reduced.abs().ilogb() <= ODD_LINEAR_MAX_EXPONENT;
    let result = if tiny {
        if use_cosine { one() } else { reduced }
    } else {
        let squared = mul(reduced, reduced);
        if use_cosine {
            polynomial(squared, &coefficients::COS)
        } else {
            mul(reduced, polynomial(squared, &coefficients::SIN))
        }
    };
    let quadrant_negative = if cosine {
        matches!(quadrant, 1 | 2)
    } else {
        quadrant & 2 != 0
    };
    if negative ^ quadrant_negative { -result } else { result }
}

pub(crate) fn sin_cos_small(x: Quad) -> (Quad, Quad) {
    if x.is_zero() || x.abs().ilogb() <= ODD_LINEAR_MAX_EXPONENT {
        // sin(x)-x and cos(x)-1 are below binary128's useful precision;
        // the instruction retirement layer retains their directed-rounding sides.
        return (x, one());
    }
    let squared = mul(x, x);
    (
        mul(x, polynomial(squared, &coefficients::SIN)),
        polynomial(squared, &coefficients::COS),
    )
}

/// For |t|<=1, atan(t)=atan(c)+atan((t-c)/(1+c*t)) with c=k/32.
/// The residual is bounded by 1/64, allowing an odd degree-17 minimax fit
/// instead of a long alternating series. The table retains binary128 precision.
pub(crate) fn atan_unit(t: Quad) -> Quad {
    let magnitude = t.abs();
    let index = nearest_cell(magnitude.scalbn(CELL_BITS));
    let center = Quad::from_u128(index as u128).value.scalbn(-CELL_BITS);
    let denominator = center.mul_add(magnitude, one()).value;
    let residual = div(sub(magnitude, center), denominator);
    let correction = if residual.is_zero() || residual.abs().ilogb() <= ODD_LINEAR_MAX_EXPONENT {
        residual
    } else {
        mul(
            residual,
            polynomial(mul(residual, residual), &coefficients::ATAN),
        )
    };
    let value = add(
        Quad::from_bits(coefficients::ATAN_CENTERS[index]),
        correction,
    );
    if t.is_negative() { -value } else { value }
}
