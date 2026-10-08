use rustc_apfloat::ieee::Quad;
use rustc_apfloat::{Float, Round};

use crate::x87_math;
use crate::x87_state::{Ext80, X87State};

use super::kernel;
use super::status;
use super::value::{self, Number};

pub(super) fn fpatan(state: &mut X87State) -> bool {
    let Some(x_raw) = crate::x87::read_st(state, 0) else { return true; };
    let Some(y_raw) = crate::x87::read_st(state, 1) else { return true; };
    let Some((x, y)) = status::inputs(state, x_raw, y_raw) else { return true; };
    if let Some(nan) = value::propagated_nan(&[x, y]) {
        finish(state, plain_result(nan, 0));
        return true;
    }

    let exact_tiny_power_two = exact_tiny_power_two_ratio(x_raw, y_raw);
    let (result, exponent_adjust, known_inexact) = atan2(x, y);
    let result = if let Some(value) = result {
        let mut result = status::round_quad_scaled(state, value, exponent_adjust, known_inexact);
        if let Some(negative) = exact_tiny_power_two {
            let round = x87_math::round_from_control_word(state.control_word);
            let rounds_toward_zero = matches!(round, Round::TowardZero)
                || matches!(round, Round::TowardNegative) && !negative
                || matches!(round, Round::TowardPositive) && negative;
            if rounds_toward_zero {
                // For a tiny ratio, atan(|r|) is strictly below |r|. The
                // power-of-two input check proves that `value` encodes the
                // exact ratio, so directed rounding toward zero selects its
                // canonical predecessor; generic Quad quotients remain in the
                // documented hard-to-round coverage gap.
                let predecessor = super::unary::next_toward_zero(result.value);
                super::unary::set_strict_neighbor(
                    &mut result,
                    predecessor,
                    false,
                    Some(false),
                    state.control_word,
                );
            } else {
                // Nearest and directed-away rounding select the exact ratio;
                // the strict magnitude inequality makes this a round-up in
                // the x87 significand/C1 convention.
                result.c1 = true;
                if let Some(range) = &mut result.range {
                    range.biased_c1 = true;
                }
            }
            result.exceptions |= super::value::PE;
        }
        result
    } else {
        plain_result(crate::x87::indefinite(), super::value::IE)
    };
    finish(state, result);
    true
}

fn exact_tiny_power_two_ratio(x: Ext80, y: Ext80) -> Option<bool> {
    let x_exponent = i32::from(x.sign_exponent & 0x7fff);
    let y_exponent = i32::from(y.sign_exponent & 0x7fff);
    let x_is_power_of_two = x.significand == 1 << 63 && (1..0x7fff).contains(&x_exponent);
    let y_is_power_of_two = y.significand == 1 << 63 && (1..0x7fff).contains(&y_exponent);
    if x.sign_exponent & 0x8000 != 0
        || !x_is_power_of_two
        || !y_is_power_of_two
        || y_exponent - x_exponent > -120
        // Below the least Ext80 subnormal, the ordinary rounded result can
        // be zero; this local neighbor proof is limited to representable r.
        || y_exponent - x_exponent < -16_445
    {
        return None;
    }
    Some(y.sign_exponent & 0x8000 != 0)
}

/// Return atan2(y,x) as a Quad significand plus a separately retained binary
/// exponent. This keeps very small finite ratios alive for x87 underflow and
/// unmasked-result exponent biasing.
fn atan2(x: super::value::Decoded, y: super::value::Decoded) -> (Option<Quad>, i32, bool) {
    let x_negative = number_sign(x.number);
    let y_negative = number_sign(y.number);
    match (x.number, y.number) {
        (Number::Unsupported, _) | (_, Number::Unsupported) => return (None, 0, false),
        (Number::NaN { .. }, _) | (_, Number::NaN { .. }) => return (None, 0, false),
        (Number::Infinity { .. }, Number::Infinity { .. }) => {
            let quarter = kernel::pi().scalbn(-2);
            let acute = if x_negative { kernel::sub(kernel::pi(), quarter) } else { quarter };
            return (Some(if y_negative { -acute } else { acute }), 0, true);
        }
        (Number::Infinity { .. }, Number::Finite(_)) => {
            if x_negative {
                let angle = kernel::pi();
                return (Some(if y_negative { -angle } else { angle }), 0, true);
            }
            return (Some(signed_zero(y_negative)), 0, false);
        }
        (Number::Finite(_), Number::Infinity { .. }) => {
            return (Some(if y_negative { -kernel::pi().scalbn(-1) } else { kernel::pi().scalbn(-1) }), 0, true);
        }
        (Number::Finite(x_value), Number::Finite(y_value)) => {
            let x_zero = x_value.is_zero();
            let y_zero = y_value.is_zero();
            if y_zero {
                if x_negative {
                    let pi = if y_negative { -kernel::pi() } else { kernel::pi() };
                    return (Some(pi), 0, true);
                }
                return (Some(signed_zero(y_negative)), 0, false);
            }
            if x_zero {
                let half_pi = kernel::pi().scalbn(-1);
                return (Some(if y_negative { -half_pi } else { half_pi }), 0, true);
            }

            let (acute, tiny_ratio) = acute_angle(x_value.abs(), y_value.abs());
            if let Some((ratio, exponent_adjust)) = tiny_ratio {
                if x_negative {
                    // pi - tiny is near pi, not subnormal; Quad cannot retain
                    // such an extreme low-order correction. The ordinary
                    // Quad pi approximation is the bounded result here; the
                    // correct final RC choice remains a numerical unknown for
                    // hard-to-round pi boundaries.
                    let pi = kernel::pi();
                    return (Some(if y_negative { -pi } else { pi }), 0, true);
                }
                return (Some(if y_negative { -ratio } else { ratio }), exponent_adjust, true);
            }
            let mut angle = acute;
            if x_negative {
                angle = kernel::sub(kernel::pi(), angle);
            }
            if y_negative {
                angle = -angle;
            }
            (Some(angle), 0, true)
        }
    }
}

fn acute_angle(x: Quad, y: Quad) -> (Quad, Option<(Quad, i32)>) {
    let swapped = y > x;
    let (small, large) = if swapped { (x, y) } else { (y, x) };
    let small_exp = small.ilogb();
    let large_exp = large.ilogb();
    let difference = small_exp - large_exp;
    let normalized_ratio = (small.scalbn(-small_exp) / large.scalbn(-large_exp)).value;
    // rustc_apfloat supplies Quad division but no atan/atan2 operation or
    // exponent-carrying tiny result. Below this threshold atan(r)=r-r^3/3+…;
    // the cubic correction is outside Quad's useful relative precision, so
    // retain the normalized ratio and exponent for x87's final rounding.
    if difference <= -120 {
        if swapped {
            return (kernel::pi().scalbn(-1), None);
        }
        return (Quad::ZERO, Some((normalized_ratio, difference)));
    }
    let ratio = normalized_ratio.scalbn(difference);
    let acute = kernel::atan_unit(ratio);
    if swapped {
        (kernel::sub(kernel::pi().scalbn(-1), acute), None)
    } else {
        (acute, None)
    }
}

fn number_sign(number: Number) -> bool {
    match number {
        Number::Finite(value) => value.is_negative(),
        Number::Infinity { negative } => negative,
        Number::NaN { raw } => value::sign(raw),
        Number::Unsupported => false,
    }
}

fn signed_zero(negative: bool) -> Quad {
    if negative { -Quad::ZERO } else { Quad::ZERO }
}

fn finish(state: &mut X87State, result: crate::x87_math::MathResult) {
    if let Some((value, c1)) = status::commit_result(state, result) {
        status::set_result_conditions(state, c1);
        crate::x87::write_st(state, 1, value);
        crate::x87::pop(state);
    }
}

fn plain_result(value: Ext80, exceptions: u16) -> crate::x87_math::MathResult {
    crate::x87_math::MathResult {
        value,
        exceptions,
        c1: false,
        range: None,
    }
}
