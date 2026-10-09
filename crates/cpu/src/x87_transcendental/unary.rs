use rustc_apfloat::{ieee::Quad, Float, Round};

use crate::x87_math;

use crate::x87_state::{Ext80, X87State, X87Tag};

use super::kernel;
use super::status;
use super::value::{self, Number};

pub(super) fn f2xm1(state: &mut X87State) -> bool {
    let Some(raw) = crate::x87::read_st(state, 0) else { return true; };
    let Some(decoded) = status::input(state, raw) else { return true; };
    if let Some(nan) = value::propagated_nan(&[decoded]) {
        finish_unary(state, nan, 0, false);
        return true;
    }
    if matches!(decoded.number, Number::Unsupported) {
        finish_unary(state, crate::x87::indefinite(), 0, false);
        return true;
    }
    if !in_f2xm1_range(raw) {
        status::set_c2_range(state);
        return true;
    }
    status::clear_c2(state);
    let Number::Finite(x) = decoded.number else { return true; };
    let result = if x.is_zero() {
        raw
    } else if magnitude_is_one(raw) {
        if raw.sign_exponent & 0x8000 != 0 {
            Ext80 { significand: 1 << 63, sign_exponent: 0xbffe }
        } else {
            Ext80 { significand: 1 << 63, sign_exponent: 0x3fff }
        }
    } else {
        let (approximation, exponent_adjust) = kernel::exp2m1(x);
        let result = status::round_quad_scaled(state, approximation, exponent_adjust, true);
        commit_rounded(state, result);
        return true;
    };
    finish_unary(state, result, 0, false);
    true
}

pub(super) fn fsin(state: &mut X87State) -> bool {
    trig(state, TrigOp::Sin)
}

pub(super) fn fcos(state: &mut X87State) -> bool {
    trig(state, TrigOp::Cos)
}

pub(super) fn fsincos(state: &mut X87State) -> bool {
    trig(state, TrigOp::SinCos)
}

pub(super) fn fptan(state: &mut X87State) -> bool {
    trig(state, TrigOp::Tan)
}

#[derive(Clone, Copy)]
enum TrigOp { Sin, Cos, SinCos, Tan }

fn trig(state: &mut X87State, op: TrigOp) -> bool {
    let Some(source) = crate::x87::read_st_with_outcome(state, 0) else { return true; };
    let raw = source.value;
    let masked_source_underflow =
        source.kind == crate::x87::StackReadKind::MaskedUnderflow;
    let decoded = value::decode(raw);
    let requires_push = matches!(op, TrigOp::SinCos | TrigOp::Tan)
        && match decoded.number {
            Number::Finite(_) => !is_trig_out_of_range(raw),
            _ => true,
        };
    if requires_push {
        match crate::x87::preflight_push(state, source.kind) {
            crate::x87::PushPreflight::Available => {}
            crate::x87::PushPreflight::MaskedSourceUnderflow => {}
            crate::x87::PushPreflight::Suppressed => return true,
            crate::x87::PushPreflight::MaskedStackOverflow => {
                // #IS has higher precedence than #D and the function result;
                // commit the masked indefinite push without applying the
                // trigonometric result to the existing source stack.
                status::clear_c2(state);
                crate::x87::commit_preflight_stack_overflow(state);
                if matches!(op, TrigOp::Tan) {
                    // The Intel 80387 FPTAN masked-overflow response makes
                    // both architectural destinations quiet NaNs.
                    crate::x87::write_st(state, 1, crate::x87::indefinite());
                }
                return true;
            }
        }
    }
    if !crate::x87::raise_flags(state, decoded.flags) {
        return true;
    }
    if let Some(nan) = value::propagated_nan(&[decoded]) {
        match op {
            TrigOp::Sin | TrigOp::Cos => finish_unary(state, nan, 0, false),
            TrigOp::SinCos => push_pair(
                state,
                plain_result(nan, 0),
                plain_result(nan, 0),
                masked_source_underflow,
            ),
            TrigOp::Tan => push_pair(
                state,
                plain_result(nan, 0),
                plain_result(one_ext80(), 0),
                masked_source_underflow,
            ),
        }
        return true;
    }
    if matches!(decoded.number, Number::Unsupported) {
        match op {
            TrigOp::Sin | TrigOp::Cos => finish_unary(state, crate::x87::indefinite(), 0, false),
            TrigOp::SinCos => push_pair(
                state,
                plain_result(crate::x87::indefinite(), 0),
                plain_result(crate::x87::indefinite(), 0),
                masked_source_underflow,
            ),
            TrigOp::Tan => push_pair(
                state,
                plain_result(crate::x87::indefinite(), 0),
                plain_result(one_ext80(), 0),
                masked_source_underflow,
            ),
        }
        return true;
    }
    let Number::Finite(x) = decoded.number else {
        // Infinities are invalid for the trigonometric instruction group.
        if let Some(indefinite) = status::invalid_result(state) {
            match op {
                TrigOp::Sin | TrigOp::Cos => finish_unary(state, indefinite, 0, false),
                TrigOp::SinCos => push_pair(
                    state,
                    plain_result(indefinite, 0),
                    plain_result(indefinite, 0),
                    masked_source_underflow,
                ),
                TrigOp::Tan => push_pair(
                    state,
                    plain_result(indefinite, 0),
                    plain_result(one_ext80(), 0),
                    masked_source_underflow,
                ),
            }
        }
        return true;
    };

    if is_trig_out_of_range(raw) {
        status::set_c2_range(state);
        return true;
    }
    status::clear_c2(state);
    let magnitude = Ext80 { sign_exponent: raw.sign_exponent & 0x7fff, ..raw };
    let nonzero = !x.is_zero();
    match op {
        TrigOp::Sin => {
            let sine = kernel::sin(magnitude, x.abs(), value::sign(raw));
            let result = round_sine(state, sine, x, raw, nonzero);
            commit_rounded(state, result);
        }
        TrigOp::Cos => {
            let cosine = kernel::cos(magnitude, x.abs());
            let result = round_cosine(state, cosine, nonzero);
            commit_rounded(state, result);
        }
        TrigOp::SinCos => {
            let (sine, cosine) = kernel::sin_cos(magnitude, x.abs(), value::sign(raw));
            let sin_result = round_sine(state, sine, x, raw, nonzero);
            let cos_result = round_cosine(state, cosine, nonzero);
            push_pair(state, sin_result, cos_result, masked_source_underflow);
        }
        TrigOp::Tan => {
            let (sine, cosine) = kernel::sin_cos(magnitude, x.abs(), value::sign(raw));
            if let Some((tangent, exponent_adjust)) = wide_quotient(sine, cosine) {
                let result = round_tangent(
                    state,
                    tangent,
                    exponent_adjust,
                    x,
                    nonzero,
                );
                push_pair(
                    state,
                    result,
                    plain_result(one_ext80(), 0),
                    masked_source_underflow,
                );
            } else {
                // The reduced series currently has no certified nonzero lower
                // bound if its cosine approximation is exactly zero. Keep the
                // existing architectural overflow fallback explicit; the
                // correct biased register significand is a documented numeric
                // coverage unknown for this approximation-only edge.
                let negative = sine.is_negative() ^ cosine.is_negative();
                let (result, flags, c1) = status::overflow_result(state, negative);
                push_pair(
                    state,
                    plain_result(result, flags).with_c1(c1),
                    plain_result(one_ext80(), 0),
                    masked_source_underflow,
                );
            }
        }
    }
    true
}

fn round_sine(
    state: &X87State,
    approximation: Quad,
    input: Quad,
    raw_input: Ext80,
    inexact: bool,
) -> crate::x87_math::MathResult {
    let mut rounded = status::round_quad(state, approximation, inexact);
    if !inexact || !approximation.bitwise_eq(input) {
        return rounded;
    }
    let reference = status::round_quad(state, input, false).value;
    let toward_zero = match x87_math::round_from_control_word(state.control_word) {
        Round::TowardZero => true,
        Round::TowardNegative => raw_input.sign_exponent & 0x8000 == 0,
        Round::TowardPositive => raw_input.sign_exponent & 0x8000 != 0,
        Round::NearestTiesToEven | Round::NearestTiesToAway => false,
    };
    if toward_zero {
        set_strict_neighbor(
            &mut rounded,
            next_toward_zero(reference),
            false,
            Some(false),
            state.control_word,
        );
        rounded
    } else {
        set_strict_neighbor(&mut rounded, reference, true, None, state.control_word);
        rounded
    }
}

fn round_cosine(
    state: &X87State,
    approximation: Quad,
    inexact: bool,
) -> crate::x87_math::MathResult {
    let mut rounded = status::round_quad(state, approximation, inexact);
    if !inexact || !approximation.bitwise_eq(kernel::one()) {
        return rounded;
    }
    let round = x87_math::round_from_control_word(state.control_word);
    if matches!(round, Round::TowardZero | Round::TowardNegative) {
        rounded.value = next_toward_zero(rounded.value);
        rounded.c1 = false;
        rounded
    } else {
        rounded.c1 = true;
        rounded
    }
}

fn round_tangent(
    state: &X87State,
    approximation: Quad,
    exponent_adjust: i32,
    input: Quad,
    inexact: bool,
) -> crate::x87_math::MathResult {
    let mut rounded = status::round_quad_scaled(state, approximation, exponent_adjust, inexact);
    if !inexact || !same_scaled_value(approximation, exponent_adjust, input) {
        return rounded;
    }
    let negative = input.is_negative();
    let round = x87_math::round_from_control_word(state.control_word);
    let away = matches!(round, Round::TowardPositive) && !negative
        || matches!(round, Round::TowardNegative) && negative;
    if away {
        let neighbor = next_away_zero(rounded.value);
        set_strict_neighbor(&mut rounded, neighbor, true, Some(true), state.control_word);
        rounded
    } else {
        rounded
    }
}

fn wide_quotient(numerator: Quad, denominator: Quad) -> Option<(Quad, i32)> {
    // APFloat division would saturate if the quotient's exponent left Quad's
    // range; normalize both operands first because the x87 tangent consumer
    // needs the exponent for its own overflow/underflow retirement.
    if denominator.is_zero() {
        return None;
    }
    if numerator.is_zero() {
        return Some((numerator, 0));
    }
    let (normalized_numerator, numerator_exponent) = normalize_quad(numerator);
    let (normalized_denominator, denominator_exponent) = normalize_quad(denominator);
    let quotient = (normalized_numerator / normalized_denominator).value;
    let (normalized_quotient, quotient_exponent) = normalize_quad(quotient);
    Some((
        normalized_quotient,
        numerator_exponent
            .saturating_sub(denominator_exponent)
            .saturating_add(quotient_exponent),
    ))
}

fn normalize_quad(value: Quad) -> (Quad, i32) {
    if value.is_zero() {
        (value, 0)
    } else {
        let exponent = value.ilogb();
        (value.scalbn(-exponent), exponent)
    }
}

fn same_scaled_value(value: Quad, exponent_adjust: i32, other: Quad) -> bool {
    let (normalized_other, other_exponent) = normalize_quad(other);
    exponent_adjust == other_exponent && value.bitwise_eq(normalized_other)
}

pub(super) fn set_strict_neighbor(
    result: &mut crate::x87_math::MathResult,
    value: Ext80,
    c1: bool,
    range_away_from_zero: Option<bool>,
    control_word: u16,
) {
    let range_base = result.value;
    result.value = value;
    result.c1 = c1;
    if result.exceptions & value::PE != 0 && value.sign_exponent & 0x7fff == 0 {
        result.exceptions |= value::UE;
    }
    if let Some(range) = &mut result.range {
        if let Some(away_from_zero) = range_away_from_zero {
            range.biased_value = adjacent_magnitude(range.biased_value, away_from_zero);
        }
        range.biased_c1 = c1;
    } else if result.exceptions & value::UE != 0 && control_word & (1 << 4) == 0 {
        if let Some(mut biased_value) = bias_underflow_result(range_base) {
            if let Some(away_from_zero) = range_away_from_zero {
                biased_value = adjacent_magnitude(biased_value, away_from_zero);
            }
            result.range = Some(crate::x87_math::RegisterRangeResult {
                kind: crate::x87_math::RegisterRangeKind::Underflow,
                biased_value,
                biased_c1: c1,
                precision_lost: true,
            });
        }
    }
}

fn bias_underflow_result(value: Ext80) -> Option<Ext80> {
    // rustc_apfloat does not retain an x87 pre-subnormal rounded value after
    // its ordinary Ext80 conversion. Reconstruct the normalized exponent from
    // this exact adjacent input, then apply Intel's register-only +24576 bias.
    let sign = value.sign_exponent & 0x8000;
    let field = i32::from(value.sign_exponent & 0x7fff);
    let (significand, exponent) = if field == 0 {
        if value.significand == 0 {
            return None;
        }
        let highest = 63 - value.significand.leading_zeros() as i32;
        let shift = 63 - highest;
        (value.significand << shift, -16_382 - shift)
    } else if field == 0x7fff {
        return None;
    } else {
        (value.significand, field - 16_383)
    };
    let biased_exponent = exponent.saturating_add(24_576);
    if biased_exponent < -16_382 {
        return Some(value::raw_zero(sign != 0));
    }
    if biased_exponent > 16_383 {
        return Some(Ext80 { significand: 1 << 63, sign_exponent: sign | 0x7fff });
    }
    Some(Ext80 {
        significand,
        sign_exponent: sign | (biased_exponent + 16_383) as u16,
    })
}

pub(super) fn next_toward_zero(value: Ext80) -> Ext80 {
    adjacent_magnitude(value, false)
}

fn next_away_zero(value: Ext80) -> Ext80 {
    adjacent_magnitude(value, true)
}

/// Return a canonical Ext80 neighbor. The APFloat contract has no operation
/// for stepping raw explicit-integer-bit encodings, so this local integer
/// helper handles subnormal/normal transitions without emitting pseudo-
/// denormals.
fn adjacent_magnitude(value: Ext80, away_from_zero: bool) -> Ext80 {
    let sign = value.sign_exponent & 0x8000;
    let exponent = value.sign_exponent & 0x7fff;
    if exponent == 0x7fff {
        if value.significand == 1 << 63 {
            return if away_from_zero {
                value
            } else {
                Ext80 { significand: u64::MAX, sign_exponent: sign | 0x7ffe }
            };
        }
        return value;
    }
    if value.significand == 0 {
        return if away_from_zero {
            Ext80 { significand: 1, sign_exponent: sign }
        } else {
            value
        };
    }

    // Canonicalize a pseudo-denormal before stepping: E=0/J=1 represents the
    // same magnitude as the ordinary E=1 encoding.
    let (significand, exponent) = if exponent == 0 && value.significand & (1 << 63) != 0 {
        (value.significand, 1)
    } else {
        (value.significand, exponent)
    };
    if away_from_zero {
        if exponent == 0 {
            if significand >= (1 << 63) - 1 {
                Ext80 { significand: 1 << 63, sign_exponent: sign | 1 }
            } else {
                Ext80 { significand: significand + 1, sign_exponent: sign }
            }
        } else if significand == u64::MAX {
            if exponent == 0x7ffe {
                Ext80 { significand: 1 << 63, sign_exponent: sign | 0x7fff }
            } else {
                Ext80 { significand: 1 << 63, sign_exponent: sign | (exponent + 1) }
            }
        } else {
            Ext80 { significand: significand + 1, sign_exponent: sign | exponent }
        }
    } else if exponent == 0 {
        Ext80 { significand: significand - 1, sign_exponent: sign }
    } else if significand > (1 << 63) {
        Ext80 { significand: significand - 1, sign_exponent: sign | exponent }
    } else if exponent == 1 {
        Ext80 { significand: (1 << 63) - 1, sign_exponent: sign }
    } else {
        Ext80 { significand: u64::MAX, sign_exponent: sign | (exponent - 1) }
    }
}

fn finish_unary(state: &mut X87State, result: Ext80, flags: u16, c1: bool) {
    if let Some((result, c1)) = status::commit_result(state, plain_result(result, flags).with_c1(c1)) {
        status::set_result_conditions(state, c1);
        crate::x87::write_st(state, 0, result);
    }
}

fn commit_rounded(state: &mut X87State, result: crate::x87_math::MathResult) {
    if let Some((value, c1)) = status::commit_result(state, result) {
        status::set_result_conditions(state, c1);
        crate::x87::write_st(state, 0, value);
    }
}

fn push_pair(
    state: &mut X87State,
    st1_result: crate::x87_math::MathResult,
    st0_result: crate::x87_math::MathResult,
    masked_source_underflow: bool,
) {
    if !status::commit_results(state, &[st1_result, st0_result]) {
        return;
    }
    let (st1_value, st1_c1) = crate::x87::register_math_result_value(st1_result);
    let (st0_value, st0_c1) = crate::x87::register_math_result_value(st0_result);
    status::set_result_conditions(state, st1_c1 || st0_c1);
    if masked_source_underflow {
        crate::x87::commit_masked_source_underflow_push(state, st0_value);
        crate::x87::write_st(state, 1, st1_value);
        return;
    }
    let stack_was_full = state.tag(state.physical_register(7)) != X87Tag::Empty;
    if !crate::x87::push(state, st0_value) || stack_was_full {
        return;
    }
    crate::x87::write_st(state, 1, st1_value);
}

fn plain_result(value: Ext80, exceptions: u16) -> crate::x87_math::MathResult {
    crate::x87_math::MathResult {
        value,
        exceptions,
        c1: false,
        range: None,
    }
}

trait WithC1 {
    fn with_c1(self, c1: bool) -> Self;
}

impl WithC1 for crate::x87_math::MathResult {
    fn with_c1(mut self, c1: bool) -> Self {
        self.c1 = c1;
        self
    }
}

fn one_ext80() -> Ext80 {
    Ext80 { significand: 1 << 63, sign_exponent: 0x3fff }
}

fn in_f2xm1_range(raw: Ext80) -> bool {
    let exponent = raw.sign_exponent & 0x7fff;
    exponent < 0x3fff || (exponent == 0x3fff && raw.significand <= 1 << 63)
}

fn magnitude_is_one(raw: Ext80) -> bool {
    raw.sign_exponent & 0x7fff == 0x3fff && raw.significand == 1 << 63
}

fn is_trig_out_of_range(raw: Ext80) -> bool {
    raw.sign_exponent & 0x7fff >= 0x403e
}
