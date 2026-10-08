use rustc_apfloat::{ieee::Quad, Round};

use crate::x87_math::{self, MathResult};
use crate::x87_state::{Ext80, X87State, X87_C1, X87_C2};

use super::value::{decode, raw_infinity, Decoded, IE, Number, OE, PE};

pub(crate) fn input(state: &mut X87State, raw: Ext80) -> Option<Decoded> {
    let decoded = decode(raw);
    crate::x87::raise_flags(state, prioritized_input_flags(&[decoded])).then_some(decoded)
}

pub(crate) fn inputs(
    state: &mut X87State,
    first: Ext80,
    second: Ext80,
) -> Option<(Decoded, Decoded)> {
    let left = decode(first);
    let right = decode(second);
    crate::x87::raise_flags(state, prioritized_input_flags(&[left, right]))
        .then_some((left, right))
}

/// Intel's exception precedence puts unsupported/SNaN invalid and QNaN
/// handling ahead of #D. APFloat's operand classifier is useful for ordinary
/// inputs, but this x87 instruction layer must choose that source class first.
pub(crate) fn prioritized_input_flags(inputs: &[Decoded]) -> u16 {
    let flags = inputs.iter().fold(0, |flags, input| flags | input.flags);
    let higher_priority = flags & IE != 0
        || inputs
            .iter()
            .any(|input| matches!(input.number, Number::NaN { .. }));
    if higher_priority {
        flags & !x87_math::X87_DE
    } else {
        flags
    }
}

/// Convert one Quad approximation to the architectural 64-bit x87 precision.
/// Transcendental instructions ignore the x87 PC field; RC still applies.
pub(crate) fn round_quad(
    state: &X87State,
    value: Quad,
    known_inexact: bool,
) -> MathResult {
    round_quad_scaled(state, value, 0, known_inexact)
}

pub(crate) fn round_quad_scaled(
    state: &X87State,
    value: Quad,
    exponent_adjust: i32,
    known_inexact: bool,
) -> MathResult {
    x87_math::from_quad_wide(value, exponent_adjust, known_inexact, state.control_word)
}

pub(crate) fn commit_result(state: &mut X87State, result: MathResult) -> Option<(Ext80, bool)> {
    crate::x87::commit_register_math_result(state, result)
}

pub(crate) fn commit_results(state: &mut X87State, results: &[MathResult]) -> bool {
    crate::x87::commit_register_math_results(state, results)
}

pub(crate) fn invalid_result(state: &mut X87State) -> Option<Ext80> {
    crate::x87::raise_flags(state, IE).then(crate::x87::indefinite)
}

/// An exact finite function result whose magnitude is known to exceed the
/// representable x87 range. Select infinity or maximum finite from RC.
pub(crate) fn overflow_result(state: &X87State, negative: bool) -> (Ext80, u16, bool) {
    let round = x87_math::round_from_control_word(state.control_word);
    let to_infinity = match round {
        Round::NearestTiesToEven => true,
        Round::TowardPositive => !negative,
        Round::TowardNegative => negative,
        Round::TowardZero | Round::NearestTiesToAway => false,
    };
    let value = if to_infinity {
        raw_infinity(negative)
    } else {
        Ext80 {
            significand: u64::MAX,
            sign_exponent: 0x7ffe | if negative { 0x8000 } else { 0 },
        }
    };
    (value, OE | PE, to_infinity)
}

pub(crate) fn set_result_conditions(state: &mut X87State, c1: bool) {
    state.status_word &= !(X87_C1 | X87_C2);
    if c1 {
        state.status_word |= X87_C1;
    }
}

pub(crate) fn set_c2_range(state: &mut X87State) {
    state.status_word = (state.status_word & !X87_C1) | X87_C2;
}

pub(crate) fn clear_c2(state: &mut X87State) {
    state.status_word &= !X87_C2;
}
