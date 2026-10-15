//! x87 transcendental execution with binary128 software arithmetic.
//!
//! Numerical kernels use independently computed minimax coefficients, dyadic
//! center tables, fused Horner evaluation, and the 256-bit Payne-Hanek reducer.
//! Coefficients are mathematical data; normal builds need neither Sollya nor a
//! native numerical library. The existing instruction layer owns operand
//! classification, stack effects, architectural exceptions, and Ext80 rounding.
//!
//! Russinoff, "Modeling the x87 Transcendental Instructions with Elementary
//! Polynomial Approximations" (2007), distinguishes approximation bounds from
//! final rounding guarantees. The fits here use different reductions and
//! degrees; their certified exact-evaluation bounds are in `coefficients.hex`.
//! They are not a proof of correctly rounded results for every input: reduction,
//! finite arithmetic, extreme exponents, and hard-to-round boundaries remain
//! separate numerical concerns. Existing tiny-result directional handling is
//! preserved at instruction retirement.

mod coefficients {
    include!(concat!(env!("OUT_DIR"), "/x87_coefficients.rs"));
}

mod atan;
mod kernel;
mod logarithm;
mod payne_hanek;
mod status;
mod unary;
mod value;

#[cfg(test)]
mod tests;

use x86_decoder::Mnemonic;

use crate::x87_state::X87State;

/// Execute an x87 transcendental instruction. Other x87 instructions remain
/// owned by the regular arithmetic, load/store, and control dispatchers.
pub(crate) fn execute(state: &mut X87State, mnemonic: Mnemonic) -> bool {
    use Mnemonic as M;
    match mnemonic {
        M::F2xm1 => unary::f2xm1(state),
        M::Fsincos => unary::fsincos(state),
        M::Fsin => unary::fsin(state),
        M::Fcos => unary::fcos(state),
        M::Fptan => unary::fptan(state),
        M::Fyl2x => logarithm::fyl2x(state, false),
        M::Fyl2xp1 => logarithm::fyl2x(state, true),
        M::Fpatan => atan::fpatan(state),
        _ => false,
    }
}
