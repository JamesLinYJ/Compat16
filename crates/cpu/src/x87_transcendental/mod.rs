//! x87 transcendental instruction execution using a Quad-precision software
//! approximation and one final extended-precision rounding step.
//!
//! The numerical identities and range-reduction approach are adapted from
//! legacy SoftFloat extension files `f2xm1.c`, `fyl2x.c`, `fpatan.c`, and
//! `fsincos.c`, originally written for Bochs by Stanislav Shwartsman. This is
//! a derivative Rust implementation; it does not copy their C implementation
//! or its historical finite-precision argument-reduction behavior. The code
//! uses an independent 256-bit Payne-Hanek reducer and the project APFloat
//! adapter.
//!
//! The relevant source header's derivative-work notice is retained here:
//!
//! > This source file is an extension to the SoftFloat IEC/IEEE Floating-point
//! > Arithmetic Package, Release 2b, written for Bochs (x86 achitecture
//! > simulator) floating point emulation.
//! >
//! > THIS SOFTWARE IS DISTRIBUTED AS IS, FOR FREE. Although reasonable effort
//! > has been made to avoid it, THIS SOFTWARE MAY CONTAIN FAULTS THAT WILL AT
//! > TIMES RESULT IN INCORRECT BEHAVIOR. USE OF THIS SOFTWARE IS RESTRICTED TO
//! > PERSONS AND ORGANIZATIONS WHO CAN AND WILL TAKE FULL RESPONSIBILITY FOR
//! > ALL LOSSES, COSTS, OR OTHER PROBLEMS THEY INCUR DUE TO THE SOFTWARE, AND
//! > WHO FURTHERMORE EFFECTIVELY INDEMNIFY JOHN HAUSER AND THE INTERNATIONAL
//! > COMPUTER SCIENCE INSTITUTE (possibly via similar legal warning) AGAINST
//! > ALL LOSSES, COSTS, OR OTHER PROBLEMS INCURRED BY THEIR CUSTOMERS AND
//! > CLIENTS DUE TO THE SOFTWARE.
//! >
//! > Derivative works are acceptable, even for commercial purposes, so long as
//! > (1) the source code for the derivative work includes prominent notice
//! > that the work is derivative, and (2) the source code includes prominent
//! > notice with these four paragraphs for those parts of this code that are
//! > retained.
//! >
//! > Written for Bochs (x86 achitecture simulator) by Stanislav Shwartsman
//! > [sshwarts at sourceforge net].
//!
//! Quad has 113 significand bits. That is enough guard precision for ordinary
//! x87 results and the reducer retains substantially more than the original
//! 128-bit reduction constant for arguments below 2^63. It is not a proof of
//! correct rounding for every hard-to-round transcendental input. Tiny results
//! that lie outside Quad's exponent range and the last-bit directed-rounding
//! cases are handled explicitly where the sign and direction are known; the
//! remaining approximation bound is documented in `kernel.rs`.

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
