use x86_decoder::Mnemonic;
use rustc_apfloat::Float;

use crate::x87_state::{Ext80, X87State, X87_C1, X87_C2};
use crate::x87_math::X87_PE;

use super::execute;

const ONE: Ext80 = Ext80 { significand: 1 << 63, sign_exponent: 0x3fff };
const TWO: Ext80 = Ext80 { significand: 1 << 63, sign_exponent: 0x4000 };

fn st(state: &mut X87State, index: u8, value: Ext80) {
    state.write_st(index, value);
}

#[test]
fn f2xm1_endpoints_are_exact_and_out_of_range_preserves_st0() {
    let mut state = X87State::default();
    let minus_one = Ext80 { significand: ONE.significand, sign_exponent: 0xbfff };
    st(&mut state, 0, minus_one);
    assert!(execute(&mut state, Mnemonic::F2xm1));
    assert_eq!(state.read_st(0), Some(Ext80 { significand: ONE.significand, sign_exponent: 0xbffe }));
    assert_eq!(state.status_word & (0x3f | X87_C2), 0);

    let outside = Ext80 { significand: 0xc000_0000_0000_0000, sign_exponent: 0x3fff };
    st(&mut state, 0, outside);
    assert!(execute(&mut state, Mnemonic::F2xm1));
    assert_eq!(state.read_st(0), Some(outside));
    assert_ne!(state.status_word & X87_C2, 0);
}

#[test]
fn trigonometric_range_failure_sets_c2_without_changing_the_stack() {
    let mut state = X87State::default();
    let edge = Ext80 { significand: ONE.significand, sign_exponent: 0x403e };
    st(&mut state, 0, edge);
    assert!(execute(&mut state, Mnemonic::Fsin));
    assert_eq!(state.read_st(0), Some(edge));
    assert_ne!(state.status_word & X87_C2, 0);
    assert_eq!(state.status_word & 0x3f, 0);
}

#[test]
fn fyl2x_zero_domain_cases_raise_the_architectural_flags_and_pop() {
    let mut state = X87State::default();
    st(&mut state, 0, Ext80::default());
    st(&mut state, 1, TWO);
    assert!(execute(&mut state, Mnemonic::Fyl2x));
    assert_eq!(state.top(), 1);
    let result = state.read_st(0).expect("masked divide-by-zero result");
    assert_eq!(result.sign_exponent, 0xffff);
    assert_eq!(result.significand, ONE.significand);
    assert_ne!(state.status_word & (1 << 2), 0);

    state = X87State::default();
    st(&mut state, 0, Ext80::default());
    st(&mut state, 1, Ext80::default());
    assert!(execute(&mut state, Mnemonic::Fyl2x));
    assert_eq!(state.top(), 1);
    assert_eq!(state.read_st(0), Some(crate::x87::indefinite()));
    assert_ne!(state.status_word & 1, 0);
    assert_ne!(state.status_word & (1 << 2), 0);
}

#[test]
fn fsincos_pushes_cosine_above_sine_and_zero_is_exact() {
    let mut state = X87State::default();
    st(&mut state, 0, Ext80::default());
    assert!(execute(&mut state, Mnemonic::Fsincos));
    assert_eq!(state.top(), 7);
    assert_eq!(state.read_st(0), Some(ONE));
    assert_eq!(state.read_st(1), Some(Ext80::default()));
    assert_eq!(state.status_word & (0x3f | X87_C1 | X87_C2), 0);
}

#[test]
fn fsincos_commits_both_results_when_precision_is_unmasked() {
    let mut state = X87State::default();
    state.control_word &= !X87_PE;
    st(&mut state, 0, ONE);

    assert!(execute(&mut state, Mnemonic::Fsincos));

    assert_eq!(state.top(), 7);
    assert!(state.read_st(0).is_some());
    assert!(state.read_st(1).is_some());
    assert_eq!(state.status_word & X87_PE, X87_PE);
    assert_eq!(state.pending_unmasked_exceptions(), X87_PE);
}

#[test]
fn fptan_commits_its_push_pair_when_precision_is_unmasked() {
    let mut state = X87State::default();
    state.control_word &= !X87_PE;
    st(&mut state, 0, ONE);

    assert!(execute(&mut state, Mnemonic::Fptan));

    assert_eq!(state.top(), 7);
    assert_eq!(state.read_st(0), Some(ONE));
    assert!(state.read_st(1).is_some());
    assert_eq!(state.status_word & X87_PE, X87_PE);
    assert_eq!(state.pending_unmasked_exceptions(), X87_PE);
}

#[test]
fn f2xm1_uses_control_rounding_for_tiny_subnormal_results() {
    let tiny = Ext80 { significand: 1, sign_exponent: 0 };
    let mut state = X87State::default();
    state.control_word = (state.control_word & !(3 << 10)) | (1 << 10); // round down
    st(&mut state, 0, tiny);
    assert!(execute(&mut state, Mnemonic::F2xm1));
    assert_eq!(state.read_st(0), Some(Ext80::default()));
    assert_ne!(state.status_word & (1 << 4), 0);
    assert_ne!(state.status_word & (1 << 5), 0);
    assert_eq!(state.status_word & X87_C1, 0);

    state = X87State::default();
    state.control_word = (state.control_word & !(3 << 10)) | (2 << 10); // round up
    st(&mut state, 0, tiny);
    assert!(execute(&mut state, Mnemonic::F2xm1));
    assert_eq!(state.read_st(0), Some(tiny));
    assert_ne!(state.status_word & X87_C1, 0);
}

#[test]
fn fpatan_on_positive_x_axis_returns_signed_zero_and_pops() {
    let mut state = X87State::default();
    st(&mut state, 0, ONE);
    st(&mut state, 1, Ext80 { significand: 0, sign_exponent: 0x8000 });
    assert!(execute(&mut state, Mnemonic::Fpatan));
    assert_eq!(state.top(), 1);
    assert_eq!(state.read_st(0), Some(Ext80 { significand: 0, sign_exponent: 0x8000 }));
    assert_eq!(state.status_word & 0x3f, 0);
}

#[test]
fn fyl2xp1_preserves_a_tiny_argument_when_the_product_is_normal() {
    let x = Ext80 { significand: ONE.significand, sign_exponent: 0x3f37 }; // 2^-200
    let y = Ext80 { significand: ONE.significand, sign_exponent: 0x40c7 }; // 2^200
    let mut state = X87State::default();
    st(&mut state, 0, x);
    st(&mut state, 1, y);
    assert!(execute(&mut state, Mnemonic::Fyl2xp1));
    assert_eq!(state.top(), 1);
    let result = state.read_st(0).expect("FYL2XP1 result");
    let (actual, _) = crate::x87_math::to_quad(result).expect("finite result");
    let (one, _) = crate::x87_math::to_quad(ONE).expect("one");
    let one_and_a_half = one.scalbn(0) + (one.scalbn(-1));
    assert!(actual > one && actual < one_and_a_half.value);
    assert_ne!(state.status_word & (1 << 5), 0);
}

#[test]
fn tiny_sine_and_cosine_keep_the_correct_directed_rounding_side() {
    let tiny = Ext80 { significand: 1, sign_exponent: 0 };
    let mut state = X87State::default();
    st(&mut state, 0, tiny);
    assert!(execute(&mut state, Mnemonic::Fsin));
    assert_eq!(state.read_st(0), Some(tiny));
    assert_ne!(state.status_word & X87_C1, 0);

    state = X87State::default();
    state.control_word = (state.control_word & !(3 << 10)) | (1 << 10); // toward -infinity
    st(&mut state, 0, tiny);
    assert!(execute(&mut state, Mnemonic::Fsin));
    assert_eq!(state.read_st(0), Some(Ext80::default()));
    assert_ne!(state.status_word & (1 << 4), 0); // UE
    assert_ne!(state.status_word & (1 << 5), 0); // PE
    assert_eq!(state.status_word & X87_C1, 0);

    state = X87State::default();
    state.control_word = (state.control_word & !(3 << 10)) | (3 << 10); // toward zero
    st(&mut state, 0, tiny);
    assert!(execute(&mut state, Mnemonic::Fcos));
    assert_eq!(
        state.read_st(0),
        Some(Ext80 { significand: u64::MAX, sign_exponent: 0x3ffe })
    );
    assert_ne!(state.status_word & (1 << 5), 0); // PE
    assert_eq!(state.status_word & (1 << 4), 0); // not tiny
}
