use super::{indefinite, pop, push, raise_result_flags, read_st};
use crate::x87_math::{X87_DE, X87_OE, X87_PE};
use crate::x87_state::{Ext80, X87State, X87Tag, X87_C1, X87_EXCEPTION_SUMMARY, X87_BUSY, X87_STACK_FAULT};

#[test]
fn push_and_pop_follow_the_rotating_stack_top() {
    let mut state = X87State::default();
    let value = Ext80 { significand: 1 << 63, sign_exponent: 0x3fff };

    assert!(push(&mut state, value));
    assert_eq!(state.top(), 7);
    assert_eq!(state.read_st(0), Some(value));
    assert!(pop(&mut state));
    assert_eq!(state.top(), 0);
    assert_eq!(state.tag(0), X87Tag::Empty);
}

#[test]
fn masked_stack_overflow_pushes_the_x87_indefinite_value() {
    let mut state = X87State::default();
    let value = Ext80 { significand: 1 << 63, sign_exponent: 0x3fff };
    for _ in 0..8 {
        assert!(push(&mut state, value));
    }

    assert!(push(&mut state, value));
    assert_eq!(state.read_st(0), Some(indefinite()));
    assert_ne!(state.status_word & X87_STACK_FAULT, 0);
    assert_ne!(state.status_word & X87_C1, 0);
}

#[test]
fn masked_stack_underflow_reads_indefinite_and_sets_stack_fault() {
    let mut state = X87State::default();

    assert_eq!(read_st(&mut state, 0), Some(indefinite()));
    assert_ne!(state.status_word & X87_STACK_FAULT, 0);
    assert_eq!(state.status_word & 1, 1);
}

#[test]
fn unmasked_stack_overflow_preserves_top_and_registers() {
    let mut state = X87State::default();
    state.control_word &= !1;
    let value = Ext80 { significand: 1 << 63, sign_exponent: 0x3fff };
    for _ in 0..8 {
        assert!(push(&mut state, value));
    }
    let top = state.top();
    let registers = state.registers;

    assert!(!push(&mut state, indefinite()));
    assert_eq!(state.top(), top);
    assert_eq!(state.registers, registers);
}

#[test]
fn initialization_clears_environment_pointers_but_leaves_data_payloads() {
    let mut state = X87State {
        instruction_pointer: 0x1234,
        instruction_segment: 0x2345,
        data_pointer: 0x3456,
        data_segment: 0x4567,
        opcode: 0x05aa,
        ..X87State::default()
    };
    let payload = Ext80 { significand: 0x8123_4567_89ab_cdef, sign_exponent: 0x4321 };
    state.registers[3] = payload;
    state.status_word = 0xffff;
    state.control_word = 0;

    state.reset();

    assert_eq!(state.control_word, 0x037f);
    assert_eq!(state.status_word, 0);
    assert_eq!(state.tag_word, 0xffff);
    assert_eq!(state.instruction_pointer, 0);
    assert_eq!(state.instruction_segment, 0);
    assert_eq!(state.data_pointer, 0);
    assert_eq!(state.data_segment, 0);
    assert_eq!(state.opcode, 0);
    assert_eq!(state.registers[3], payload);
}

#[test]
fn unmasked_precision_is_deferred_after_result_flags_are_recorded() {
    let mut state = X87State::default();
    state.control_word &= !X87_PE;

    assert!(raise_result_flags(&mut state, X87_PE));
    assert_eq!(state.status_word & X87_PE, X87_PE);
    assert_eq!(state.pending_unmasked_exceptions(), X87_PE);
    assert_ne!(state.status_word & X87_EXCEPTION_SUMMARY, 0);
    assert_ne!(state.status_word & X87_BUSY, 0);
}

#[test]
fn unmasked_nonprecision_exception_suppresses_result_and_precision_flag() {
    let mut state = X87State::default();
    state.control_word &= !(X87_OE | X87_PE);

    assert!(!raise_result_flags(&mut state, X87_OE | X87_PE));
    assert_eq!(state.status_word & X87_OE, X87_OE);
    assert_eq!(state.status_word & X87_PE, 0);
    assert_eq!(state.pending_unmasked_exceptions(), X87_OE);
}

#[test]
fn unmasked_denormal_input_suppresses_later_precision_commit() {
    let mut state = X87State::default();
    state.control_word &= !(X87_DE | X87_PE);

    assert!(!raise_result_flags(&mut state, X87_DE | X87_PE));
    assert_eq!(state.status_word & X87_DE, X87_DE);
    assert_eq!(state.status_word & X87_PE, 0);
}

#[test]
fn masked_overflow_with_unmasked_precision_still_commits_result_flags() {
    let mut state = X87State::default();
    state.control_word &= !X87_PE;

    assert!(raise_result_flags(&mut state, X87_OE | X87_PE));
    assert_eq!(state.status_word & (X87_OE | X87_PE), X87_OE | X87_PE);
    assert_eq!(state.pending_unmasked_exceptions(), X87_PE);
}

#[test]
fn multiple_result_commits_allow_precision_pending_within_one_instruction() {
    let mut state = X87State::default();
    state.control_word &= !X87_PE;

    assert!(raise_result_flags(&mut state, X87_PE));
    assert!(raise_result_flags(&mut state, X87_PE));
    assert_eq!(state.pending_unmasked_exceptions(), X87_PE);
}

#[test]
fn masked_stack_overflow_still_commits_with_precision_pending() {
    let mut state = X87State::default();
    let value = Ext80 { significand: 1 << 63, sign_exponent: 0x3fff };
    for _ in 0..8 {
        assert!(push(&mut state, value));
    }
    state.control_word &= !X87_PE;
    assert!(raise_result_flags(&mut state, X87_PE));
    let previous_top = state.top();

    assert!(push(&mut state, value));

    assert_eq!(state.top(), previous_top.wrapping_sub(1) & 7);
    assert_eq!(state.read_st(0), Some(indefinite()));
    assert_eq!(state.pending_unmasked_exceptions(), X87_PE);
}
