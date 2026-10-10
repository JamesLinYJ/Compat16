use x86_decoder::{Decoder, DecoderOptions};

use crate::x86_decode::{DecodedInstruction, NormalizedInstruction};
use crate::x87_state::{Ext80, X87State, X87_C1, X87_STACK_FAULT};
use crate::x87_math::{self, MathResult, RegisterRangeKind, RegisterRangeResult, X87_IE, X87_OE, X87_PE};

use super::{
    binary_register_indices, commit_register_math_result, execute_unary_or_scale,
    second_register,
};

fn decode_x87(bytes: &[u8]) -> NormalizedInstruction {
    let mut decoder = Decoder::with_ip(16, bytes, 0, DecoderOptions::NONE);
    let instruction = decoder.decode();
    let escape = bytes[0];
    let modrm = bytes[1];
    NormalizedInstruction::new(DecodedInstruction {
        instruction,
        opcode: escape,
        operand32: false,
        x87_opcode: Some((u16::from(escape & 7) << 8) | u16::from(modrm)),
        start_ip: 0,
        next_ip: bytes.len() as u32,
    })
}

#[test]
fn explicit_self_add_preserves_both_st_zero_operands() {
    let instruction = decode_x87(&[0xd8, 0xc0]);
    assert_eq!(binary_register_indices(&instruction), (0, 0));
}

#[test]
fn reversed_and_popped_register_arithmetic_preserve_destination_order() {
    let normal = decode_x87(&[0xd8, 0xc1]); // fadd st0, st1
    let reversed = decode_x87(&[0xdc, 0xc1]); // fadd st1, st0
    let popped = decode_x87(&[0xde, 0xc1]); // faddp st1, st0

    assert_eq!(binary_register_indices(&normal), (0, 1));
    assert_eq!(binary_register_indices(&reversed), (1, 0));
    assert_eq!(binary_register_indices(&popped), (1, 0));
}

#[test]
fn fcom_st_zero_is_not_rewritten_to_st_one() {
    let self_compare = decode_x87(&[0xd8, 0xd0]);
    let st_one = decode_x87(&[0xd8, 0xd1]);

    assert_eq!(second_register(&self_compare), 0);
    assert_eq!(second_register(&st_one), 1);
}

#[test]
fn fxtract_places_significand_in_st_zero_and_exponent_in_st_one() {
    let instruction = decode_x87(&[0xd9, 0xf4]);
    let mut state = X87State::default();
    let input = Ext80 { significand: 0xc000_0000_0000_0000, sign_exponent: 0x4002 };
    state.write_st(0, input);
    let expected = x87_math::extract(input);

    assert!(execute_unary_or_scale(&mut state, &instruction).unwrap());

    assert_eq!(state.read_st(0), Some(expected.significand));
    assert_eq!(state.read_st(1), Some(expected.exponent));
}

#[test]
fn fxtract_unmasked_stack_overflow_does_not_replace_any_register() {
    let instruction = decode_x87(&[0xd9, 0xf4]);
    let mut state = X87State::default();
    let value = Ext80 { significand: 1 << 63, sign_exponent: 0x3fff };
    for _ in 0..8 { assert!(crate::x87::push(&mut state, value)); }
    state.control_word &= !1;
    let top = state.top();
    let registers = state.registers;
    let tags = state.tag_word;

    assert!(execute_unary_or_scale(&mut state, &instruction).unwrap());

    assert_eq!(state.top(), top);
    assert_eq!(state.registers, registers);
    assert_eq!(state.tag_word, tags);
    assert_ne!(state.status_word & X87_STACK_FAULT, 0);
    assert_ne!(state.status_word & X87_C1, 0);
}

#[test]
fn unmasked_register_overflow_uses_biased_adapter_value_and_c1() {
    let mut state = X87State::default();
    state.control_word &= !(1 << 3); // unmask OE
    let normal = Ext80 { significand: 0x8000_0000_0000_0000, sign_exponent: 0x7fff };
    let biased = Ext80 { significand: 0x8123_4567_89ab_cdef, sign_exponent: 0x1fff };
    let result = MathResult {
        value: normal,
        exceptions: X87_OE | X87_PE,
        c1: false,
        range: Some(RegisterRangeResult {
            kind: RegisterRangeKind::Overflow,
            biased_value: biased,
            biased_c1: true,
            precision_lost: true,
        }),
    };

    assert_eq!(commit_register_math_result(&mut state, result), Some((biased, true)));
    assert_eq!(state.status_word & (X87_OE | X87_PE), X87_OE | X87_PE);
}

#[test]
fn exact_unmasked_register_underflow_uses_biased_value_without_precision_flag() {
    let mut state = X87State::default();
    state.control_word &= !(1 << 4); // unmask UE
    let normal = Ext80::default();
    let biased = Ext80 { significand: 1 << 63, sign_exponent: 0x0001 };
    let underflow_flag = 1 << 4;
    let result = MathResult {
        value: normal,
        exceptions: underflow_flag,
        c1: false,
        range: Some(RegisterRangeResult {
            kind: RegisterRangeKind::Underflow,
            biased_value: biased,
            biased_c1: false,
            precision_lost: false,
        }),
    };

    assert_eq!(commit_register_math_result(&mut state, result), Some((biased, false)));
    assert_eq!(state.status_word & underflow_flag, underflow_flag);
    assert_eq!(state.status_word & X87_PE, 0);
}

#[test]
fn unmasked_precompute_invalid_suppresses_register_range_commit() {
    let mut state = X87State::default();
    state.control_word &= !(X87_IE | (1 << 3)); // unmask IE and OE
    let biased = Ext80 { significand: 1 << 63, sign_exponent: 0x2000 };
    let result = MathResult {
        value: Ext80::default(),
        exceptions: X87_IE | X87_OE | X87_PE,
        c1: false,
        range: Some(RegisterRangeResult {
            kind: RegisterRangeKind::Overflow,
            biased_value: biased,
            biased_c1: true,
            precision_lost: true,
        }),
    };

    assert_eq!(commit_register_math_result(&mut state, result), None);
    assert_eq!(state.status_word & X87_IE, X87_IE);
    assert_eq!(state.status_word & (X87_OE | X87_PE), 0);
}
