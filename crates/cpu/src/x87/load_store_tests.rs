use super::{
    commit_rounded_store, decode_packed_bcd, encode_packed_bcd,
    encode_packed_bcd_with_sign, packed_bcd_to_ext80, BCD_INDEFINITE,
};
use crate::x87_math::{X87_OE, X87_PE};
use crate::x87_state::{Ext80, X87State, X87_C1};

#[test]
fn packed_bcd_uses_byte_nibbles_and_sign_bit_79() {
    let mut encoded = [0_u8; 10];
    encoded[0] = 0x45;
    encoded[1] = 0x23;
    encoded[2] = 0x01;
    encoded[9] = 0x80;

    assert_eq!(decode_packed_bcd(&encoded), -12_345);
    assert_eq!(encode_packed_bcd(-12_345), Some(encoded));
}

#[test]
fn packed_bcd_invalid_result_uses_architectural_indefinite_encoding() {
    assert_eq!(encode_packed_bcd(1_000_000_000_000_000_000), None);
    assert_eq!(BCD_INDEFINITE, [0, 0, 0, 0, 0, 0, 0, 0xc0, 0xff, 0xff]);
}

#[test]
fn packed_bcd_preserves_signed_zero_on_load_and_store() {
    let mut encoded = [0_u8; 10];
    encoded[9] = 0x80;
    assert_eq!(decode_packed_bcd(&encoded), 0);
    assert_eq!(
        packed_bcd_to_ext80(&encoded),
        Ext80 { significand: 0, sign_exponent: 0x8000 },
    );

    assert_eq!(
        encode_packed_bcd_with_sign(0, true),
        Some(encoded),
    );
    assert_eq!(
        encode_packed_bcd_with_sign(0, false),
        Some([0; 10]),
    );
}

#[test]
fn unmasked_store_overflow_clears_c1_and_does_not_commit_precision() {
    let mut state = X87State::default();
    state.control_word &= !(X87_OE | X87_PE);
    state.status_word |= X87_C1;

    assert!(!commit_rounded_store(&mut state, X87_OE | X87_PE, true));
    assert_eq!(state.status_word & X87_C1, 0);
    assert_eq!(state.status_word & X87_OE, X87_OE);
    assert_eq!(state.status_word & X87_PE, 0);
}

#[test]
fn masked_store_overflow_with_unmasked_precision_can_commit() {
    let mut state = X87State::default();
    state.control_word &= !X87_PE;

    assert!(commit_rounded_store(&mut state, X87_OE | X87_PE, true));
    assert_eq!(state.status_word & (X87_OE | X87_PE), X87_OE | X87_PE);
    assert_ne!(state.status_word & X87_C1, 0);
}
