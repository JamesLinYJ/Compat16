//! Numeric DBCS codes remain ordinary little-endian WORDs in guest memory.

use super::{encode_abc_widths, encode_kerning_pairs};
use crate::{Win16HostAbcWidth, Win16HostKerningPair};

#[test]
fn kerning_numeric_codes_keep_little_endian_six_byte_guest_records() {
    let entries = [
        Win16HostKerningPair { first: 0x82a0, second: 0xb0a1, amount: -9 },
        Win16HostKerningPair { first: 0x0041, second: 0x0080, amount: 7 },
    ];
    assert_eq!(
        encode_kerning_pairs(&entries),
        Some(vec![0xa0, 0x82, 0xa1, 0xb0, 0xf7, 0xff, 0x41, 0x00, 0x80, 0x00, 0x07, 0x00]),
    );
}

#[test]
fn abc_widths_keep_signed_unsigned_six_byte_guest_layout() {
    let entries = [Win16HostAbcWidth { abc_a: -3, abc_b: 0x8000, abc_c: -5 }];
    assert_eq!(encode_abc_widths(&entries), Some(vec![0xfd, 0xff, 0x00, 0x80, 0xfb, 0xff]));
}
