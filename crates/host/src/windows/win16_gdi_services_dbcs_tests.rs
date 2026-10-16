//! Numeric-character conversion checks using Windows NLS, without font queries.

use super::{guest_character_from_wide, guest_character_range};
use crate::windows::guest_text::GuestTextCodec;

#[test]
fn abc_numeric_dbcs_codes_decode_lead_byte_first() {
    for (page, code, character) in [
        (932, 0x82a0, 0x3042),
        (936, 0xd6d0, 0x4e2d),
        (949, 0xb0a1, 0xac00),
        (950, 0xa440, 0x4e00),
    ] {
        let codec = GuestTextCodec::new(page).unwrap();
        assert_eq!(
            guest_character_range(codec, code, code),
            Some(vec![character]),
            "code page {page}, numeric character {code:#06x}",
        );
    }
}

#[test]
fn abc_numeric_ranges_preserve_guest_character_order() {
    let codec = GuestTextCodec::new(932).unwrap();
    assert_eq!(
        guest_character_range(codec, 0x8140, 0x8142),
        Some(vec![0x3000, 0x3001, 0x3002]),
    );
    assert_eq!(
        guest_character_range(codec, 0x82a0, 0x82a2),
        Some(vec![0x3042, 0x3043, 0x3044]),
    );
    // Loading DBCS string bytes 81 40 as a little-endian WORD is not a
    // numeric GDI character code. Its decoded bytes 40 81 are not one character.
    assert_eq!(guest_character_range(codec, 0x4081, 0x4081), None);
    assert_eq!(guest_character_range(codec, 0x8142, 0x8140), None);
}

#[test]
fn kerning_numeric_dbcs_codes_pack_lead_byte_high() {
    for (page, character, code) in [
        (932, 0x3042, 0x82a0),
        (936, 0x4e2d, 0xd6d0),
        (949, 0xac00, 0xb0a1),
        (950, 0x4e00, 0xa440),
    ] {
        let codec = GuestTextCodec::new(page).unwrap();
        let actual = guest_character_from_wide(codec, character);
        assert_eq!(actual, Some(code), "code page {page}, Unicode {character:#06x}");
        assert_eq!(
            guest_character_range(codec, actual.unwrap(), actual.unwrap()),
            Some(vec![character]),
        );
    }
}

#[test]
fn numeric_sbcs_codes_keep_existing_mappings() {
    let western = GuestTextCodec::new(1252).unwrap();
    for (code, character) in [(0, 0), (0x41, 0x41), (0x80, 0x20ac), (0x81, 0x81), (0xff, 0xff)] {
        assert_eq!(guest_character_range(western, code, code), Some(vec![character]));
        assert_eq!(guest_character_from_wide(western, character), Some(code));
    }
    assert_eq!(
        guest_character_range(western, 0x41, 0x43),
        Some(vec![0x41, 0x42, 0x43]),
    );
    let japanese = GuestTextCodec::new(932).unwrap();
    assert_eq!(guest_character_range(japanese, 0xa6, 0xa6), Some(vec![0xff66]));
    assert_eq!(guest_character_from_wide(japanese, 0xff66), Some(0xa6));
}

#[test]
fn numeric_conversion_retains_existing_replacement_policy() {
    let japanese = GuestTextCodec::new(932).unwrap();
    // ABC decoding retains the general text codec's replacement policy;
    // changing numeric byte order must not adopt GetCharWidth's strict decoder.
    let expected = japanese.to_wide(&[0x81]).ok().filter(|wide| wide.len() == 1);
    assert_eq!(guest_character_range(japanese, 0x81, 0x81), expected);
    // Kerning projection continues to omit characters requiring substitution.
    let western = GuestTextCodec::new(1252).unwrap();
    assert_eq!(guest_character_from_wide(western, 0x4e2d), None);
}
