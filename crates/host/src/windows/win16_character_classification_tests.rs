//! Native NLS contract tests; no windows or global locale mutations.
use super::*;
use runtime::Win16CharacterClassification as Classification;

const CLASSIFICATIONS: [Classification; 4] = [
    Classification::Alpha, Classification::AlphaNumeric, Classification::Upper, Classification::Lower,
];

fn native(character: u16, classification: Classification) -> bool {
    // SAFETY: The predicates take a UTF-16 scalar value, not a pointer.
    unsafe {
        (match classification {
            Classification::Alpha => IsCharAlphaW(character),
            Classification::AlphaNumeric => IsCharAlphaNumericW(character),
            Classification::Upper => IsCharUpperW(character),
            Classification::Lower => IsCharLowerW(character),
        }) != 0
    }
}

#[test]
fn character_classification_ascii_case_digit_punctuation_and_nul() {
    let codec = GuestTextCodec::new(1252).unwrap();
    for (byte, expected) in [
        (b'A', [true, true, true, false]),
        (b'a', [true, true, false, true]),
        (b'7', [false, true, false, false]),
        (b'!', [false, false, false, false]),
        (0, [false, false, false, false]),
    ] {
        for (classification, expected) in CLASSIFICATIONS.into_iter().zip(expected) {
            assert_eq!(classify_character(codec, byte, classification).unwrap(), expected,
                "byte {byte:#x}, {classification:?}");
        }
    }
}

#[test]
fn character_classification_uses_fixed_code_page_and_observed_native_predicates() {
    for (page, bytes) in [
        // Accents and letters which differ from historical English Win16
        // tables deliberately follow modern Windows NLS after codec decoding.
        (1252, &[0xc9, 0xe9, 0xaa, 0xb5, 0xba, 0x8e, 0x9e, 0x81][..]),
        // Half-width katakana, plus a lone DBCS lead. Do not hard-code false
        // for lead/undefined bytes: observe the established codec policy.
        (932, &[0xa6, 0xb1, 0x81][..]),
    ] {
        let codec = GuestTextCodec::new(page).unwrap();
        for &byte in bytes {
            let wide = codec.to_wide(&[byte]).unwrap();
            assert_eq!(wide.len(), 1, "page {page}, byte {byte:#x}");
            for classification in CLASSIFICATIONS {
                assert_eq!(classify_character(codec, byte, classification).unwrap(),
                    native(wide[0], classification), "page {page}, byte {byte:#x}, {classification:?}");
            }
        }
    }
    let cp1252 = GuestTextCodec::new(1252).unwrap();
    assert!(classify_character(cp1252, 0xc9, Classification::Upper).unwrap());
    assert!(classify_character(cp1252, 0xe9, Classification::Lower).unwrap());
}

#[test]
fn character_classification_preserves_strict_codec_errors() {
    for page in [65001, 54936] {
        let codec = GuestTextCodec::new(page).unwrap();
        let expected = codec.to_wide(&[0x81]).unwrap_err();
        for classification in CLASSIFICATIONS {
            let actual = classify_character(codec, 0x81, classification).unwrap_err();
            assert_eq!(actual.kind(), expected.kind());
            assert_eq!(actual.to_string(), expected.to_string());
        }
    }
}
