use super::{guest_wide_z_required, wide_output_text, write_guest_string};
use crate::windows::guest_text::GuestTextCodec;

#[test]
fn ver_wide_paths_decode_using_the_fixed_guest_page() {
    let codec = GuestTextCodec::new(932).expect("Windows-932 is installed");
    let path =
        guest_wide_z_required(codec, b"\x93\xfa.txt", "test path").expect("decode guest path");
    assert_eq!(path, "日.txt\0".encode_utf16().collect::<Vec<_>>());
    // Legacy DBCS pages use the codec's Windows replacement semantics for an
    // incomplete character; a VER path must not impose a separate decoder.
    let mut expected = codec
        .to_wide(b"\x93")
        .expect("decode incomplete guest text");
    expected.push(0);
    assert_eq!(
        guest_wide_z_required(codec, b"\x93", "incomplete path").unwrap(),
        expected
    );
}

#[test]
fn ver_output_counts_guest_bytes_and_never_splits_dbcs_characters() {
    let codec = GuestTextCodec::new(932).expect("Windows-932 is installed");
    let text = [0x65e5_u16]; // 日
    let mut short = [0xCC_u8; 2];
    let (required, truncated) =
        write_guest_string(codec, &text, &mut short, "test VerLanguageName output")
            .expect("encode bounded guest output");
    assert_eq!(required, 3); // two guest bytes plus NUL
    assert!(truncated);
    assert_eq!(short, [0, 0xCC]);

    let mut enough = [0xCC_u8; 4];
    let (required, truncated) =
        write_guest_string(codec, &text, &mut enough, "test VerLanguageName output")
            .expect("encode complete guest output");
    assert_eq!(required, 3);
    assert!(!truncated);
    assert_eq!(enough, [0x93, 0xFA, 0, 0xCC]);
}

#[test]
fn ver_wide_length_includes_the_native_nul_without_returning_it_as_text() {
    let native = [0x65e5_u16, 0];
    assert_eq!(
        wide_output_text(&native, 2, "test VER output").expect("parse output"),
        &[0x65e5]
    );
    let empty: &[u16] = &[];
    assert_eq!(
        wide_output_text(&[0_u16], 0, "empty VER output").expect("empty output"),
        empty
    );
    assert!(wide_output_text(&[0x65e5], 1, "unterminated VER output").is_err());
}
