use super::{ProfileSectionOutput, encode_profile_output};
use crate::windows::guest_text::GuestTextCodec;
use windows_sys::Win32::Globalization::CP_UTF8;

fn utf8_codec() -> GuestTextCodec {
    GuestTextCodec::new(CP_UTF8).expect("Windows provides UTF-8 code-page conversion")
}

fn encode(
    codec: GuestTextCodec,
    source: &[u16],
    native_truncated: bool,
    capacity: usize,
) -> ProfileSectionOutput {
    encode_profile_output(codec, source, native_truncated, vec![0; capacity])
        .expect("profile output conversion succeeds")
}

#[test]
fn exact_capacity_preserves_the_complete_final_entry() {
    let source = [97, 61, 98, 0];
    let output = encode(utf8_codec(), &source, false, 5);
    assert_eq!(output.buffer, b"a=b\0\0");
    assert_eq!(output.copied, 4);
}

#[test]
fn complete_multisz_keeps_each_separator_and_final_entry_nul_in_count() {
    let codec = utf8_codec();
    let source = codec
        .to_wide("first=1\0second=你好\0".as_bytes())
        .expect("guest MULTI_SZ decodes");

    let output = encode(codec, &source, false, 40);
    let expected = "first=1\0second=你好\0".as_bytes();

    assert_eq!(usize::from(output.copied), expected.len());
    assert_eq!(&output.buffer[..expected.len()], expected);
    assert_eq!(output.buffer[expected.len()], 0);
}

#[test]
fn guest_multibyte_truncation_keeps_a_scalar_boundary_and_double_nul() {
    let codec = utf8_codec();
    let source = codec
        .to_wide("A🍎B\0".as_bytes())
        .expect("guest MULTI_SZ decodes");

    // Four content bytes are available, but A plus the four-byte scalar does
    // not fit before the entry NUL. The UTF-8 scalar is omitted as a whole.
    let output = encode(codec, &source, false, 6);

    assert_eq!(output.copied, 4);
    assert_eq!(&output.buffer[..3], &[b'A', 0, 0]);
}

#[test]
fn native_truncation_clips_a_dangling_high_surrogate_and_uses_guest_sentinel() {
    let codec = utf8_codec();
    let source = [b'A' as u16, 0xD83D];

    let output = encode(codec, &source, true, 10);

    assert_eq!(output.copied, 8);
    assert_eq!(&output.buffer[..3], &[b'A', 0, 0]);
}

#[test]
fn capacities_zero_one_and_two_have_explicit_empty_multisz_results() {
    let codec = utf8_codec();
    let source = codec.to_wide(b"entry\0").expect("guest text decodes");

    for (capacity, expected) in [(0, &[][..]), (1, &[0][..]), (2, &[0, 0][..])] {
        let output = encode(codec, &source, false, capacity);

        assert_eq!(output.copied, 0);
        assert_eq!(output.buffer, expected);
    }
}
