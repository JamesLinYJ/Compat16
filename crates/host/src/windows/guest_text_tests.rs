use super::*;

#[test]
fn symbolic_host_pages_are_rejected() {
    for page in [CP_ACP, CP_OEMCP, CP_MACCP, CP_THREAD_ACP] {
        assert!(GuestTextCodec::new(page).is_err());
    }
}

#[test]
fn explicit_single_byte_page_preserves_embedded_nuls_and_offsets() {
    let codec = GuestTextCodec::new(1252).unwrap();
    let source = [b'A', 0, 0xe9];
    let (wide, spans) = codec.to_wide_with_ranges(&source).unwrap();
    assert_eq!(wide, [0x41, 0, 0xe9]);
    assert_eq!(spans.len(), 3);
    for (index, span) in spans.iter().enumerate() {
        assert_eq!(span.guest_bytes, index..index + 1);
        assert_eq!(span.utf16_units, index..index + 1);
    }
    assert_eq!(codec.from_wide(&wide).unwrap().bytes, source);
}

#[test]
fn dbcs_ranges_preserve_byte_offsets_across_nul() {
    let codec = GuestTextCodec::new(936).unwrap();
    let source = [0xd6, 0xd0, 0, 0xce, 0xc4];
    let (wide, spans) = codec.to_wide_with_ranges(&source).unwrap();
    assert_eq!(wide, "中\0文".encode_utf16().collect::<Vec<_>>());
    assert_eq!(spans[0].guest_bytes, 0..2);
    assert_eq!(spans[1].guest_bytes, 2..3);
    assert_eq!(spans[2].guest_bytes, 3..5);
    assert_eq!(spans[2].utf16_units, 2..3);
}

#[test]
fn utf8_ranges_keep_surrogate_pairs_together() {
    let codec = GuestTextCodec::new(CP_UTF8).unwrap();
    let (wide, spans) = codec.to_wide_with_ranges("A😀中".as_bytes()).unwrap();
    assert_eq!(wide.len(), 4);
    assert_eq!(spans[1].guest_bytes, 1..5);
    assert_eq!(spans[1].utf16_units, 1..3);
    assert_eq!(spans[2].guest_bytes, 5..8);
}

#[test]
fn bounded_dbcs_output_never_splits_a_character() {
    let codec = GuestTextCodec::new(936).unwrap();
    let wide = "中文".encode_utf16().collect::<Vec<_>>();
    let short = codec.from_wide_bounded(&wide, 1).unwrap();
    assert!(short.bytes.is_empty());
    assert!(short.truncated);
    let exact = codec.from_wide_bounded(&wide, 2).unwrap();
    assert_eq!(exact.bytes, [0xd6, 0xd0]);
    assert_eq!(exact.source_utf16_units, 1);
    assert!(exact.truncated);
    assert_eq!(
        codec.from_wide_bounded(&wide, 4).unwrap().bytes,
        [0xd6, 0xd0, 0xce, 0xc4]
    );
}

#[test]
fn utf8_output_never_splits_a_surrogate_pair() {
    let codec = GuestTextCodec::new(CP_UTF8).unwrap();
    let wide = "😀A".encode_utf16().collect::<Vec<_>>();
    assert!(codec.from_wide_bounded(&wide, 3).unwrap().bytes.is_empty());
    let exact = codec.from_wide_bounded(&wide, 4).unwrap();
    assert_eq!(exact.bytes, "😀".as_bytes());
    assert_eq!(exact.source_utf16_units, 2);
}
