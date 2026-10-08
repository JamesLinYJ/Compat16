use super::*;

#[test]
fn cp437_uses_oem_mapping_and_rejects_unrepresentable_text() {
    let encoded = encode("π≈22/7", CodePage::Cp437).expect("CP437 encoding");
    assert_eq!(encoded, vec![0xe3, 0xf7, b'2', b'2', b'/', b'7']);
    assert_eq!(decode(&encoded, CodePage::Cp437).expect("CP437 decoding"), "π≈22/7");
    assert!(matches!(encode("中文", CodePage::Cp437), Err(TextError::UnrepresentableText { .. })));
}

#[test]
fn cp936_round_trips_known_simplified_chinese_bytes() {
    let bytes = [0xd6, 0xd0, 0xce, 0xc4]; // “中文” in GBK/CP936.
    assert_eq!(decode(&bytes, CodePage::Cp936).expect("CP936 decoding"), "中文");
    assert_eq!(encode("中文", CodePage::Cp936).expect("CP936 encoding"), bytes.to_vec());
}

#[test]
fn cp936_stream_keeps_a_split_chinese_pair_between_writes() {
    let mut decoder = StreamDecoder::new(CodePage::Cp936);
    assert_eq!(decoder.push(&[0xd6], false).expect("split lead"), "");
    assert_eq!(decoder.push(&[0xd0, 0xce], false).expect("complete first pair"), "中");
    assert_eq!(decoder.push(&[0xc4], true).expect("complete final pair"), "文");
    assert_eq!(decoder.push(&[], true), Err(TextError::StreamFinished));
}

#[test]
fn malformed_and_unrepresentable_cp936_data_are_errors() {
    assert!(matches!(decode(&[0x81, b'0'], CodePage::Cp936), Err(TextError::MalformedInput { .. })));
    assert!(matches!(decode(&[0xd6], CodePage::Cp936), Err(TextError::MalformedInput { .. })));
    assert!(matches!(encode("😀", CodePage::Cp936), Err(TextError::UnrepresentableText { .. })));

    let mut decoder = StreamDecoder::new(CodePage::Cp936);
    assert_eq!(decoder.push(&[0xd6], false).expect("buffer lead"), "");
    assert!(matches!(decoder.push(&[], true), Err(TextError::MalformedInput { .. })));
    assert_eq!(decoder.push(b"ignored", false), Err(TextError::StreamFailed));
}

#[test]
fn row_decoding_preserves_dbcs_byte_positions_without_cross_row_pairing() {
    let row = decode_text_row(b"A\xd6\xd0B", CodePage::Cp936).expect("valid row");
    assert_eq!(row.len(), 4);
    assert_eq!(row[0], DecodedCell { byte_index: 0, character: Some('A'), role: CellRole::Single });
    assert_eq!(row[1], DecodedCell { byte_index: 1, character: Some('中'), role: CellRole::Lead });
    assert_eq!(row[2], DecodedCell { byte_index: 2, character: None, role: CellRole::Trail });
    assert_eq!(row[3], DecodedCell { byte_index: 3, character: Some('B'), role: CellRole::Single });
    assert!(matches!(decode_text_row(&[0xd6], CodePage::Cp936), Err(TextError::IncompleteSequence { byte_index: 0, .. })));
    assert!(matches!(decode_text_row(&[0xd6, b'0'], CodePage::Cp936), Err(TextError::MalformedInput { byte_index: Some(0), .. })));
}

#[test]
fn only_the_documented_code_pages_are_accepted() {
    assert_eq!(CodePage::try_from(437_u16), Ok(CodePage::Cp437));
    assert_eq!(CodePage::try_from(936_u32), Ok(CodePage::Cp936));
    assert_eq!(CodePage::try_from(932_u32), Err(TextError::UnsupportedCodePage(932)));
}

#[test]
fn text_errors_display_code_page_offsets_and_readable_causes() {
    assert_eq!(
        TextError::UnsupportedCodePage(932).to_string(),
        "unsupported Windows code page 932"
    );
    assert_eq!(
        TextError::MalformedInput { code_page: CodePage::Cp936, byte_index: Some(4) }.to_string(),
        "malformed input sequence for code page 936 at byte offset 4"
    );
    assert_eq!(
        TextError::IncompleteSequence { code_page: CodePage::Cp936, byte_index: 7 }.to_string(),
        "incomplete input sequence for code page 936 at byte offset 7"
    );
    assert_eq!(
        TextError::UnrepresentableText { code_page: CodePage::Cp437 }.to_string(),
        "text contains characters that cannot be represented in code page 437"
    );

    for error in [
        TextError::StreamFinished,
        TextError::StreamFailed,
        TextError::OutputTooLarge,
        TextError::AllocationFailed,
    ] {
        let message = error.to_string();
        assert!(!message.contains('{'));
        assert!(!message.contains("TextError"));
    }
}

#[test]
fn encoded_character_ranges_keep_gbk_trail_backslash_out_of_ascii_matching() {
    let bytes = [0x81, b'\\', b'\\', b'/', b'.', b'*', b'?'];
    let characters = encoded_characters(&bytes, CodePage::Cp936)
        .collect::<Result<Vec<_>, _>>()
        .expect("valid GBK text");

    assert_eq!(characters[0].byte_range, 0..2);
    assert!(!characters[0].is_standalone_ascii(b'\\'));
    assert_eq!(characters[1].byte_range, 2..3);
    assert!(characters[1].is_standalone_ascii(b'\\'));
    for (index, byte) in [(2, b'/'), (3, b'.'), (4, b'*'), (5, b'?')] {
        assert_eq!(characters[index].byte_range.len(), 1);
        assert!(characters[index].is_standalone_ascii(byte));
    }
}

#[test]
fn oem_uppercase_uses_dos_mapping_and_preserves_dbcs_trail_bytes() {
    let cp936 = [b'a', 0x81, b'a', b'z'];
    assert_eq!(
        uppercase_oem_name(&cp936, CodePage::Cp936).expect("uppercase CP936 name"),
        vec![b'A', 0x81, b'a', b'Z']
    );

    // Microsoft DOS retains sharp s but maps y-diaeresis to ASCII Y and
    // e-acute to E. Unicode uppercasing alone does not have these DOS rules.
    let cp437 = [b'a', 0xe1, 0x98, 0x82];
    assert_eq!(
        uppercase_oem_name(&cp437, CodePage::Cp437).expect("uppercase CP437 name"),
        vec![b'A', 0xe1, b'Y', b'E']
    );
    assert!(matches!(
        uppercase_oem_name(&[0xd6], CodePage::Cp936),
        Err(TextError::IncompleteSequence { code_page: CodePage::Cp936, byte_index: 0 })
    ));
}

#[test]
fn filename_case_mapping_matches_every_byte_of_the_guest_nls_table() {
    let input: Vec<u8> = (0..=255).collect();
    let output = uppercase_oem_name(&input, CodePage::Cp437).unwrap();
    let table = dos_code_page_tables(CodePage::Cp437).unwrap();
    assert_eq!(&table.uppercase_record()[..2], &[128, 0]);
    assert_eq!(&output[0x80..], &table.uppercase_record()[2..]);
    for byte in 0..128u8 { assert_eq!(output[usize::from(byte)], byte.to_ascii_uppercase()); }
    assert!(dos_code_page_tables(CodePage::Cp936).is_none());
}
