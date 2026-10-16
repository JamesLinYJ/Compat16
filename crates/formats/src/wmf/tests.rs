use super::*;

fn record(function: u16, words: &[u16]) -> Vec<u8> {
    let mut bytes = ((words.len() + 3) as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(&function.to_le_bytes());
    for word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}
fn stream(records: &[Vec<u8>], objects: u16) -> Vec<u8> {
    let length = 18 + records.iter().map(Vec::len).sum::<usize>();
    let mut bytes = vec![0; 18];
    bytes[..2].copy_from_slice(&1u16.to_le_bytes());
    bytes[2..4].copy_from_slice(&9u16.to_le_bytes());
    bytes[4..6].copy_from_slice(&0x300u16.to_le_bytes());
    bytes[6..10].copy_from_slice(&((length / 2) as u32).to_le_bytes());
    bytes[10..12].copy_from_slice(&objects.to_le_bytes());
    for r in records {
        bytes.extend_from_slice(r);
    }
    bytes
}
#[test]
fn wmf_iterator_checks_actual_maximum_and_preserves_allocation_padding() {
    let mut bytes = stream(&[record(0x0214, &[1, 2]), record(0, &[])], 3);
    bytes[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    let logical = bytes.len();
    bytes.extend_from_slice(&[0xff; 18]);
    let parsed = parse_wmf(&bytes).unwrap();
    assert_eq!(parsed.header().object_count, 3);
    assert_eq!(parsed.header().declared_maximum_record_words, u32::MAX);
    assert_eq!(parsed.maximum_record_words(), 5);
    assert_eq!(parsed.bytes().len(), logical);
    let mut records = parsed.records();
    assert_eq!(records.len(), 2);
    let first = records.next().unwrap();
    assert_eq!(first.offset(), 18);
    assert_eq!(first.parameters(), &[1, 0, 2, 0]);
    assert!(records.next().unwrap().is_end());
    assert!(records.next().is_none());
    assert!(records.next().is_none());
}
#[test]
fn wmf_rejects_truncation_bad_lengths_and_early_or_missing_end() {
    let bytes = stream(&[record(0x0214, &[1, 2]), record(0, &[])], 0);
    for size in 0..bytes.len() {
        assert!(parse_wmf(&bytes[..size]).is_err(), "size {size}");
    }
    for size in [0, 1, 2, u32::MAX] {
        let mut bad = bytes.clone();
        bad[18..22].copy_from_slice(&size.to_le_bytes());
        assert!(parse_wmf(&bad).is_err());
    }
    assert!(parse_wmf(&stream(&[record(0, &[]), record(0, &[])], 0)).is_err());
    assert!(parse_wmf(&stream(&[record(0, &[1])], 0)).is_err());
    assert!(parse_wmf(&stream(&[record(0x0214, &[1, 2])], 0)).is_err());
}
#[test]
fn wmf_rejects_header_layout_aliases_and_reports_escape_low_byte() {
    let bytes = stream(&[record(0x9926, &[]), record(0, &[])], 0);
    assert!(parse_wmf(&bytes).unwrap().has_escape());
    for (offset, value) in [(0, 0), (0, 3), (2, 8), (4, 0x200)] {
        let mut bad = bytes.clone();
        bad[offset..offset + 2].copy_from_slice(&u16::to_le_bytes(value));
        assert!(parse_wmf(&bad).is_err());
    }
}
#[test]
fn wmf_record_requires_exact_framing_and_fixed_parameter_extents() {
    let good = record(0x0214, &[1, 2]);
    assert!(validate_wmf_record_playback(&good, 0).is_ok());
    assert!(validate_wmf_record_playback(&record(0x0214, &[1]), 0).is_err());
    assert!(validate_wmf_record_playback(&record(0x9914, &[1, 2]), 0).is_err());
    let mut bad = good.clone();
    bad.extend_from_slice(&[0, 0]);
    assert!(parse_wmf_record(&bad).is_err());
    assert!(validate_wmf_record_playback(&record(0x02fa, &[0; 4]), 1).is_err());
    assert!(
        validate_wmf_record_playback(&record(0x02fa, &[0; 5]), 1)
            .unwrap()
            .creates_object
    );
}
#[test]
fn wmf_record_text_bounds_cover_padding_rectangles_and_spacing() {
    assert!(validate_wmf_record_playback(&record(0x0521, &[3, 0x4241, 0x43, 1, 2]), 0).is_ok());
    assert!(validate_wmf_record_playback(&record(0x0521, &[4, 0x4241, 1, 2]), 0).is_err());
    let good = [1, 2, 3, 6, 0, 0, 10, 10, 0x4241, 0x43];
    assert!(validate_wmf_record_playback(&record(0x0a32, &good), 0).is_ok());
    let mut short_dx = good.to_vec();
    short_dx.push(1);
    assert!(validate_wmf_record_playback(&record(0x0a32, &short_dx), 0).is_err());
    short_dx.extend_from_slice(&[2, 3]);
    assert!(validate_wmf_record_playback(&record(0x0a32, &short_dx), 0).is_ok());
}
#[test]
fn wmf_record_polygon_counts_and_table_indices_are_checked() {
    assert!(validate_wmf_record_playback(&record(0x0324, &[2, 0, 0, 1, 1]), 0).is_ok());
    assert!(validate_wmf_record_playback(&record(0x0324, &[u16::MAX, 0, 0]), 0).is_err());
    assert!(validate_wmf_record_playback(&record(0x0538, &[2, 1, 1, 0, 0, 1, 1]), 0).is_ok());
    assert!(validate_wmf_record_playback(&record(0x0538, &[2, 1, u16::MAX, 0, 0]), 0).is_err());
    assert!(validate_wmf_record_playback(&record(0x012d, &[1]), 1).is_err());
    assert!(validate_wmf_record_playback(&record(0x012d, &[0x8007]), 0).is_ok());
    assert!(validate_wmf_record_playback(&record(0x0228, &[0, 1]), 1).is_err());
    assert!(validate_wmf_record_playback(&record(0x01f0, &[0]), 1).is_ok());
}
#[test]
fn wmf_record_nested_handle_payloads_never_reach_pointer_only_native_api() {
    for function in [0x0626, 0x9926, 0x0940, 0x0142, 0x0149, 0x06ff] {
        assert_eq!(
            validate_wmf_record_playback(&record(function, &[0; 32]), 1),
            Err(WmfPlaybackError::Unsupported(function))
        );
    }
    assert_eq!(
        validate_wmf_record_playback(&record(0x02fc, &[3, 0, 0, 0xffff]), 1),
        Err(WmfPlaybackError::Unsupported(0x02fc))
    );
    assert!(
        validate_wmf_record_playback(&record(0x7777, &[]), 0)
            .unwrap()
            .ignored
    );
}
