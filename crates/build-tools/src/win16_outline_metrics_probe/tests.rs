use super::*;
use formats::{NeFixupAddressType, NeFixupTarget, parse_ne};

#[test]
fn outline_metrics_probe_has_owned_bounded_segments_and_exact_imports() {
    let image = win16_outline_metrics_probe_bytes().unwrap();
    assert_eq!(image, win16_outline_metrics_probe_bytes().unwrap());
    let module = parse_ne(&image).unwrap();
    assert_eq!(module.header.initial_cs, 1);
    assert_eq!(module.header.initial_ss, 2);
    assert_eq!(module.header.automatic_data_segment, 2);
    assert_eq!(module.header.initial_sp, 4096);
    assert_eq!(module.segments.len(), 2);
    assert!(module.resource_types.is_empty());
    assert_eq!(module.imported_modules.len(), 1);
    assert_eq!(module.imported_modules[0].name, b"GDI");
    let code = &module.segments[0];
    let data = &module.segments[1];
    assert_eq!(data.file_size, 2306);
    let data_start = data.file_offset.unwrap();
    assert_eq!(&image[data_start..data_start + 2306], &[0; 2306]);
    let code_start = code.file_offset.unwrap();
    let code_end = code_start + code.file_size as usize;
    let ordinals = [52, 330, 57, 45, 308, 308, 308, 45, 69, 68];
    assert_eq!(code.fixups.len(), ordinals.len());
    assert!(code_end + 2 + 8 * ordinals.len() <= data_start);
    for (fixup, ordinal) in code.fixups.iter().zip(ordinals) {
        assert_eq!(fixup.address_type, NeFixupAddressType::FarPointer32);
        assert_eq!(fixup.target, NeFixupTarget::ImportOrdinal { module_index: 1, ordinal });
        assert!(!fixup.additive);
        let source = code_start + usize::from(fixup.source_offset);
        assert_eq!(image[source - 1], 0x9a);
        assert_eq!(&image[source..source + 4], &[0xff, 0xff, 0, 0]);
        assert!(source + 4 <= code_end);
    }
}

#[test]
fn outline_metrics_guest_encodes_real_pascal_calls_and_distinct_failure_paths() {
    let (code, fixups) = guest_code().unwrap();
    let contains = |bytes: &[u8]| code.windows(bytes.len()).any(|window| window == bytes);
    let call = |index: usize| usize::from(u16::from_le_bytes([fixups[index][2], fixups[index][3]])) - 1;
    assert_eq!(&code[call(4) - 10..call(4)], &[0xff, 0x36, 0, 0, 0x6a, 0, 0x6a, 0, 0x6a, 0]);
    for (index, count, buffer) in [(5, PARTIAL, 128u16), (6, CAPACITY, FULL)] {
        let mut expected = vec![0xff, 0x36, 0, 0, 0x68];
        expected.extend_from_slice(&count.to_le_bytes());
        expected.extend_from_slice(&[0x1e, 0x68]);
        expected.extend_from_slice(&buffer.to_le_bytes());
        assert_eq!(&code[call(index) - expected.len()..call(index)], &expected);
    }
    assert!(contains(&[0x66, 0x3d, 1, 0, 0x34, 0x12]));
    assert!(contains(&[0xc4, 0x76, 16, 0xbf, 32, 0, 0xb9, 50, 0]));
    assert!(contains(&[0xb8, 1, 0, 0xf7, 0x46, 10, 4, 0]));
    assert_eq!(&code[code.len() - 9..], &[0x5f, 0x5e, 0x5b, 0x07, 0x1f, 0x5d, 0xca, 14, 0]);
    for status in (20..=46).chain(60..=68) {
        assert!(contains(&[0xc7, 0x06, 4, 0, status, 0]), "missing assertion {status}");
    }
    assert!(contains(&[0xc7, 0x06, 4, 0, 77, 0])); // no fonts cannot pass
    assert!(contains(&[0xc7, 0x06, 16, 0, b'O', b'0']));
    assert!(contains(&[0xc7, 0x06, 16, 0, b'O', b'1']));
    assert!(contains(&[0xc7, 0x06, 20, 0, b'Q', b'0']));
    assert!(contains(&[0xf6, 0x06, 10, 0, 1])); // measured unrounded query parity
    assert!(contains(&[0xc6, 0x06, 21, 0, b'1']));
}

#[test]
fn outline_metrics_guest_checks_packed_relative_layout_and_caller_canaries() {
    let (code, _) = guest_code().unwrap();
    let contains = |bytes: &[u8]| code.windows(bytes.len()).any(|window| window == bytes);
    for bytes in [
        &[0x81, 0x3e, 106, 1, 114, 0][..], // first name: packed header length
        &[0xa1, 10, 0, 0x40, 0x25, 0xfe, 0xff, 0x3b, 0x06, 0, 1],
        &[0xbe, 128, 0, 0xbf, 0, 1, 0xb9, 113, 0, 0xfc, 0xf3, 0xa6],
        &[0x8b, 0x4d, 2], // bound names by next relative offset
        &[0x36, 0x3b, 0x26, 12, 0], // independently saved SP
        &[0x8c, 0xd8, 0x36, 0x3b, 0x06, 14, 0],
        &[0x8c, 0xc0, 0x36, 0x3b, 0x06, 14, 0],
        &[0x80, 0x3c, 0xa5], // full-buffer unrequested tail
    ] { assert!(contains(bytes), "missing assertion {bytes:x?}"); }
}
