use super::win16_user_queries_probe_bytes;
use formats::{NeFixupAddressType, NeFixupTarget, parse_ne};

#[test]
fn user_queries_ne_serializes_exact_read_only_imports_and_bounded_segments() {
    let image = win16_user_queries_probe_bytes().unwrap();
    assert_eq!(image, win16_user_queries_probe_bytes().unwrap());
    let module = parse_ne(&image).unwrap();
    assert_eq!(module.header.initial_cs, 1);
    assert_eq!(module.header.initial_ss, 2);
    assert_eq!(module.header.automatic_data_segment, 2);
    assert_eq!(module.header.initial_sp, 0x1000);
    assert_eq!(module.segments.len(), 2);
    assert_eq!(module.imported_modules.len(), 1);
    assert_eq!(module.imported_modules[0].name, b"USER");
    assert!(module.resource_types.is_empty());
    let code = &module.segments[0];
    let data = &module.segments[1];
    assert_eq!(data.file_size, 24);
    let data_start = data.file_offset.unwrap();
    assert_eq!(&image[data_start..data_start + 24], &[0; 24]);
    let start = code.file_offset.unwrap();
    let end = start + code.file_size as usize;
    assert!(end + 2 + code.fixups.len() * 8 <= data_start);
    assert_eq!(data_start % 16, 0);
    let ordinals = [433, 433, 433, 433, 434, 434, 434, 434,
        435, 435, 435, 435, 436, 436, 436, 436, 52, 247, 309];
    assert_eq!(code.fixups.len(), ordinals.len());
    for (fixup, ordinal) in code.fixups.iter().zip(ordinals) {
        assert_eq!(fixup.address_type, NeFixupAddressType::FarPointer32);
        assert_eq!(fixup.target, NeFixupTarget::ImportOrdinal { module_index: 1, ordinal });
        assert!(!fixup.additive);
        let source = start + usize::from(fixup.source_offset);
        assert_eq!(image[source - 1], 0x9a);
        assert_eq!(&image[source..source + 4], &[0xff, 0xff, 0, 0]);
        assert!(source + 4 <= end);
    }
}

#[test]
fn user_queries_serialized_machine_code_asserts_ascii_word_results_and_pascal_slots() {
    let image = win16_user_queries_probe_bytes().unwrap();
    let module = parse_ne(&image).unwrap();
    let segment = &module.segments[0];
    let start = segment.file_offset.unwrap();
    let code = &image[start..start + segment.file_size as usize];
    // Independent expected truth table: A, a, digit, punctuation.
    let expected = [1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0];
    for (index, fixup) in segment.fixups[..16].iter().enumerate() {
        let source = usize::from(fixup.source_offset);
        assert_eq!(&code[source - 4..source - 1], &[0x68, [0x41, 0x61, 0x30, 0x21][index % 4], 0xff]);
        assert_eq!(&code[source + 4..source + 10], &[0x66, 0x3d, expected[index], 0, 0x34, 0x12]);
        assert_eq!(&code[source + 10..source + 17], &[0x74, 5, 0xb8, 10 + index as u8, 0x4c, 0xcd, 0x21]);
    }
    let cursor = usize::from(segment.fixups[17].source_offset);
    assert_eq!(&code[cursor + 4..cursor + 13], &[0xa3, 6, 0, 0x66, 0x25, 0, 0, 0xff, 0xff]);
    let clip = usize::from(segment.fixups[18].source_offset);
    assert_eq!(&code[clip - 4..clip - 1], &[0x1e, 0x6a, 10]);
    assert_eq!(&code[clip + 4..clip + 10], &[0x66, 0x3d, 0x5a, 0xa5, 0x34, 0x12]);
    assert_eq!(&code[code.len() - 5..], &[0xb8, 0, 0x4c, 0xcd, 0x21]);
}

#[test]
fn user_queries_serialized_checks_preserve_caller_state_and_bound_rect_writes() {
    let image = win16_user_queries_probe_bytes().unwrap();
    let module = parse_ne(&image).unwrap();
    let segment = &module.segments[0];
    let start = segment.file_offset.unwrap();
    let code = &image[start..start + segment.file_size as usize];
    let count = |bytes: &[u8]| code.windows(bytes.len()).filter(|window| *window == bytes).count();
    for comparison in [
        &[0x66, 0x81, 0xfa, 0xa5, 0x5a, 0x78, 0x56][..],
        &[0x66, 0x81, 0xfb, 0x57, 0x13, 0xbc, 0x9a],
        &[0x66, 0x81, 0xf9, 0x68, 0x24, 0xcd, 0xab],
        &[0x66, 0x81, 0xfe, 0x9c, 0x36, 0xde, 0xbc],
        &[0x66, 0x81, 0xff, 0xad, 0x48, 0xef, 0xcd],
        &[0x66, 0x81, 0xfd, 0xbe, 0x5a, 0xf0, 0xde],
        &[0x36, 0x3b, 0x26, 0, 0],
        &[0x8c, 0xd8, 0x36, 0x3b, 0x06, 2, 0],
        &[0x8c, 0xc0, 0x36, 0x3b, 0x06, 2, 0],
    ] {
        assert_eq!(count(comparison), 19, "missing per-call caller-state assertion");
    }
    for comparison in [
        &[0x81, 0x3e, 8, 0, 0x57, 0x13, 0x74, 5][..],
        &[0x81, 0x3e, 18, 0, 0x68, 0x24, 0x74, 5],
        &[0x66, 0x3d, 0, 0, 0x34, 0x12, 0x73, 5],
        &[0x66, 0x3d, 1, 0, 0x34, 0x12, 0x76, 5],
    ] {
        assert_eq!(count(comparison), 1);
    }
    // Every short assertion's success branch skips exactly MOV AX/status + INT21.
    for status in (10..=25).chain(30..=37).chain(60..=68) {
        assert!(count(&[0xb8, status, 0x4c, 0xcd, 0x21]) > 0);
    }
}
