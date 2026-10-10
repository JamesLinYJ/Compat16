use super::win16_modeless_probe_bytes;
use formats::{NeFixupAddressType, NeFixupTarget, NeResourceId, parse_ne};

fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

#[test]
fn win16_modeless_probe_serializes_real_code_data_resources_and_only_expected_user_imports() {
    let image = win16_modeless_probe_bytes().unwrap();
    let module = parse_ne(&image).unwrap();
    assert_eq!(image, win16_modeless_probe_bytes().unwrap());
    assert_eq!(module.header.initial_cs, 1);
    assert_eq!(module.header.initial_ss, 2);
    assert_eq!(module.header.automatic_data_segment, 2);
    assert_eq!(module.header.initial_sp, 0x1000);
    assert_eq!(module.segments.len(), 2);
    assert_eq!(module.segments[1].file_size, 12);
    assert_eq!(module.imported_modules[0].name, b"USER");
    let code_start = module.segments[0].file_offset.unwrap();
    let code_end = code_start + module.segments[0].file_size as usize;
    let data_start = module.segments[1].file_offset.unwrap();
    assert_eq!(&image[data_start..data_start + 12], &[0; 12]);
    let fixups = &module.segments[0].fixups;
    assert_eq!(fixups.len(), 8);
    assert!(code_end + 2 + fixups.len() * 8 <= data_start);
    for (fixup, ordinal) in fixups.iter().zip([89, 91, 111, 174, 53, 47, 174, 53]) {
        assert_eq!(fixup.address_type, NeFixupAddressType::FarPointer32);
        assert_eq!(fixup.target, NeFixupTarget::ImportOrdinal { module_index: 1, ordinal });
        assert!(!fixup.additive);
        let source = code_start + usize::from(fixup.source_offset);
        assert_eq!(image[source - 1], 0x9a);
        assert_eq!(&image[source..source + 4], &[0xff, 0xff, 0, 0]);
        assert!(source + 4 <= code_end);
    }
    // Share the already-validated hidden template and complete group/DIB bytes.
    let modal = crate::win16_dialog_probe_bytes().unwrap();
    let modal_module = parse_ne(&modal).unwrap();
    assert_eq!(module.resource_types.len(), 3);
    for (kind, id) in [(5, 1), (14, 7), (3, 9)] {
        let get = |definition: &formats::NeModule| {
            let resource = definition.resource_types.iter()
                .find(|entry| entry.id == NeResourceId::Numeric(kind)).unwrap()
                .resources.iter().find(|entry| entry.id == NeResourceId::Numeric(id)).unwrap();
            resource.file_offset..resource.file_offset + resource.byte_length
        };
        assert_eq!(image[get(&module)], modal[get(&modal_module)]);
    }
}

#[test]
fn win16_modeless_probe_checks_two_cycles_and_immediate_retirement_in_serialized_code() {
    let image = win16_modeless_probe_bytes().unwrap();
    let module = parse_ne(&image).unwrap();
    let segment = &module.segments[0];
    let start = segment.file_offset.unwrap();
    let code = &image[start..start + segment.file_size as usize];
    let contains = |bytes: &[u8]| code.windows(bytes.len()).any(|window| window == bytes);
    assert_eq!(&code[..10], &[0x89, 0x3e, 0, 0, 0xc7, 0x06, 10, 0, 1, 0]);
    assert!(contains(&[0xa1, 2, 0, 0x3b, 0x06, 10, 0])); // init_count == expected
    assert!(contains(&[0x50, 0x68, 1, 4, 0x6a, 0, 0x6a, 0, 0x6a, 0])); // STM_GETICON
    assert!(contains(&[0xa3, 8, 0])); // preserve nonzero returned icon
    assert_eq!(code.windows(4).filter(|bytes| *bytes == [0x3b, 0x06, 8, 0]).count(), 2);
    let destroy = usize::from(segment.fixups[4].source_offset);
    let is_window = usize::from(segment.fixups[5].source_offset);
    let reload = usize::from(segment.fixups[6].source_offset);
    assert!(destroy < is_window && is_window < reload);
    assert_eq!(&code[is_window - 5..is_window - 1], &[0xff, 0x36, 6, 0]);
    assert_eq!(&code[is_window + 4..is_window + 7], &[0x85, 0xc0, 0x74]); // require FALSE
    assert!(code[is_window + 4..reload].windows(6)
        .any(|bytes| bytes == [0xc7, 0x06, 6, 0, 0, 0])); // clear destroyed HWND
    let loop_check = code.windows(9)
        .position(|bytes| bytes == [0xff, 0x06, 10, 0, 0x83, 0x3e, 10, 0, 3]).unwrap();
    assert_eq!(code[loop_check + 9], 0x74); // stop when expected count becomes3
    assert_eq!(code[loop_check + 11], 0xe9);
    let jump_end = loop_check + 14;
    let relative = i16::from_le_bytes(code[loop_check + 12..jump_end].try_into().unwrap());
    assert_eq!(jump_end as isize + relative as isize, 10); // cycle starts after initialization
}

#[test]
fn win16_modeless_probe_serialized_callback_and_failure_paths_are_bounded_and_pascal() {
    let image = win16_modeless_probe_bytes().unwrap();
    let module = parse_ne(&image).unwrap();
    let segment = &module.segments[0];
    let start = segment.file_offset.unwrap();
    let code = &image[start..start + segment.file_size as usize];
    let procedure = usize::from(word(code, 22)); // offset pushed after CS in CreateDialog args
    assert_eq!(&code[procedure..procedure + 10], &[0x55, 0x89, 0xe5, 0x1e, 0x06, 0x53, 0x56, 0x57, 0x16, 0x1f]);
    assert!(code[procedure..].windows(7).any(|bytes| bytes == [0xff, 0x06, 2, 0, 0xb8, 1, 0]));
    assert_eq!(&code[code.len() - 9..], &[0x5f, 0x5e, 0x5b, 0x07, 0x1f, 0x5d, 0xca, 10, 0]);
    let cleanup_call = usize::from(segment.fixups[7].source_offset);
    assert!(cleanup_call < procedure);
    assert_eq!(&code[cleanup_call - 5..cleanup_call - 1], &[0xff, 0x36, 6, 0]);
    assert!(code[..cleanup_call].windows(5).any(|bytes| bytes == [0x83, 0x3e, 6, 0, 0]));
    assert!(code[cleanup_call..procedure].windows(7)
        .any(|bytes| bytes == [0xa1, 4, 0, 0xb4, 0x4c, 0xcd, 0x21]));
    for status in 10..=17 {
        assert!(code[..procedure].windows(6)
            .any(|bytes| bytes == [0xc7, 0x06, 4, 0, status, 0]));
    }
}
