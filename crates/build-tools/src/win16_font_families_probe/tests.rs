use super::win16_font_families_probe_bytes;
use formats::{NeFixupAddressType, NeFixupTarget, parse_ne};

fn serialized_code(image: &[u8]) -> Vec<u8> {
    let module = parse_ne(image).unwrap();
    let code = &module.segments[0];
    let start = code.file_offset.unwrap();
    image[start..start + code.file_size as usize].to_vec()
}

#[test]
fn win16_font_families_probe_serializes_bounded_segments_and_exact_gdi_imports() {
    let image = win16_font_families_probe_bytes().unwrap();
    assert_eq!(image, win16_font_families_probe_bytes().unwrap());
    let module = parse_ne(&image).unwrap();
    assert_eq!(module.header.initial_cs, 1);
    assert_eq!(module.header.initial_ss, 2);
    assert_eq!(module.header.automatic_data_segment, 2);
    assert_eq!(module.header.initial_sp, 0x1000);
    assert_eq!(module.segments.len(), 2);
    assert_eq!(module.imported_modules.len(), 1);
    assert_eq!(module.imported_modules[0].name, b"GDI");
    assert!(module.resource_types.is_empty());
    let code = &module.segments[0];
    let data = &module.segments[1];
    assert_eq!(data.file_size, 84);
    let data_start = data.file_offset.unwrap();
    assert_eq!(&image[data_start..data_start + 84], &[0; 84]);
    assert_eq!(code.fixups.len(), 3);
    let code_start = code.file_offset.unwrap();
    let code_end = code_start + code.file_size as usize;
    assert!(code_end + 2 + code.fixups.len() * 8 <= data_start);
    assert_eq!(data_start % 16, 0);
    for (fixup, ordinal) in code.fixups.iter().zip([52, 330, 68]) {
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
fn win16_font_families_probe_serialized_arguments_and_callback_are_pascal14() {
    let image = win16_font_families_probe_bytes().unwrap();
    let module = parse_ne(&image).unwrap();
    let code = serialized_code(&image);
    let contains = |bytes: &[u8]| code.windows(bytes.len()).any(|window| window == bytes);
    assert_eq!(&code[..2], &[0x6a, 0]); // CreateCompatibleDC(NULL)
    let call = usize::from(module.segments[0].fixups[1].source_offset);
    assert_eq!(&code[call - 11..call - 9], &[0x0e, 0x68]);
    let callback = usize::from(u16::from_le_bytes(code[call - 9..call - 7].try_into().unwrap()));
    assert_eq!(&code[call - 7..call - 1], &[0x68, 0x5e, 0xa1, 0x68, 0xcd, 0x42]);
    assert_eq!(&code[callback..callback + 10], &[0x55, 0x89, 0xe5, 0x1e, 0x06, 0x53, 0x56, 0x57, 0x16, 0x1f]);
    assert_eq!(&code[code.len() - 11..], &[0x31, 0xc0, 0x5f, 0x5e, 0x5b, 0x07, 0x1f, 0x5d, 0xca, 14, 0]);
    assert!(contains(&[0x81, 0x7e, 6, 0xcd, 0x42]));
    assert!(contains(&[0x81, 0x7e, 8, 0x5e, 0xa1]));
    assert!(contains(&[0x6a, 0, 0x6a, 0])); // discover without a family name
    assert!(contains(&[0x1e, 0x6a, 10])); // reuse guest-owned copied family name
    assert!(contains(&[0x3b, 0x26, 6, 0])); // API stack restored
    assert!(contains(&[0xa1, 8, 0, 0x40, 0x3b, 0x06, 0, 0])); // callback count == phase+1
    assert!(contains(&[0xff, 0x06, 8, 0, 0x83, 0x3e, 8, 0, 2])); // exactly two calls
    for comparison in [
        &[0x81, 0xfb, 0x57, 0x13][..], &[0x81, 0xfe, 0x68, 0x24],
        &[0x81, 0xff, 0x9c, 0x36], &[0x81, 0xfd, 0xbc, 0x4a],
        &[0x8c, 0xc0, 0x8c, 0xda, 0x39, 0xd0],
    ] {
        assert!(contains(comparison));
    }
}

#[test]
fn win16_font_families_probe_serialized_checks_cover_record_bounds_and_fail_closed() {
    let image = win16_font_families_probe_bytes().unwrap();
    let code = serialized_code(&image);
    let contains = |bytes: &[u8]| code.windows(bytes.len()).any(|window| window == bytes);
    assert!(contains(&[0xc4, 0x76, 16, 0x83, 0xc6, 18, 0xbf, 10, 0, 0xb9, 32, 0]));
    assert!(contains(&[0x3a, 0x05, 0x74, 9])); // returned face equals named input
    assert!(contains(&[0x8b, 0x46, 18, 0x3b, 0x46, 14])); // same record selector
    assert!(contains(&[0x8b, 0x46, 16, 0x05, 146, 0, 0x3b, 0x46, 12]));
    assert!(contains(&[0xc4, 0x76, 16, 0x83, 0xc6, 50, 0xb9, 64, 0]));
    assert!(contains(&[0xc4, 0x76, 16, 0x83, 0xc6, 114, 0xb9, 32, 0]));
    assert!(contains(&[0xc4, 0x76, 12, 0xbf, 42, 0, 0xb9, 31, 0]));
    assert!(contains(&[0x83, 0xc1, 10])); // TrueType adds only the ten-byte extension
    assert!(contains(&[0xf7, 0x46, 10, 4, 0, 0x74])); // TrueType-only assertions
    assert!(contains(&[0x83, 0x3e, 77, 0, 0])); // packed metric+35, not host alignment
    assert!(contains(&[0xa1, 4, 0, 0xb4, 0x4c, 0xcd, 0x21])); // DOS exits saved assertion status
    for status in 20..=40 {
        assert!(contains(&[0xc7, 0x06, 4, 0, status, 0]), "missing status {status}");
    }
}

#[test]
fn win16_font_families_shared_packager_rejects_unrepresentable_or_overlapping_layouts() {
    use crate::win16_dialog_probe::build_image_with_import;
    assert!(build_image_with_import(&[0xcb], &[], 0, b"GDI", false).is_err());
    assert!(build_image_with_import(&[0xcb], &[], 0x1001, b"GDI", false).is_err());
    assert!(build_image_with_import(&[0xcb], &[], 1, b"", false).is_err());
    assert!(build_image_with_import(&[0xcb], &[], 1, b"TOOLONG", false).is_err());
    assert!(build_image_with_import(&[0xcb], &[], 257, b"USER", true).is_err());
    assert!(build_image_with_import(&vec![0x90; 65535], &[], 84, b"GDI", false).is_err());
}
