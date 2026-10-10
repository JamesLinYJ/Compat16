use super::*;
use formats::{NeFixupAddressType, NeFixupTarget, NeResourceId, parse_ne};

fn read_word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn read_dword(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn resource(image: &[u8], kind: u16, id: u16) -> &[u8] {
    let module = parse_ne(image).expect("generated fixture is valid NE");
    let entry = module.resource_types.iter()
        .find(|entry| entry.id == NeResourceId::Numeric(kind)).unwrap()
        .resources.iter().find(|entry| entry.id == NeResourceId::Numeric(id)).unwrap();
    &image[entry.file_offset..entry.file_offset + entry.byte_length]
}

#[test]
fn win16_dialog_probe_has_real_code_data_stack_and_user_imports() {
    let image = win16_dialog_probe_bytes().unwrap();
    let module = parse_ne(&image).unwrap();
    assert_eq!(image, win16_dialog_probe_bytes().unwrap());
    assert_eq!(module.header.target_os, 2);
    assert_eq!(module.header.initial_cs, 1);
    assert_eq!(module.header.initial_ip, 0);
    assert_eq!(module.header.automatic_data_segment, 2);
    assert_eq!(module.header.initial_ss, 2);
    assert_eq!(module.header.initial_sp, 0x1000);
    assert_eq!(module.header.stack_size, 0x1000);
    assert_eq!(module.segments.len(), 2);
    assert_eq!(module.segments[0].file_offset, Some(CODE));
    assert_eq!(module.segments[1].file_offset, Some(DATA));
    assert_eq!(module.segments[1].memory_size, 0x1000);
    assert_eq!(&image[DATA..DATA + 6], &[0; 6]);
    assert_eq!(module.imported_modules.len(), 1);
    assert_eq!(module.imported_modules[0].name, b"USER");
    let fixups = &module.segments[0].fixups;
    assert_eq!(fixups.len(), 4);
    for (fixup, ordinal) in fixups.iter().zip([87, 91, 111, 88]) {
        assert_eq!(fixup.address_type, NeFixupAddressType::FarPointer32);
        assert_eq!(fixup.target, NeFixupTarget::ImportOrdinal { module_index: 1, ordinal });
        assert!(!fixup.additive);
        let source = CODE + usize::from(fixup.source_offset);
        assert_eq!(image[source - 1], 0x9a);
        assert_eq!(&image[source..source + 4], &[0xff, 0xff, 0, 0]);
        assert!(u32::from(fixup.source_offset) + 4 <= module.segments[0].file_size);
    }
}

#[test]
fn win16_dialog_probe_template_is_hidden_standard_dialog_with_icon_ordinal() {
    let image = win16_dialog_probe_bytes().unwrap();
    let bytes = resource(&image, 5, 1);
    assert_eq!(bytes.len(), 35);
    assert_eq!(read_dword(bytes, 0), 0x8000_0000); // WS_POPUP, no WS_VISIBLE
    assert_eq!(bytes[4], 1);
    assert_eq!(&bytes[13..16], &[0, 0, 0]); // menu/class/title
    assert_eq!(read_word(bytes, 24), 10);
    assert_eq!(read_dword(bytes, 26), 0x4000_0003); // hidden WS_CHILD|SS_ICON
    assert_eq!(&bytes[30..], &[0x82, 0xff, 7, 0, 0]); // STATIC, ordinal7, no data
}

#[test]
fn win16_dialog_probe_icon_group_resolves_to_complete_opaque_dib() {
    let image = win16_dialog_probe_bytes().unwrap();
    let group = resource(&image, 14, 7);
    let icon = resource(&image, 3, 9);
    assert_eq!(group.len(), 20);
    assert_eq!(read_word(group, 2), 1);
    assert_eq!(read_word(group, 4), 1);
    assert_eq!(&group[6..10], &[16, 16, 0, 0]);
    assert_eq!(read_word(group, 10), 1);
    assert_eq!(read_word(group, 12), 32);
    assert_eq!(read_dword(group, 14) as usize, icon.len());
    assert_eq!(read_word(group, 18), 9);
    assert_eq!(read_dword(icon, 0), 40);
    assert_eq!(read_dword(icon, 4), 16);
    assert_eq!(read_dword(icon, 8), 32);
    assert_eq!(read_word(icon, 12), 1);
    assert_eq!(read_word(icon, 14), 32);
    assert_eq!(read_dword(icon, 16), 0); // BI_RGB
    assert_eq!(icon.len(), 40 + 1024 + 64);
    assert!(icon[40..1064].chunks_exact(4).all(|pixel| pixel == [0x40, 0x80, 0xc0, 0xff]));
    assert!(icon[1064..].iter().all(|byte| *byte == 0));
}

#[test]
fn win16_dialog_probe_guest_checks_modal_result_and_uses_pascal_callback() {
    let image = win16_dialog_probe_bytes().unwrap();
    let module = parse_ne(&image).unwrap();
    let segment = &module.segments[0];
    let start = segment.file_offset.unwrap();
    let code = &image[start..start + segment.file_size as usize];
    assert_eq!(&code[..4], &[0x89, 0x3e, 0, 0]); // save startup DI instance
    let procedure = usize::from(read_word(&code, 13)); // pushed CS:dlgproc offset
    assert_eq!(&code[procedure..procedure + 9], &[0x55, 0x89, 0xe5, 0x1e, 0x06, 0x53, 0x56, 0x57, 0x16]);
    assert_eq!(&code[code.len() - 9..], &[0x5f, 0x5e, 0x5b, 0x07, 0x1f, 0x5d, 0xca, 10, 0]);
    let contains = |bytes: &[u8]| code.windows(bytes.len()).any(|window| window == bytes);
    assert!(contains(&[0x3d, 17, 0])); // modal return AX17
    assert!(contains(&[0x83, 0x3e, 2, 0, 1])); // exactly one init
    assert!(contains(&[0x81, 0x7e, 12, 0x10, 1])); // WM_INITDIALOG at correct BP offset
    assert!(contains(&[0x50, 0x68, 1, 4, 0x6a, 0, 0x6a, 0, 0x6a, 0])); // Win16 STM_GETICON
    let end = usize::from(segment.fixups[3].source_offset);
    assert_eq!(&code[end - 6..end - 1], &[0xff, 0x76, 14, 0x6a, 17]);
    assert!(contains(&[0xc7, 0x06, 4, 0, 4, 0])); // child failure
    assert!(contains(&[0xc7, 0x06, 4, 0, 5, 0])); // icon failure
    assert!(contains(&[0xa1, 4, 0, 0xb4, 0x4c, 0xcd, 0x21])); // propagate failure
}
