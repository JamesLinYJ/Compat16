use formats::{NeModule, NeResource, NeResourceId as Id, NeResourceType, collect_ne_text_profile, parse_ne};

fn fixture() -> (Vec<u8>, NeModule) {
    let bytes = super::minimal_ne();
    let image = parse_ne(&bytes).unwrap();
    (bytes, image)
}

fn resource(bytes: &mut Vec<u8>, image: &mut NeModule, kind: u16, id: Id, data: &[u8]) {
    let entry = NeResource { id, file_offset: bytes.len(), byte_length: data.len(), flags: 0, handle: 0, usage: 0 };
    bytes.extend_from_slice(data);
    image.resource_types.push(NeResourceType { id: Id::Numeric(kind), resources: vec![entry] });
}

fn menu(label: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0, 0, 0x80, 0, 1, 0];
    bytes.extend_from_slice(label); bytes.push(0);
    bytes
}

#[test]
fn text_profile_collects_nested_menu_labels_without_headers_separators_or_trailing_bytes() {
    let (mut bytes, mut image) = fixture();
    let mut data = vec![0, 0, 0, 0, 0x90, 0]; // Last root entry is a popup.
    data.extend_from_slice(b"\xce\xc4\xbc\xfe\0");
    data.extend_from_slice(&[0, 0, 1, 0]); data.extend_from_slice(b"\xb4\xf2\xbf\xaa\0");
    data.extend_from_slice(&[0, 8, 0, 0, 0]); // Separator.
    data.extend_from_slice(&[0x80, 0, 2, 0]); data.extend_from_slice(b"Exit\0BINARY-TRAILER");
    resource(&mut bytes, &mut image, 4, Id::Numeric(1), &data);
    assert_eq!(collect_ne_text_profile(&bytes, &image).menu_strings,
        [b"\xce\xc4\xbc\xfe".to_vec(), b"\xb4\xf2\xbf\xaa".to_vec(), b"Exit".to_vec()]);
}

#[test]
fn text_profile_menu_ids_follow_first_match_and_named_ascii_case_rules() {
    let (mut bytes, mut image) = fixture();
    resource(&mut bytes, &mut image, 4, Id::Name(b"Main".to_vec()), &menu(b"FIRST"));
    resource(&mut bytes, &mut image, 4, Id::Name(b"MAIN".to_vec()), &menu(b"SECOND"));
    resource(&mut bytes, &mut image, 4, Id::Numeric(2), &menu(b"OTHER"));
    assert_eq!(collect_ne_text_profile(&bytes, &image).menu_strings, [b"FIRST".to_vec(), b"OTHER".to_vec()]);
}

#[test]
fn text_profile_damaged_menu_cannot_select_its_duplicate_or_hide_valid_strings() {
    let (mut bytes, mut image) = fixture();
    resource(&mut bytes, &mut image, 4, Id::Numeric(1), &[0, 0, 0]);
    resource(&mut bytes, &mut image, 4, Id::Numeric(1), &menu(b"DUPLICATE"));
    let mut strings = b"\x02OK".to_vec(); strings.extend_from_slice(&[0; 15]);
    resource(&mut bytes, &mut image, 6, Id::Numeric(1), &strings);
    let profile = collect_ne_text_profile(&bytes, &image);
    assert_eq!(profile.strings, [b"OK".to_vec()]);
    assert!(profile.menu_strings.is_empty());
}

#[test]
fn text_profile_does_not_interpret_pre30_menu_layouts_or_unrelated_resource_bytes() {
    let (mut bytes, mut image) = fixture();
    resource(&mut bytes, &mut image, 4, Id::Numeric(1), &menu(b"MENU"));
    resource(&mut bytes, &mut image, 2, Id::Numeric(1), b"BITMAP\xd6\xd0");
    resource(&mut bytes, &mut image, 16, Id::Numeric(1), b"VERSION\xd6\xd0");
    image.header.expected_windows_version = 0x0200;
    let profile = collect_ne_text_profile(&bytes, &image);
    assert!(profile.strings.is_empty());
    assert!(profile.menu_strings.is_empty());
    assert_eq!(profile.version_resource_ranges.len(), 1);
}

#[test]
fn text_profile_unaddressable_menu_is_skipped_without_overflow() {
    let (bytes, mut image) = fixture();
    image.resource_types.push(NeResourceType { id: Id::Numeric(4), resources: vec![NeResource {
        id: Id::Numeric(1), file_offset: usize::MAX, byte_length: 2, flags: 0, handle: 0, usage: 0,
    }] });
    assert!(collect_ne_text_profile(&bytes, &image).menu_strings.is_empty());
}
