use super::*;
use std::mem::offset_of;
use windows_sys::Win32::Graphics::Gdi::*;

fn mode(private: u16) -> Vec<u8> {
    let mut bytes = vec![0; size_of::<DEVMODEW>() + usize::from(private)];
    for (at, value) in [
        (offset_of!(DEVMODEW, dmSpecVersion), 0x0401),
        (offset_of!(DEVMODEW, dmDriverVersion), 7),
        (offset_of!(DEVMODEW, dmSize), size_of::<DEVMODEW>() as u16),
        (offset_of!(DEVMODEW, dmDriverExtra), private),
    ] {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn fields(bytes: &mut [u8], fields: u32) {
    let at = offset_of!(DEVMODEW, dmFields);
    bytes[at..at + 4].copy_from_slice(&fields.to_le_bytes());
}

#[test]
fn ext_device_mode_size_query_includes_wow_fields_and_trailer() {
    assert_eq!(projected_size(220).unwrap(), 168);
    assert_eq!(projected_size(241).unwrap(), 189);
    assert_eq!(projected_size(65535 + 52).unwrap(), 65535);
    for invalid in [-1, 0, 219, 65535 + 53, i32::MAX] {
        assert!(projected_size(invalid).is_err());
    }
}

#[test]
fn ext_device_mode_null_copy_output_keeps_wow_query_semantics() {
    assert!(size_only(0, None));
    for flags in [2, 3, 6, 7, 10, 0x800f] {
        assert!(size_only(flags, None));
    }
    for flags in [1, 4, 5, 8, 0x8000] {
        assert!(!size_only(flags, None));
    }
    assert!(!size_only(2, Some(1000)));
    assert_eq!(native_flags(4), 12); // Prompt and per-user input.
    assert_eq!(native_flags(1), 11); // Update requires a private output copy.
    assert_eq!(native_flags(0x8004), 0x800c); // Other flag bits stay intact.
}

#[test]
fn ext_device_mode_merge_preserves_unselected_values_and_native_identity() {
    let mut current = mode(3);
    fields(&mut current, DM_ORIENTATION | DM_COPIES | DM_DUPLEX);
    current[76..92].fill(0x11);
    current[196..200].copy_from_slice(&42_u32.to_le_bytes());
    current[220..].fill(0x5a);
    let mut input = mode(3);
    fields(&mut input, DM_ORIENTATION | DM_FORMNAME | DM_MEDIATYPE);
    input[76..78].copy_from_slice(&2_i16.to_le_bytes());
    input[102..166].fill(0x33);
    input[196..200].copy_from_slice(&99_u32.to_le_bytes());
    input[220..].copy_from_slice(&[0, 0xff, 0xa5]);
    let mut expected = current.clone();
    fields(
        &mut expected,
        DM_ORIENTATION | DM_COPIES | DM_DUPLEX | DM_FORMNAME | DM_MEDIATYPE,
    );
    expected[76..78].copy_from_slice(&input[76..78]);
    expected[102..166].copy_from_slice(&input[102..166]);
    expected[196..200].copy_from_slice(&input[196..200]);
    expected[220..].copy_from_slice(&input[220..]);
    merge::apply(&mut current, &input).unwrap();
    assert_eq!(current, expected);
}

#[test]
fn ext_device_mode_merge_ignores_absent_or_differently_sized_private_data() {
    for size in [0, 2, 4] {
        let mut current = mode(3);
        current[220..].fill(0x5a);
        merge::apply(&mut current, &mode(size)).unwrap();
        assert_eq!(&current[220..], &[0x5a; 3]);
    }
}

#[test]
fn ext_device_mode_merge_rejects_bad_lengths_before_mutation() {
    let mut current = mode(3);
    let before = current.clone();
    assert!(merge::apply(&mut current, &mode(3)[..222]).is_err());
    assert_eq!(current, before);
}

fn response(public: u16, private: u16) -> Vec<u8> {
    let head = size_of::<PRINTER_INFO_9W>();
    let mut bytes = vec![0; head + usize::from(public) + usize::from(private)];
    let pointer = bytes.as_ptr() as usize + head;
    bytes[..head].copy_from_slice(&pointer.to_ne_bytes());
    bytes[head + 68..head + 70].copy_from_slice(&public.to_le_bytes());
    bytes[head + 70..head + 72].copy_from_slice(&private.to_le_bytes());
    bytes
}

#[test]
fn ext_device_mode_preferences_copy_only_an_owned_native_span() {
    let bytes = response(220, 7);
    let value = preferences::decode(&bytes).unwrap().unwrap();
    assert_eq!(value, bytes[size_of::<PRINTER_INFO_9W>()..]);
    let mut escaped = bytes.clone();
    // Cloning invalidates the saved pointer; it must not become a native dereference.
    assert!(preferences::decode(&escaped).is_err());
    escaped[..size_of::<usize>()].fill(0);
    assert!(preferences::decode(&escaped).unwrap().is_none());
}

#[test]
fn ext_device_mode_stale_preferences_do_not_replace_current_driver_defaults() {
    let bytes = response(188, 0);
    let saved = preferences::decode(&bytes).unwrap().unwrap();
    assert!(!compatible(&mode(0), &saved));
    let mut truncated = response(220, 0);
    let head = size_of::<PRINTER_INFO_9W>();
    truncated[head + 70..head + 72].copy_from_slice(&4_u16.to_le_bytes());
    assert!(preferences::decode(&truncated).unwrap().is_none());
}
