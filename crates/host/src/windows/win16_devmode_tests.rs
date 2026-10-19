use super::super::win16_gdi::native_devmode;
use super::*;

fn sample(private_size: u16) -> Vec<u8> {
    let mut bytes = vec![0; size_of::<DEVMODEW>() + usize::from(private_size)];
    for range in [W_SPEC..W_FORM, W_TAIL..size_of::<DEVMODEW>()] {
        for i in range {
            bytes[i] = (i as u8).wrapping_mul(3);
        }
    }
    for (field, value) in [
        (offset_of!(DEVMODEW, dmSpecVersion), 0x0401),
        (offset_of!(DEVMODEW, dmDriverVersion), 17),
        (offset_of!(DEVMODEW, dmSize), size_of::<DEVMODEW>() as u16),
        (offset_of!(DEVMODEW, dmDriverExtra), private_size),
    ] {
        bytes[field..field + 2].copy_from_slice(&value.to_le_bytes());
    }
    let fields = offset_of!(DEVMODEW, dmFields);
    bytes[fields..fields + 4].copy_from_slice(&0x0681_ffff_u32.to_le_bytes());
    for start in [0, W_FORM] {
        bytes[start..start + 6].copy_from_slice(&[b'A', 0, b'B', 0, 0, 0]);
    }
    for (i, byte) in bytes[size_of::<DEVMODEW>()..].iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(131);
    }
    bytes
}

#[test]
fn wow_devmode_native_fields_and_binary_private_data_survive_guest_edit() {
    let codec = GuestTextCodec::new(1252).unwrap();
    let mut expected = sample(19);
    let mut value = project(&expected, codec).unwrap().value;
    assert_eq!(value.public_size, 68);
    assert_eq!(value.spec_version, 0x030a);
    assert_eq!(value.driver_extra.len(), 19 + WOW_EXTRA_OVERHEAD);
    assert!(value.has_mapped_fields());
    value.settings[0] = 2; // The application changes the visible orientation.
    let at = offset_of!(DEVMODEW, Anonymous1);
    expected[at..at + 2].copy_from_slice(&2_i16.to_le_bytes());
    let restored = native_devmode(&value, codec).unwrap();
    assert_eq!(restored.as_bytes(), expected);
    let second = project(restored.as_bytes(), codec).unwrap().value;
    assert_eq!(second, value);
}

#[test]
fn wow_devmode_native_unknown_size_and_truncated_private_tail_fail() {
    let codec = GuestTextCodec::new(1252).unwrap();
    let mut bytes = sample(2);
    assert!(project(&bytes[..bytes.len() - 1], codec).is_err());
    let at = offset_of!(DEVMODEW, dmSize);
    bytes[at..at + 2].copy_from_slice(&219_u16.to_le_bytes());
    assert!(project(&bytes, codec).is_err());
    assert!(project(&bytes[..219], codec).is_err());
}

#[test]
fn wow_devmode_fixed_dbcs_names_stop_before_a_partial_character() {
    let codec = GuestTextCodec::new(936).unwrap();
    let mut bytes = sample(0);
    for start in [0, W_FORM] {
        for i in 0..32 {
            bytes[start + 2 * i..start + 2 * i + 2].copy_from_slice(&0x4e2d_u16.to_le_bytes());
        }
    }
    let projected = project(&bytes, codec).unwrap();
    assert!(projected.truncated);
    assert!(!projected.used_default_char);
    assert_eq!(&projected.value.device_name[30..], &[0, 0]);
    let restored = native_devmode(&projected.value, codec).unwrap();
    for start in [0, W_FORM] {
        let units: Vec<_> = restored.as_bytes()[start..start + 64]
            .chunks_exact(2)
            .map(|x| u16::from_le_bytes([x[0], x[1]]))
            .collect();
        assert_eq!(&units[..15], &[0x4e2d; 15]);
        assert!(units[15..].iter().all(|x| *x == 0));
    }
}

#[test]
fn wow_devmode_malformed_tagged_data_cannot_be_native_driver_private_data() {
    let codec = GuestTextCodec::new(1252).unwrap();
    let mut value = project(&sample(3), codec).unwrap().value;
    let end = value.driver_extra.len();
    value.driver_extra[end - 4..end - 2].copy_from_slice(&4_u16.to_le_bytes());
    assert!(!value.has_mapped_fields());
    assert!(native_devmode(&value, codec).is_err());
}

#[test]
fn wow_devmode_unsupported_older_native_layout_is_not_guessed() {
    let codec = GuestTextCodec::new(1252).unwrap();
    let mut value = project(&sample(0), codec).unwrap().value;
    value.driver_extra = encode_wow_devmode_extra(0x0401, &[0; 80], &[]).unwrap();
    assert!(!value.has_mapped_fields());
    assert!(native_devmode(&value, codec).is_err());
}

#[test]
fn wow_devmode_guest_block_size_includes_public_prefix_and_trailer() {
    let codec = GuestTextCodec::new(1252).unwrap();
    let maximum = (65536 - DEVMODE16_SIZE - WOW_EXTRA_OVERHEAD) as u16;
    let value = project(&sample(maximum), codec).unwrap().value;
    assert_eq!(DEVMODE16_SIZE + value.driver_extra.len(), 65536);
    assert!(project(&sample(maximum + 1), codec).is_err());
}

#[test]
fn wow_devmode_printer_input_requires_a_mapped_private_layout() {
    let codec = GuestTextCodec::new(1252).unwrap();
    let mut value = project(&sample(7), codec).unwrap().value;
    assert!(printer_input(&value, codec).is_ok());
    value.driver_extra = vec![0xa5, 0x5a];
    value.fields = 1;
    assert!(printer_input(&value, codec).is_err());
    value.driver_extra.clear();
    assert!(printer_input(&value, codec).is_ok());
}
