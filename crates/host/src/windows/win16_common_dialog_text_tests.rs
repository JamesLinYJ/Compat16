use super::*;

fn gbk() -> GuestTextCodec {
    GuestTextCodec::new(936).expect("Windows provides the guest GBK code page")
}

#[test]
fn native_multisz_uses_exact_terminators_at_capacity() {
    let wide = [65, 0, 66, 0, 0];
    for (capacity, expected, truncated) in [
        (5, b"A\0B\0\0".as_slice(), false),
        (4, b"A\0\0".as_slice(), true),
        (3, b"A\0\0".as_slice(), true),
    ] {
        let result =
            native_wide_multisz_to_guest_with_codec(gbk(), &wide, capacity, "test MULTI_SZ")
                .unwrap();
        assert_eq!(result.bytes, expected);
        assert_eq!(result.truncated, truncated);
    }
}

#[test]
fn dbcs_multisz_keeps_utf16_separators_and_final_empty_string() {
    let codec = gbk();
    let first = codec
        .from_wide(&"中文".encode_utf16().collect::<Vec<_>>())
        .unwrap()
        .bytes;
    let second = codec
        .from_wide(&"文本".encode_utf16().collect::<Vec<_>>())
        .unwrap()
        .bytes;
    let mut guest = first.clone();
    guest.push(0);
    guest.extend_from_slice(&second);
    guest.extend_from_slice(&[0, 0]);

    let wide = guest_multisz_to_wide_with_codec(
        codec,
        &guest,
        "test MULTI_SZ must be double terminated",
    )
    .unwrap();
    let expected = "中文"
        .encode_utf16()
        .chain([0])
        .chain("文本".encode_utf16())
        .chain([0, 0])
        .collect::<Vec<_>>();
    assert_eq!(wide, expected);
    assert!(guest_multisz_to_wide_with_codec(
        codec,
        &[0],
        "test MULTI_SZ must be double terminated"
    )
    .is_err());
}

#[test]
fn custom_filter_pair_uses_double_nul_prefix_and_bounded_gbk_output() {
    let codec = gbk();
    let guest_input = b"Custom\0*.txt\0\0uninitialized tail";
    let wide = guest_custom_filter_to_wide_with_codec(
        codec,
        guest_input,
        "test custom filter must have a double-NUL prefix",
    )
    .unwrap();
    let expected_wide = "Custom"
        .encode_utf16()
        .chain([0])
        .chain("*.txt".encode_utf16())
        .chain([0, 0])
        .collect::<Vec<_>>();
    assert_eq!(wide, expected_wide);
    assert!(guest_custom_filter_to_wide_with_codec(
        codec,
        b"Custom\0*.txt\0uninitialized tail",
        "test custom filter must have a double-NUL prefix",
    )
    .is_err());
    assert_eq!(
        guest_custom_filter_to_wide_with_codec(
            codec,
            b"Custom\0\0unused tail",
            "test custom filter must have a double-NUL prefix",
        )
        .unwrap(),
        "Custom".encode_utf16().chain([0, 0]).collect::<Vec<_>>()
    );

    let native = "中文\0*.txt\0".encode_utf16().collect::<Vec<_>>();
    let full = native_custom_filter_to_guest_with_codec(codec, &native, 12, "test custom filter")
        .unwrap();
    assert_eq!(full.bytes, b"\xD6\xD0\xCE\xC4\0*.txt\0\0");
    assert!(!full.truncated);

    let bounded =
        native_custom_filter_to_guest_with_codec(codec, &native, 5, "test custom filter")
            .unwrap();
    assert_eq!(bounded.bytes, b"\xD6\xD0\0\0");
    assert!(bounded.truncated);
}

#[test]
fn dbcs_wide_offsets_project_to_guest_byte_offsets() {
    let codec = gbk();
    let wide = "中/file.txt".encode_utf16().collect::<Vec<_>>();
    let offset_after_directory = 2;
    assert_eq!(
        native_wide_prefix_guest_bytes_with_codec(
            codec,
            &wide[..offset_after_directory],
            "test path offset conversion"
        )
        .unwrap(),
        3
    );
}

#[test]
fn devnames_roundtrip_translates_byte_offsets_to_utf16_units() {
    let codec = gbk();
    let driver = codec
        .from_wide(&"驱动".encode_utf16().collect::<Vec<_>>())
        .unwrap()
        .bytes;
    let device = codec
        .from_wide(&"打印机".encode_utf16().collect::<Vec<_>>())
        .unwrap()
        .bytes;
    let output = b"LPT1:";
    let driver_offset = DEVNAMES_HEADER_BYTES as u16;
    let device_offset = (DEVNAMES_HEADER_BYTES + driver.len() + 1) as u16;
    let output_offset = (DEVNAMES_HEADER_BYTES + driver.len() + device.len() + 2) as u16;
    let mut guest = Vec::new();
    for word in [driver_offset, device_offset, output_offset, 1] {
        guest.extend_from_slice(&word.to_le_bytes());
    }
    guest.extend_from_slice(&driver);
    guest.push(0);
    guest.extend_from_slice(&device);
    guest.push(0);
    guest.extend_from_slice(output);
    guest.push(0);

    let native = guest_devnames_to_wide_with_codec(codec, &guest).unwrap();
    let native_driver_offset = u16::from_le_bytes([native[0], native[1]]);
    let native_device_offset = u16::from_le_bytes([native[2], native[3]]);
    let native_output_offset = u16::from_le_bytes([native[4], native[5]]);
    assert_eq!(native_driver_offset, 4);
    assert_eq!(
        native_device_offset,
        4 + "驱动".encode_utf16().count() as u16 + 1
    );
    assert_eq!(
        native_output_offset,
        native_device_offset + "打印机".encode_utf16().count() as u16 + 1
    );
    assert_eq!(
        native_wide_devnames_to_guest_with_codec(codec, &native).unwrap(),
        (guest, false)
    );
}

#[test]
fn devnames_rejects_offsets_into_the_fixed_header() {
    let codec = gbk();
    let mut guest = vec![0_u8; DEVNAMES_HEADER_BYTES];
    for (index, word) in [4_u16, 4, 4, 0].into_iter().enumerate() {
        guest[index * 2..index * 2 + 2].copy_from_slice(&word.to_le_bytes());
    }
    assert!(guest_devnames_to_wide_with_codec(codec, &guest).is_err());
}
