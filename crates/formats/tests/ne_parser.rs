use formats::{
    parse_ne, FormatError, NeEntryKind, NeFixupAddressType, NeFixupTarget, NeRelocationKind,
    NeResourceId,
};

#[test]
fn parses_ne_header_segments_entries_imports_and_names() {
    let bytes = minimal_ne();
    let parsed = parse_ne(&bytes).expect("valid NE");
    assert_eq!(parsed.header.segment_count, 1);
    assert_eq!(parsed.segments.len(), 1);
    assert_eq!(parsed.segments[0].file_size, 4);
    assert_eq!(parsed.segments[0].memory_size, 16);
    assert_eq!(parsed.entries[0].kind, NeEntryKind::Fixed { segment: 1, offset: 0 });
    assert_eq!(parsed.resident_names[0].name, b"APP");
    assert_eq!(parsed.nonresident_names[0].name, b"EXTRA");
    assert_eq!(parsed.imported_modules[0].name, b"KERNEL");
}

#[test]
fn zero_segment_alignment_uses_nine_without_rewriting_the_header() {
    let mut bytes = minimal_ne();
    bytes[0xb2..0xb4].copy_from_slice(&0_u16.to_le_bytes());
    bytes[0xd8..0xda].copy_from_slice(&1_u16.to_le_bytes());
    bytes.resize(0x204, 0);
    bytes[0x200..0x204].copy_from_slice(&[0x90, 0x90, 0xc3, 0]);

    let parsed = parse_ne(&bytes).expect("zero alignment selects 512-byte sectors");
    assert_eq!(parsed.header.alignment_shift, 0);
    assert_eq!(parsed.header.segment_alignment_shift(), 9);
    assert_eq!(parsed.segments[0].file_offset, Some(0x200));
    assert_eq!(parsed.segments[0].file_size, 4);
    assert_eq!(parsed.segments[0].memory_size, 16);
}

#[test]
fn explicit_segment_alignment_shifts_are_preserved() {
    for shift in 1_u16..=15 {
        let mut bytes = minimal_ne();
        let offset = 0x200_usize.max(1_usize << shift);
        let sector = (offset >> shift) as u16;
        bytes[0xb2..0xb4].copy_from_slice(&shift.to_le_bytes());
        bytes[0xd8..0xda].copy_from_slice(&sector.to_le_bytes());
        bytes.resize(offset + 4, 0);
        bytes[offset..offset + 4].copy_from_slice(&[0x90, 0x90, 0xc3, 0]);

        let parsed = parse_ne(&bytes).expect("explicit segment alignment");
        assert_eq!(parsed.header.alignment_shift, shift);
        assert_eq!(parsed.header.segment_alignment_shift(), shift);
        assert_eq!(parsed.segments[0].file_offset, Some(offset));
    }
}

#[test]
fn zero_sector_remains_unallocated_with_default_alignment() {
    let mut bytes = minimal_ne();
    bytes[0xb2..0xb4].copy_from_slice(&0_u16.to_le_bytes());
    bytes[0xd8..0xda].copy_from_slice(&0_u16.to_le_bytes());

    let parsed = parse_ne(&bytes).expect("unallocated segment has no file image");
    assert_eq!(parsed.header.segment_alignment_shift(), 9);
    assert_eq!(parsed.segments[0].file_offset, None);
    assert_eq!(parsed.segments[0].file_size, 0);
    assert_eq!(parsed.segments[0].memory_size, 16);
}

#[test]
fn parses_real_ne_relocation_record_and_target() {
    let bytes = minimal_ne_with_fixup();
    let parsed = parse_ne(&bytes).expect("valid NE with relocation");
    let fixup = parsed.segments.first().and_then(|segment| segment.fixups.first()).expect("fixup record");
    assert_eq!(fixup.address_type, NeFixupAddressType::Offset16);
    assert_eq!(fixup.relocation_kind, NeRelocationKind::Internal);
    assert_eq!(fixup.target, NeFixupTarget::InternalSegment { segment: 1, offset: 0 });
    assert_eq!(fixup.source_offset, 0);
}

#[test]
fn truncated_ne_table_and_bad_entry_offset_are_rejected() {
    let mut bytes = minimal_ne();
    bytes.truncate(100);
    assert!(matches!(parse_ne(&bytes), Err(FormatError::Truncated { .. })));
    let mut bytes = minimal_ne();
    bytes[0x84..0x86].copy_from_slice(&0xffff_u16.to_le_bytes());
    assert!(matches!(parse_ne(&bytes), Err(FormatError::Truncated { .. })));
}

#[test]
fn import_by_name_fixups_are_decoded_from_the_import_name_table() {
    let bytes = minimal_ne_with_import_name_fixup();
    let parsed = parse_ne(&bytes).expect("valid import-name fixup");
    let fixup = parsed.segments.first().and_then(|segment| segment.fixups.first()).expect("fixup record");
    assert_eq!(fixup.target, NeFixupTarget::ImportName { module_index: 1, name: b"GetVersion".to_vec() });
}

#[test]
fn resource_table_parses_numeric_type_and_resource_ids() {
    let mut bytes = minimal_ne();
    bytes[0xa4..0xa6].copy_from_slice(&0x60_u16.to_le_bytes()); // resource table starts at NE+0x60
    bytes[0xa6..0xa8].copy_from_slice(&0x80_u16.to_le_bytes()); // resident names start at NE+0x80
    bytes[0xa8..0xaa].copy_from_slice(&0x90_u16.to_le_bytes()); // module refs
    bytes[0xaa..0xac].copy_from_slice(&0x92_u16.to_le_bytes()); // imported names
    bytes[0x84..0x86].copy_from_slice(&0xb0_u16.to_le_bytes()); // entry table
    bytes[0xe0..0xe2].copy_from_slice(&0_u16.to_le_bytes()); // resource alignment
    bytes[0xe2..0xe4].copy_from_slice(&0x8003_u16.to_le_bytes()); // RT_ICON
    bytes[0xe4..0xe6].copy_from_slice(&1_u16.to_le_bytes()); // one resource
    bytes[0xe6..0xea].copy_from_slice(&0_u32.to_le_bytes());
    bytes[0xea..0xec].copy_from_slice(&0x160_u16.to_le_bytes()); // resource bytes offset
    bytes[0xec..0xee].copy_from_slice(&1_u16.to_le_bytes()); // one byte long
    bytes[0xee..0xf0].copy_from_slice(&0x0020_u16.to_le_bytes()); // flags
    bytes[0xf0..0xf2].copy_from_slice(&0x8007_u16.to_le_bytes()); // resource id 7
    bytes[0xf2..0xf6].copy_from_slice(&[0, 0, 0, 0]);
    bytes[0xf6..0xf8].copy_from_slice(&0_u16.to_le_bytes()); // type terminator
    bytes[0x100] = 3;
    bytes[0x101..0x104].copy_from_slice(b"APP");
    bytes[0x104..0x106].copy_from_slice(&0_u16.to_le_bytes());
    bytes[0x106] = 0;
    bytes[0x110..0x112].copy_from_slice(&0_u16.to_le_bytes());
    bytes[0x112] = 6;
    bytes[0x113..0x119].copy_from_slice(b"KERNEL");
    bytes[0x130..0x136].copy_from_slice(&[1, 1, 0, 0, 0, 0]);
    bytes[0x160] = 0xaa;
    let parsed = parse_ne(&bytes).expect("valid NE resources");
    let resource_type = parsed.resource_types.first().expect("resource type");
    assert_eq!(resource_type.id, NeResourceId::Numeric(3));
    let resource = resource_type.resources.first().expect("resource");
    assert_eq!(resource.id, NeResourceId::Numeric(7));
    assert_eq!((resource.file_offset, resource.byte_length), (0x160, 1));

    // Default segment alignment must not change the resource table's own
    // zero shift: resource offsets and lengths remain byte-granular.
    bytes[0xb2..0xb4].copy_from_slice(&0_u16.to_le_bytes());
    bytes[0xd8..0xda].copy_from_slice(&1_u16.to_le_bytes());
    bytes.resize(0x204, 0);
    let parsed = parse_ne(&bytes).expect("independent segment and resource alignment");
    assert_eq!(parsed.header.segment_alignment_shift(), 9);
    assert_eq!(parsed.segments[0].file_offset, Some(0x200));
    let resource = &parsed.resource_types[0].resources[0];
    assert_eq!((resource.file_offset, resource.byte_length), (0x160, 1));
}

fn minimal_ne() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x180];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x08..0x0a].copy_from_slice(&4_u16.to_le_bytes());
    bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    bytes[0x80..0x82].copy_from_slice(b"NE");
    bytes[0x84..0x86].copy_from_slice(&0x90_u16.to_le_bytes()); // entry table
    bytes[0x86..0x88].copy_from_slice(&6_u16.to_le_bytes());
    bytes[0x8c..0x8e].copy_from_slice(&0_u16.to_le_bytes());
    bytes[0x9c..0x9e].copy_from_slice(&1_u16.to_le_bytes()); // segments
    bytes[0x9e..0xa0].copy_from_slice(&1_u16.to_le_bytes()); // module refs
    bytes[0xa2..0xa4].copy_from_slice(&0x58_u16.to_le_bytes()); // segment table
    bytes[0xa4..0xa6].copy_from_slice(&0x60_u16.to_le_bytes()); // resource table: absent below resident table
    bytes[0xa6..0xa8].copy_from_slice(&0x60_u16.to_le_bytes()); // resident names
    bytes[0xa8..0xaa].copy_from_slice(&0x70_u16.to_le_bytes()); // module refs
    bytes[0xaa..0xac].copy_from_slice(&0x72_u16.to_le_bytes()); // import names
    bytes[0xac..0xb0].copy_from_slice(&0x170_u32.to_le_bytes()); // nonresident names
    bytes[0xb0..0xb2].copy_from_slice(&0_u16.to_le_bytes()); // movable count
    bytes[0xb2..0xb4].copy_from_slice(&4_u16.to_le_bytes()); // alignment shift
    bytes[0xbe..0xc0].copy_from_slice(&0x0400_u16.to_le_bytes()); // expected version
    // Segment table at NE+0x58: sector 0x0c => file offset 0xc0, length 4, alloc 16.
    bytes[0xd8..0xda].copy_from_slice(&0x0c_u16.to_le_bytes());
    bytes[0xda..0xdc].copy_from_slice(&4_u16.to_le_bytes());
    bytes[0xde..0xe0].copy_from_slice(&16_u16.to_le_bytes());
    bytes[0xc0..0xc4].copy_from_slice(&[0x90, 0x90, 0xc3, 0x00]);
    // Resident-name table.
    bytes[0xe0] = 3;
    bytes[0xe1..0xe4].copy_from_slice(b"APP");
    bytes[0xe4..0xe6].copy_from_slice(&0_u16.to_le_bytes());
    bytes[0xe6] = 0;
    // Module reference word points to the first Pascal name in imported names.
    bytes[0xf0..0xf2].copy_from_slice(&0_u16.to_le_bytes());
    bytes[0xf2] = 6;
    bytes[0xf3..0xf9].copy_from_slice(b"KERNEL");
    // Entry table: one fixed entry at ordinal 1, then terminator.
    bytes[0x110..0x116].copy_from_slice(&[1, 1, 0, 0, 0, 0]);
    // Nonresident names.
    bytes[0x170] = 5;
    bytes[0x171..0x176].copy_from_slice(b"EXTRA");
    bytes[0x176..0x178].copy_from_slice(&9_u16.to_le_bytes());
    bytes[0x178] = 0;
    bytes[0xa0..0xa2].copy_from_slice(&10_u16.to_le_bytes());
    bytes
}

fn minimal_ne_with_fixup() -> Vec<u8> {
    let mut bytes = minimal_ne();
    bytes[0xdc..0xde].copy_from_slice(&0x0100_u16.to_le_bytes());
    bytes[0xc0..0xc4].copy_from_slice(&[0, 0, 0xc3, 0]);
    bytes[0xc4..0xc6].copy_from_slice(&1_u16.to_le_bytes());
    bytes[0xc6..0xce].copy_from_slice(&[5, 0, 0, 0, 1, 0, 0, 0]);
    bytes
}

fn minimal_ne_with_import_name_fixup() -> Vec<u8> {
    let mut bytes = minimal_ne();
    bytes[0xdc..0xde].copy_from_slice(&0x0100_u16.to_le_bytes());
    // KERNEL occupies offsets 0..7; the fixup target points at GetVersion.
    bytes[0xf9] = 10;
    bytes[0xfa..0x104].copy_from_slice(b"GetVersion");
    bytes[0xc4..0xc6].copy_from_slice(&1_u16.to_le_bytes());
    bytes[0xc6..0xce].copy_from_slice(&[5, 2, 0, 0, 1, 0, 7, 0]);
    bytes
}
