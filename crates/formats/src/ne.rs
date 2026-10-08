use crate::{read_u16, read_u32, FormatError};

const MZ_HEADER_SIZE_FOR_NE: usize = 0x40;
const NE_HEADER_SIZE: usize = 0x40;
const NE_SEGMENT_RECORD_SIZE: usize = 8;
const NE_FIXUP_RECORD_SIZE: usize = 8;
const SEGMENT_FLAG_HAS_FIXUPS: u16 = 0x0100;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeHeader {
    pub linker_version: u8,
    pub linker_revision: u8,
    pub entry_table_offset: u16,
    pub entry_table_length: u16,
    pub checksum: u32,
    pub flags: u16,
    pub automatic_data_segment: u16,
    pub heap_size: u16,
    pub stack_size: u16,
    pub initial_ip: u16,
    pub initial_cs: u16,
    pub initial_sp: u16,
    pub initial_ss: u16,
    pub segment_count: u16,
    pub module_reference_count: u16,
    pub nonresident_name_length: u16,
    pub segment_table_offset: u16,
    pub resource_table_offset: u16,
    pub resident_name_table_offset: u16,
    pub module_reference_table_offset: u16,
    pub imported_name_table_offset: u16,
    pub nonresident_name_table_offset: u32,
    pub movable_entry_count: u16,
    pub alignment_shift: u16,
    pub resource_segment_count: u16,
    pub target_os: u8,
    pub other_flags: u8,
    pub return_thunk_offset: u16,
    pub segment_reference_thunk_offset: u16,
    pub minimum_code_swap_area: u16,
    pub expected_windows_version: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeModule {
    pub ne_header_offset: usize,
    pub header: NeHeader,
    pub segments: Vec<NeSegment>,
    pub entries: Vec<NeEntry>,
    pub resident_names: Vec<NeNamedEntry>,
    pub nonresident_names: Vec<NeNamedEntry>,
    pub imported_modules: Vec<NeImportModule>,
    pub resource_types: Vec<NeResourceType>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeSegment {
    /// One-based NE segment number.
    pub number: u16,
    pub file_offset: Option<usize>,
    pub file_size: u32,
    pub memory_size: u32,
    pub flags: u16,
    pub fixups: Vec<NeFixup>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeEntry {
    pub ordinal: u16,
    pub kind: NeEntryKind,
    pub flags: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NeEntryKind {
    Unused,
    Fixed { segment: u16, offset: u16 },
    Movable { segment: u16, offset: u16 },
    Constant(u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeNamedEntry {
    pub name: Vec<u8>,
    pub ordinal: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeImportModule {
    /// One-based module reference used in fixup records.
    pub index: u16,
    pub name_table_offset: u16,
    pub name: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeResourceType {
    pub id: NeResourceId,
    pub resources: Vec<NeResource>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeResource {
    pub id: NeResourceId,
    pub file_offset: usize,
    pub byte_length: usize,
    pub flags: u16,
    pub handle: u16,
    pub usage: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NeResourceId {
    Numeric(u16),
    Name(Vec<u8>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NeFixup {
    pub source_offset: u16,
    pub address_type: NeFixupAddressType,
    pub relocation_kind: NeRelocationKind,
    pub additive: bool,
    pub target: NeFixupTarget,
    pub raw_target1: u16,
    pub raw_target2: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NeFixupAddressType {
    LowByte,
    Selector,
    FarPointer32,
    Offset16,
    FarPointer48,
    Offset32,
    Unknown(u8),
}

impl NeFixupAddressType {
    pub(crate) fn width(self) -> Option<u32> {
        match self {
            Self::LowByte => Some(1),
            Self::Selector | Self::Offset16 => Some(2),
            Self::FarPointer32 | Self::Offset32 => Some(4),
            Self::FarPointer48 => Some(6),
            Self::Unknown(_) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NeRelocationKind {
    Internal,
    ImportByOrdinal,
    ImportByName,
    OsFixup,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NeFixupTarget {
    InternalSegment { segment: u16, offset: u16 },
    InternalEntry { ordinal: u16 },
    ImportOrdinal { module_index: u16, ordinal: u16 },
    ImportName { module_index: u16, name: Vec<u8> },
    OsFixup { target1: u16, target2: u16 },
}

/// Parse all structural NE tables and relocation records from an MZ-wrapped NE.
/// This routine only reads file bytes; it does not allocate or load NE segments.
pub fn parse_ne(bytes: &[u8]) -> Result<NeModule, FormatError> {
    if bytes.get(0..2) != Some(b"MZ".as_slice()) {
        return Err(FormatError::InvalidSignature { expected: "MZ-wrapped NE" });
    }
    if bytes.len() < MZ_HEADER_SIZE_FOR_NE {
        return Err(FormatError::Truncated { context: "MZ header containing NE offset", offset: 0, needed: MZ_HEADER_SIZE_FOR_NE });
    }
    let dos_header_size = usize::from(read_u16(bytes, 0x08, "MZ header paragraphs")?)
        .checked_mul(16)
        .ok_or(FormatError::ArithmeticOverflow)?;
    if dos_header_size < MZ_HEADER_SIZE_FOR_NE {
        return Err(FormatError::InvalidNe("MZ header is too short to contain the NE offset"));
    }
    let ne_header_offset = usize::try_from(read_u32(bytes, 0x3c, "MZ NE offset")?)
        .map_err(|_| FormatError::ArithmeticOverflow)?;
    if ne_header_offset < dos_header_size {
        return Err(FormatError::InvalidNe("NE header overlaps the DOS header"));
    }
    let fixed_header = checked_range(bytes, ne_header_offset, NE_HEADER_SIZE, "NE fixed header")?;
    if fixed_header.get(0..2) != Some(b"NE".as_slice()) {
        return Err(FormatError::InvalidSignature { expected: "NE" });
    }
    let header = parse_ne_header(bytes, ne_header_offset)?;
    if header.alignment_shift > 15 {
        return Err(FormatError::InvalidNe("segment alignment shift exceeds 15"));
    }
    if header.segment_count > 255 {
        return Err(FormatError::InvalidNe("segment count exceeds the one-byte NE reference limit"));
    }

    let segment_records_len = usize::from(header.segment_count)
        .checked_mul(NE_SEGMENT_RECORD_SIZE)
        .ok_or(FormatError::ArithmeticOverflow)?;
    let segment_table_start = relative_offset(ne_header_offset, header.segment_table_offset)?;
    let segment_table = checked_range(bytes, segment_table_start, segment_records_len, "NE segment table")?;

    let resident_start = relative_offset(ne_header_offset, header.resident_name_table_offset)?;
    let module_refs_start = relative_offset(ne_header_offset, header.module_reference_table_offset)?;
    let imported_names_start = relative_offset(ne_header_offset, header.imported_name_table_offset)?;
    let entry_table_start = relative_offset(ne_header_offset, header.entry_table_offset)?;
    if module_refs_start < resident_start || imported_names_start < module_refs_start || entry_table_start < imported_names_start {
        return Err(FormatError::InvalidNe("resident, module-reference, import-name, and entry tables are out of order"));
    }
    let resident_table = checked_range(bytes, resident_start, module_refs_start - resident_start, "NE resident names")?;
    let module_ref_bytes = usize::from(header.module_reference_count)
        .checked_mul(2)
        .ok_or(FormatError::ArithmeticOverflow)?;
    let module_ref_end = module_refs_start.checked_add(module_ref_bytes).ok_or(FormatError::ArithmeticOverflow)?;
    if module_ref_end > imported_names_start {
        return Err(FormatError::InvalidNe("module-reference table overlaps imported names"));
    }
    checked_range(bytes, module_refs_start, module_ref_bytes, "NE module references")?;
    let import_names_table = checked_range(bytes, imported_names_start, entry_table_start - imported_names_start, "NE imported names")?;
    let entry_table = checked_range(bytes, entry_table_start, usize::from(header.entry_table_length), "NE entry table")?;

    let resource_types = parse_resource_table(bytes, ne_header_offset, &header)?;
    let resident_names = parse_name_table(resident_table, "NE resident names")?;
    let nonresident_names = parse_nonresident_names(bytes, &header)?;
    let mut segments = parse_segments(bytes, segment_table, &header)?;
    let imported_modules = parse_import_modules(bytes, module_refs_start, module_ref_bytes, import_names_table)?;
    let entries = parse_entries(entry_table, &header, &segments)?;
    parse_segment_fixups(bytes, &import_names_table, &imported_modules, &entries, &mut segments)?;

    Ok(NeModule {
        ne_header_offset,
        header,
        segments,
        entries,
        resident_names,
        nonresident_names,
        imported_modules,
        resource_types,
    })
}

fn parse_ne_header(bytes: &[u8], base: usize) -> Result<NeHeader, FormatError> {
    let field = |offset: usize, name| read_u16(bytes, base.checked_add(offset).ok_or(FormatError::ArithmeticOverflow)?, name);
    let byte = |offset: usize, name| read_u8(bytes, base.checked_add(offset).ok_or(FormatError::ArithmeticOverflow)?, name);
    Ok(NeHeader {
        linker_version: byte(0x02, "NE linker version")?,
        linker_revision: byte(0x03, "NE linker revision")?,
        entry_table_offset: field(0x04, "NE entry table offset")?,
        entry_table_length: field(0x06, "NE entry table length")?,
        checksum: read_u32(bytes, base.checked_add(0x08).ok_or(FormatError::ArithmeticOverflow)?, "NE checksum")?,
        flags: field(0x0c, "NE flags")?,
        automatic_data_segment: field(0x0e, "NE automatic data segment")?,
        heap_size: field(0x10, "NE heap size")?,
        stack_size: field(0x12, "NE stack size")?,
        initial_ip: field(0x14, "NE initial IP")?,
        initial_cs: field(0x16, "NE initial CS")?,
        initial_sp: field(0x18, "NE initial SP")?,
        initial_ss: field(0x1a, "NE initial SS")?,
        segment_count: field(0x1c, "NE segment count")?,
        module_reference_count: field(0x1e, "NE module-reference count")?,
        nonresident_name_length: field(0x20, "NE nonresident-name length")?,
        segment_table_offset: field(0x22, "NE segment table offset")?,
        resource_table_offset: field(0x24, "NE resource table offset")?,
        resident_name_table_offset: field(0x26, "NE resident-name table offset")?,
        module_reference_table_offset: field(0x28, "NE module-reference table offset")?,
        imported_name_table_offset: field(0x2a, "NE imported-name table offset")?,
        nonresident_name_table_offset: read_u32(bytes, base.checked_add(0x2c).ok_or(FormatError::ArithmeticOverflow)?, "NE nonresident-name table offset")?,
        movable_entry_count: field(0x30, "NE movable-entry count")?,
        alignment_shift: field(0x32, "NE alignment shift")?,
        resource_segment_count: field(0x34, "NE resource segment count")?,
        target_os: byte(0x36, "NE target OS")?,
        other_flags: byte(0x37, "NE other flags")?,
        return_thunk_offset: field(0x38, "NE return-thunk offset")?,
        segment_reference_thunk_offset: field(0x3a, "NE segment-reference-thunk offset")?,
        minimum_code_swap_area: field(0x3c, "NE minimum code swap area")?,
        expected_windows_version: field(0x3e, "NE expected Windows version")?,
    })
}

fn parse_segments(bytes: &[u8], table: &[u8], header: &NeHeader) -> Result<Vec<NeSegment>, FormatError> {
    let mut segments = Vec::with_capacity(usize::from(header.segment_count));
    for index in 0..usize::from(header.segment_count) {
        let record_offset = index.checked_mul(NE_SEGMENT_RECORD_SIZE).ok_or(FormatError::ArithmeticOverflow)?;
        let sector = read_u16(table, record_offset, "NE segment sector offset")?;
        let raw_file_size = read_u16(table, record_offset + 2, "NE segment file length")?;
        let flags = read_u16(table, record_offset + 4, "NE segment flags")?;
        let raw_memory_size = read_u16(table, record_offset + 6, "NE segment allocation size")?;
        let file_offset = if sector == 0 {
            None
        } else {
            let absolute = u32::from(sector)
                .checked_shl(u32::from(header.alignment_shift))
                .ok_or(FormatError::InvalidNe("segment file offset overflows"))?;
            Some(usize::try_from(absolute).map_err(|_| FormatError::ArithmeticOverflow)?)
        };
        let file_size = match file_offset {
            None => 0,
            Some(_) if raw_file_size == 0 => 0x1_0000,
            Some(_) => u32::from(raw_file_size),
        };
        let file_size_usize = usize::try_from(file_size).map_err(|_| FormatError::ArithmeticOverflow)?;
        if let Some(offset) = file_offset {
            checked_range(bytes, offset, file_size_usize, "NE segment image")?;
        }
        let raw_memory_size = if raw_memory_size == 0 { 0x1_0000 } else { u32::from(raw_memory_size) };
        let memory_size = raw_memory_size.max(file_size);
        segments.push(NeSegment {
            number: u16::try_from(index + 1).map_err(|_| FormatError::ArithmeticOverflow)?,
            file_offset,
            file_size,
            memory_size,
            flags,
            fixups: Vec::new(),
        });
    }
    Ok(segments)
}

fn parse_entries(table: &[u8], header: &NeHeader, segments: &[NeSegment]) -> Result<Vec<NeEntry>, FormatError> {
    let mut position = 0_usize;
    let mut ordinal = 1_u32;
    let mut movable_count = 0_u16;
    let mut entries = Vec::new();
    let mut terminated = false;
    while position < table.len() {
        let count = usize::from(read_u8(table, position, "NE entry bundle count")?);
        position = position.checked_add(1).ok_or(FormatError::ArithmeticOverflow)?;
        if count == 0 {
            terminated = true;
            break;
        }
        let bundle_segment = read_u8(table, position, "NE entry bundle segment")?;
        position = position.checked_add(1).ok_or(FormatError::ArithmeticOverflow)?;
        let last_ordinal = ordinal.checked_add(u32::try_from(count).map_err(|_| FormatError::ArithmeticOverflow)?)
            .ok_or(FormatError::InvalidNe("entry ordinals overflow"))?;
        if last_ordinal > u32::from(u16::MAX) + 1 {
            return Err(FormatError::InvalidNe("entry ordinal exceeds 65535"));
        }
        if bundle_segment == 0 {
            for current in ordinal..last_ordinal {
                entries.push(NeEntry {
                    ordinal: u16::try_from(current).map_err(|_| FormatError::ArithmeticOverflow)?,
                    kind: NeEntryKind::Unused,
                    flags: 0,
                });
            }
        } else {
            for current in ordinal..last_ordinal {
                let flags = read_u8(table, position, "NE entry flags")?;
                position = position.checked_add(1).ok_or(FormatError::ArithmeticOverflow)?;
                let kind = if bundle_segment == 0xff {
                    // Movable entries include the two-byte INT 3F instruction before segment:offset.
                    checked_range(table, position, 2, "NE movable-entry interrupt marker")?;
                    position = position.checked_add(2).ok_or(FormatError::ArithmeticOverflow)?;
                    let segment = u16::from(read_u8(table, position, "NE movable-entry segment")?);
                    position = position.checked_add(1).ok_or(FormatError::ArithmeticOverflow)?;
                    let offset = read_u16(table, position, "NE movable-entry offset")?;
                    position = position.checked_add(2).ok_or(FormatError::ArithmeticOverflow)?;
                    movable_count = movable_count.checked_add(1).ok_or(FormatError::InvalidNe("movable-entry count overflows"))?;
                    NeEntryKind::Movable { segment, offset }
                } else if bundle_segment == 0xfe {
                    // Windows 3.1 Programmer's Reference, Vol. 4 (1992),
                    // §6.2.7 defines FEh as a module constant. The earlier
                    // 1991 EXEFMT note conflicts by treating FEh as a segment;
                    // this parser follows the later target-version manual.
                    let value = read_u16(table, position, "NE module constant")?;
                    position = position.checked_add(2).ok_or(FormatError::ArithmeticOverflow)?;
                    NeEntryKind::Constant(value)
                } else {
                    let offset = read_u16(table, position, "NE fixed-entry offset")?;
                    position = position.checked_add(2).ok_or(FormatError::ArithmeticOverflow)?;
                    NeEntryKind::Fixed { segment: u16::from(bundle_segment), offset }
                };
                match kind {
                    NeEntryKind::Fixed { segment, offset } | NeEntryKind::Movable { segment, offset } => {
                        let segment_index = segment.checked_sub(1)
                            .ok_or(FormatError::InvalidNe("entry references segment zero"))?;
                        let segment_record = segments.get(usize::from(segment_index))
                            .ok_or(FormatError::InvalidNe("entry references a nonexistent segment"))?;
                        if u32::from(offset) >= segment_record.memory_size {
                            return Err(FormatError::InvalidNe("entry offset is outside its segment"));
                        }
                    }
                    NeEntryKind::Constant(_) => {}
                    NeEntryKind::Unused => return Err(FormatError::InvalidNe("unexpected unused entry")),
                }
                entries.push(NeEntry {
                    ordinal: u16::try_from(current).map_err(|_| FormatError::ArithmeticOverflow)?,
                    kind,
                    flags,
                });
            }
        }
        ordinal = last_ordinal;
    }
    if !terminated {
        return Err(FormatError::InvalidNe("entry table has no zero-count terminator"));
    }
    if movable_count != header.movable_entry_count {
        return Err(FormatError::InvalidNe("movable-entry count disagrees with the entry table"));
    }
    Ok(entries)
}

fn parse_import_modules(
    bytes: &[u8],
    refs_start: usize,
    refs_len: usize,
    import_names: &[u8],
) -> Result<Vec<NeImportModule>, FormatError> {
    let refs = checked_range(bytes, refs_start, refs_len, "NE module references")?;
    let mut modules = Vec::with_capacity(refs_len / 2);
    for index in 0..(refs_len / 2) {
        let name_table_offset = read_u16(refs, index.checked_mul(2).ok_or(FormatError::ArithmeticOverflow)?, "NE module-name reference")?;
        let name = read_pascal_string(import_names, usize::from(name_table_offset), "NE imported module name")?;
        modules.push(NeImportModule {
            index: u16::try_from(index + 1).map_err(|_| FormatError::ArithmeticOverflow)?,
            name_table_offset,
            name,
        });
    }
    Ok(modules)
}

fn parse_segment_fixups(
    bytes: &[u8],
    import_names: &[u8],
    imports: &[NeImportModule],
    entries: &[NeEntry],
    segments: &mut [NeSegment],
) -> Result<(), FormatError> {
    for segment_index in 0..segments.len() {
        let (flags, file_offset, file_size, memory_size) = {
            let segment = segments.get(segment_index).ok_or(FormatError::InvalidNe("missing segment record"))?;
            (segment.flags, segment.file_offset, segment.file_size, segment.memory_size)
        };
        if flags & SEGMENT_FLAG_HAS_FIXUPS == 0 { continue; }
        let image_start = file_offset.ok_or(FormatError::InvalidNe("segment without file data has relocation records"))?;
        let fixup_table_start = image_start.checked_add(usize::try_from(file_size).map_err(|_| FormatError::ArithmeticOverflow)?)
            .ok_or(FormatError::ArithmeticOverflow)?;
        let count = usize::from(read_u16(bytes, fixup_table_start, "NE fixup count")?);
        let records_start = fixup_table_start.checked_add(2).ok_or(FormatError::ArithmeticOverflow)?;
        let record_bytes = count.checked_mul(NE_FIXUP_RECORD_SIZE).ok_or(FormatError::ArithmeticOverflow)?;
        let records = checked_range(bytes, records_start, record_bytes, "NE fixup records")?;
        let mut fixups = Vec::with_capacity(count);
        for index in 0..count {
            let record_offset = index.checked_mul(NE_FIXUP_RECORD_SIZE).ok_or(FormatError::ArithmeticOverflow)?;
            let raw_address = read_u8(records, record_offset, "NE fixup address type")?;
            let raw_relocation = read_u8(records, record_offset + 1, "NE fixup relocation type")?;
            let source_offset = read_u16(records, record_offset + 2, "NE fixup source offset")?;
            let target1 = read_u16(records, record_offset + 4, "NE fixup target one")?;
            let target2 = read_u16(records, record_offset + 6, "NE fixup target two")?;
            let address_type = decode_address_type(raw_address & 0x7f);
            let relocation_kind = decode_relocation_kind(raw_relocation & 0x03);
            let additive = raw_relocation & 0x04 != 0;
            if let Some(width) = address_type.width() {
                let source_end = u32::from(source_offset).checked_add(width).ok_or(FormatError::ArithmeticOverflow)?;
                if source_end > memory_size {
                    return Err(FormatError::InvalidNe("fixup source extends past its segment"));
                }
            } else if u32::from(source_offset) >= memory_size {
                return Err(FormatError::InvalidNe("unknown fixup source is outside its segment"));
            }
            let target = decode_fixup_target(target1, target2, relocation_kind, import_names, imports, entries, segments)?;
            fixups.push(NeFixup { source_offset, address_type, relocation_kind, additive, target, raw_target1: target1, raw_target2: target2 });
        }
        let segment = segments.get_mut(segment_index).ok_or(FormatError::InvalidNe("missing segment record"))?;
        segment.fixups = fixups;
    }
    Ok(())
}

fn decode_fixup_target(
    target1: u16,
    target2: u16,
    kind: NeRelocationKind,
    import_names: &[u8],
    imports: &[NeImportModule],
    entries: &[NeEntry],
    segments: &[NeSegment],
) -> Result<NeFixupTarget, FormatError> {
    match kind {
        NeRelocationKind::Internal => {
            let segment_number = target1 & 0x00ff;
            if segment_number == 0xff {
                if target2 == 0 || !entries.iter().any(|entry| entry.ordinal == target2 && entry.kind != NeEntryKind::Unused) {
                    return Err(FormatError::InvalidNe("internal fixup references a missing entry ordinal"));
                }
                Ok(NeFixupTarget::InternalEntry { ordinal: target2 })
            } else {
                let segment_index = segment_number.checked_sub(1)
                    .ok_or(FormatError::InvalidNe("internal fixup references segment zero"))?;
                let segment = segments.get(usize::from(segment_index))
                    .ok_or(FormatError::InvalidNe("internal fixup references a nonexistent segment"))?;
                if u32::from(target2) >= segment.memory_size {
                    return Err(FormatError::InvalidNe("internal fixup offset is outside its segment"));
                }
                Ok(NeFixupTarget::InternalSegment { segment: segment_number, offset: target2 })
            }
        }
        NeRelocationKind::ImportByOrdinal => {
            let module_index = target1.checked_sub(1).ok_or(FormatError::InvalidNe("ordinal fixup module index is zero"))?;
            let import = imports.get(usize::from(module_index))
                .ok_or(FormatError::InvalidNe("ordinal fixup references a nonexistent import module"))?;
            if target2 == 0 { return Err(FormatError::InvalidNe("import ordinal is zero")); }
            Ok(NeFixupTarget::ImportOrdinal { module_index: import.index, ordinal: target2 })
        }
        NeRelocationKind::ImportByName => {
            let module_index = target1.checked_sub(1).ok_or(FormatError::InvalidNe("name fixup module index is zero"))?;
            let import = imports.get(usize::from(module_index))
                .ok_or(FormatError::InvalidNe("name fixup references a nonexistent import module"))?;
            let name = read_pascal_string(import_names, usize::from(target2), "NE imported function name")?;
            Ok(NeFixupTarget::ImportName { module_index: import.index, name })
        }
        NeRelocationKind::OsFixup => Ok(NeFixupTarget::OsFixup { target1, target2 }),
    }
}

fn parse_resource_table(bytes: &[u8], ne_base: usize, header: &NeHeader) -> Result<Vec<NeResourceType>, FormatError> {
    if header.resource_table_offset == 0 || header.resource_table_offset == header.resident_name_table_offset {
        return Ok(Vec::new());
    }
    if header.resource_table_offset > header.resident_name_table_offset {
        return Err(FormatError::InvalidNe("resource table ends before it starts"));
    }
    let start = relative_offset(ne_base, header.resource_table_offset)?;
    let end = relative_offset(ne_base, header.resident_name_table_offset)?;
    let table = checked_range(bytes, start, end.checked_sub(start).ok_or(FormatError::InvalidNe("resource table bounds are reversed"))?, "NE resource table")?;
    let shift = read_u16(table, 0, "NE resource alignment shift")?;
    if shift > 15 { return Err(FormatError::InvalidNe("resource alignment shift exceeds 15")); }
    let mut position = 2_usize;
    let mut types = Vec::new();
    let mut terminated = false;
    while position < table.len() {
        let raw_type = read_u16(table, position, "NE resource type")?;
        position = position.checked_add(2).ok_or(FormatError::ArithmeticOverflow)?;
        if raw_type == 0 {
            terminated = true;
            break;
        }
        let count = usize::from(read_u16(table, position, "NE resource count")?);
        let _reserved = read_u32(table, position.checked_add(2).ok_or(FormatError::ArithmeticOverflow)?, "NE resource type reserved word")?;
        position = position.checked_add(6).ok_or(FormatError::ArithmeticOverflow)?;
        let mut resources = Vec::with_capacity(count);
        for _ in 0..count {
            let resource_offset = read_u16(table, position, "NE resource data offset")?;
            let resource_length = read_u16(table, position.checked_add(2).ok_or(FormatError::ArithmeticOverflow)?, "NE resource data length")?;
            let flags = read_u16(table, position.checked_add(4).ok_or(FormatError::ArithmeticOverflow)?, "NE resource flags")?;
            let raw_id = read_u16(table, position.checked_add(6).ok_or(FormatError::ArithmeticOverflow)?, "NE resource id")?;
            let handle = read_u16(table, position.checked_add(8).ok_or(FormatError::ArithmeticOverflow)?, "NE resource handle")?;
            let usage = read_u16(table, position.checked_add(10).ok_or(FormatError::ArithmeticOverflow)?, "NE resource usage")?;
            position = position.checked_add(12).ok_or(FormatError::ArithmeticOverflow)?;
            let byte_offset = u32::from(resource_offset).checked_shl(u32::from(shift)).ok_or(FormatError::ArithmeticOverflow)?;
            let byte_length = u32::from(resource_length).checked_shl(u32::from(shift)).ok_or(FormatError::ArithmeticOverflow)?;
            let byte_offset = usize::try_from(byte_offset).map_err(|_| FormatError::ArithmeticOverflow)?;
            let byte_length = usize::try_from(byte_length).map_err(|_| FormatError::ArithmeticOverflow)?;
            checked_range(bytes, byte_offset, byte_length, "NE resource data")?;
            resources.push(NeResource {
                id: parse_resource_id(table, raw_id)?,
                file_offset: byte_offset,
                byte_length,
                flags,
                handle,
                usage,
            });
        }
        types.push(NeResourceType { id: parse_resource_id(table, raw_type)?, resources });
    }
    if !terminated { return Err(FormatError::InvalidNe("resource table has no zero-type terminator")); }
    Ok(types)
}

fn parse_resource_id(table: &[u8], raw: u16) -> Result<NeResourceId, FormatError> {
    if raw & 0x8000 != 0 {
        Ok(NeResourceId::Numeric(raw & 0x7fff))
    } else {
        Ok(NeResourceId::Name(read_pascal_string(table, usize::from(raw), "NE resource name")?))
    }
}

fn parse_nonresident_names(bytes: &[u8], header: &NeHeader) -> Result<Vec<NeNamedEntry>, FormatError> {
    if header.nonresident_name_length == 0 { return Ok(Vec::new()); }
    let start = usize::try_from(header.nonresident_name_table_offset).map_err(|_| FormatError::ArithmeticOverflow)?;
    let table = checked_range(bytes, start, usize::from(header.nonresident_name_length), "NE nonresident names")?;
    parse_name_table(table, "NE nonresident names")
}

fn parse_name_table(table: &[u8], context: &'static str) -> Result<Vec<NeNamedEntry>, FormatError> {
    let mut position = 0_usize;
    let mut names = Vec::new();
    let mut terminated = false;
    while position < table.len() {
        let length = usize::from(read_u8(table, position, context)?);
        position = position.checked_add(1).ok_or(FormatError::ArithmeticOverflow)?;
        if length == 0 {
            terminated = true;
            break;
        }
        let end_name = position.checked_add(length).ok_or(FormatError::ArithmeticOverflow)?;
        let name = table.get(position..end_name).ok_or(FormatError::Truncated { context, offset: position, needed: length })?.to_vec();
        position = end_name;
        let ordinal = read_u16(table, position, context)?;
        position = position.checked_add(2).ok_or(FormatError::ArithmeticOverflow)?;
        names.push(NeNamedEntry { name, ordinal });
    }
    if !terminated { return Err(FormatError::InvalidNe("name table has no zero-length terminator")); }
    Ok(names)
}

fn read_pascal_string(table: &[u8], offset: usize, context: &'static str) -> Result<Vec<u8>, FormatError> {
    let length = usize::from(read_u8(table, offset, context)?);
    let start = offset.checked_add(1).ok_or(FormatError::ArithmeticOverflow)?;
    let end = start.checked_add(length).ok_or(FormatError::ArithmeticOverflow)?;
    let text = table.get(start..end).ok_or(FormatError::Truncated { context, offset: start, needed: length })?;
    Ok(text.to_vec())
}

fn decode_address_type(raw: u8) -> NeFixupAddressType {
    match raw {
        0 => NeFixupAddressType::LowByte,
        2 => NeFixupAddressType::Selector,
        3 => NeFixupAddressType::FarPointer32,
        5 => NeFixupAddressType::Offset16,
        11 => NeFixupAddressType::FarPointer48,
        13 => NeFixupAddressType::Offset32,
        value => NeFixupAddressType::Unknown(value),
    }
}

fn decode_relocation_kind(raw: u8) -> NeRelocationKind {
    match raw & 0x03 {
        0 => NeRelocationKind::Internal,
        1 => NeRelocationKind::ImportByOrdinal,
        2 => NeRelocationKind::ImportByName,
        _ => NeRelocationKind::OsFixup,
    }
}

fn relative_offset(base: usize, relative: u16) -> Result<usize, FormatError> {
    base.checked_add(usize::from(relative)).ok_or(FormatError::ArithmeticOverflow)
}

fn checked_range<'a>(bytes: &'a [u8], start: usize, length: usize, context: &'static str) -> Result<&'a [u8], FormatError> {
    let end = start.checked_add(length).ok_or(FormatError::ArithmeticOverflow)?;
    bytes.get(start..end).ok_or(FormatError::Truncated { context, offset: start, needed: length })
}

fn read_u8(bytes: &[u8], offset: usize, context: &'static str) -> Result<u8, FormatError> {
    bytes.get(offset).copied().ok_or(FormatError::Truncated { context, offset, needed: 1 })
}
