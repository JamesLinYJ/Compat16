use object::endian::LittleEndian as LE;
use object::pe::ImageSectionHeader;
use object::read::pe::SectionTable;

use super::pe32_types::{Pe32Error, Pe32Section};

pub(super) fn copy_and_validate_sections(
    file_bytes: &[u8],
    table: SectionTable<'_>,
    header_end: u64,
    header_size: u32,
    image_size: u32,
    file_alignment: u32,
    section_alignment: u32,
) -> Result<Vec<Pe32Section>, Pe32Error> {
    validate_alignments(file_alignment, section_alignment)?;
    if header_end > u64::from(header_size) {
        return Err(Pe32Error::InvalidImage(
            "SizeOfHeaders does not cover the section table",
        ));
    }
    if header_size == 0
        || header_size % file_alignment != 0
        || header_size > image_size
        || image_size % section_alignment != 0
    {
        return Err(Pe32Error::InvalidImage(
            "SizeOfHeaders or SizeOfImage violates PE alignment",
        ));
    }

    let section_count = table.iter().len();
    let mut sections = Vec::new();
    sections
        .try_reserve_exact(section_count)
        .map_err(|_| Pe32Error::OutOfMemory("allocating PE section metadata"))?;

    let mut virtual_ranges = Vec::new();
    virtual_ranges
        .try_reserve_exact(section_count)
        .map_err(|_| Pe32Error::OutOfMemory("validating PE section ranges"))?;
    let mut raw_ranges = Vec::new();
    raw_ranges
        .try_reserve_exact(section_count + 1)
        .map_err(|_| Pe32Error::OutOfMemory("validating PE raw ranges"))?;
    raw_ranges.push((0_u32, header_size));

    for header in table.iter() {
        let section = own_section(file_bytes, header, file_alignment, section_alignment)?;
        if section.virtual_size != 0 {
            let virtual_end = section
                .rva
                .checked_add(section.virtual_size)
                .ok_or(Pe32Error::InvalidImage("section virtual end overflows"))?;
            if section.rva < header_size || virtual_end > image_size {
                return Err(Pe32Error::InvalidImage(
                    "section virtual range aliases headers or exceeds SizeOfImage",
                ));
            }
            virtual_ranges.push((section.rva, virtual_end));
        }
        if section.raw_size != 0 {
            let raw_end = section
                .raw_file_offset
                .checked_add(section.raw_size)
                .ok_or(Pe32Error::InvalidImage("section raw end overflows"))?;
            raw_ranges.push((section.raw_file_offset, raw_end));
        }
        sections.push(section);
    }

    virtual_ranges.sort_unstable_by_key(|range| range.0);
    for pair in virtual_ranges.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(Pe32Error::InvalidImage("section RVA ranges overlap"));
        }
    }
    raw_ranges.sort_unstable_by_key(|range| range.0);
    for pair in raw_ranges.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(Pe32Error::InvalidImage("section raw ranges overlap"));
        }
    }
    Ok(sections)
}

fn own_section(
    file_bytes: &[u8],
    header: &ImageSectionHeader,
    file_alignment: u32,
    section_alignment: u32,
) -> Result<Pe32Section, Pe32Error> {
    let virtual_size = header.virtual_size.get(LE);
    let rva = header.virtual_address.get(LE);
    let raw_size = header.size_of_raw_data.get(LE);
    let raw_file_offset = header.pointer_to_raw_data.get(LE);
    let characteristics = header.characteristics.get(LE).0;
    if virtual_size != 0 && rva % section_alignment != 0 {
        return Err(Pe32Error::InvalidImage("section RVA is not aligned"));
    }
    if raw_size != 0 {
        let raw_end = raw_file_offset
            .checked_add(raw_size)
            .ok_or(Pe32Error::InvalidImage("section raw range overflows"))?;
        if raw_file_offset == 0
            || raw_file_offset % file_alignment != 0
            || raw_size % file_alignment != 0
            || raw_end as u64 > file_bytes.len() as u64
        {
            return Err(Pe32Error::InvalidImage(
                "section raw range is unaligned or outside the file",
            ));
        }
        // Microsoft PE/COFF's “Section Data” rule for low SectionAlignment
        // requires the section's file offset to equal its loaded RVA.
        if section_alignment < 0x1000 && raw_file_offset != rva {
            return Err(Pe32Error::InvalidImage(
                "low-alignment section raw offset differs from its RVA",
            ));
        }
    }
    let mut name_end = header.name.len();
    while name_end > 0 && header.name[name_end - 1] == 0 {
        name_end -= 1;
    }
    let mut name = Vec::new();
    name.try_reserve_exact(name_end)
        .map_err(|_| Pe32Error::OutOfMemory("copying a PE section name"))?;
    name.extend_from_slice(&header.name[..name_end]);

    let raw_data = if raw_size == 0 {
        Vec::new()
    } else {
        let start = usize::try_from(raw_file_offset)
            .map_err(|_| Pe32Error::InvalidImage("raw file offset does not fit host size"))?;
        let raw_length = usize::try_from(raw_size)
            .map_err(|_| Pe32Error::InvalidImage("raw size does not fit host size"))?;
        let end = start
            .checked_add(raw_length)
            .ok_or(Pe32Error::InvalidImage(
                "raw file range does not fit host size",
            ))?;
        let bytes = file_bytes
            .get(start..end)
            .ok_or(Pe32Error::InvalidImage("section raw bytes are truncated"))?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| Pe32Error::OutOfMemory("owning PE section bytes"))?;
        owned.extend_from_slice(bytes);
        owned
    };

    // Microsoft PE/COFF's “Section Table (Section Headers)” defines VirtualSize
    // as the loaded section length and
    // zero-fills when that exceeds SizeOfRawData; object::pe_file_range instead
    // returns min(VirtualSize, SizeOfRawData), so the guest mapper applies the
    // documented rule itself and never maps file-alignment padding as data.
    Ok(Pe32Section {
        name,
        rva,
        virtual_size,
        raw_file_offset,
        raw_size,
        characteristics,
        raw_data,
    })
}

fn validate_alignments(file_alignment: u32, section_alignment: u32) -> Result<(), Pe32Error> {
    if file_alignment == 0
        || section_alignment == 0
        || !file_alignment.is_power_of_two()
        || !section_alignment.is_power_of_two()
        || file_alignment > 0x1_0000
        || section_alignment < file_alignment
    {
        return Err(Pe32Error::InvalidImage("invalid PE file/section alignment"));
    }
    if section_alignment < 0x1000 {
        if file_alignment != section_alignment {
            return Err(Pe32Error::InvalidImage(
                "low SectionAlignment requires matching FileAlignment",
            ));
        }
    } else if file_alignment < 0x200 {
        return Err(Pe32Error::InvalidImage(
            "FileAlignment is below the PE minimum",
        ));
    }
    Ok(())
}
