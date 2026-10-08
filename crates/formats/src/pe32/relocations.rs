use object::read::pe::{DataDirectories, RelocationBlockIterator};

use super::pe32_rva::Pe32RvaReader;
use super::pe32_types::{Pe32Error, Pe32Relocation};

const RELOCATION_HIGHLOW: u16 = object::pe::IMAGE_REL_BASED_HIGHLOW.0;
const RELOCATION_HIGHADJ: u16 = object::pe::IMAGE_REL_BASED_HIGHADJ.0;

pub(super) fn parse_relocations(
    reader: &Pe32RvaReader<'_>,
    directories: DataDirectories<'_>,
) -> Result<(Vec<Pe32Relocation>, bool), Pe32Error> {
    let Some(directory) = directories.get(object::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC) else {
        return Ok((Vec::new(), false));
    };
    let (directory_rva, directory_size) = directory.address_range();
    if directory_size == 0 {
        return Err(Pe32Error::InvalidImage("empty base-relocation directory"));
    }
    let bytes = reader.read_raw(directory_rva, directory_size)?;
    let mut relocations = Vec::new();
    let blocks = RelocationBlockIterator::new(bytes);
    let mut block_offset = 0_usize;
    for block in blocks {
        let block = block.map_err(|_| Pe32Error::InvalidImage("invalid base-relocation block"))?;
        let page_rva = block.virtual_address();
        let block_size = usize::try_from(block.size())
            .map_err(|_| Pe32Error::InvalidImage("relocation block size does not fit host"))?;
        let block_end = block_offset
            .checked_add(block_size)
            .ok_or(Pe32Error::InvalidImage("relocation block range overflows"))?;
        let block_bytes = bytes
            .get(block_offset..block_end)
            .ok_or(Pe32Error::InvalidImage(
                "relocation block exceeds directory",
            ))?;
        if block_bytes.len() < 8 || (block_bytes.len() - 8) % 2 != 0 {
            return Err(Pe32Error::InvalidImage(
                "relocation block has a truncated WORD table",
            ));
        }
        block_offset = block_end;
        if page_rva & 0x0fff != 0 || page_rva >= reader.image_size {
            return Err(Pe32Error::InvalidImage(
                "base-relocation block page RVA is invalid",
            ));
        }

        // object supplies checked block framing, but its RelocationIterator
        // filters zero WORDs and exposes a HIGHADJ payload as another entry.
        // The Microsoft PE/COFF “Base Relocation Types” contract consumes the
        // WORD after HIGHADJ as signed adjustment data, not a relocation.
        let entries = &block_bytes[8..];
        let mut words = entries.chunks_exact(2);
        while let Some(word_bytes) = words.next() {
            let encoded = u16::from_le_bytes([word_bytes[0], word_bytes[1]]);
            let kind = encoded >> 12;
            let page_offset = u32::from(encoded & 0x0fff);
            if kind == object::pe::IMAGE_REL_BASED_ABSOLUTE.0 {
                continue;
            }
            let target_rva = page_rva
                .checked_add(page_offset)
                .ok_or(Pe32Error::InvalidImage("relocation target RVA overflows"))?;
            if target_rva >= reader.image_size {
                return Err(Pe32Error::InvalidImage(
                    "base-relocation target exceeds SizeOfImage",
                ));
            }
            let target_width = match kind {
                1 | 2 | RELOCATION_HIGHADJ => 2,
                RELOCATION_HIGHLOW => 4,
                _ => 1,
            };
            reader.validate_mapped_range(target_rva, target_width)?;
            let highadj_adjustment = if kind == RELOCATION_HIGHADJ {
                let payload_bytes = words.next().ok_or(Pe32Error::InvalidImage(
                    "HIGHADJ relocation has no paired adjustment WORD",
                ))?;
                Some(u16::from_le_bytes([payload_bytes[0], payload_bytes[1]]))
            } else {
                None
            };
            relocations
                .try_reserve(1)
                .map_err(|_| Pe32Error::OutOfMemory("recording base relocations"))?;
            relocations.push(Pe32Relocation {
                kind,
                target_rva,
                highadj_adjustment,
            });
        }
    }
    if block_offset != bytes.len() {
        return Err(Pe32Error::InvalidImage(
            "base-relocation blocks do not cover the directory",
        ));
    }
    Ok((relocations, true))
}
