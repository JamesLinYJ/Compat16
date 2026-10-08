use object::pod::Pod;
use object::read::ReadRef;

use super::pe32_types::{Pe32Error, Pe32Section};

/// Checked view from guest RVAs into headers and section raw bytes.
///
/// `object` exposes first-match section helpers for file inspection. The guest
/// contract needs alias rejection and a distinction between raw-backed bytes
/// and zero-fill, so this adapter resolves only previously validated ranges.
pub(super) struct Pe32RvaReader<'a> {
    pub(super) image_size: u32,
    pub(super) header_bytes: &'a [u8],
    pub(super) sections: &'a [Pe32Section],
}

impl<'a> Pe32RvaReader<'a> {
    pub(super) fn read_raw(&self, rva: u32, length: u32) -> Result<&'a [u8], Pe32Error> {
        let end = rva
            .checked_add(length)
            .ok_or(Pe32Error::InvalidImage("RVA range overflow"))?;
        if end > self.image_size {
            return Err(Pe32Error::InvalidImage("RVA range exceeds SizeOfImage"));
        }

        let length = usize::try_from(length)
            .map_err(|_| Pe32Error::InvalidImage("RVA range does not fit host size"))?;
        if rva < self.header_bytes.len() as u32
            || (length == 0 && rva == self.header_bytes.len() as u32)
        {
            let offset = usize::try_from(rva)
                .map_err(|_| Pe32Error::InvalidImage("header RVA does not fit host size"))?;
            let range_end = offset
                .checked_add(length)
                .ok_or(Pe32Error::InvalidImage("header range overflow"))?;
            return self
                .header_bytes
                .get(offset..range_end)
                .ok_or(Pe32Error::InvalidImage("header RVA is not file-backed"));
        }

        for section in self.sections {
            let section_end = section
                .rva
                .checked_add(section.virtual_size)
                .ok_or(Pe32Error::InvalidImage("section RVA range overflow"))?;
            if rva < section.rva || end > section_end {
                continue;
            }
            let offset = usize::try_from(rva - section.rva)
                .map_err(|_| Pe32Error::InvalidImage("section offset does not fit host size"))?;
            let range_end = offset
                .checked_add(length)
                .ok_or(Pe32Error::InvalidImage("section byte range overflow"))?;
            return section
                .raw_data
                .get(offset..range_end)
                .ok_or(Pe32Error::InvalidImage(
                    "RVA range enters zero-filled section data",
                ));
        }
        Err(Pe32Error::InvalidImage(
            "RVA range is not backed by one section",
        ))
    }

    pub(super) fn read_record<T: Pod + Copy>(&self, rva: u32) -> Result<T, Pe32Error> {
        let length = u32::try_from(core::mem::size_of::<T>())
            .map_err(|_| Pe32Error::InvalidImage("record size does not fit PE32"))?;
        self.read_raw(rva, length)?
            .read_at::<T>(0)
            .map(|value| *value)
            .map_err(|_| Pe32Error::InvalidImage("typed PE record is truncated"))
    }

    pub(super) fn read_c_string(
        &self,
        rva: u32,
        context: &'static str,
    ) -> Result<Vec<u8>, Pe32Error> {
        let available = self.readable_tail(rva)?;
        let terminator = available
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(Pe32Error::InvalidImage(context))?;
        if terminator == 0 {
            return Err(Pe32Error::InvalidImage(context));
        }
        let mut result = Vec::new();
        result
            .try_reserve_exact(terminator)
            .map_err(|_| Pe32Error::OutOfMemory("copying a PE name"))?;
        result.extend_from_slice(&available[..terminator]);
        Ok(result)
    }

    pub(super) fn read_u32(&self, rva: u32) -> Result<u32, Pe32Error> {
        let bytes = self.read_raw(rva, 4)?;
        let array: [u8; 4] = bytes
            .try_into()
            .map_err(|_| Pe32Error::InvalidImage("DWORD is truncated"))?;
        Ok(u32::from_le_bytes(array))
    }

    pub(super) fn validate_mapped_range(&self, rva: u32, length: u32) -> Result<(), Pe32Error> {
        let end = rva
            .checked_add(length)
            .ok_or(Pe32Error::InvalidImage("mapped RVA range overflow"))?;
        if end > self.image_size {
            return Err(Pe32Error::InvalidImage("mapped RVA exceeds SizeOfImage"));
        }
        if end <= self.header_bytes.len() as u32 {
            return Ok(());
        }
        for section in self.sections {
            let section_end = section
                .rva
                .checked_add(section.virtual_size)
                .ok_or(Pe32Error::InvalidImage("section RVA range overflow"))?;
            if rva >= section.rva && end <= section_end {
                return Ok(());
            }
        }
        Err(Pe32Error::InvalidImage(
            "mapped RVA range crosses an image gap",
        ))
    }

    pub(super) fn is_executable_rva(&self, rva: u32) -> bool {
        self.sections.iter().any(|section| {
            let Some(end) = section.rva.checked_add(section.virtual_size) else {
                return false;
            };
            section.is_executable() && rva >= section.rva && rva < end
        })
    }

    fn readable_tail(&self, rva: u32) -> Result<&'a [u8], Pe32Error> {
        if rva < self.header_bytes.len() as u32 {
            let offset = usize::try_from(rva)
                .map_err(|_| Pe32Error::InvalidImage("header RVA does not fit host size"))?;
            return self
                .header_bytes
                .get(offset..)
                .ok_or(Pe32Error::InvalidImage("header string address is invalid"));
        }
        for section in self.sections {
            let raw_length = u32::try_from(section.raw_data.len())
                .map_err(|_| Pe32Error::InvalidImage("section raw data does not fit PE32"))?
                .min(section.virtual_size);
            let end = section
                .rva
                .checked_add(raw_length)
                .ok_or(Pe32Error::InvalidImage("section raw range overflow"))?;
            if rva >= section.rva && rva < end {
                let offset = usize::try_from(rva - section.rva).map_err(|_| {
                    Pe32Error::InvalidImage("section offset does not fit host size")
                })?;
                let raw_length = usize::try_from(raw_length).map_err(|_| {
                    Pe32Error::InvalidImage("section raw length does not fit host size")
                })?;
                // File-alignment padding beyond VirtualSize is not guest memory;
                // require string terminators to live in bytes the loader maps.
                return section
                    .raw_data
                    .get(offset..raw_length)
                    .ok_or(Pe32Error::InvalidImage("section string address is invalid"));
            }
        }
        Err(Pe32Error::InvalidImage("string RVA is not file-backed"))
    }
}
