//! DOS 4 SEARCH.ASM: 22-byte input continuation, drive + 32-byte directory entry.
use super::super::{directory, state::DosSearchPattern};
use crate::{
    DosCallAddressSpace, DosError, DosErrorCode, DosFarPointer, DosPointerAccess, DosSpanPolicy,
};

pub(super) struct Request {
    pub pointer: DosFarPointer,
    pub skip: usize,
    pub attributes: u8,
    pub bytes: [u8; 22],
}

impl Request {
    pub fn read(
        memory: &mut impl DosCallAddressSpace,
        segment: u16,
        offset: u16,
    ) -> Result<Self, DosError> {
        let pointer = memory.resolve_caller_pointer(segment, offset)?;
        let mut prefix = [0; 7];
        memory.read_caller_range(pointer, 0, &mut prefix[..1], DosSpanPolicy::OffsetWrap)?;
        let skip = if prefix[0] == 0xff {
            memory.read_caller_range(pointer, 0, &mut prefix, DosSpanPolicy::OffsetWrap)?;
            7
        } else {
            0
        };
        let mut bytes = [0; 22];
        memory.read_caller_range(pointer, skip, &mut bytes, DosSpanPolicy::OffsetWrap)?;
        memory.validate_caller_range(
            pointer,
            skip + 1,
            21,
            DosPointerAccess::Write,
            DosSpanPolicy::OffsetWrap,
        )?;
        Ok(Self {
            pointer,
            skip,
            attributes: if skip == 0 { 0 } else { prefix[6] },
            bytes,
        })
    }

    pub fn pattern(&self, page: text_codec::CodePage) -> Result<DosSearchPattern, DosErrorCode> {
        let mut pattern = DosSearchPattern {
            name: [b' '; 8],
            extension: [b' '; 3],
        };
        let base = &self.bytes[1..9];
        if base == b".       " || base == b"..      " {
            pattern.name.copy_from_slice(base);
        } else {
            directory::expand_pattern_field(base, &mut pattern.name, page)?
                .ok_or(DosErrorCode::InvalidData)?;
        }
        directory::expand_pattern_field(&self.bytes[9..12], &mut pattern.extension, page)?
            .ok_or(DosErrorCode::InvalidData)?;
        Ok(pattern)
    }

    pub fn cookie(&self) -> Option<(u32, u32)> {
        let identity = u32::from_le_bytes(self.bytes[13..17].try_into().ok()?);
        let next = u32::from_le_bytes(self.bytes[17..21].try_into().ok()?);
        (identity != 0).then_some((identity, next))
    }

    pub fn publish_cookie(
        &mut self,
        memory: &mut impl DosCallAddressSpace,
        identity: u32,
        next: u32,
        drive: u8,
        pattern: &DosSearchPattern,
    ) -> Result<(), DosError> {
        // CONTINFO keeps the 11-byte pattern, search attribute and eight
        // file-system-dependent bytes. Preserve this layout and user drive.
        self.bytes[1..9].copy_from_slice(&pattern.name);
        self.bytes[9..12].copy_from_slice(&pattern.extension);
        self.bytes[12] = self.attributes;
        self.bytes[13..17].copy_from_slice(&identity.to_le_bytes());
        self.bytes[17..21].copy_from_slice(&next.to_le_bytes());
        self.bytes[21] = drive;
        memory.write_caller_range(
            self.pointer,
            self.skip + 1,
            &self.bytes[1..],
            DosSpanPolicy::OffsetWrap,
        )
    }

    pub fn result(&self, drive: u8, record: &[u8; 32]) -> ([u8; 40], usize) {
        let mut output = [0; 40];
        if self.skip != 0 {
            output[0] = 0xff;
            output[6] = self.attributes;
        }
        output[self.skip] = drive;
        output[self.skip + 1..self.skip + 33].copy_from_slice(record);
        (output, self.skip + 33)
    }
}

pub(super) fn record(
    entry: &crate::DosDirectoryEntry,
    page: text_codec::CodePage,
) -> Result<[u8; 32], DosError> {
    let (name, extension) = directory::short_name_fields(&entry.short_name, page).ok_or(
        DosError::HostContractViolation("invalid FCB directory short name"),
    )?;
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&name);
    bytes[8..11].copy_from_slice(&extension);
    bytes[11] = entry.attributes;
    bytes[22..24].copy_from_slice(&entry.write_time.to_le_bytes());
    bytes[24..26].copy_from_slice(&entry.write_date.to_le_bytes());
    bytes[28..32].copy_from_slice(&entry.size.to_le_bytes());
    Ok(bytes)
}
