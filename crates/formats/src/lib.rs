//! Checked readers and DOS image loaders for Win16-era executable formats.
//!
//! MZ/COM bytes are copied into the caller's shared guest memory. The caller
//! supplies a bounded DOS-allocation view (normally no larger than conventional
//! DOS memory), the PSP segment, and owns PSP construction and process state.
//! NE segments are loaded into caller-allocated selectors through an explicit
//! resolver. Win16 execution state and ABI frames are owned by the runtime.
#![forbid(unsafe_code)]

mod mz;
mod diagnostics;
mod ne;
mod ne_checked;
mod ne_entrypoints;
mod ne_icon_table;
mod ne_load;
mod ne_menu;
mod ne_prologs;
mod ne_reloc;
mod ne_segments;
mod ne_string_table;
mod ne_text_profile;
mod pe32;
mod pe_header;

pub use mz::{load_com, load_mz, parse_mz, MzHeader, MzImage, MzRelocation};
pub use diagnostics::{FormatError, GuestMemoryRollbackFailure, NeDataImportIssue};
pub use ne::{parse_ne, NeEntry, NeEntryKind, NeFixup, NeFixupAddressType, NeFixupTarget,
    NeImportModule, NeModule, NeNamedEntry, NeRelocationKind, NeResource, NeResourceId,
    NeResourceType, NeSegment, NeHeader};
pub use ne_load::{
    extract_ne_resource, load_ne_segments, load_ne_segments_unlinked, ne_segment_allocation_size, plan_ne_segments,
    FarAddress, NeImportTarget, NeImportValue, NeLoadResolver, NeLoadedModule, NeLoadedSegment,
};
pub use ne_icon_table::{NeCursorResourceTable, NeIconResourceTable};
pub use ne_menu::{parse_win16_menu, NeMenuResourceTable, Win16Menu, Win16MenuItem};
pub use ne_string_table::NeStringTable;
pub use ne_text_profile::{collect_ne_text_profile, NeTextProfile};
pub use pe32::{
    parse_pe32, plan_pe32_load, Pe32LoadOptions, Pe32LoadPlan,
    Pe32DataDirectory, Pe32DataDirectoryKind, Pe32DirectoryAddressKind,
    Pe32DelayImportMetadata, Pe32Error, Pe32Export, Pe32ExportTarget,
    Pe32ForwardTarget, Pe32Image, Pe32ImportKind, Pe32ImportModule,
    Pe32ImportSymbol, Pe32ImportTarget, Pe32LoadSection, Pe32Relocation,
    Pe32Section, Pe32TlsMetadata,
};
pub use pe_header::{inspect_pe_header, PeHeaderKind, PeImageHeader};

use guest_core::{GuestMemory, PhysAddr, Registers};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageKind {
    Com,
    Mz,
}

/// A loaded DOS image and its initial real-mode register state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedImage {
    pub kind: ImageKind,
    pub load_address: PhysAddr,
    pub image_size: u32,
    pub registers: Registers,
}

/// Load an MZ DOS executable or a COM image into shared guest memory.
///
/// MZ files carrying NE/PE/LX headers are recognized but not executed here.
/// COM images are selected when the input does not start with the MZ signature.
pub fn load_executable(
    bytes: &[u8],
    psp_segment: u16,
    memory: &mut impl GuestMemory,
) -> Result<LoadedImage, FormatError> {
    if bytes.get(0..2) != Some(b"MZ".as_slice()) {
        return load_com(bytes, psp_segment, memory);
    }

    // e_lfanew is meaningful only when the declared DOS header actually
    // contains that field. Older 28-byte MZ headers may have executable bytes
    // at file offset 0x3c, so do not interpret those bytes as a pointer.
    if bytes.len() >= 0x40 {
        let header_paragraphs = read_u16(bytes, 0x08, "MZ header paragraphs")?;
        let header_length = usize::from(header_paragraphs).checked_mul(16).ok_or(FormatError::ArithmeticOverflow)?;
        if header_length >= 0x40 {
            let extended_offset = usize::try_from(read_u32(bytes, 0x3c, "MZ extended header offset")?)
                .map_err(|_| FormatError::ArithmeticOverflow)?;
            let signature_end = extended_offset.checked_add(2).ok_or(FormatError::ArithmeticOverflow)?;
            if let Some(signature) = bytes.get(extended_offset..signature_end) {
                if signature == b"NE" {
                    let _metadata = parse_ne(bytes)?;
                    return Err(FormatError::UnsupportedNeLoading);
                }
                if signature == b"PE" { return Err(FormatError::UnsupportedExecutable("PE")); }
                if signature == b"LE" || signature == b"LX" {
                    return Err(FormatError::UnsupportedExecutable("LE/LX"));
                }
            }
        }
    }
    load_mz(bytes, psp_segment, memory)
}

fn ensure_memory_range(
    memory_len: u32,
    address: u32,
    length: usize,
) -> Result<(), FormatError> {
    let length_u32 = u32::try_from(length).map_err(|_| FormatError::ArithmeticOverflow)?;
    let end = address.checked_add(length_u32).ok_or(FormatError::ArithmeticOverflow)?;
    if end > memory_len {
        return Err(FormatError::AddressOutOfRange { address, length, memory_len });
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize, context: &'static str) -> Result<u16, FormatError> {
    let end = offset.checked_add(2).ok_or(FormatError::ArithmeticOverflow)?;
    let slice = bytes.get(offset..end).ok_or(FormatError::Truncated { context, offset, needed: 2 })?;
    let low = *slice.first().ok_or(FormatError::Truncated { context, offset, needed: 2 })?;
    let high = *slice.get(1).ok_or(FormatError::Truncated { context, offset, needed: 2 })?;
    Ok(u16::from_le_bytes([low, high]))
}

fn read_u32(bytes: &[u8], offset: usize, context: &'static str) -> Result<u32, FormatError> {
    let end = offset.checked_add(4).ok_or(FormatError::ArithmeticOverflow)?;
    let slice = bytes.get(offset..end).ok_or(FormatError::Truncated { context, offset, needed: 4 })?;
    let b0 = *slice.first().ok_or(FormatError::Truncated { context, offset, needed: 4 })?;
    let b1 = *slice.get(1).ok_or(FormatError::Truncated { context, offset, needed: 4 })?;
    let b2 = *slice.get(2).ok_or(FormatError::Truncated { context, offset, needed: 4 })?;
    let b3 = *slice.get(3).ok_or(FormatError::Truncated { context, offset, needed: 4 })?;
    Ok(u32::from_le_bytes([b0, b1, b2, b3]))
}
