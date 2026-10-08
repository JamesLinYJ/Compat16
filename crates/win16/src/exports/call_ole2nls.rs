//! Checked decoder for the OLE2NLS locale and ANSI-string query exports.

use guest_core::GuestMemory;
use crate::{Access, SegmentedPointer, SelectorTable, Win16Argument, Win16Error};

use super::request::{Win16Ole2NlsRequest, Win16Ole2NlsString};
use super::Win16ExportDescriptor;

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16Ole2NlsRequest, Win16Error> {
    if !descriptor.id.module().eq_ignore_ascii_case("OLE2NLS")
        || arguments.len() != descriptor.parameters.len()
    {
        return Err(Win16Error::InvalidRange);
    }

    match descriptor.ordinal() {
        1 if arguments.is_empty() => Ok(Win16Ole2NlsRequest::GetUserDefaultLcid),
        2 if arguments.is_empty() => Ok(Win16Ole2NlsRequest::GetSystemDefaultLcid),
        3 if arguments.is_empty() => Ok(Win16Ole2NlsRequest::GetUserDefaultLangId),
        4 if arguments.is_empty() => Ok(Win16Ole2NlsRequest::GetSystemDefaultLangId),
        5 => {
            let capacity = word(arguments, 3)?;
            Ok(Win16Ole2NlsRequest::GetLocaleInfoA {
                lcid: dword(arguments, 0)?,
                info_type: dword(arguments, 1)?,
                output: checked_output(dword(arguments, 2)?, usize::from(capacity), selectors, memory)?,
                capacity,
            })
        }
        6 => {
            let source_count = signed_word(arguments, 3)?;
            let destination_capacity = word(arguments, 5)?;
            Ok(Win16Ole2NlsRequest::LcMapStringA {
                lcid: dword(arguments, 0)?,
                flags: dword(arguments, 1)?,
                source: counted_string(dword(arguments, 2)?, source_count, selectors, memory)?,
                destination: checked_output(
                    dword(arguments, 4)?, usize::from(destination_capacity), selectors, memory,
                )?,
                destination_capacity,
            })
        }
        7 => {
            let source_count = signed_word(arguments, 3)?;
            let source = counted_string(dword(arguments, 2)?, source_count, selectors, memory)?;
            let output_bytes = string_type_output_bytes(&source)?;
            Ok(Win16Ole2NlsRequest::GetStringTypeA {
                lcid: dword(arguments, 0)?,
                info_type: dword(arguments, 1)?,
                source,
                output: checked_output(dword(arguments, 4)?, output_bytes, selectors, memory)?,
            })
        }
        8 => Ok(Win16Ole2NlsRequest::CompareStringA {
            lcid: dword(arguments, 0)?,
            flags: dword(arguments, 1)?,
            left: counted_string(
                dword(arguments, 2)?, signed_word(arguments, 3)?, selectors, memory,
            )?,
            right: counted_string(
                dword(arguments, 4)?, signed_word(arguments, 5)?, selectors, memory,
            )?,
        }),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn counted_string(
    far: u32,
    declared_count: i16,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16Ole2NlsString, Win16Error> {
    let is_null = far == 0;
    let bytes = if is_null {
        Vec::new()
    } else if declared_count < 0 {
        read_ansi_z_in_segment(far, selectors, memory)?
    } else {
        read_extent_in_segment(far, declared_count as usize, selectors, memory)?
    };
    Ok(Win16Ole2NlsString { bytes, declared_count, is_null })
}

fn read_extent_in_segment(
    far: u32,
    length: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    if length == 0 { return Ok(Vec::new()); }
    if length > crate::MAX_WIN16_STRING_BYTES { return Err(Win16Error::InvalidRange); }
    let start = selectors.pointer_from_far(far)?;
    check_single_segment_extent(start, length, selectors)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| Win16Error::OutOfMemory)?;
    bytes.resize(length, 0);
    selectors.read(memory, start, &mut bytes)?;
    Ok(bytes)
}

fn read_ansi_z_in_segment(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    let start = selectors.pointer_from_far(far)?;
    let descriptor = selectors.describe(start.selector())?;
    let available = descriptor.limit.checked_sub(u32::from(start.offset()))
        .and_then(|value| value.checked_add(1))
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(Win16Error::InvalidRange)?;
    let count = available.min(crate::MAX_WIN16_STRING_BYTES);
    let mut bytes = Vec::new();
    bytes.try_reserve(count.min(128)).map_err(|_| Win16Error::OutOfMemory)?;
    for offset in 0..count {
        let offset = u32::try_from(offset).map_err(|_| Win16Error::InvalidRange)?;
        let pointer = selectors.add_bytes(start, offset)?;
        let mut byte = [0_u8; 1];
        selectors.read(memory, pointer, &mut byte)?;
        if byte[0] == 0 { return Ok(bytes); }
        bytes.try_reserve(1).map_err(|_| Win16Error::OutOfMemory)?;
        bytes.push(byte[0]);
    }
    Err(Win16Error::InvalidRange)
}

fn checked_output(
    far: u32,
    length: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<SegmentedPointer>, Win16Error> {
    if length == 0 { return Ok(None); }
    if far == 0 { return Ok(None); }
    let pointer = selectors.pointer_from_far(far)?;
    check_single_segment_extent(pointer, length, selectors)?;
    selectors.translate(pointer, Access::Write, length, memory)?;
    Ok(Some(pointer))
}

fn check_single_segment_extent(
    pointer: SegmentedPointer,
    length: usize,
    selectors: &SelectorTable,
) -> Result<(), Win16Error> {
    let descriptor = selectors.describe(pointer.selector())?;
    let available = descriptor.limit.checked_sub(u32::from(pointer.offset()))
        .and_then(|value| value.checked_add(1))
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(Win16Error::InvalidRange)?;
    if length > available { return Err(Win16Error::InvalidRange); }
    Ok(())
}

fn string_type_output_bytes(source: &Win16Ole2NlsString) -> Result<usize, Win16Error> {
    let words = if source.declared_count >= 0 {
        source.declared_count as usize
    } else if source.is_null {
        0
    } else {
        source.bytes.len().checked_add(1).ok_or(Win16Error::InvalidRange)?
    };
    words.checked_mul(std::mem::size_of::<u16>()).ok_or(Win16Error::InvalidRange)
}

fn dword(arguments: &[Win16Argument], index: usize) -> Result<u32, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Dword(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn word(arguments: &[Win16Argument], index: usize) -> Result<u16, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Word(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn signed_word(arguments: &[Win16Argument], index: usize) -> Result<i16, Win16Error> {
    Ok(word(arguments, index)? as i16)
}
