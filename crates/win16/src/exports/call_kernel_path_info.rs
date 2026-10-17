//! Decoding for the independent KERNEL directory and temporary-file APIs.

use super::request::Win16KernelPathInfoRequest;
use super::Win16ExportId;
use crate::{SelectorTable, Win16Argument, Win16Error, MAX_WIN16_STRING_BYTES};
use guest_core::GuestMemory;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16KernelPathInfoRequest>, Win16Error> {
    if !export.module().eq_ignore_ascii_case("KERNEL") {
        return Ok(None);
    }

    let request = match (export.ordinal(), arguments) {
        (92, [Win16Argument::Byte(drive)]) =>
            Win16KernelPathInfoRequest::GetTempDrive { drive: *drive },
        (134, [Win16Argument::Dword(output), Win16Argument::Word(capacity)]) =>
            Win16KernelPathInfoRequest::GetWindowsDirectory {
                output: *output, capacity: *capacity,
            },
        (135, [Win16Argument::Dword(output), Win16Argument::Word(capacity)]) =>
            Win16KernelPathInfoRequest::GetSystemDirectory {
                output: *output, capacity: *capacity,
            },
        (97, [Win16Argument::Word(drive), Win16Argument::Dword(prefix),
            Win16Argument::Word(unique), Win16Argument::Dword(output)]) => {
            let prefix = if *prefix == 0 { None } else {
                Some(read_ordinary_far_string(selectors, memory, *prefix)?)
            };
            Win16KernelPathInfoRequest::GetTempFileName {
                drive: *drive as u8,
                prefix,
                unique: *unique,
                output: *output,
            }
        }
        (274, [Win16Argument::Dword(path), Win16Argument::Dword(output),
            Win16Argument::Word(capacity)]) => {
            let long_path = if *path == 0 { None } else {
                Some(read_ordinary_far_string(selectors, memory, *path)?)
            };
            Win16KernelPathInfoRequest::GetShortPathName {
                long_path,
                output: *output,
                capacity: *capacity,
            }
        }
        (92 | 97 | 134 | 135 | 274, _) => return Err(Win16Error::InvalidRange),
        _ => return Ok(None),
    };
    Ok(Some(request))
}

#[cfg(test)]
#[path = "call_get_temp_drive_tests.rs"]
mod get_temp_drive_tests;

/// LPCSTR in the SDK prototype is an ordinary FAR string. Stop at the end of
/// its first selector instead of following a huge-pointer segment chain.
fn read_ordinary_far_string(
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
    far: u32,
) -> Result<Vec<u8>, Win16Error> {
    let start = selectors.pointer_from_far(far)?;
    let descriptor = selectors.describe(start.selector())?;
    let remaining = descriptor.limit
        .checked_sub(u32::from(start.offset()))
        .and_then(|length| length.checked_add(1))
        .and_then(|length| usize::try_from(length).ok())
        .ok_or(Win16Error::InvalidRange)?;
    let bound = remaining.min(MAX_WIN16_STRING_BYTES);
    let mut result = Vec::new();
    result.try_reserve(bound.min(128)).map_err(|_| Win16Error::OutOfMemory)?;
    for offset in 0..bound {
        let pointer = selectors.add_bytes(
            start,
            u32::try_from(offset).map_err(|_| Win16Error::InvalidRange)?,
        )?;
        let mut byte = [0];
        selectors.read(memory, pointer, &mut byte)?;
        if byte[0] == 0 { return Ok(result); }
        result.try_reserve(1).map_err(|_| Win16Error::OutOfMemory)?;
        result.push(byte[0]);
    }
    Err(Win16Error::InvalidRange)
}
