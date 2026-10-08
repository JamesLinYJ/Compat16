//! Decoding for the Windows 3.1 KERNEL file-system export family.

use super::Win16ExportId;
use super::request::Win16KernelFileSystemRequest;
use crate::{MAX_WIN16_STRING_BYTES, SelectorTable, Win16Argument, Win16Error};
use guest_core::GuestMemory;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16KernelFileSystemRequest>, Win16Error> {
    if !export.module().eq_ignore_ascii_case("KERNEL") {
        return Ok(None);
    }

    let request = match (export.ordinal(), arguments) {
        (130, [Win16Argument::Dword(procedure)]) => Win16KernelFileSystemRequest::FileCdr {
            procedure: *procedure,
        },
        (
            144,
            [
                Win16Argument::Dword(path),
                Win16Argument::Dword(security_attributes),
            ],
        ) => Win16KernelFileSystemRequest::CreateDirectory {
            path: read_ordinary_far_string(selectors, memory, *path)?,
            security_attributes: *security_attributes,
        },
        (145, [Win16Argument::Dword(path)]) => Win16KernelFileSystemRequest::RemoveDirectory {
            path: read_ordinary_far_string(selectors, memory, *path)?,
        },
        (146, [Win16Argument::Dword(path)]) => Win16KernelFileSystemRequest::DeleteFile {
            path: read_ordinary_far_string(selectors, memory, *path)?,
        },
        (411, [Win16Argument::Dword(capacity), Win16Argument::Dword(output)]) => {
            Win16KernelFileSystemRequest::GetCurrentDirectory {
                capacity: *capacity,
                output: *output,
            }
        }
        (412, [Win16Argument::Dword(path)]) => Win16KernelFileSystemRequest::SetCurrentDirectory {
            path: read_ordinary_far_string(selectors, memory, *path)?,
        },
        (
            413,
            [
                Win16Argument::Dword(search_file),
                Win16Argument::Dword(find_data),
            ],
        ) => Win16KernelFileSystemRequest::FindFirstFile {
            search_file: read_ordinary_far_string(selectors, memory, *search_file)?,
            find_data: *find_data,
        },
        (
            414,
            [
                Win16Argument::Word(search_handle),
                Win16Argument::Dword(find_data),
            ],
        ) => Win16KernelFileSystemRequest::FindNextFile {
            search_handle: *search_handle,
            find_data: *find_data,
        },
        (415, [Win16Argument::Word(search_handle)]) => Win16KernelFileSystemRequest::FindClose {
            search_handle: *search_handle,
        },
        (420, [Win16Argument::Dword(path)]) => Win16KernelFileSystemRequest::GetFileAttributes {
            path: read_ordinary_far_string(selectors, memory, *path)?,
        },
        (421, [Win16Argument::Dword(path), Win16Argument::Dword(attributes)]) => {
            Win16KernelFileSystemRequest::SetFileAttributes {
                path: read_ordinary_far_string(selectors, memory, *path)?,
                attributes: *attributes,
            }
        }
        (
            422,
            [
                Win16Argument::Dword(root_path),
                Win16Argument::Dword(sectors_per_cluster),
                Win16Argument::Dword(bytes_per_sector),
                Win16Argument::Dword(free_clusters),
                Win16Argument::Dword(total_clusters),
            ],
        ) => {
            let root_path = if *root_path == 0 {
                None
            } else {
                Some(read_ordinary_far_string(selectors, memory, *root_path)?)
            };
            Win16KernelFileSystemRequest::GetDiskFreeSpace {
                root_path,
                sectors_per_cluster: *sectors_per_cluster,
                bytes_per_sector: *bytes_per_sector,
                free_clusters: *free_clusters,
                total_clusters: *total_clusters,
            }
        }
        (130 | 144 | 145 | 146 | 411 | 412 | 413 | 414 | 415 | 420 | 421 | 422, _) => {
            return Err(Win16Error::InvalidRange);
        }
        _ => return Ok(None),
    };
    Ok(Some(request))
}

/// Win16 LPCSTR parameters are ordinary FAR strings. Never walk into another
/// selector when the ASCIIZ terminator is missing from this segment.
fn read_ordinary_far_string(
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
    far: u32,
) -> Result<Vec<u8>, Win16Error> {
    let start = selectors.pointer_from_far(far)?;
    let descriptor = selectors.describe(start.selector())?;
    let remaining = descriptor
        .limit
        .checked_sub(u32::from(start.offset()))
        .and_then(|length| length.checked_add(1))
        .and_then(|length| usize::try_from(length).ok())
        .ok_or(Win16Error::InvalidRange)?;
    let bound = remaining.min(MAX_WIN16_STRING_BYTES);
    let mut result = Vec::new();
    result
        .try_reserve(bound.min(128))
        .map_err(|_| Win16Error::OutOfMemory)?;
    for offset in 0..bound {
        let pointer = selectors.add_bytes(
            start,
            u32::try_from(offset).map_err(|_| Win16Error::InvalidRange)?,
        )?;
        let mut byte = [0];
        selectors.read(memory, pointer, &mut byte)?;
        if byte[0] == 0 {
            return Ok(result);
        }
        result.try_reserve(1).map_err(|_| Win16Error::OutOfMemory)?;
        result.push(byte[0]);
    }
    Err(Win16Error::InvalidRange)
}
