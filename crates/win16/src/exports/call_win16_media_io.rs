//! Decoding for synchronous MMIO calls and ordinary FAR string inputs.

use super::call::call_helpers::{dword_argument, word_argument};
use super::request::Win16MediaIoRequest;
use super::Win16ExportDescriptor;
use crate::{SelectorTable, Win16Argument, Win16Error, MAX_WIN16_STRING_BYTES};
use guest_core::GuestMemory;

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16MediaIoRequest, Win16Error> {
    if !descriptor.module().eq_ignore_ascii_case("MMSYSTEM") {
        return Err(Win16Error::InvalidRange);
    }
    let request = match descriptor.ordinal() {
        1210 => {
            let path_far = dword_argument(arguments, 0)?;
            let info = dword_argument(arguments, 1)?;
            Win16MediaIoRequest::Open {
                path_far,
                info,
                flags: dword_argument(arguments, 2)?,
            }
        }
        1211 => Win16MediaIoRequest::Close {
            handle: word_argument(arguments, 0)?,
            flags: word_argument(arguments, 1)?,
        },
        1212 => Win16MediaIoRequest::Read {
            handle: word_argument(arguments, 0)?,
            buffer: dword_argument(arguments, 1)?,
            count: dword_argument(arguments, 2)? as i32,
        },
        1213 => Win16MediaIoRequest::Write {
            handle: word_argument(arguments, 0)?,
            buffer: dword_argument(arguments, 1)?,
            count: dword_argument(arguments, 2)? as i32,
        },
        1214 => Win16MediaIoRequest::Seek {
            handle: word_argument(arguments, 0)?,
            offset: dword_argument(arguments, 1)? as i32,
            origin: word_argument(arguments, 2)? as i16,
        },
        1218 => Win16MediaIoRequest::Flush {
            handle: word_argument(arguments, 0)?,
            flags: word_argument(arguments, 1)?,
        },
        1220 => {
            let far = dword_argument(arguments, 0)?;
            Win16MediaIoRequest::StringToFourCc {
                text: if far == 0 {
                    None
                } else {
                    Some(ordinary_string(far, selectors, memory)?)
                },
                flags: word_argument(arguments, 1)?,
            }
        }
        1223 => Win16MediaIoRequest::Descend {
            handle: word_argument(arguments, 0)?,
            chunk: dword_argument(arguments, 1)?,
            parent: dword_argument(arguments, 2)?,
            flags: word_argument(arguments, 3)?,
        },
        1224 => Win16MediaIoRequest::Ascend {
            handle: word_argument(arguments, 0)?,
            chunk: dword_argument(arguments, 1)?,
            flags: word_argument(arguments, 2)?,
        },
        1225 => Win16MediaIoRequest::CreateChunk {
            handle: word_argument(arguments, 0)?,
            chunk: dword_argument(arguments, 1)?,
            flags: word_argument(arguments, 2)?,
        },
        1226 => Win16MediaIoRequest::Rename {
            old_path: ordinary_string(dword_argument(arguments, 0)?, selectors, memory)?,
            new_path: ordinary_string(dword_argument(arguments, 1)?, selectors, memory)?,
            info: dword_argument(arguments, 2)?,
            flags: dword_argument(arguments, 3)?,
        },
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(request)
}

/// SDK 3.1 declares these paths as ordinary LPSTR/FAR strings, not HPSTR.
/// Stop at the first descriptor boundary instead of following a huge chain.
fn ordinary_string(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    let start = selectors.pointer_from_far(far)?;
    let descriptor = selectors.describe(start.selector())?;
    let available = descriptor.limit.checked_sub(u32::from(start.offset()))
        .and_then(|length| length.checked_add(1))
        .and_then(|length| usize::try_from(length).ok())
        .ok_or(Win16Error::InvalidRange)?;
    let bound = available.min(MAX_WIN16_STRING_BYTES);
    let mut bytes = Vec::new();
    bytes.try_reserve(bound.min(128)).map_err(|_| Win16Error::OutOfMemory)?;
    for offset in 0..bound {
        let pointer = selectors.add_bytes(
            start,
            u32::try_from(offset).map_err(|_| Win16Error::InvalidRange)?,
        )?;
        let mut byte = [0_u8; 1];
        selectors.read(memory, pointer, &mut byte)?;
        if byte[0] == 0 { return Ok(bytes); }
        bytes.try_reserve(1).map_err(|_| Win16Error::OutOfMemory)?;
        bytes.push(byte[0]);
    }
    Err(Win16Error::InvalidRange)
}
