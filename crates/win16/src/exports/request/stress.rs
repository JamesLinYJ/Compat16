//! Typed STRESS compatibility calls. The request layer preserves the declared
//! Win16 argument widths; runtime code must own any resources it allocates.

use crate::{Win16Argument, Win16Error};

pub const EDS_WIN: u16 = 1;
pub const EDS_CUR: u16 = 2;
pub const EDS_TEMP: u16 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16StressRequest {
    AllocMem { size: u32 },
    FreeAllMem,
    AllocFileHandles { count: u16 },
    UnAllocFileHandles,
    GetFreeFileHandles,
    AllocDiskSpace { bytes: i32, location: u16 },
    UnAllocDiskSpace { location: u16 },
    AllocUserMem { size: u16 },
    FreeAllUserMem,
    AllocGdiMem { size: u16 },
    FreeAllGdiMem,
}

pub fn decode_stress(
    ordinal: u16,
    arguments: &[Win16Argument],
) -> Result<Option<Win16StressRequest>, Win16Error> {
    let expected = match ordinal {
        2 | 12 | 14 => 1,
        3 | 7 | 8 | 13 | 15 => 0,
        6 | 11 => 1,
        10 => 2,
        _ => return Ok(None),
    };
    if arguments.len() != expected {
        return Err(Win16Error::InvalidRange);
    }

    let request = match ordinal {
        2 => Win16StressRequest::AllocMem { size: dword(arguments, 0)? },
        3 if arguments.is_empty() => Win16StressRequest::FreeAllMem,
        6 => Win16StressRequest::AllocFileHandles { count: word(arguments, 0)? },
        7 if arguments.is_empty() => Win16StressRequest::UnAllocFileHandles,
        8 if arguments.is_empty() => Win16StressRequest::GetFreeFileHandles,
        10 => Win16StressRequest::AllocDiskSpace {
            bytes: i32::from_le_bytes(dword(arguments, 0)?.to_le_bytes()),
            location: word(arguments, 1)?,
        },
        11 => Win16StressRequest::UnAllocDiskSpace { location: word(arguments, 0)? },
        12 => Win16StressRequest::AllocUserMem { size: word(arguments, 0)? },
        13 if arguments.is_empty() => Win16StressRequest::FreeAllUserMem,
        14 => Win16StressRequest::AllocGdiMem { size: word(arguments, 0)? },
        15 if arguments.is_empty() => Win16StressRequest::FreeAllGdiMem,
        _ => unreachable!("recognized STRESS ordinal was checked above"),
    };
    Ok(Some(request))
}
