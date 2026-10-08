//! Typed Win16 SHELL icon requests and image destruction calls.

use guest_core::GuestMemory;

use crate::{SelectorTable, Win16Argument, Win16Error};
use crate::strings::read_ansi_z;

const MAX_WIN16_STRING_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16GuestImageKind {
    Icon,
    Cursor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16DestroyImageRequest {
    pub kind: Win16GuestImageKind,
    pub handle: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ShellIconRequest {
    ExtractIcon { instance: u16, path: Vec<u8>, index: i16 },
    ExtractAssociatedIcon { instance: u16, path: u32, index: u32 },
    InternalExtractIcon { instance: u16, path: Vec<u8>, index: i16, count: u16 },
    ExtractIconEx {
        path: Vec<u8>,
        index: i16,
        large_output: u32,
        small_output: u32,
        count: u16,
    },
}

/// Decode icon calls while keeping guest pointers as guest values. The
/// associated-icon path is an in/out buffer with no capacity argument; its
/// runtime bridge must not pass guest memory to the native API.
pub fn decode_shell_icon_export(
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ShellIconRequest, Win16Error> {
    let request = match ordinal {
        34 => Win16ShellIconRequest::ExtractIcon {
            instance: word(arguments, 0)?,
            path: read_ansi_z(selectors, memory, dword(arguments, 1)?, MAX_WIN16_STRING_BYTES)?,
            index: word(arguments, 2)? as i16,
        },
        36 => Win16ShellIconRequest::ExtractAssociatedIcon {
            instance: word(arguments, 0)?,
            path: dword(arguments, 1)?,
            index: dword(arguments, 2)?,
        },
        39 => {
            let count = word(arguments, 3)?;
            // The internal ordinal returns zero for n == 0 before using the
            // file pointer, so that unused guest address is not dereferenced.
            Win16ShellIconRequest::InternalExtractIcon {
                instance: word(arguments, 0)?,
                path: if count == 0 {
                    Vec::new()
                } else {
                    read_ansi_z(selectors, memory, dword(arguments, 1)?, MAX_WIN16_STRING_BYTES)?
                },
                index: word(arguments, 2)? as i16,
                count,
            }
        }
        40 => Win16ShellIconRequest::ExtractIconEx {
            path: read_ansi_z(selectors, memory, dword(arguments, 0)?, MAX_WIN16_STRING_BYTES)?,
            index: word(arguments, 1)? as i16,
            large_output: dword(arguments, 2)?,
            small_output: dword(arguments, 3)?,
            count: word(arguments, 4)?,
        },
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(request)
}

/// Decode USER.457 DestroyIcon and USER.458 DestroyCursor using their exact
/// Win16 WORD handle parameters.
pub fn decode_destroy_image(
    ordinal: u16,
    arguments: &[Win16Argument],
) -> Result<Win16DestroyImageRequest, Win16Error> {
    let kind = match ordinal {
        457 => Win16GuestImageKind::Icon,
        458 => Win16GuestImageKind::Cursor,
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(Win16DestroyImageRequest { kind, handle: word(arguments, 0)? })
}

fn word(arguments: &[Win16Argument], index: usize) -> Result<u16, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Word(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn dword(arguments: &[Win16Argument], index: usize) -> Result<u32, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Dword(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}
