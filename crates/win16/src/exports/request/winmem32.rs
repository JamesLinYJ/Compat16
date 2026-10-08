//! Typed WINMEM32 guest calls. FAR output addresses remain guest values until
//! the runtime validates and writes them through the selector table.

use crate::{Win16Argument, Win16Error};

/// Version 1.00, as declared by the Windows 3.1 SDK header.
pub const WINMEM32_VERSION_1_00: u16 = 0x0100;
pub const WINMEM32_MAX_OBJECT_BYTES: u32 = 0x0400_0000;
pub const WINMEM32_MAX_16BIT_ALIAS_BYTES: u32 = 0x0001_0000;
pub const WINMEM32_INVALID_FUNCTION: u16 = 1;
pub const WINMEM32_INVALID_FLAGS: u16 = 2;
pub const WINMEM32_INVALID_ARGUMENT: u16 = 3;
pub const WINMEM32_INSUFFICIENT_SELECTORS: u16 = 4;
pub const WINMEM32_INSUFFICIENT_MEMORY: u16 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16Winmem32Request {
    GetVersion,
    Global32Alloc { size: u32, selector_output: u32, max_size: u32, flags: u16 },
    Global32Realloc { selector: u16, new_size: u32, flags: u16 },
    Global32Free { selector: u16, flags: u16 },
    Global16PointerAlloc {
        selector: u16,
        offset: u32,
        alias_output: u32,
        size: u32,
        flags: u16,
    },
    Global16PointerFree { selector: u16, alias: u32, flags: u16 },
    Global32CodeAlias { selector: u16, alias_output: u32, flags: u16 },
    Global32CodeAliasFree { selector: u16, alias: u16, flags: u16 },
}

pub fn decode_winmem32(
    ordinal: u16,
    arguments: &[Win16Argument],
) -> Result<Option<Win16Winmem32Request>, Win16Error> {
    let expected = match ordinal {
        1 => 0,
        2 => 4,
        3 | 7 | 8 => 3,
        4 => 2,
        5 => 5,
        6 => 3,
        _ => return Ok(None),
    };
    if arguments.len() != expected {
        return Err(Win16Error::InvalidRange);
    }

    let request = match ordinal {
        1 => Win16Winmem32Request::GetVersion,
        2 => Win16Winmem32Request::Global32Alloc {
            size: dword(arguments, 0)?, selector_output: dword(arguments, 1)?,
            max_size: dword(arguments, 2)?, flags: word(arguments, 3)?,
        },
        3 => Win16Winmem32Request::Global32Realloc {
            selector: word(arguments, 0)?, new_size: dword(arguments, 1)?,
            flags: word(arguments, 2)?,
        },
        4 => Win16Winmem32Request::Global32Free {
            selector: word(arguments, 0)?, flags: word(arguments, 1)?,
        },
        5 => Win16Winmem32Request::Global16PointerAlloc {
            selector: word(arguments, 0)?, offset: dword(arguments, 1)?,
            alias_output: dword(arguments, 2)?, size: dword(arguments, 3)?,
            flags: word(arguments, 4)?,
        },
        6 => Win16Winmem32Request::Global16PointerFree {
            selector: word(arguments, 0)?, alias: dword(arguments, 1)?,
            flags: word(arguments, 2)?,
        },
        7 => Win16Winmem32Request::Global32CodeAlias {
            selector: word(arguments, 0)?, alias_output: dword(arguments, 1)?,
            flags: word(arguments, 2)?,
        },
        8 => Win16Winmem32Request::Global32CodeAliasFree {
            selector: word(arguments, 0)?, alias: word(arguments, 1)?,
            flags: word(arguments, 2)?,
        },
        _ => unreachable!("recognized WINMEM32 ordinal was checked above"),
    };
    Ok(Some(request))
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
