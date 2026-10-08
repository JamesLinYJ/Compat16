//! Decoded USER window-property operations.
//!
//! The Win16 SDK 3.1 `WINDOWS.H` declares `SetProp(HWND, LPCSTR, HANDLE)`,
//! `GetProp`, `RemoveProp`, and `EnumProps(HWND, PROPENUMPROC)`; ordinals and
//! stack layouts are taken from this project's `USER.SPEC` 24–27 entries.
//! The 3.1 Programmer's Reference defines the string/global-atom name contract
//! and the fixed-segment callback. The raw atom representation is retained so
//! the runtime never guesses a guest atom's name or handle domain.

use crate::{Win16Argument, Win16Error};

/// A property key after guest memory has been checked and copied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16WindowPropertyName {
    /// Opaque Win16 atom bits. The runtime must not guess an atom's name.
    Atom(u16),
    /// ANSI bytes copied from the guest; empty names are rejected by USER.
    String(Vec<u8>),
}

/// One decoded Win16 USER.24–27 property API request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16WindowPropertyRequest {
    Remove {
        window: u16,
        name: Win16WindowPropertyName,
    },
    Get {
        window: u16,
        name: Win16WindowPropertyName,
    },
    Set {
        window: u16,
        name: Win16WindowPropertyName,
        data: u16,
    },
    Enum {
        window: u16,
        callback: u32,
    },
}

fn property_name(
    raw: u32,
    selectors: &crate::SelectorTable,
    memory: &impl guest_core::GuestMemory,
) -> Result<Win16WindowPropertyName, Win16Error> {
    if raw >> 16 == 0 {
        Ok(Win16WindowPropertyName::Atom(raw as u16))
    } else {
        crate::strings::read_ansi_z(
            selectors,
            memory,
            raw,
            crate::exports::MAX_WIN16_STRING_BYTES,
        )
        .map(Win16WindowPropertyName::String)
    }
}

/// Decode the exact stack layouts from USER.SPEC ordinals 24–27.
pub fn decode_window_properties(
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &crate::SelectorTable,
    memory: &impl guest_core::GuestMemory,
) -> Result<Win16WindowPropertyRequest, Win16Error> {
    let word = |index: usize| match arguments.get(index) {
        Some(Win16Argument::Word(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    };
    let dword = |index: usize| match arguments.get(index) {
        Some(Win16Argument::Dword(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    };
    match (ordinal, arguments.len()) {
        (24, 2) => Ok(Win16WindowPropertyRequest::Remove {
            window: word(0)?,
            name: property_name(dword(1)?, selectors, memory)?,
        }),
        (25, 2) => Ok(Win16WindowPropertyRequest::Get {
            window: word(0)?,
            name: property_name(dword(1)?, selectors, memory)?,
        }),
        (26, 3) => Ok(Win16WindowPropertyRequest::Set {
            window: word(0)?,
            name: property_name(dword(1)?, selectors, memory)?,
            data: word(2)?,
        }),
        (27, 2) => Ok(Win16WindowPropertyRequest::Enum {
            window: word(0)?,
            callback: dword(1)?,
        }),
        _ => Err(Win16Error::InvalidRange),
    }
}
