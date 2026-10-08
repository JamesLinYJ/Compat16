//! Typed requests for native-backed KEYBOARD driver exports.

use guest_core::GuestMemory;

use crate::{SelectorTable, Win16Argument, Win16Error};
use crate::strings::read_ansi_z;

const MAX_WIN16_STRING_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KeyboardConversion {
    AnsiToOem,
    OemToAnsi,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KeyboardRequest {
    ConvertString {
        conversion: Win16KeyboardConversion,
        source: Vec<u8>,
        destination: u32,
    },
    ConvertBuffer {
        conversion: Win16KeyboardConversion,
        source: u32,
        destination: u32,
        byte_count: u16,
    },
    ToAscii {
        virtual_key: u16,
        scan_code: u16,
        key_state: [u8; 256],
        output: u32,
        flags: u16,
    },
    /// KEYBOARD.7: low five bits select the rate; 0xffff asks whether
    /// software speed control is supported.
    SetSpeed { speed: u16 },
    /// KEYBOARD.100 is an OS/2 screen-switch hint and has no DOS effect.
    ScreenSwitchEnable { enabled: u16 },
    OemKeyScan { character: u16 },
    VirtualKeyScan { ansi_character: u8 },
    KeyboardType { selector: i16 },
    MapVirtualKey { code: u16, map_type: u16 },
    GetCodePage,
    GetKeyNameText { parameter: i32, output: u32, capacity: u16 },
}

/// Decode the implemented KEYBOARD subset by its exact driver ordinal.
/// Ordinal 6 (`OemToAnsi`) remains on the established generic route; unknown
/// exports stay unsupported rather than acquiring a guessed generic result.
pub fn decode_keyboard_export(
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16KeyboardRequest, Win16Error> {
    let request = match ordinal {
        4 => {
            let key_state_far = dword(arguments, 2)?;
            let pointer = selectors.pointer_from_far(key_state_far)?;
            let mut key_state = [0_u8; 256];
            selectors.read(memory, pointer, &mut key_state)?;
            Win16KeyboardRequest::ToAscii {
                virtual_key: word(arguments, 0)?,
                scan_code: word(arguments, 1)?,
                key_state,
                output: dword(arguments, 3)?,
                flags: word(arguments, 4)?,
            }
        }
        5 => Win16KeyboardRequest::ConvertString {
            conversion: Win16KeyboardConversion::AnsiToOem,
            source: read_ansi_z(selectors, memory, dword(arguments, 0)?, MAX_WIN16_STRING_BYTES)?,
            destination: dword(arguments, 1)?,
        },
        7 => Win16KeyboardRequest::SetSpeed {
            speed: decode_keyboard_set_speed(arguments)?,
        },
        100 => Win16KeyboardRequest::ScreenSwitchEnable {
            enabled: word(arguments, 0)?,
        },
        128 => Win16KeyboardRequest::OemKeyScan { character: word(arguments, 0)? },
        129 => Win16KeyboardRequest::VirtualKeyScan {
            ansi_character: word(arguments, 0)? as u8,
        },
        130 => Win16KeyboardRequest::KeyboardType {
            selector: word(arguments, 0)? as i16,
        },
        131 => Win16KeyboardRequest::MapVirtualKey {
            code: word(arguments, 0)?,
            map_type: word(arguments, 1)?,
        },
        132 => Win16KeyboardRequest::GetCodePage,
        133 => Win16KeyboardRequest::GetKeyNameText {
            parameter: dword(arguments, 0)? as i32,
            output: dword(arguments, 1)?,
            capacity: word(arguments, 2)?,
        },
        134 => Win16KeyboardRequest::ConvertBuffer {
            conversion: Win16KeyboardConversion::AnsiToOem,
            source: dword(arguments, 0)?,
            destination: dword(arguments, 1)?,
            byte_count: word(arguments, 2)?,
        },
        135 => Win16KeyboardRequest::ConvertBuffer {
            conversion: Win16KeyboardConversion::OemToAnsi,
            source: dword(arguments, 0)?,
            destination: dword(arguments, 1)?,
            byte_count: word(arguments, 2)?,
        },
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(request)
}

/// Decode the one WIFEMAN API with a confirmed direct Windows code-page
/// equivalent. The argument is a WORD and its low byte is the tested value.
pub fn decode_wifeman_dbcs_lead_byte(
    arguments: &[Win16Argument],
) -> Result<u8, Win16Error> {
    Ok(word(arguments, 0)? as u8)
}

/// Decode the keyboard driver's WORD speed argument without consuming its
/// 0xffff capability-query sentinel or low-five-bit rate semantics.
pub fn decode_keyboard_set_speed(arguments: &[Win16Argument]) -> Result<u16, Win16Error> {
    word(arguments, 0)
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
