//! Guest ABI arguments for USER class-word and class-long accessors.

use crate::{Win16Argument, Win16Error};

/// A decoded USER.129–132 request.
///
/// The window identifies a class in the runtime's guest registry. The signed
/// Win16 index selects a predefined class field or class-extra bytes; neither
/// it nor a LONG value is interpreted as a native pointer at the ABI boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16ClassDataRequest {
    /// USER.129: retrieve a WORD at a signed class-field/extra-byte index.
    GetClassWord { window: u16, index: i16 },
    /// USER.130: store a WORD and return the previous WORD.
    SetClassWord { window: u16, index: i16, value: u16 },
    /// USER.131: retrieve a LONG bit pattern at an index.
    GetClassLong { window: u16, index: i16 },
    /// USER.132: store a LONG and return the previous LONG.
    SetClassLong { window: u16, index: i16, value: i32 },
}

/// Decode the exact scalar argument layouts declared for USER.129–132.
pub fn decode_class_data(
    ordinal: u16,
    arguments: &[Win16Argument],
) -> Result<Win16ClassDataRequest, Win16Error> {
    let request = match (ordinal, arguments) {
        (129, [Win16Argument::Word(window), Win16Argument::Word(index)]) => {
            Win16ClassDataRequest::GetClassWord {
                window: *window,
                index: *index as i16,
            }
        }
        (130, [Win16Argument::Word(window), Win16Argument::Word(index), Win16Argument::Word(value)]) => {
            Win16ClassDataRequest::SetClassWord {
                window: *window,
                index: *index as i16,
                value: *value,
            }
        }
        (131, [Win16Argument::Word(window), Win16Argument::Word(index)]) => {
            Win16ClassDataRequest::GetClassLong {
                window: *window,
                index: *index as i16,
            }
        }
        (132, [Win16Argument::Word(window), Win16Argument::Word(index), Win16Argument::Dword(value)]) => {
            Win16ClassDataRequest::SetClassLong {
                window: *window,
                index: *index as i16,
                value: *value as i32,
            }
        }
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(request)
}

// Win16 class-field offsets from Open Watcom's Win16 API header. GCW_STYLE and
// the extra-byte sizes are WORD fields; GCL_WNDPROC and GCL_MENUNAME are LONG
// fields, independent of native pointer width.
// Source: https://raw.githubusercontent.com/open-watcom/open-watcom-v2/08a5064dd9831edf10234844630e605e83606989/bld/w16api/include/win16.mh
/// Guest class atom.
pub const GCW_ATOM: i16 = -32;
/// Guest WORD class style.
pub const GCW_STYLE: i16 = -26;
/// Guest class procedure's 16:16 FAR pointer bits.
pub const GCL_WNDPROC: i16 = -24;
/// Guest class-extra allocation size.
pub const GCW_CBCLSEXTRA: i16 = -20;
/// Guest per-window extra allocation size.
pub const GCW_CBWNDEXTRA: i16 = -18;
/// Guest class module handle.
pub const GCW_HMODULE: i16 = -16;
/// Guest class icon handle.
pub const GCW_HICON: i16 = -14;
/// Guest class cursor handle.
pub const GCW_HCURSOR: i16 = -12;
/// Guest class background brush or encoded system-color value.
pub const GCW_HBRBACKGROUND: i16 = -10;
/// Guest class menu-name FAR pointer.
pub const GCL_MENUNAME: i16 = -8;
