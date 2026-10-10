//! Guest ABI arguments for USER window fields and public SetParent.
//!
//! Predefined indexes follow the Microsoft Windows 3.1 SDK 3.10 `WINDOWS.H`:
//! its “Window field offsets” block names the negative window-structure fields,
//! and its “Get/SetWindowWord/Long offsets for use with WC_DIALOG” block
//! defines `DWL_MSGRESULT`, `DWL_DLGPROC`, and `DWL_USER`. The SDK guide's
//! “Window Words” discussion describes nonnegative offsets into class-allocated
//! window-extra storage.
//!
//! Sources: [Microsoft Windows 3.1 SDK 3.10 WINDOWS.H, mirrored with its
//! original Microsoft copyright header](https://gist.githubusercontent.com/markusbkk/8028606096290b965e69a552fc1bde72/raw/2c2cf282e6e7a195929c4a437edf1fddd73e28f1/WINDOWS.H);
//! [Microsoft Windows 3.1 SDK Guide to Programming](https://www.bitsavers.org/pdf/microsoft/windows_3.1/Microsoft_Windows_3.1_SDK_1992/PC28919-0492_Guide_to_Programming_199204.pdf).

use crate::{Win16Argument, Win16Error};

/// A decoded USER.133–136 or USER.233 request.
///
/// Window handles and LONG values retain their Win16 bit patterns. The signed
/// index is an `INT16`; positive values address guest window-extra bytes, while
/// negative values select fields in the guest window structure. Any storage,
/// special-field handling, and result-width behavior belongs to the runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16WindowDataRequest {
    /// USER.233: native reparenting, distinct from the parent/owner field.
    SetParent { window: u16, parent: u16 },
    /// USER.133: retrieve a WORD at a signed window-field/extra-byte index.
    GetWindowWord { window: u16, index: i16 },
    /// USER.134: store a WORD and return the previous WORD.
    SetWindowWord { window: u16, index: i16, value: u16 },
    /// USER.135: retrieve a signed LONG bit pattern at an index.
    GetWindowLong { window: u16, index: i16 },
    /// USER.136: store a LONG and return the previous LONG.
    SetWindowLong { window: u16, index: i16, value: i32 },
}

/// Decode USER.133–136 and USER.233's exact stack argument layouts.
///
/// The SDK declares `int` for the index; retaining the WORD's bit pattern as
/// `i16` is required for the negative predefined field offsets.
pub fn decode_window_data(
    ordinal: u16,
    arguments: &[Win16Argument],
) -> Result<Win16WindowDataRequest, Win16Error> {
    let request = match (ordinal, arguments) {
        (233, [Win16Argument::Word(window), Win16Argument::Word(parent)]) => {
            Win16WindowDataRequest::SetParent { window: *window, parent: *parent }
        }
        (133, [Win16Argument::Word(window), Win16Argument::Word(index)]) => {
            Win16WindowDataRequest::GetWindowWord {
                window: *window,
                index: *index as i16,
            }
        }
        (134, [Win16Argument::Word(window), Win16Argument::Word(index), Win16Argument::Word(value)]) => {
            Win16WindowDataRequest::SetWindowWord {
                window: *window,
                index: *index as i16,
                value: *value,
            }
        }
        (135, [Win16Argument::Word(window), Win16Argument::Word(index)]) => {
            Win16WindowDataRequest::GetWindowLong {
                window: *window,
                index: *index as i16,
            }
        }
        (136, [Win16Argument::Word(window), Win16Argument::Word(index), Win16Argument::Dword(value)]) => {
            Win16WindowDataRequest::SetWindowLong {
                window: *window,
                index: *index as i16,
                value: *value as i32,
            }
        }
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(request)
}

/// Guest window-procedure FARPROC field in the window structure.
pub const GWL_WNDPROC: i16 = -4;
/// Guest window-instance field in the window structure.
pub const GWW_HINSTANCE: i16 = -6;
/// Guest parent-window field in the window structure.
pub const GWW_HWNDPARENT: i16 = -8;
/// Guest control identifier field in the window structure.
pub const GWW_ID: i16 = -12;
/// Guest window-style field in the window structure.
pub const GWL_STYLE: i16 = -16;
/// Guest extended-window-style field in the window structure.
pub const GWL_EXSTYLE: i16 = -20;

/// Dialog-box procedure result field, relative to the guest dialog extra area.
/// The Win16 SDK 3.10 `WINDOWS.H` defines these in its “Get/SetWindowWord/Long
/// offsets for use with WC_DIALOG” block; they are not inferred from modern
/// pointer-width-dependent `DWLP_*` definitions.
pub const DWL_MSGRESULT: i16 = 0;
/// Guest dialog-procedure FARPROC field, relative to the guest dialog extra area.
pub const DWL_DLGPROC: i16 = 4;
/// First application-defined dialog extra-data offset.
pub const DWL_USER: i16 = 8;
