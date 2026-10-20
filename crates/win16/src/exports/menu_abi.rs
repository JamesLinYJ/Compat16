//! Windows 3.1 USER menu flag values and insertion sentinel.
//!
//! Source: Microsoft Windows 3.1 SDK Programmer's Reference, Volume 2,
//! entries for `AppendMenu`, `InsertMenu`, and menu flag values (1992).
//! Original reference:
//! <https://www.bitsavers.org/pdf/microsoft/windows_3.1/Microsoft_Windows_3.1_SDK_1992/PC28916-0492_Programmers_Reference_Volume_2_199204.pdf>.
//! Values are guest ABI constants. The overlapping flag meanings are
//! interpreted by the called API; callers must preserve unknown bits.

pub const MF_INSERT: u16 = 0x0000;
pub const MF_CHANGE: u16 = 0x0080;
pub const MF_APPEND: u16 = 0x0100;
pub const MF_DELETE: u16 = 0x0200;
pub const MF_REMOVE: u16 = 0x1000;

pub const MF_BYCOMMAND: u16 = 0x0000;
pub const MF_BYPOSITION: u16 = 0x0400;

pub const MF_ENABLED: u16 = 0x0000;
pub const MF_GRAYED: u16 = 0x0001;
pub const MF_DISABLED: u16 = 0x0002;

pub const MF_UNCHECKED: u16 = 0x0000;
pub const MF_CHECKED: u16 = 0x0008;
pub const MF_USECHECKBITMAPS: u16 = 0x0200;

pub const MF_STRING: u16 = 0x0000;
pub const MF_BITMAP: u16 = 0x0004;
pub const MF_OWNERDRAW: u16 = 0x0100;
pub const MF_POPUP: u16 = 0x0010;
pub const MF_MENUBARBREAK: u16 = 0x0020;
pub const MF_MENUBREAK: u16 = 0x0040;
pub const MF_SEPARATOR: u16 = 0x0800;

pub const MF_UNHILITE: u16 = 0x0000;
pub const MF_HILITE: u16 = 0x0080;
pub const MF_DEFAULT: u16 = 0x1000;
pub const MF_SYSMENU: u16 = 0x2000;
pub const MF_HELP: u16 = 0x4000;
pub const MF_RIGHTJUSTIFY: u16 = 0x4000;
pub const MF_MOUSESELECT: u16 = 0x8000;
/// Resource-template terminator; runtime AppendMenu/InsertMenu calls should not pass it.
pub const MF_END: u16 = 0x0080;

/// `InsertMenu(..., MF_BYPOSITION, ...)` uses this position to append at end.
pub const MENU_POSITION_APPEND: u16 = u16::MAX;

/// Win32 `InsertMenu` position. `MF_BYPOSITION` with [`MENU_POSITION_APPEND`]
/// is the 16-bit form of -1 and must become `u32::MAX`. A command id of
/// `0xFFFF` stays the zero-extended word.
pub fn insert_menu_native_position(position: u16, flags: u16) -> u32 {
    if flags & MF_BYPOSITION != 0 && position == MENU_POSITION_APPEND {
        u32::MAX
    } else {
        u32::from(position)
    }
}
