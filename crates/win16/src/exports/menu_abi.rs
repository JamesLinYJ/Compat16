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

/// Previous state returned by `EnableMenuItem`.
///
/// The previous state is `MF_DISABLED`, `MF_ENABLED`, or `MF_GRAYED`, or -1
/// when the item does not exist. A grayed item is often reported with both
/// grayed and disabled bits set; the guest word is the documented grayed value.
///
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enablemenuitem>
pub fn enable_menu_item_state(previous: i32) -> u16 {
    if previous == -1 {
        return u16::MAX;
    }
    let bits = previous as u16;
    if bits & MF_GRAYED != 0 {
        MF_GRAYED
    } else if bits & MF_DISABLED != 0 {
        MF_DISABLED
    } else {
        MF_ENABLED
    }
}

/// Previous state returned by `CheckMenuItem`.
///
/// The previous state is `MF_CHECKED` or `MF_UNCHECKED`. A missing item is
/// `UINT_MAX`, which is the 16-bit failure word. Other flag bits are not part
/// of that result.
///
/// Source: <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-checkmenuitem>
pub fn check_menu_item_state(previous: u32) -> u16 {
    if previous == u32::MAX {
        u16::MAX
    } else if previous & u32::from(MF_CHECKED) != 0 {
        MF_CHECKED
    } else {
        MF_UNCHECKED
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MF_BYPOSITION, MF_CHECKED, MF_DISABLED, MF_ENABLED, MF_GRAYED, MF_UNCHECKED,
        check_menu_item_state, enable_menu_item_state, insert_menu_native_position,
    };

    #[test]
    fn enable_menu_item_state_is_one_documented_flag_or_missing() {
        assert_eq!(enable_menu_item_state(-1), u16::MAX);
        assert_eq!(enable_menu_item_state(0), MF_ENABLED);
        assert_eq!(enable_menu_item_state(i32::from(MF_GRAYED)), MF_GRAYED);
        assert_eq!(enable_menu_item_state(i32::from(MF_DISABLED)), MF_DISABLED);
        assert_eq!(
            enable_menu_item_state(i32::from(MF_GRAYED | MF_DISABLED)),
            MF_GRAYED
        );
        assert_eq!(enable_menu_item_state(0x1_0002), MF_DISABLED);
        assert_eq!(enable_menu_item_state(i32::MIN), MF_ENABLED);
    }

    #[test]
    fn check_menu_item_state_keeps_the_checked_bit_or_missing() {
        assert_eq!(check_menu_item_state(u32::MAX), u16::MAX);
        assert_eq!(check_menu_item_state(0), MF_UNCHECKED);
        assert_eq!(
            check_menu_item_state(u32::from(MF_CHECKED | MF_GRAYED)),
            MF_CHECKED
        );
        assert_eq!(check_menu_item_state(0xFFFF), MF_CHECKED);
    }

    #[test]
    fn insert_menu_appends_only_for_the_byposition_sentinel() {
        assert_eq!(
            insert_menu_native_position(u16::MAX, MF_BYPOSITION),
            u32::MAX
        );
        assert_eq!(
            insert_menu_native_position(u16::MAX, 0),
            u32::from(u16::MAX)
        );
        assert_eq!(insert_menu_native_position(0, MF_BYPOSITION), 0);
    }
}
