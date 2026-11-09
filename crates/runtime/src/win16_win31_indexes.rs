//! Windows 3.1 index tables that later Windows extended.
//!
//! Guest calls check these tables before a host query. An index or mode
//! outside the table is the documented failure and is not forwarded.

/// `SM_CXSCREEN` (0) through `SM_DBCSENABLED` (42).
///
/// Windows 3.1 `WINDOWS.H` defines `SM_CMETRICS` as 43, the count of those
/// indexes, not a query index. `SM_CMOUSEBUTTONS` was added later at 43.
/// Later headers reuse 44 for `SM_SECURE` and add `SM_CXSMICON` at 49. Learn
/// returns 0 when `GetSystemMetrics` fails.
pub const WIN31_LAST_SYSTEM_METRIC: i32 = 42;

/// `BLACKONWHITE`, `WHITEONBLACK`, and `COLORONCOLOR`.
///
/// The Windows 3.1 SDK lists those three stretching modes. `HALFTONE` (4)
/// is a later mode. `SetStretchBltMode` returns 0 when the mode is not one
/// of the three.
pub fn win31_stretch_blt_mode(mode: i32) -> bool {
    matches!(mode, 1..=3)
}

/// Windows 3.1 `GetSystemMetrics` index.
pub fn win31_system_metric(index: i32) -> bool {
    (0..=WIN31_LAST_SYSTEM_METRIC).contains(&index)
}

/// Windows 3.1 `GetStockObject` index.
///
/// `WINDOWS.H` lists brushes and pens `0..=8` and fonts and the default
/// palette `10..=16`. Index 9 is unused. `DEFAULT_GUI_FONT` (17),
/// `DC_BRUSH` (18), and `DC_PEN` (19) are later objects. Learn returns NULL
/// when `GetStockObject` fails.
pub fn win31_stock_object(index: i16) -> bool {
    matches!(index, 0..=8 | 10..=16)
}

/// Windows 3.1 virtual-key code.
///
/// Programmer's Reference Volume 3, Appendix B, is the table
/// `GetKeyState`, `GetAsyncKeyState`, `GetKeyboardState`, and
/// `SetKeyboardState` use. Undefined and unassigned codes are not
/// forwarded. Win32 later used them for other keys, including the X
/// buttons (`05`–`06`), the Windows keys (`5B`–`5F`), and the left and
/// right modifiers (`A0`–`A5`, inside unassigned `92`–`B9`). Kanji
/// reservations and OEM-specific ranges stay, because Appendix B assigns
/// those codes.
pub fn win31_virtual_key(key: i32) -> bool {
    let Ok(key) = u8::try_from(key) else {
        return false;
    };
    !matches!(
        key,
        0x00
            | 0x05..=0x07
            | 0x0A..=0x0B
            | 0x0E..=0x0F
            | 0x1A
            | 0x3A..=0x40
            | 0x5B..=0x5F
            | 0x88..=0x8F
            | 0x92..=0xB9
            | 0xC1..=0xDA
            | 0xE5
            | 0xE7..=0xE8
            | 0xF6..=0xFF
    )
}

/// Copy Windows 3.1 virtual-key bytes from the guest table onto the host
/// table. Every other byte keeps the host value, so a later Win32 key is
/// not cleared or rewritten.
pub fn merge_win31_keyboard_state(host: &[u8; 256], guest: &[u8; 256]) -> [u8; 256] {
    let mut merged = *host;
    for index in 0..=u8::MAX {
        if win31_virtual_key(i32::from(index)) {
            let slot = usize::from(index);
            merged[slot] = guest[slot];
        }
    }
    merged
}

/// Replace bytes Appendix B leaves undefined with the guest table.
/// Windows 3.1 virtual keys keep the host state.
pub fn overlay_win31_keyboard_slots(keys: &mut [u8; 256], saved: &[u8; 256]) {
    for index in 0..=u8::MAX {
        if !win31_virtual_key(i32::from(index)) {
            let slot = usize::from(index);
            keys[slot] = saved[slot];
        }
    }
}

/// `GetKeyState` word for one keyboard-state byte.
///
/// The high bit is down (`0x8000`) and the low bit is the toggle. The
/// Windows 3.1 descriptions of `GetKeyState` and `GetKeyboardState` define
/// those two bits.
pub fn win31_key_state_word(byte: u8) -> i16 {
    let mut state = 0_u16;
    if byte & 0x80 != 0 {
        state |= 0x8000;
    }
    if byte & 0x01 != 0 {
        state |= 0x0001;
    }
    state as i16
}

#[cfg(test)]
mod tests {
    use super::{
        merge_win31_keyboard_state, overlay_win31_keyboard_slots, win31_key_state_word,
        win31_stock_object, win31_stretch_blt_mode, win31_system_metric, win31_virtual_key,
    };

    #[test]
    fn win31_system_metric_stops_at_dbcs_enabled() {
        assert!(win31_system_metric(0));
        assert!(win31_system_metric(42));
        assert!(!win31_system_metric(-1));
        assert!(!win31_system_metric(43));
        assert!(!win31_system_metric(44));
        assert!(!win31_system_metric(49));
    }

    #[test]
    fn win31_stretch_blt_mode_is_the_three_win31_modes() {
        assert!(win31_stretch_blt_mode(1));
        assert!(win31_stretch_blt_mode(2));
        assert!(win31_stretch_blt_mode(3));
        assert!(!win31_stretch_blt_mode(0));
        assert!(!win31_stretch_blt_mode(4));
    }

    #[test]
    fn win31_stock_object_skips_the_unused_and_later_indexes() {
        for index in [0, 8, 10, 16] {
            assert!(win31_stock_object(index), "{index}");
        }
        for index in [-1, 9, 17, 18, 19] {
            assert!(!win31_stock_object(index), "{index}");
        }
    }

    #[test]
    fn win31_virtual_key_keeps_assigned_codes_and_rejects_later_ones() {
        for key in [
            0x01, 0x04, 0x08, 0x10, 0x14, 0x15, 0x19, 0x1B, 0x1C, 0x1F, 0x20, 0x2A, 0x30, 0x39,
            0x41, 0x5A, 0x60, 0x70, 0x87, 0x90, 0x91, 0xBA, 0xC0, 0xDB, 0xE4, 0xE6, 0xE9, 0xF5,
        ] {
            assert!(win31_virtual_key(key), "{key:#x}");
        }
        for key in [
            -1, 0, 0x05, 0x06, 0x07, 0x0A, 0x1A, 0x3A, 0x40, 0x5B, 0x5C, 0x5D, 0x5F, 0x88, 0x8F,
            0x92, 0xA0, 0xA1, 0xA2, 0xA5, 0xB9, 0xC1, 0xDA, 0xE5, 0xE7, 0xE8, 0xF6, 0xFE, 0xFF,
            256,
        ] {
            assert!(!win31_virtual_key(key), "{key:#x}");
        }
    }

    #[test]
    fn keyboard_state_merge_leaves_later_virtual_keys_unchanged() {
        let mut host = [0_u8; 256];
        let mut guest = [0_u8; 256];
        host[0x10] = 0x01;
        host[0x5B] = 0x80;
        host[0xA0] = 0x80;
        guest[0x10] = 0x80;
        guest[0x41] = 0x81;
        guest[0x5B] = 0x80;
        guest[0xA0] = 0x01;
        let merged = merge_win31_keyboard_state(&host, &guest);
        assert_eq!(merged[0x10], 0x80);
        assert_eq!(merged[0x41], 0x81);
        assert_eq!(merged[0x5B], 0x80);
        assert_eq!(merged[0xA0], 0x80);
    }

    #[test]
    fn keyboard_state_overlay_publishes_saved_unassigned_slots() {
        let mut keys = [0x7F_u8; 256];
        let mut saved = [0_u8; 256];
        saved[0x5B] = 0x80;
        saved[0xA0] = 0x01;
        saved[0x10] = 0x80;
        overlay_win31_keyboard_slots(&mut keys, &saved);
        assert_eq!(keys[0x10], 0x7F);
        assert_eq!(keys[0x41], 0x7F);
        assert_eq!(keys[0x5B], 0x80);
        assert_eq!(keys[0xA0], 0x01);
        assert_eq!(win31_key_state_word(saved[0x5B]), i16::MIN);
        assert_eq!(win31_key_state_word(saved[0xA0]), 1);
        assert_eq!(win31_key_state_word(0x81), -32767);
        assert_eq!(win31_key_state_word(0x7E), 0);
    }
}
