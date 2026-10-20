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

#[cfg(test)]
mod tests {
    use super::{win31_stock_object, win31_stretch_blt_mode, win31_system_metric};

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
}
