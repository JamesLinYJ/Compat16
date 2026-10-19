//! Signed Win16 count results at the native GetDeviceCaps boundary.

use windows_sys::Win32::Graphics::Gdi::{NUMBRUSHES, NUMCOLORS, NUMPENS};

pub(super) fn project_count(index: i16, native: i32) -> i16 {
    match (index as u32, native) {
        // Legacy WOW exposes a finite positive count for these unlimited
        // Win32 counts. Passing -1 through makes signed INT16 color tests
        // classify a true-color device as monochrome. This does not change
        // the native DC, bitmap format, or genuine two-color count.
        (NUMBRUSHES | NUMPENS | NUMCOLORS, -1) => 2048,
        // A finite native color count can also exceed signed INT16. Saturate
        // before narrowing, so e.g. 65536 does not become zero colors.
        (NUMCOLORS, colors) if colors > i32::from(i16::MAX) => i16::MAX,
        _ => native as i16,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Graphics::Gdi::{BITSPIXEL, RASTERCAPS, TECHNOLOGY};

    #[test]
    fn unlimited_device_counts_remain_positive_in_win16() {
        for index in [NUMBRUSHES, NUMPENS, NUMCOLORS] {
            assert_eq!(project_count(index as i16, -1), 2048);
        }
    }

    #[test]
    fn actual_monochrome_and_palette_counts_are_preserved() {
        for colors in [2, 4, 16, 256, 2048, 32767] {
            assert_eq!(project_count(NUMCOLORS as i16, colors), colors as i16);
        }
    }

    #[test]
    fn finite_color_overflow_cannot_wrap_to_zero_or_monochrome() {
        for colors in [32768, 65535, 65536, 1 << 24, i32::MAX] {
            assert_eq!(project_count(NUMCOLORS as i16, colors), i16::MAX);
        }
    }

    #[test]
    fn zero_and_other_negative_count_results_are_not_invented_successes() {
        for index in [NUMBRUSHES, NUMPENS, NUMCOLORS] {
            assert_eq!(project_count(index as i16, 0), 0);
            assert_eq!(project_count(index as i16, -2), -2);
        }
    }

    #[test]
    fn unrelated_capabilities_keep_native_values_and_word_bits() {
        assert_eq!(project_count(BITSPIXEL as i16, 32), 32);
        assert_eq!(project_count(TECHNOLOGY as i16, 1), 1);
        assert_eq!(project_count(RASTERCAPS as i16, 0x8f81), 0x8f81_u16 as i16);
        assert_eq!(project_count(BITSPIXEL as i16, -1), -1);
        assert_eq!(project_count(-1, -1), -1);
    }
}
