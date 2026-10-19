//! Noninteractive native GDI and guest-code-page checks for GetCharWidth.

use super::*;
use std::ptr;
use windows_sys::Win32::Graphics::Gdi::{
    CreateFontIndirectW, DEFAULT_CHARSET, GetTextMetricsW, HDC, HGDIOBJ, LOGFONTW, MM_ANISOTROPIC,
    SYSTEM_FONT, SelectObject, SetMapMode, SetViewportExtEx, SetWindowExtEx, TEXTMETRICW,
    TMPF_TRUETYPE,
};

#[test]
fn get_char_width_maps_explicit_sbcs_cp932_and_cp936_character_codes() {
    assert_eq!(
        guest_character_range(GuestTextCodec::new(1252).unwrap(), 0x80, 0x80),
        Some(vec![0x20ac])
    );
    assert_eq!(
        guest_character_range(GuestTextCodec::new(1252).unwrap(), 0x81, 0x81),
        Some(vec![0x81])
    );
    let japanese = GuestTextCodec::new(932).unwrap();
    assert_eq!(
        guest_character_range(japanese, 0x8140, 0x8142),
        Some(vec![0x3000, 0x3001, 0x3002])
    );
    assert_eq!(
        guest_character_range(japanese, 0x82a0, 0x82a2),
        Some(vec![0x3042, 0x3043, 0x3044])
    );
    // Distinguish numeric character codes from little-endian memory bytes.
    assert_eq!(guest_character_range(japanese, 0x4081, 0x4081), None);
    assert_eq!(guest_character_range(japanese, 0x81, 0x81), None);
    assert_eq!(guest_character_range(japanese, 0x827f, 0x827f), None);
    assert_eq!(
        guest_character_range(GuestTextCodec::new(936).unwrap(), 0xd6d0, 0xd6d0),
        Some(vec![0x4e2d])
    );
    assert_eq!(guest_character_range(japanese, 1, 0), None);
    assert_eq!(guest_character_range(japanese, 0, u16::MAX), None);
}

#[test]
fn get_char_width_groups_only_adjacent_unicode_mappings_in_guest_order() {
    let characters = [0x41, 0x42, 0x20ac, 0x3000, 0x3001, 0xffff, 0];
    let mut widths = [0; 7];
    let mut ranges = Vec::new();
    assert!(query_runs(
        &characters,
        &mut widths,
        |first, last, output| {
            ranges.push((first, last, output.len()));
            for (index, width) in output.iter_mut().enumerate() {
                *width = i32::from(first) + index as i32;
            }
            true
        }
    ));
    assert_eq!(
        ranges,
        [
            (0x41, 0x42, 2),
            (0x20ac, 0x20ac, 1),
            (0x3000, 0x3001, 2),
            (0xffff, 0xffff, 1),
            (0, 0, 1)
        ]
    );
    assert_eq!(widths, characters.map(i32::from));
}

#[test]
fn get_char_width_stops_native_queries_on_failure_and_rejects_wrong_lengths() {
    let mut calls = 0;
    let mut widths = [0; 3];
    assert!(!query_runs(&[1, 3, 5], &mut widths, |_, _, output| {
        calls += 1;
        output[0] = 77;
        calls < 2
    }));
    assert_eq!(calls, 2);
    assert!(!query_runs(&[], &mut [], |_, _, _| panic!("empty query")));
    assert!(!query_runs(&[1, 2], &mut widths, |_, _, _| panic!(
        "mismatched query"
    )));
}

struct SelectedFont {
    hdc: HDC,
    previous: HGDIOBJ,
    font: HGDIOBJ,
    owned: bool,
}

impl SelectedFont {
    fn select(hdc: HDC, font: HGDIOBJ, owned: bool) -> Self {
        assert!(!font.is_null());
        // SAFETY: Both handles are native objects owned for this synchronous test.
        let previous = unsafe { SelectObject(hdc, font) };
        assert!(!previous.is_null() && previous as usize != usize::MAX);
        Self {
            hdc,
            previous,
            font,
            owned,
        }
    }
}

impl Drop for SelectedFont {
    fn drop(&mut self) {
        // SAFETY: The surrounding test retains the DC lease until after this
        // guard restores its previous font. Only test-created fonts are freed.
        unsafe {
            SelectObject(self.hdc, self.previous);
            if self.owned {
                crate::windows::win32_safe::delete_object(self.font);
            }
        }
    }
}

fn compare_native_range(dcs: &Win16Dcs, dc: Win16HostDc, first: u16, last: u16) -> bool {
    let lease = dcs.lease_dc(dc).unwrap().unwrap();
    let characters = guest_character_range(dcs.text_codec(), first, last).unwrap();
    let mut expected = Vec::new();
    let mut success = true;
    for character in characters {
        let mut width = 0_i32;
        // SAFETY: The HDC is leased; one requested code unit writes one INT.
        if unsafe {
            GetCharWidthW(
                lease.native(),
                u32::from(character),
                u32::from(character),
                &mut width,
            )
        } == 0
        {
            success = false;
            break;
        }
        expected.push(width);
    }
    let actual = execute(dcs, dc, first, last).unwrap();
    assert_eq!(
        actual,
        ResultValue::CharWidths {
            success,
            entries: if success { expected } else { Vec::new() },
        }
    );
    success
}

#[test]
fn get_char_width_native_uses_selected_raster_font_and_logical_mapping() {
    let dcs = Win16Dcs::with_text_codec(GuestTextCodec::new(1252).unwrap());
    let dc = dcs.create_compatible(None).unwrap().unwrap();
    let lease = dcs.lease_dc(dc).unwrap().unwrap();
    // SAFETY: SYSTEM_FONT is a shared stock font; it must not be deleted.
    let font = crate::windows::win32_safe::stock_object(SYSTEM_FONT);
    let _selected = SelectedFont::select(lease.native(), font, false);
    let mut metrics = TEXTMETRICW::default();
    // SAFETY: Leased HDC and one writable native TEXTMETRICW.
    assert_ne!(unsafe { GetTextMetricsW(lease.native(), &mut metrics) }, 0);
    assert_eq!(metrics.tmPitchAndFamily & TMPF_TRUETYPE, 0);
    assert!(compare_native_range(&dcs, dc, 65, 90));
    assert!(compare_native_range(&dcs, dc, 0x80, 0x85));
    // SAFETY: Each call modifies only this test-owned DC and uses no output pointer.
    unsafe {
        assert_ne!(SetMapMode(lease.native(), MM_ANISOTROPIC), 0);
        assert_ne!(SetWindowExtEx(lease.native(), 3, 5, ptr::null_mut()), 0);
        assert_ne!(SetViewportExtEx(lease.native(), 2, 7, ptr::null_mut()), 0);
    }
    assert!(compare_native_range(&dcs, dc, 65, 67));
}

#[test]
fn get_char_width_native_preserves_truetype_result_and_dbcs_guest_order() {
    for (page, first, last) in [
        (1252, 0x80, 0x85),
        (932, 0x82a0, 0x82a2),
        (936, 0xd6d0, 0xd6d2),
    ] {
        let dcs = Win16Dcs::with_text_codec(GuestTextCodec::new(page).unwrap());
        let dc = dcs.create_compatible(None).unwrap().unwrap();
        let lease = dcs.lease_dc(dc).unwrap().unwrap();
        let mut description = LOGFONTW::default();
        description.lfHeight = -24;
        description.lfItalic = 1;
        description.lfCharSet = DEFAULT_CHARSET;
        let face: Vec<u16> = "Arial".encode_utf16().collect();
        description.lfFaceName[..face.len()].copy_from_slice(&face);
        // SAFETY: A complete, initialized LOGFONTW with a terminated face name.
        let font = unsafe { CreateFontIndirectW(&description) };
        let _selected = SelectedFont::select(lease.native(), font, true);
        let mut metrics = TEXTMETRICW::default();
        // SAFETY: Leased HDC and one writable native TEXTMETRICW.
        assert_ne!(unsafe { GetTextMetricsW(lease.native(), &mut metrics) }, 0);
        assert_ne!(metrics.tmPitchAndFamily & TMPF_TRUETYPE, 0);
        // Windows versions can disagree with the documented TrueType
        // limitation. The adapter must match the actual compatibility API,
        // including failure, rather than fabricate an ABC-derived success.
        compare_native_range(&dcs, dc, 65, 90);
        compare_native_range(&dcs, dc, first, last);
    }
}

#[test]
fn get_char_width_native_unknown_dc_and_oversized_ranges_fail_cleanly() {
    let dcs = Win16Dcs::with_text_codec(GuestTextCodec::new(1252).unwrap());
    for (first, last) in [(65, 65), (1, 0), (0, u16::MAX)] {
        assert_eq!(
            execute(&dcs, Win16HostDc(u64::MAX), first, last).unwrap(),
            ResultValue::CharWidths {
                success: false,
                entries: Vec::new()
            }
        );
    }
}
