//! Opt-in native oracle using only a private memory DC and owned font.

use crate::windows::{guest_text::GuestTextCodec, win16_gdi::Win16Dcs};
use runtime::Win16HostDc;
use std::{mem::size_of, ptr};
use windows_sys::Win32::Graphics::Gdi::{
    ANSI_CHARSET, CreateFontIndirectW, DeleteObject, GetMapMode, GetOutlineTextMetricsW,
    GetTextMetricsW, HDC, HGDIOBJ, LOGFONTW, MM_ANISOTROPIC, MM_TEXT,
    OUTLINETEXTMETRICW, SelectObject, SetMapMode, TEXTMETRICW, TMPF_TRUETYPE,
};

struct MemoryDc {
    dcs: Win16Dcs,
    token: Win16HostDc,
}

impl Drop for MemoryDc {
    fn drop(&mut self) {
        self.dcs.delete(self.token);
    }
}

struct OwnedSelectedFont {
    dc: HDC,
    font: HGDIOBJ,
    previous: HGDIOBJ,
}

impl OwnedSelectedFont {
    fn arial(dc: HDC) -> Self {
        let mut description = LOGFONTW::default();
        description.lfHeight = -24;
        description.lfCharSet = ANSI_CHARSET;
        let face: Vec<u16> = "Arial".encode_utf16().collect();
        description.lfFaceName[..face.len()].copy_from_slice(&face);
        // SAFETY: Fully initialized LOGFONTW, including terminated face name.
        let font = unsafe { CreateFontIndirectW(&description) };
        assert!(!font.is_null(), "CreateFontIndirectW must create an owned font");
        // Establish ownership before a selection assertion can unwind.
        let mut owned = Self { dc, font, previous: ptr::null_mut() };
        // SAFETY: This test owns the font and retains the memory DC lease.
        let previous = unsafe { SelectObject(dc, font) };
        assert!(!previous.is_null() && previous as usize != usize::MAX,
            "SelectObject must select the owned font");
        owned.previous = previous;
        owned
    }
}

impl Drop for OwnedSelectedFont {
    fn drop(&mut self) {
        // SAFETY: This guard is dropped before the surrounding lease and DC.
        // Restore the original font before deleting only the test-created font.
        unsafe {
            if !self.previous.is_null() {
                SelectObject(self.dc, self.previous);
            }
            DeleteObject(self.font);
        }
    }
}

struct MappingMode {
    dc: HDC,
    previous: i32,
}

impl Drop for MappingMode {
    fn drop(&mut self) {
        // SAFETY: Only this test's leased DC was changed by the guard.
        if self.previous != 0 {
            unsafe { SetMapMode(self.dc, self.previous); }
        }
    }
}

#[test]
#[ignore = "requires native Windows GDI and an installed TrueType font"]
fn get_outline_text_metrics_native_matches_independent_oracle_and_rejects_non_mm_text() {
    let dcs = Win16Dcs::with_text_codec(GuestTextCodec::new(1252).unwrap());
    let token = dcs.create_compatible(None).unwrap().expect("private memory DC");
    let owned_dc = MemoryDc { dcs, token };
    let lease = owned_dc.dcs.lease_dc(token).unwrap().expect("memory DC lease");
    let dc = lease.native();
    let _font = OwnedSelectedFont::arial(dc);
    let mut selected = TEXTMETRICW::default();
    // SAFETY: Leased DC and correctly sized writable native metrics.
    assert_ne!(unsafe { GetTextMetricsW(dc, &mut selected) }, 0);
    // A missing/substituted raster font is a failure, never a silent skip.
    assert_ne!(selected.tmPitchAndFamily & TMPF_TRUETYPE, 0,
        "Arial or its installed substitute must be TrueType");
    assert_eq!(unsafe { GetMapMode(dc) }, MM_TEXT);

    // Independent native oracle: no production parser or fixed-field encoder.
    let required = unsafe { GetOutlineTextMetricsW(dc, 0, ptr::null_mut()) } as usize;
    assert!(required >= size_of::<OUTLINETEXTMETRICW>(), "native outline query must succeed");
    let mut storage = vec![0usize; required.div_ceil(size_of::<usize>())];
    let pointer = storage.as_mut_ptr().cast::<OUTLINETEXTMETRICW>();
    // SAFETY: usize storage supplies native alignment and enough writable bytes.
    let copied = unsafe { GetOutlineTextMetricsW(dc, required.try_into().unwrap(), pointer) } as usize;
    assert!((size_of::<OUTLINETEXTMETRICW>()..=required).contains(&copied));
    let native = unsafe { &*pointer };
    assert_eq!(native.otmSize as usize, copied,
        "native otmSize must describe the returned allocation, including names");
    let actual = owned_dc.dcs.get_outline_text_metrics(token).unwrap()
        .expect("MM_TEXT TrueType host helper must return outline metrics");
    let fixed = &actual.fixed;
    assert_eq!(fixed.len(), 106);
    assert_eq!(&fixed[..2], &[0, 0], "guest size is populated by the runtime packer");
    // Read fields individually at the original packed Win16 offsets. Do not
    // construct expected bytes with encode_outline_fixed or an equivalent codec.
    macro_rules! signed {
        ($offset:expr, $expected:expr) => {
            assert_eq!(i32::from(i16::from_le_bytes([fixed[$offset], fixed[$offset + 1]])),
                $expected, "signed field at {}", $offset);
        };
    }
    macro_rules! unsigned {
        ($offset:expr, $expected:expr) => {
            assert_eq!(u32::from(u16::from_le_bytes([fixed[$offset], fixed[$offset + 1]])),
                $expected, "unsigned field at {}", $offset);
        };
    }
    let text = &native.otmTextMetrics;
    signed!(2, text.tmHeight);
    signed!(4, text.tmAscent);
    signed!(6, text.tmDescent);
    signed!(8, text.tmInternalLeading);
    signed!(10, text.tmExternalLeading);
    signed!(12, text.tmAveCharWidth);
    signed!(14, text.tmMaxCharWidth);
    signed!(16, text.tmWeight);
    assert_eq!(&fixed[18..21], &[text.tmItalic, text.tmUnderlined, text.tmStruckOut]);
    assert_eq!(text.tmCharSet, ANSI_CHARSET);
    assert_eq!(fixed[21], text.tmDefaultChar.wrapping_sub(1) as u8);
    assert_eq!(fixed[22], text.tmLastChar.min(255) as u8);
    // Standard ANSI TrueType marker characters are ASCII in CP1252. Verify the
    // premise rather than reusing the adapter's character conversion helper.
    assert!(text.tmDefaultChar <= 127 && text.tmBreakChar <= 127);
    assert_eq!(fixed[23], text.tmDefaultChar as u8);
    assert_eq!(fixed[24], text.tmBreakChar as u8);
    assert_eq!(fixed[25], text.tmPitchAndFamily);
    assert_eq!(fixed[26], text.tmCharSet);
    signed!(27, text.tmOverhang);
    signed!(29, text.tmDigitizedAspectX);
    signed!(31, text.tmDigitizedAspectY);
    assert_eq!(fixed[33], native.otmFiller);
    let panose = &native.otmPanoseNumber;
    assert_eq!(&fixed[34..44], &[
        panose.bFamilyType, panose.bSerifStyle, panose.bWeight, panose.bProportion,
        panose.bContrast, panose.bStrokeVariation, panose.bArmStyle,
        panose.bLetterform, panose.bMidline, panose.bXHeight,
    ]);
    unsigned!(44, native.otmfsSelection);
    unsigned!(46, native.otmfsType);
    signed!(48, native.otmsCharSlopeRise);
    signed!(50, native.otmsCharSlopeRun);
    signed!(52, native.otmItalicAngle);
    unsigned!(54, native.otmEMSquare);
    signed!(56, native.otmAscent);
    signed!(58, native.otmDescent);
    unsigned!(60, native.otmLineGap);
    unsigned!(62, native.otmsCapEmHeight);
    unsigned!(64, native.otmsXHeight);
    signed!(66, native.otmrcFontBox.left);
    signed!(68, native.otmrcFontBox.top);
    signed!(70, native.otmrcFontBox.right);
    signed!(72, native.otmrcFontBox.bottom);
    signed!(74, native.otmMacAscent);
    signed!(76, native.otmMacDescent);
    unsigned!(78, native.otmMacLineGap);
    unsigned!(80, native.otmusMinimumPPEM);
    signed!(82, native.otmptSubscriptSize.x);
    signed!(84, native.otmptSubscriptSize.y);
    signed!(86, native.otmptSubscriptOffset.x);
    signed!(88, native.otmptSubscriptOffset.y);
    signed!(90, native.otmptSuperscriptSize.x);
    signed!(92, native.otmptSuperscriptSize.y);
    signed!(94, native.otmptSuperscriptOffset.x);
    signed!(96, native.otmptSuperscriptOffset.y);
    unsigned!(98, native.otmsStrikeoutSize);
    signed!(100, native.otmsStrikeoutPosition);
    // Win16 differs from the native struct: position at 102, then size at 104.
    signed!(102, native.otmsUnderscorePosition);
    assert_eq!(i32::from(i16::from_le_bytes([fixed[104], fixed[105]])),
        i32::try_from(native.otmsUnderscoreSize).unwrap());
    assert_ne!(native.otmsUnderscorePosition, i32::try_from(native.otmsUnderscoreSize).unwrap(),
        "the selected font must distinguish the two underscore fields");

    // Native name members contain relative byte offsets, not live pointers.
    // Inspect UTF-16 units directly, independently of copy_outline_name.
    let units = unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u16>(), copied / 2) };
    for (index, offset) in [native.otmpFamilyName, native.otmpFaceName,
        native.otmpStyleName, native.otmpFullName].into_iter().enumerate() {
        let offset = offset as usize;
        assert!(offset >= size_of::<OUTLINETEXTMETRICW>() && offset < copied && offset % 2 == 0);
        let tail = &units[offset / 2..];
        let end = tail.iter().position(|unit| *unit == 0).expect("native name terminator");
        assert_eq!(actual.names[index], tail[..end], "native name {index}");
        assert!(!actual.names[index].contains(&0));
    }
    assert!(!actual.names[0].is_empty() && !actual.names[1].is_empty());

    // A second helper call must enforce the bounded MM_TEXT-only policy.
    let mapping = MappingMode { dc, previous: unsafe { SetMapMode(dc, MM_ANISOTROPIC) } };
    assert_eq!(mapping.previous, MM_TEXT);
    assert!(owned_dc.dcs.get_outline_text_metrics(token).unwrap().is_none());
    drop(mapping);
    assert_eq!(unsafe { GetMapMode(dc) }, MM_TEXT);
    assert_eq!(owned_dc.dcs.get_outline_text_metrics(token).unwrap().unwrap(), actual);
    // Reverse drop order restores the font, deletes it, releases the lease,
    // and finally deletes the memory DC, including on assertion failure.
}
