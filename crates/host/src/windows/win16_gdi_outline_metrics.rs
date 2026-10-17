//! Bounded fixed-mapping-mode projection of native outline metrics.
//!
//! MM_TEXT through MM_TWIPS use the logical units native GDI already returns.
//! MM_ISOTROPIC and MM_ANISOTROPIC stay rejected. Unrepresentable fields fail
//! closed. Guest output is not prefilled with a debug poison pattern.
//!
//! Native offset and layout contract:
//! https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-outlinetextmetricw
//! Query/retrieve contract:
//! https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-getoutlinetextmetricsw
//! Checked narrowing below is a modern safety policy, not original Win16
//! scaling behavior. The original SDK field layout is summarized in README.

use std::mem::size_of;
use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostDc, Win16HostOutlineTextMetrics};
use windows_sys::Win32::Graphics::Gdi::{
    GetMapMode, GetOutlineTextMetricsW, MM_ANISOTROPIC, MM_HIENGLISH, MM_HIMETRIC, MM_ISOTROPIC,
    MM_LOENGLISH, MM_LOMETRIC, MM_TEXT, MM_TWIPS, OUTLINETEXTMETRICW,
};
use super::Win16Dcs;

// The runtime predicate uses the public numeric constants. Keep those names
// attached to the same values the host reads from the DC.
const _: () = assert!(
    MM_TEXT == 1
        && MM_LOMETRIC == 2
        && MM_HIMETRIC == 3
        && MM_LOENGLISH == 4
        && MM_HIENGLISH == 5
        && MM_TWIPS == 6
        && MM_ISOTROPIC == 7
        && MM_ANISOTROPIC == 8
);

// A Win16 result must fit a WORD (including its rounded stored size). Native
// UTF-16 names require at most twice that space plus the native fixed header.
const MAX_NATIVE_OUTLINE_BYTES: usize = 2 * u16::MAX as usize + size_of::<OUTLINETEXTMETRICW>();

impl Win16Dcs {
    pub(in crate::windows) fn get_outline_text_metrics(
        &self,
        token: Win16HostDc,
    ) -> Result<Option<Win16HostOutlineTextMetrics>, RuntimeError> {
        let Some(dc_use) = self.lease_dc(token)? else { return Ok(None); };
        // SAFETY: One DC lease covers mapping validation, query, retrieval and
        // copying. No native pointer or borrowed native storage escapes it.
        // Fixed modes are already in logical units. Extent modes stay unsupported.
        let mode = unsafe { GetMapMode(dc_use.native()) };
        if !runtime::win16_outline_text_map_mode_supported(mode) { return Ok(None); }
        // SAFETY: The live DC is queried without an output buffer.
        let required = unsafe { GetOutlineTextMetricsW(dc_use.native(), 0, std::ptr::null_mut()) } as usize;
        if !(size_of::<OUTLINETEXTMETRICW>()..=MAX_NATIVE_OUTLINE_BYTES).contains(&required) {
            return Ok(None);
        }
        // usize storage supplies native struct alignment on both host targets.
        let words = required.div_ceil(size_of::<usize>());
        let mut storage = Vec::<usize>::new();
        storage.try_reserve_exact(words).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve native outline text metrics", error))?;
        storage.resize(words, 0);
        let pointer = storage.as_mut_ptr().cast::<OUTLINETEXTMETRICW>();
        // SAFETY: The allocation is aligned, initialized, and at least required
        // bytes long. The lease prevents HDC deletion between both calls.
        let copied = unsafe { GetOutlineTextMetricsW(dc_use.native(), required as u32, pointer) } as usize;
        if copied < size_of::<OUTLINETEXTMETRICW>() || copied > required { return Ok(None); }
        // SAFETY: copied covers the native fixed header and pointer is aligned.
        let metric = unsafe { &*pointer };
        if metric.otmSize as usize != copied { return Ok(None); }
        // SAFETY: Read only initialized allocation bytes within the API result.
        let bytes = unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), copied) };
        let mut names: [Vec<u16>; 4] = std::array::from_fn(|_| Vec::new());
        for (name, offset) in names.iter_mut().zip([
            metric.otmpFamilyName as usize, metric.otmpFaceName as usize,
            metric.otmpStyleName as usize, metric.otmpFullName as usize,
        ]) {
            let Some(copied_name) = copy_outline_name(bytes, offset)? else { return Ok(None); };
            *name = copied_name;
        }
        let Some(markers) = super::fonts::metric_markers_w_to_guest(
            self.text_codec(), &metric.otmTextMetrics,
        )? else { return Ok(None); };
        let Some(fixed) = encode_outline_fixed(metric, markers) else { return Ok(None); };
        Ok(Some(Win16HostOutlineTextMetrics { fixed, names }))
    }
}

fn copy_outline_name(bytes: &[u8], offset: usize) -> Result<Option<Vec<u16>>, RuntimeError> {
    // Native otmp* members are byte offsets, NOT dereferenceable pointers.
    if offset < size_of::<OUTLINETEXTMETRICW>() || offset % 2 != 0 || offset >= bytes.len() {
        return Ok(None);
    }
    let tail = &bytes[offset..];
    let Some(length) = tail.chunks_exact(2).position(|word| word == [0, 0]) else {
        return Ok(None);
    };
    if length > u16::MAX as usize - 114 { return Ok(None); }
    let mut name = Vec::new();
    name.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "copy native outline name", error))?;
    name.extend(tail.chunks_exact(2).take(length).map(|word| u16::from_le_bytes([word[0], word[1]])));
    Ok(Some(name))
}

fn encode_outline_fixed(metric: &OUTLINETEXTMETRICW, markers: [u8; 4]) -> Option<[u8; 106]> {
    let mut bytes = [0_u8; 106];
    let text = &metric.otmTextMetrics;
    for (offset, value) in [
        (2, text.tmHeight), (4, text.tmAscent), (6, text.tmDescent),
        (8, text.tmInternalLeading), (10, text.tmExternalLeading),
        (12, text.tmAveCharWidth), (14, text.tmMaxCharWidth), (16, text.tmWeight),
        (27, text.tmOverhang), (29, text.tmDigitizedAspectX), (31, text.tmDigitizedAspectY),
        (48, metric.otmsCharSlopeRise), (50, metric.otmsCharSlopeRun),
        (52, metric.otmItalicAngle), (56, metric.otmAscent), (58, metric.otmDescent),
        (66, metric.otmrcFontBox.left), (68, metric.otmrcFontBox.top),
        (70, metric.otmrcFontBox.right), (72, metric.otmrcFontBox.bottom),
        (74, metric.otmMacAscent), (76, metric.otmMacDescent),
        (82, metric.otmptSubscriptSize.x), (84, metric.otmptSubscriptSize.y),
        (86, metric.otmptSubscriptOffset.x), (88, metric.otmptSubscriptOffset.y),
        (90, metric.otmptSuperscriptSize.x), (92, metric.otmptSuperscriptSize.y),
        (94, metric.otmptSuperscriptOffset.x), (96, metric.otmptSuperscriptOffset.y),
        (100, metric.otmsStrikeoutPosition), (102, metric.otmsUnderscorePosition),
    ] {
        bytes[offset..offset + 2].copy_from_slice(&i16::try_from(value).ok()?.to_le_bytes());
    }
    for (offset, value) in [
        (44, metric.otmfsSelection), (46, metric.otmfsType), (54, metric.otmEMSquare),
        (60, metric.otmLineGap), (62, metric.otmsCapEmHeight), (64, metric.otmsXHeight),
        (78, metric.otmMacLineGap), (80, metric.otmusMinimumPPEM),
        (98, metric.otmsStrikeoutSize),
    ] {
        bytes[offset..offset + 2].copy_from_slice(&u16::try_from(value).ok()?.to_le_bytes());
    }
    // Win16 places signed underscore POSITION before signed underscore SIZE.
    bytes[104..106].copy_from_slice(&i16::try_from(metric.otmsUnderscoreSize).ok()?.to_le_bytes());
    bytes[18..27].copy_from_slice(&[
        text.tmItalic, text.tmUnderlined, text.tmStruckOut,
        markers[0], markers[1], markers[2], markers[3], text.tmPitchAndFamily, text.tmCharSet,
    ]);
    bytes[33] = metric.otmFiller;
    let panose = &metric.otmPanoseNumber;
    bytes[34..44].copy_from_slice(&[
        panose.bFamilyType, panose.bSerifStyle, panose.bWeight, panose.bProportion,
        panose.bContrast, panose.bStrokeVariation, panose.bArmStyle,
        panose.bLetterform, panose.bMidline, panose.bXHeight,
    ]);
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_outline_text_metrics_packed_fields_and_underscore_order() {
        let mut native = OUTLINETEXTMETRICW::default();
        native.otmTextMetrics.tmHeight = -123;
        native.otmTextMetrics.tmOverhang = -7;
        native.otmTextMetrics.tmDigitizedAspectX = 300;
        native.otmTextMetrics.tmDigitizedAspectY = 301;
        native.otmFiller = 0x39;
        native.otmPanoseNumber.bFamilyType = 2;
        native.otmPanoseNumber.bXHeight = 9;
        native.otmfsSelection = 0x1234;
        native.otmfsType = 0xffff;
        native.otmsCharSlopeRise = -21;
        native.otmEMSquare = 65535;
        native.otmLineGap = 40000;
        native.otmrcFontBox.left = -34;
        native.otmsStrikeoutSize = 40001;
        native.otmsStrikeoutPosition = -16;
        native.otmsUnderscoreSize = 7;
        native.otmsUnderscorePosition = -11;
        let bytes = encode_outline_fixed(&native, [0x41, 0xff, 0x3f, 0x20]).unwrap();
        assert_eq!(&bytes[2..4], &(-123_i16).to_le_bytes());
        assert_eq!(&bytes[21..25], &[0x41, 0xff, 0x3f, 0x20]);
        assert_eq!(&bytes[27..33], &[0xf9, 0xff, 0x2c, 1, 0x2d, 1]);
        assert_eq!(bytes[33], 0x39);
        assert_eq!(bytes[34], 2);
        assert_eq!(bytes[43], 9);
        assert_eq!(&bytes[44..50], &[0x34, 0x12, 0xff, 0xff, 0xeb, 0xff]);
        assert_eq!(&bytes[54..56], &[0xff, 0xff]);
        assert_eq!(&bytes[60..62], &40000_u16.to_le_bytes());
        assert_eq!(&bytes[66..68], &(-34_i16).to_le_bytes());
        assert_eq!(&bytes[98..106], &[0x41, 0x9c, 0xf0, 0xff, 0xf5, 0xff, 7, 0]);
    }

    #[test]
    fn get_outline_text_metrics_checked_signed_and_unsigned_ranges() {
        let mut native = OUTLINETEXTMETRICW::default();
        native.otmTextMetrics.tmHeight = 32768;
        assert!(encode_outline_fixed(&native, [0; 4]).is_none());
        native.otmTextMetrics.tmHeight = -32769;
        assert!(encode_outline_fixed(&native, [0; 4]).is_none());
        native.otmTextMetrics.tmHeight = -32768;
        native.otmLineGap = 65535;
        assert!(encode_outline_fixed(&native, [0; 4]).is_some());
        native.otmLineGap = 65536;
        assert!(encode_outline_fixed(&native, [0; 4]).is_none());
        native.otmLineGap = 0;
        native.otmsUnderscoreSize = 32768;
        assert!(encode_outline_fixed(&native, [0; 4]).is_none());
    }

    #[test]
    fn get_outline_text_metrics_native_names_use_validated_relative_offsets() {
        let offset = size_of::<OUTLINETEXTMETRICW>();
        let mut bytes = vec![0; offset];
        bytes.extend_from_slice(&[0x41, 0, 0, 1, 0x3d, 0xd8, 0, 0]);
        assert_eq!(copy_outline_name(&bytes, offset).unwrap(), Some(vec![0x41, 0x100, 0xd83d]));
        for invalid in [0, offset - 2, offset + 1, bytes.len(), usize::MAX] {
            assert!(copy_outline_name(&bytes, invalid).unwrap().is_none());
        }
        bytes.truncate(bytes.len() - 2);
        assert!(copy_outline_name(&bytes, offset).unwrap().is_none());
        bytes.push(0); // A single terminal byte cannot terminate a UTF-16 name.
        assert!(copy_outline_name(&bytes, offset).unwrap().is_none());
    }
}

#[cfg(test)]
#[path = "win16_gdi_outline_metrics_native_tests.rs"]
mod native_tests;
