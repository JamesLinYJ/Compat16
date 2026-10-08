//! Win16 font records adapted through each DC's fixed guest codec.
//!
//! The Windows 3.1 SDK declares LOGFONT face names as 32 ANSI bytes and the
//! TEXTMETRIC character fields as byte metadata. Native calls use W APIs;
//! fixed-width names and individual character markers use the guest codec.

use std::ptr;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostDc, Win16HostFontRecord, Win16HostTextFace,
    Win16HostTextMetrics,
};
use windows_sys::Win32::Graphics::Gdi::{
    EnumFontsW, GetTextFaceW, GetTextMetricsW, LOGFONTW, NEWTEXTMETRICW,
    SYMBOL_CHARSET, TEXTMETRICW, TMPF_TRUETYPE, TRUETYPE_FONTTYPE,
};
use windows_sys::Win32::Globalization::{GetCPInfoExW, CPINFOEXW};

use super::super::guest_text::GuestTextCodec;
use super::Win16Dcs;

pub(in crate::windows) fn create_face_name_wide(
    codec: GuestTextCodec,
    source: &[u8],
) -> Result<Option<Vec<u16>>, RuntimeError> {
    if source.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 font face name contains an embedded NUL",
        ));
    }
    let wide = codec.to_wide_z(source)?;
    // CreateFontW documents a maximum face-name length of 32 UTF-16
    // characters including its terminator.
    if wide.len() > 32 {
        return Ok(None);
    }
    Ok(Some(wide))
}

pub(in crate::windows) fn create_logfont_face_wide(
    codec: GuestTextCodec,
    source: &[u8; 32],
) -> Result<Option<[u16; 32]>, RuntimeError> {
    let Some(end) = source.iter().position(|byte| *byte == 0) else {
        // LOGFONT's fixed face field is documented as NUL terminated. Do not
        // silently truncate an unterminated guest field to make a W string.
        return Ok(None);
    };
    let wide = codec.to_wide(&source[..end])?;
    if wide.len() >= 32 {
        return Ok(None);
    }
    let mut face_name = [0_u16; 32];
    face_name[..wide.len()].copy_from_slice(&wide);
    Ok(Some(face_name))
}

pub(in crate::windows) fn guest_face_name(
    codec: GuestTextCodec,
    source: &[u16; 32],
) -> Result<[u8; 32], RuntimeError> {
    // The Win16 LOGFONT contract reserves a NUL within its fixed 32-byte
    // face-name field. Clip only at complete encoded character boundaries.
    let end = source
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(source.len());
    let converted = codec.from_wide_bounded(&source[..end], 31)?;
    let mut face_name = [0_u8; 32];
    face_name[..converted.bytes.len()].copy_from_slice(&converted.bytes);
    Ok(face_name)
}

fn range_markers_w_to_guest(metric: &TEXTMETRICW) -> (u8, u8) {
    // TEXTMETRIC16's range fields are BYTE metadata, not independent text:
    // the Windows 3.1 SDK declares them as BYTE at
    // `work/reference/windows-sdk/3.1/files/include/WINDOWS.H:1870-1875`, while the
    // Win32 TEXTMETRICW contract describes WCHAR character values. Keep the
    // established charset/technology projection so sentinel ranges such as
    // U+FFFF remain ordinary one-byte metadata rather than conversion errors.
    let (first, last) = if metric.tmCharSet == SYMBOL_CHARSET {
        (0x1e, 0xff)
    } else if metric.tmPitchAndFamily & TMPF_TRUETYPE != 0 {
        (
            metric.tmDefaultChar.wrapping_sub(1) as u8,
            metric.tmLastChar.min(0xff) as u8,
        )
    } else {
        (
            metric.tmFirstChar.min(0xff) as u8,
            metric.tmLastChar.min(0xff) as u8,
        )
    };
    (first, last)
}

fn default_guest_marker(codec: GuestTextCodec) -> Option<u8> {
    let mut info = CPINFOEXW::default();
    // SAFETY: `info` is a live, initialized CPINFOEXW and the codec retains
    // the exact numeric guest code page selected for this executable.
    if unsafe { GetCPInfoExW(codec.code_page(), 0, &mut info) } == 0 {
        return None;
    }
    // Win16 exposes one byte even when a page's native default replacement is
    // a DBCS pair. Preserve the first documented replacement byte as an
    // explicit lossy metadata projection; the second byte has no guest field.
    Some(info.DefaultChar[0])
}

fn metric_character_marker_w_to_guest(
    codec: GuestTextCodec,
    value: u16,
) -> Result<Option<u8>, RuntimeError> {
    match codec.from_wide_bounded(&[value], 1) {
        Ok(encoded) if encoded.bytes.len() == 1 => Ok(Some(encoded.bytes[0])),
        Ok(_) => Ok(default_guest_marker(codec)),
        Err(error) if error.kind() == Kind::ResourceExhausted => Err(error),
        // A failed one-character conversion is an ordinary marker mapping
        // failure. Use the selected page's documented default character when
        // its metadata is available; otherwise the caller reports no metrics.
        Err(_) => Ok(default_guest_marker(codec)),
    }
}

fn metric_markers_w_to_guest(
    codec: GuestTextCodec,
    metric: &TEXTMETRICW,
) -> Result<Option<[u8; 4]>, RuntimeError> {
    let (first, last) = range_markers_w_to_guest(metric);
    let Some(default) = metric_character_marker_w_to_guest(codec, metric.tmDefaultChar)? else {
        return Ok(None);
    };
    let Some(break_char) = metric_character_marker_w_to_guest(codec, metric.tmBreakChar)? else {
        return Ok(None);
    };
    Ok(Some([first, last, default, break_char]))
}

struct FontEnumeration {
    codec: GuestTextCodec,
    records: Vec<Win16HostFontRecord>,
    failure: Option<RuntimeError>,
}

unsafe extern "system" fn collect_font(
    logfont: *const LOGFONTW,
    metric: *const TEXTMETRICW,
    font_type: u32,
    context: isize,
) -> i32 {
    // SAFETY: EnumFontsW invokes this callback synchronously. The stack-owned
    // state and native records remain valid until the callback returns; no
    // guest execution or borrowed native record escapes this call.
    let state = unsafe { &mut *(context as *mut FontEnumeration) };
    if logfont.is_null() || metric.is_null() {
        state.failure = Some(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 EnumFontsW received a null native font record",
        ));
        return 0;
    }
    let font = unsafe { &*logfont };
    let text = unsafe { &*metric };
    let newtextmetric_extra = if font_type & TRUETYPE_FONTTYPE != 0 {
        // EnumFontsW supplies NEWTEXTMETRICW for TrueType records.
        let extended = unsafe { &*(metric.cast::<NEWTEXTMETRICW>()) };
        Some([
            extended.ntmFlags,
            extended.ntmSizeEM,
            extended.ntmCellHeight,
            extended.ntmAvgWidth,
        ])
    } else {
        None
    };
    let guest_characters = match metric_markers_w_to_guest(state.codec, text) {
        Ok(Some(markers)) => markers,
        Ok(None) => return 0,
        Err(error) => {
            state.failure = Some(error);
            return 0;
        }
    };
    let face_name = match guest_face_name(state.codec, &font.lfFaceName) {
        Ok(face_name) => face_name,
        Err(error) => {
            state.failure = Some(error);
            return 0;
        }
    };
    if let Err(error) = state.records.try_reserve(1) {
        state.failure = Some(RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve Win16 host font enumeration record",
            error,
        ));
        return 0;
    }
    state.records.push(Win16HostFontRecord {
        logfont_dimensions: [
            font.lfHeight,
            font.lfWidth,
            font.lfEscapement,
            font.lfOrientation,
            font.lfWeight,
        ],
        logfont_styles: [
            font.lfItalic,
            font.lfUnderline,
            font.lfStrikeOut,
            font.lfCharSet,
            font.lfOutPrecision,
            font.lfClipPrecision,
            font.lfQuality,
            font.lfPitchAndFamily,
        ],
        face_name,
        textmetric_dimensions: [
            text.tmHeight,
            text.tmAscent,
            text.tmDescent,
            text.tmInternalLeading,
            text.tmExternalLeading,
            text.tmAveCharWidth,
            text.tmMaxCharWidth,
            text.tmWeight,
        ],
        textmetric_styles: [
            text.tmItalic,
            text.tmUnderlined,
            text.tmStruckOut,
            guest_characters[0],
            guest_characters[1],
            guest_characters[2],
            guest_characters[3],
            text.tmPitchAndFamily,
            text.tmCharSet,
        ],
        textmetric_extra: [
            text.tmOverhang,
            text.tmDigitizedAspectX,
            text.tmDigitizedAspectY,
        ],
        newtextmetric_extra,
        font_type: font_type as u16,
    });
    1
}

impl Win16Dcs {
    pub(in crate::windows) fn get_text_metrics(
        &self,
        token: Win16HostDc,
    ) -> Result<Option<Win16HostTextMetrics>, RuntimeError> {
        let Some(dc_use) = self.lease_dc(token)? else {
            return Ok(None);
        };
        let mut metric = TEXTMETRICW::default();
        // GetTextMetricsW is the native metrics entry point. The four guest
        // BYTE marker fields are projected from its WCHAR values below.
        // SAFETY: The HDC lease remains live and `metric` is writable for the
        // duration of this synchronous GDI query.
        if unsafe { GetTextMetricsW(dc_use.native(), &mut metric) } == 0 {
            return Ok(None);
        }
        let Some(guest_characters) = metric_markers_w_to_guest(self.text_codec(), &metric)? else {
            return Ok(None);
        };
        Ok(Some(Win16HostTextMetrics {
            dimensions: [
                metric.tmHeight,
                metric.tmAscent,
                metric.tmDescent,
                metric.tmInternalLeading,
                metric.tmExternalLeading,
                metric.tmAveCharWidth,
                metric.tmMaxCharWidth,
                metric.tmWeight,
            ],
            styles: [
                metric.tmItalic,
                metric.tmUnderlined,
                metric.tmStruckOut,
                guest_characters[0],
                guest_characters[1],
                guest_characters[2],
                guest_characters[3],
                metric.tmPitchAndFamily,
                metric.tmCharSet,
            ],
            extra: [
                metric.tmOverhang,
                metric.tmDigitizedAspectX,
                metric.tmDigitizedAspectY,
            ],
        }))
    }

    pub(in crate::windows) fn get_text_face(
        &self,
        token: Win16HostDc,
        count: i16,
        output: Option<Vec<u8>>,
    ) -> Result<Option<Win16HostTextFace>, RuntimeError> {
        let Some(dc_use) = self.lease_dc(token)? else {
            return Ok(None);
        };
        let has_output = output.is_some();
        if count < 0 && has_output {
            return Ok(Some(Win16HostTextFace {
                result: 0,
                bytes: Vec::new(),
            }));
        }
        let mut bytes = output.unwrap_or_default();
        if count > 0 && has_output && bytes.len() != count as usize {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 GetTextFace buffer does not match byte-sized nCount",
            ));
        }
        if count == 0 && has_output {
            // A zero-byte guest capacity cannot carry a UTF-16 unit or a guest
            // terminator. The normal GetTextFace failure result is zero.
            return Ok(Some(Win16HostTextFace {
                result: 0,
                bytes: Vec::new(),
            }));
        }

        let Some(face) = read_text_face(dc_use.native())? else {
            return Ok(Some(Win16HostTextFace { result: 0, bytes }));
        };
        let codec = self.text_codec();
        if count > 0 && has_output {
            let capacity = count as usize;
            let converted = codec.from_wide_bounded(&face, capacity - 1)?;
            let copied = converted.bytes.len();
            bytes[..copied].copy_from_slice(&converted.bytes);
            bytes[copied] = 0;
            let result = i32::try_from(copied + 1).map_err(|_| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 GetTextFace byte count exceeds the host result range",
                )
            })?;
            return Ok(Some(Win16HostTextFace { result, bytes }));
        }

        // NULL output is the documented size query. ANSI/Win16 reports bytes,
        // including the terminator; a W API's UTF-16 unit count is not the
        // guest-visible return value.
        let converted = codec.from_wide(&face)?;
        let result = i32::try_from(converted.bytes.len() + 1).map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 GetTextFace byte count exceeds the host result range",
            )
        })?;
        Ok(Some(Win16HostTextFace {
            result,
            bytes: Vec::new(),
        }))
    }

    pub(in crate::windows) fn enum_fonts(
        &self,
        token: Win16HostDc,
        face: Option<&[u8]>,
    ) -> Result<Vec<Win16HostFontRecord>, RuntimeError> {
        let Some(dc_use) = self.lease_dc(token)? else {
            // The runtime maps no native records to EnumFonts' zero result.
            return Ok(Vec::new());
        };
        let face = match face {
            Some(bytes) => match create_face_name_wide(self.text_codec(), bytes)? {
                Some(face) => Some(face),
                None => return Ok(Vec::new()),
            },
            None => None,
        };
        let mut enumeration = FontEnumeration {
            codec: self.text_codec(),
            records: Vec::new(),
            failure: None,
        };
        // SAFETY: The HDC is pinned, the optional UTF-16 C string is retained,
        // and EnumFontsW completes all callbacks before returning.
        unsafe {
            EnumFontsW(
                dc_use.native(),
                face.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
                Some(collect_font),
                (&mut enumeration as *mut FontEnumeration) as isize,
            );
        }
        if let Some(error) = enumeration.failure {
            return Err(error);
        }
        Ok(enumeration.records)
    }
}

fn read_text_face(
    hdc: windows_sys::Win32::Graphics::Gdi::HDC,
) -> Result<Option<Vec<u16>>, RuntimeError> {
    // GetTextFaceW defines a NULL output pointer as a query for the UTF-16
    // count including the terminator. Fetch into owned storage in a second
    // call so guest byte-capacity clipping happens after code-page encoding.
    let required = unsafe { GetTextFaceW(hdc, 0, ptr::null_mut()) };
    if required <= 0 {
        return Ok(None);
    }
    let capacity = required as usize;
    let mut wide = Vec::new();
    wide.try_reserve_exact(capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve Win16 UTF-16 face name",
            error,
        )
    })?;
    wide.resize(capacity, 0);
    let copied = unsafe { GetTextFaceW(hdc, required, wide.as_mut_ptr()) };
    if copied <= 0 || copied as usize > wide.len() {
        return Ok(None);
    }
    wide.truncate(copied as usize);
    let Some(end) = wide.iter().position(|unit| *unit == 0) else {
        return Ok(None);
    };
    wide.truncate(end);
    Ok(Some(wide))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp936() -> GuestTextCodec {
        GuestTextCodec::new(936).expect("Windows should provide code page 936")
    }

    #[test]
    fn textmetric_ranges_keep_symbol_and_true_type_byte_metadata() {
        let mut metric = TEXTMETRICW::default();
        metric.tmCharSet = SYMBOL_CHARSET;
        assert_eq!(range_markers_w_to_guest(&metric), (0x1e, 0xff));

        metric.tmCharSet = 0;
        metric.tmPitchAndFamily = TMPF_TRUETYPE;
        metric.tmDefaultChar = 0x4e2d;
        metric.tmLastChar = 0xffff;
        // These fields describe the Win16 BYTE range, not a string to encode;
        // the wide sentinel must not turn a normal font result into an error.
        assert_eq!(range_markers_w_to_guest(&metric), (0x2c, 0xff));
    }

    #[test]
    fn textmetric_default_and_break_markers_use_guest_page_projection() {
        let codec = cp936();
        let mut metric = TEXTMETRICW::default();
        metric.tmFirstChar = 0x20;
        metric.tmLastChar = 0xffff;
        metric.tmDefaultChar = b'A' as u16;
        metric.tmBreakChar = b' ' as u16;
        assert_eq!(
            metric_markers_w_to_guest(codec, &metric).unwrap(),
            Some([0x20, 0xff, b'A', b' ']),
        );

        // CP936's two-byte character and U+FFFF cannot occupy a single
        // TEXTMETRIC16 marker byte. Project both through the code page's
        // documented default-byte metadata instead of propagating an error.
        let default_byte = default_guest_marker(codec).unwrap();
        metric.tmDefaultChar = 0x4e2d;
        metric.tmBreakChar = 0xffff;
        assert_eq!(
            metric_markers_w_to_guest(codec, &metric).unwrap(),
            Some([0x20, 0xff, default_byte, default_byte]),
        );
    }
}
