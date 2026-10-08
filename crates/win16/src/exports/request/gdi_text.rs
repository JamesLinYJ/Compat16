//! Owned request values for this Win16 API family.

use super::super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16GdiTextRequest {
    CreateFont {
        height: i16,
        width: i16,
        escapement: i16,
        orientation: i16,
        weight: i16,
        italic: u16,
        underline: u16,
        strikeout: u16,
        char_set: u16,
        out_precision: u16,
        clip_precision: u16,
        quality: u16,
        pitch_and_family: u16,
        face_name: Option<Vec<u8>>,
    },

    CreateFontIndirect {
        logfont: crate::gdi_abi::LogFont16,
    },

    SetTextCharacterExtra {
        dc: u16,
        extra: i16,
    },

    GetTextCharacterExtra {
        dc: u16,
    },

    SetTextJustification {
        dc: u16,
        extra: i16,
        breaks: i16,
    },

    GetBkColor {
        dc: u16,
    },
    GetNearestColor { dc: u16, color: u32 },

    GetBkMode {
        dc: u16,
    },

    GetTextColor {
        dc: u16,
    },

    GetTextAlign {
        dc: u16,
    },

    SetTextAlign {
        dc: u16,
        alignment: u16,
    },

    ExtTextOut {
        dc: u16,
        x: i16,
        y: i16,
        options: u16,
        rect: Option<Rect16>,
        text: Vec<u8>,
        count: u16,
        spacing: Option<Vec<i16>>,
    },

    GetTextExtentPoint {
        dc: u16,
        text: Vec<u8>,
        count: i16,
        output: u32,
    },

    /// Enumerate fonts through an optional copied face-name string and a guest
    /// FARPROC. A null face name requests all faces. The callback remains a
    /// typed guest selector:offset value; it is never converted to a host
    /// function pointer. LPARAM is preserved as signed 32-bit guest data.
    EnumFonts {
        dc: u16,
        face_name: Option<Vec<u8>>,
        callback: u32,
        parameter: i32,
    },

    /// Set the guest DC background color; returns the previous COLORREF in DX:AX.
    SetBkColor {
        dc: u16,
        color: u32,
    },

    /// Set the guest DC background mode; the previous signed INT16 is returned in AX.
    SetBkMode {
        dc: u16,
        mode: i16,
    },

    /// Set the guest DC text color; returns the previous COLORREF in DX:AX.
    SetTextColor {
        dc: u16,
        color: u32,
    },

    /// Draw exactly `count` copied guest bytes; a negative count is preserved
    /// for runtime failure handling and causes no decoder memory access.
    TextOut {
        dc: u16,
        x: i16,
        y: i16,
        text: Vec<u8>,
        count: i16,
    },

    /// Measure exactly `count` copied bytes and return the packed SIZE in DX:AX.
    GetTextExtent {
        dc: u16,
        text: Vec<u8>,
        count: i16,
    },

    /// Copy TEXTMETRIC16 into the raw guest output address after complete
    /// 31-byte write preflight in the runtime.
    GetTextMetrics {
        dc: u16,
        output: u32,
    },

    /// Return a face-name character count and write bounded ANSI output. The
    /// signed count and raw guest address let the runtime avoid touching a
    /// buffer for negative counts.
    GetTextFace {
        dc: u16,
        count: i16,
        output: u32,
    },
}
