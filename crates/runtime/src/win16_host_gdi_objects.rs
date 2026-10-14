//! Owned data for native GDI resource factories.
//!
//! Handles are opaque host identities. Guest pointers and native pointers do
//! not appear in this protocol; buffers remain owned throughout each call.

use crate::{Win16DrawingPoint, Win16DrawingRect, Win16HostDc, Win16HostGdiObject};

/// Owned DIB header/table and pixels after the guest ABI has checked their
/// complete extents. The host reconstructs aligned native storage as needed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostDib {
    pub info: Vec<u8>,
    pub bits: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostLogPen {
    pub style: u16,
    pub width_x: i16,
    pub width_y: i16,
    pub color: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostLogBrush {
    pub style: u16,
    pub color: u32,
    pub hatch: u32,
}

/// Copied native EnumObjects data. Pattern bitmaps retain opaque GDI identity;
/// a native LOGBRUSH handle or address is never narrowed into guest storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostGdiObjectRecord {
    Pen(Win16HostLogPen),
    Brush { brush: Win16HostLogBrush, pattern: Option<Win16HostGdiObject> },
}

/// Fixed-size ANSI font description shared by factories and USER settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostLogFont {
    pub height: i16,
    pub width: i16,
    pub escapement: i16,
    pub orientation: i16,
    pub weight: i16,
    pub italic: u8,
    pub underline: u8,
    pub strikeout: u8,
    pub char_set: u8,
    pub out_precision: u8,
    pub clip_precision: u8,
    pub quality: u8,
    pub pitch_and_family: u8,
    pub face_name: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostBitmapInfo {
    pub kind: i16,
    pub width: i16,
    pub height: i16,
    pub width_bytes: i16,
    pub planes: u8,
    pub bits_per_pixel: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16GdiObjectOperation {
    CreatePen { style: i16, width: i16, color: u32 },
    CreatePenIndirect { logpen: Win16HostLogPen },
    CreateFont {
        height: i16, width: i16, escapement: i16, orientation: i16, weight: i16,
        italic: u16, underline: u16, strikeout: u16, char_set: u16,
        out_precision: u16, clip_precision: u16, quality: u16, pitch_and_family: u16,
        face_name: Option<Vec<u8>>,
    },
    CreateFontIndirect { logfont: Win16HostLogFont },
    CreateBitmap {
        width: i16, height: i16, planes: u16, bits_per_pixel: u16,
        bits: Option<Vec<u8>>,
    },
    LoadSystemBitmap { resource_id: u16 },
    CreateBitmapIndirect { bitmap: Win16HostBitmapInfo, bits: Option<Vec<u8>> },
    CreateBrushIndirect {
        logbrush: Win16HostLogBrush,
        pattern_bitmap: Option<Win16HostGdiObject>,
        dib_pattern: Option<Win16HostDib>,
    },
    CreateCompatibleBitmap { dc: Win16HostDc, width: i16, height: i16 },
    CreateDibitmap {
        dc: Win16HostDc,
        header: Option<Vec<u8>>,
        init_flags: u32,
        bits: Option<Vec<u8>>,
        info: Option<Vec<u8>>,
        color_usage: u32,
    },
    CreateEllipticRgn { rect: Win16DrawingRect },
    CreateEllipticRgnIndirect { rect: Option<Win16DrawingRect> },
    CreatePolygonRgn { points: Vec<Win16DrawingPoint>, count: i16, fill_mode: i16 },
    CreateRectRgn { rect: Win16DrawingRect },
    CreateRectRgnIndirect { rect: Option<Win16DrawingRect> },
    CreateRoundRectRgn {
        rect: Win16DrawingRect, ellipse_width: i16, ellipse_height: i16,
    },
    CreatePolyPolygonRgn {
        points: Vec<Win16DrawingPoint>, polygon_counts: Vec<i16>,
        polygon_count: i16, fill_mode: i16, valid: bool,
    },
}
