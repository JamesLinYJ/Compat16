//! Owned requests for Win16 bitmap, DIB, palette, and printer services.
//!
//! Guest FAR values remain guest addresses here. Runtime must validate them
//! against the selector table before reading or writing memory; host adapters
//! only receive owned byte buffers and opaque GDI identities.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PaletteEntry16 {
    pub red: u8,
    pub green: u8,
    pub blue: u8,
    pub flags: u8,
}

/// Raw Win16 RGBQUAD memory order used by DIB color tables.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DibRgbQuad16 {
    pub blue: u8,
    pub green: u8,
    pub red: u8,
    pub reserved: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaletteTransferKind {
    Get,
    Set,
    Animate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DibColorTableKind {
    Get,
    Set,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrintOperation {
    EndDocument,
    StartPage,
    EndPage,
    AbortDocument,
}

/// Pointer-free copy of the Win16 DOCINFO structure. Each non-null FAR string
/// is copied by the decoder before the request crosses into runtime or host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocInfo16 {
    pub document_name: Option<Vec<u8>>,
    pub output: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GdiDeviceRequest {
    GetObject { object: u16, count: i16, output: u32 },
    GetBitmapBits { bitmap: u16, byte_count: i32, output: u32 },
    SetBitmapBits { bitmap: u16, byte_count: i32, bytes: Vec<u8> },
    SetDibits {
        bitmap: u16, dc: u16, start_scan: u16, scan_lines: u16,
        bits: u32, info: u32, color_usage: u16,
    },
    GetDibits {
        bitmap: u16, dc: u16, start_scan: u16, scan_lines: u16,
        bits: u32, info: u32, color_usage: u16,
    },
    SetDibitsToDevice {
        dc: u16, destination_x: i16, destination_y: i16,
        width: i16, height: i16, source_x: i16, source_y: i16,
        start_scan: u16, scan_lines: u16, bits: u32, info: u32,
        color_usage: u16,
    },
    StretchDibits {
        dc: u16, destination_x: i16, destination_y: i16,
        destination_width: i16, destination_height: i16,
        source_x: i16, source_y: i16, source_width: i16, source_height: i16,
        info: u32, bits: u32, usage: u16, rop: u32,
    },
    CreateDibitmap {
        dc: u16, header: u32, init_flags: u32, bits: u32, info: u32,
        color_usage: u16,
    },
    CreateDiscardableBitmap { dc: u16, width: i16, height: i16 },
    CreatePalette { version: u16, entries: Vec<PaletteEntry16> },
    SelectPalette { dc: u16, palette: u16, force_background: bool },
    RealizePalette { dc: u16 },
    RealizeDefaultPalette { dc: u16 },
    UpdateColors { dc: u16 },
    PaletteEntries {
        kind: PaletteTransferKind, palette: u16, start: u16, count: u16,
        entries: Option<Vec<PaletteEntry16>>, output: u32,
    },
    ResizePalette { palette: u16, count: u16 },
    GetNearestPaletteIndex { palette: u16, color: u32 },
    SetSystemPaletteUse { dc: u16, use_mode: u16 },
    GetSystemPaletteUse { dc: u16 },
    GetSystemPaletteEntries { dc: u16, start: u16, count: u16, output: u32 },
    DibColorTable {
        kind: DibColorTableKind, dc: u16, start: u16, count: u16,
        entries: Option<Vec<DibRgbQuad16>>, output: u32,
    },
    CreateHalftonePalette { dc: u16 },
    GetBitmapDimension { bitmap: u16 },
    SetBitmapDimension { bitmap: u16, width: i16, height: i16 },
    GetBitmapDimensionEx { bitmap: u16, output: u32 },
    SetBitmapDimensionEx { bitmap: u16, width: i16, height: i16, output: u32 },
    ResetDc { dc: u16, devmode: u32 },
    StartDoc { dc: u16, doc_info: Option<DocInfo16> },
    Print { operation: PrintOperation, dc: u16 },
    SetAbortProc { dc: u16, callback: u32 },
    WinGCreateDc,
    WinGRecommendDibFormat { info: u32 },
    WinGCreateBitmap { dc: u16, info: u32, bits_output: u32 },
    WinGGetDibPointer { bitmap: u16, info: u32 },
    WinGCreateHalfTonePalette,
    WinGCreateHalfToneBrush { dc: u16, color: u32, dither_type: u16 },
    WinGBitBlt {
        destination: u16, destination_x: i16, destination_y: i16,
        width: i16, height: i16, source: u16, source_x: i16, source_y: i16,
    },
    WinGStretchBlt {
        destination: u16, destination_x: i16, destination_y: i16,
        destination_width: i16, destination_height: i16,
        source: u16, source_x: i16, source_y: i16,
        source_width: i16, source_height: i16,
    },
}
