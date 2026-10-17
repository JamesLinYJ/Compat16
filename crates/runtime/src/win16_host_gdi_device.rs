//! Owned Windows GDI palette, bitmap-metadata, and print operation DTOs.

use std::rc::Rc;

use guest_core::memory::MemoryMappedDevice;
use crate::{Win16HostDc, Win16HostDevMode, Win16HostGdiObject};

/// Object descriptions contain copied values and opaque pattern identities,
/// never native BITMAP bits or LOGBRUSH pointer fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16GdiObjectInfo {
    Pen(crate::Win16HostLogPen),
    Font(crate::Win16HostLogFont),
    Brush { brush: crate::Win16HostLogBrush, pattern: Option<Win16HostGdiObject> },
    Bitmap(crate::Win16HostBitmapInfo),
    Palette(u16),
    UnsupportedBrush,
}

/// A host-owned WinG DIB section with a separate safe view over the same
/// process-owned section. Native bitmap/view pointers remain host-private.
#[derive(Clone)]
pub struct Win16HostDibSection {
    pub object: Win16HostGdiObject,
    pub extent: u32,
    pub header: [u8; 40],
    pub memory: Rc<dyn MemoryMappedDevice>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16PaletteTransferKind {
    Get,
    Set,
    Animate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16DibColorTableKind {
    Get,
    Set,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16PrintOperation {
    EndDocument,
    StartPage,
    EndPage,
    AbortDocument,
}

/// WinG's three documented ordered-dither brush families. The host creates
/// real pattern brushes; these values never identify a native brush pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16DitherPattern {
    Dispersed4x4,
    Dispersed8x8,
    Clustered4x4,
}

/// Read-only Escape queries with explicit host conversions. No arbitrary
/// driver escape code or guest pointer can cross this boundary.
/// Job variants are support probes only; execution uses StartDoc and the
/// print operations, still without a guest pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16EscapeQuery {
    QuerySupport,
    PhysicalPageSize,
    PrintingOffset,
    ScalingFactor,
    StartDocument,
    NewFrame,
    EndDocument,
    AbortDocument,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16GdiDeviceOperation {
    QueryEscapeSupport { dc: Win16HostDc, query: Win16EscapeQuery },
    EscapeQuery { dc: Win16HostDc, query: Win16EscapeQuery },
    GetObject { object: Win16HostGdiObject },
    RecommendWinGDibFormat,
    CreateWinGDibSection {
        dc: Win16HostDc,
        info: Vec<u8>,
        image_bytes: u32,
    },
    CreatePalette { version: u16, entries: Vec<[u8; 4]> },
    CreateDiscardableBitmap { dc: Win16HostDc, width: i16, height: i16 },
    CreateHalftonePalette { dc: Win16HostDc },
    CreateWinGHalftonePalette,
    CreateWinGHalftoneBrush {
        dc: Win16HostDc,
        color: u32,
        pattern: Win16DitherPattern,
    },
    WinGStretchBlt {
        destination: Win16HostDc,
        destination_x: i16,
        destination_y: i16,
        destination_width: i16,
        destination_height: i16,
        source: Win16HostDc,
        source_x: i16,
        source_y: i16,
        source_width: i16,
        source_height: i16,
    },
    SelectPalette { dc: Win16HostDc, palette: Win16HostGdiObject, force_background: bool },
    RealizePalette { dc: Win16HostDc },
    UnrealizeObject { object: Win16HostGdiObject },
    RealizeDefaultPalette { dc: Win16HostDc },
    UpdateColors { dc: Win16HostDc },
    PaletteEntries {
        kind: Win16PaletteTransferKind,
        palette: Win16HostGdiObject,
        start: u16,
        count: u16,
        entries: Option<Vec<[u8; 4]>>,
    },
    ResizePalette { palette: Win16HostGdiObject, count: u16 },
    GetNearestPaletteIndex { palette: Win16HostGdiObject, color: u32 },
    SetSystemPaletteUse { dc: Win16HostDc, use_mode: u16 },
    GetSystemPaletteUse { dc: Win16HostDc },
    GetSystemPaletteEntries { dc: Win16HostDc, start: u16, count: u16 },
    DibColorTable {
        kind: Win16DibColorTableKind,
        dc: Win16HostDc,
        start: u16,
        count: u16,
        entries: Option<Vec<[u8; 4]>>,
    },
    GetBitmapDimension { bitmap: Win16HostGdiObject },
    SetBitmapDimension { bitmap: Win16HostGdiObject, width: i16, height: i16 },
    ResetDc { dc: Win16HostDc, devmode: Option<Win16HostDevMode> },
    StartDoc {
        dc: Win16HostDc,
        document_name: Option<Vec<u8>>,
        output: Option<Vec<u8>>,
    },
    Print { operation: Win16PrintOperation, dc: Win16HostDc },
}

#[derive(Clone)]
pub enum Win16GdiDeviceResult {
    ObjectInfo(Option<Win16GdiObjectInfo>),
    Count(i32),
    Bool(bool),
    Object(Option<Win16HostGdiObject>),
    Dc(Option<Win16HostDc>),
    PaletteEntries { count: i32, entries: Vec<[u8; 4]> },
    Point { success: bool, x: i32, y: i32 },
    DibHeader(Option<[u8; 40]>),
    DibSection(Option<Win16HostDibSection>),
}
