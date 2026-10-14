//! Owned request values for this Win16 API family.

use super::super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16GdiObjectsRequest {
    GetMetaFile { path: Vec<u8> },
    PlayMetaFile { dc: u16, metafile: u16 },
    CopyMetaFile { metafile: u16, path: Option<Vec<u8>> },
    DeleteMetaFile { metafile: u16 },

    /// Enumerate LOGPEN16 or LOGBRUSH16 through a checked guest FAR callback.
    EnumObjects {
        dc: u16,
        object_type: i16,
        callback: u32,
        parameter: i32,
    },

    /// GDI object creation requests own decoded fixed Win16 structure values;
    /// bitmap pixel data remains a guest FAR address for runtime-side sizing.
    CreatePen {
        style: i16,
        width: i16,
        color: u32,
    },

    CreatePenIndirect {
        logpen: crate::gdi_abi::LogPen16,
    },

    CreateBitmap {
        width: i16,
        height: i16,
        planes: u16,
        bits_per_pixel: u16,
        bits: u32,
    },

    CreateBitmapIndirect {
        bitmap: crate::gdi_abi::Bitmap16,
    },

    CreateBrushIndirect {
        logbrush: crate::gdi_abi::LogBrush16,
    },

    CreateCompatibleBitmap {
        dc: u16,
        width: i16,
        height: i16,
    },

    CreateEllipticRgn {
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
    },

    CreateEllipticRgnIndirect {
        rect: Option<Rect16>,
    },

    CreatePolygonRgn {
        points: Vec<Point16>,
        count: i16,
        fill_mode: i16,
    },

    CreateRectRgn {
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
    },

    CreateRectRgnIndirect {
        rect: Option<Rect16>,
    },

    CreateRoundRectRgn {
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
        ellipse_width: i16,
        ellipse_height: i16,
    },

    CreatePolyPolygonRgn {
        points: Vec<Point16>,
        polygon_counts: Vec<i16>,
        polygon_count: i16,
        fill_mode: i16,
        valid: bool,
    },

    /// Create a compatible device context based on a guest HDC. The runtime
    /// translates the guest handle; it is never interpreted as a host handle.
    CreateCompatibleDc {
        source: u16,
    },

    /// Delete a device context represented by a guest HDC.
    DeleteDc {
        dc: u16,
    },

    /// Delete a GDI object represented by its guest HGDIOBJ. Runtime translates
    /// the guest handle before invoking or emulating the host operation.
    DeleteObject {
        object: u16,
    },
    /// Invalidate a brush/palette realization without deleting its identity.
    UnrealizeObject { object: u16 },

    /// Query a device capability through the runtime's translated guest HDC.
    /// The capability selector is a signed Win16 `INT` value.
    GetDeviceCaps {
        dc: u16,
        index: i16,
    },

    /// Resolve a Win16 stock-object selector to a guest GDI handle.
    GetStockObject {
        index: i16,
    },

    /// Select a guest GDI object into a guest device context.
    SelectObject {
        dc: u16,
        object: u16,
    },

    /// Create a solid brush from a Win16 COLORREF and return its guest handle.
    CreateSolidBrush {
        color: u32,
    },

    /// Create a device context from copied nullable ANSI strings and a raw
    /// optional guest DEVMODE16 pointer. The pointer is not a host address.
    CreateDc {
        driver: Option<Vec<u8>>,
        device: Option<Vec<u8>>,
        output: Option<Vec<u8>>,
        init_data: u32,
    },

    /// Create an information context using the same Win16 input layout as CreateDC.
    CreateIc {
        driver: Option<Vec<u8>>,
        device: Option<Vec<u8>>,
        output: Option<Vec<u8>>,
        init_data: u32,
    },

    /// Win16 metafile bits retain the original guest global-memory identity.
    GetMetaFileBits { metafile: u16 },
    SetMetaFileBits { bits: u16 },
    /// Transfer the block to the shared global-memory class via GMEM_MODIFY.
    SetMetaFileBitsBetter { bits: u16 },
}
