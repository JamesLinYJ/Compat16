//! Pointer-free operations for Win16 GDI device-context state and object queries.

use crate::{Win16DrawingRect, Win16HostDc, Win16HostGdiObject};

/// Native glyph metrics, kept separate from the SDK 3.1 12-byte record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostGlyphMetrics {
    pub black_box_x: u32,
    pub black_box_y: u32,
    pub origin_x: i32,
    pub origin_y: i32,
    pub cell_inc_x: i16,
    pub cell_inc_y: i16,
}

/// GGO_GLYPH_INDEX and GGO_UNHINTED modify the underlying output mode.
pub(crate) fn glyph_metrics_only(format: u16) -> bool { format & !0x0180 == 0 }

/// One native ABC width returned by Windows. Runtime narrows these fields to
/// the Windows 3.1 `ABC` layout before writing guest memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostAbcWidth {
    pub abc_a: i32,
    pub abc_b: u32,
    pub abc_c: i32,
}

/// One native kerning pair. `i_kern_amount` is 32-bit in Win32 but 16-bit in
/// the Windows 3.1 guest structure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostKerningPair {
    pub first: u16,
    pub second: u16,
    pub amount: i32,
}

/// Fixed-width values copied from native `RASTERIZER_STATUS`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostRasterizerCaps {
    pub size: i16,
    pub flags: i16,
    pub language_id: i16,
}

/// A resolved guest GDI handle. DCs and drawing objects share guest handle
/// allocation but keep separate typed identities at the host boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostGdiIdentity {
    Dc(Win16HostDc),
    Object(Win16HostGdiObject),
}

/// A GDI request after the runtime has resolved guest handles and copied any
/// guest structures into owned values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16GdiServicesOperation {
    GetGlyphOutline {
        dc: Win16HostDc, character: u16, format: u16, matrix: [u32; 4],
        byte_count: u32, copy_buffer: bool,
    },
    SetBoundsRect {
        dc: Win16HostDc,
        rect: Option<Win16DrawingRect>,
        flags: u32,
    },
    GetBoundsRect {
        dc: Win16HostDc,
        flags: u32,
    },
    SetMapperFlags {
        dc: Win16HostDc,
        flags: u32,
    },
    GetAspectRatioFilter {
        dc: Win16HostDc,
    },
    GetAspectRatioFilterEx {
        dc: Win16HostDc,
    },
    AddFontResource {
        guest_path: Vec<u8>,
    },
    RemoveFontResource {
        guest_path: Vec<u8>,
    },
    /// `current_path` is present only for a bare font filename. A directory
    /// already present in `font_file` is resolved on its own.
    CreateScalableFontResource {
        hidden: u16,
        resource_file: Vec<u8>,
        font_file: Vec<u8>,
        current_path: Option<Vec<u8>>,
    },
    GetCharWidth {
        dc: Win16HostDc,
        first: u16,
        last: u16,
    },
    GetCharAbcWidths {
        dc: Win16HostDc,
        first: u16,
        last: u16,
    },
    GetFontData {
        dc: Win16HostDc,
        table: u32,
        offset: u32,
        byte_count: u32,
        copy_buffer: bool,
    },
    GetRasterizerCaps {
        byte_count: i16,
    },
    GetKerningPairs {
        dc: Win16HostDc,
        pair_count: u16,
    },
    IsGdiObject {
        identity: Win16HostGdiIdentity,
    },
    /// Query whether a pinned native HDC is a classic metafile DC.
    IsMetafileDc {
        dc: Win16HostDc,
    },
}

/// Native results retain full Windows widths. The Win16 runtime narrows
/// RECT/SIZE fields and packs the legacy GetAspectRatioFilter DWORD.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16GdiServicesResult {
    GlyphOutline {
        result: u32,
        metrics: Option<Win16HostGlyphMetrics>,
        bytes: Vec<u8>,
    },
    Dword(u32),
    Bool(bool),
    BoundsRect {
        flags: u32,
        rect: Win16DrawingRect,
    },
    AspectRatio {
        success: bool,
        width: i32,
        height: i32,
    },
    FontResourceCount(i32),
    CharWidths {
        success: bool,
        entries: Vec<i32>,
    },
    AbcWidths {
        success: bool,
        entries: Vec<Win16HostAbcWidth>,
    },
    FontData {
        result: u32,
        bytes: Vec<u8>,
    },
    RasterizerCaps {
        success: bool,
        caps: Win16HostRasterizerCaps,
    },
    KerningPairs {
        count: u32,
        entries: Vec<Win16HostKerningPair>,
    },
}
