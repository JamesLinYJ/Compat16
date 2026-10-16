//! Guest-side requests for GDI device-context state and object queries.

use crate::window_geometry::Rect16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16FontResourceInput {
    Null,
    Path(Vec<u8>),
    Module(u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16GdiServicesRequest {
    GetGlyphOutline {
        dc: u16, character: u16, format: u16, metrics: u32,
        byte_count: u32, buffer: u32, matrix: u32,
    },
    SetBoundsRect {
        dc: u16,
        rect: Option<Rect16>,
        flags: u16,
    },
    GetBoundsRect {
        dc: u16,
        output: u32,
        flags: u16,
    },
    SetMapperFlags {
        dc: u16,
        flags: u32,
    },
    GetAspectRatioFilter {
        dc: u16,
    },
    GetAspectRatioFilterEx {
        dc: u16,
        output: u32,
    },
    AddFontResource {
        input: Win16FontResourceInput,
    },
    RemoveFontResource {
        input: Win16FontResourceInput,
    },
    GetCharWidth {
        dc: u16,
        first: u16,
        last: u16,
        output: u32,
    },
    GetCharAbcWidths {
        dc: u16,
        first: u16,
        last: u16,
        output: u32,
    },
    GetFontData {
        dc: u16,
        table: u32,
        offset: u32,
        output: u32,
        byte_count: u32,
    },
    GetRasterizerCaps {
        output: u32,
        byte_count: u16,
    },
    GetKerningPairs {
        dc: u16,
        pair_count: i16,
        output: u32,
    },
    IsGdiObject {
        object: u16,
    },
}
