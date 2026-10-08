//! Fixed-width printer capability records shared by Win16 decoding services.

use zerocopy::byteorder::little_endian::I32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

const RESOLUTION_PAIR16_SIZE: usize = 8;

/// One Win16 `DC_ENUMRESOLUTIONS` entry: horizontal and vertical LONG DPI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolutionPair16 {
    pub x: i32,
    pub y: i32,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct ResolutionPair16Wire {
    x: I32,
    y: I32,
}

impl ResolutionPair16 {
    /// Encodes one fixed eight-byte little-endian Win16 record.
    pub fn encode(self) -> [u8; RESOLUTION_PAIR16_SIZE] {
        zerocopy::transmute!(ResolutionPair16Wire {
            x: I32::new(self.x),
            y: I32::new(self.y),
        })
    }

    /// Decodes exactly one fixed eight-byte little-endian Win16 record.
    pub fn decode(bytes: &[u8; RESOLUTION_PAIR16_SIZE]) -> Self {
        let wire: ResolutionPair16Wire = zerocopy::transmute!(*bytes);
        Self { x: wire.x.get(), y: wire.y.get() }
    }
}

const _: () = {
    assert!(core::mem::size_of::<ResolutionPair16Wire>() == RESOLUTION_PAIR16_SIZE);
    assert!(core::mem::align_of::<ResolutionPair16Wire>() == 1);
    assert!(core::mem::offset_of!(ResolutionPair16Wire, x) == 0);
    assert!(core::mem::offset_of!(ResolutionPair16Wire, y) == 4);
};
