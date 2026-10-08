//! Private fixed-layout Win16 GDI wire representations.
//!
//! Zerocopy supplies byte-order-aware field access and checked layout traits;
//! it does not define the public GDI ABI or validate caller-owned ranges.

use core::mem::{align_of, offset_of, size_of};

pub(super) use zerocopy::byteorder::little_endian::{I16, U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct LogPen16Wire {
    pub(super) style: U16,
    pub(super) width_x: I16,
    pub(super) width_y: I16,
    pub(super) color: U32,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct LogFont16Wire {
    pub(super) dimensions: [I16; 5],
    pub(super) styles: [u8; 8],
    pub(super) face_name: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct LogBrush16Wire {
    pub(super) style: U16,
    pub(super) color: U32,
    pub(super) hatch: I16,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct Bitmap16Wire {
    pub(super) bitmap_type: I16,
    pub(super) width: I16,
    pub(super) height: I16,
    pub(super) width_bytes: I16,
    pub(super) planes: u8,
    pub(super) bits_per_pixel: u8,
    pub(super) bits: U32,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct TextMetric16Wire {
    pub(super) dimensions: [I16; 8],
    pub(super) styles: [u8; 9],
    pub(super) extra: [I16; 3],
}

const _: () = {
    assert!(size_of::<LogPen16Wire>() == super::LOGPEN16_SIZE);
    assert!(align_of::<LogPen16Wire>() == 1);
    assert!(offset_of!(LogPen16Wire, style) == 0);
    assert!(offset_of!(LogPen16Wire, width_x) == 2);
    assert!(offset_of!(LogPen16Wire, width_y) == 4);
    assert!(offset_of!(LogPen16Wire, color) == 6);

    assert!(size_of::<LogFont16Wire>() == super::LOGFONT16_SIZE);
    assert!(align_of::<LogFont16Wire>() == 1);
    assert!(offset_of!(LogFont16Wire, dimensions) == 0);
    assert!(offset_of!(LogFont16Wire, styles) == 10);
    assert!(offset_of!(LogFont16Wire, face_name) == 18);

    assert!(size_of::<LogBrush16Wire>() == super::LOGBRUSH16_SIZE);
    assert!(align_of::<LogBrush16Wire>() == 1);
    assert!(offset_of!(LogBrush16Wire, style) == 0);
    assert!(offset_of!(LogBrush16Wire, color) == 2);
    assert!(offset_of!(LogBrush16Wire, hatch) == 6);

    assert!(size_of::<Bitmap16Wire>() == super::BITMAP16_SIZE);
    assert!(align_of::<Bitmap16Wire>() == 1);
    assert!(offset_of!(Bitmap16Wire, bitmap_type) == 0);
    assert!(offset_of!(Bitmap16Wire, width) == 2);
    assert!(offset_of!(Bitmap16Wire, height) == 4);
    assert!(offset_of!(Bitmap16Wire, width_bytes) == 6);
    assert!(offset_of!(Bitmap16Wire, planes) == 8);
    assert!(offset_of!(Bitmap16Wire, bits_per_pixel) == 9);
    assert!(offset_of!(Bitmap16Wire, bits) == 10);

    assert!(size_of::<TextMetric16Wire>() == super::TEXTMETRIC16_SIZE);
    assert!(align_of::<TextMetric16Wire>() == 1);
    assert!(offset_of!(TextMetric16Wire, dimensions) == 0);
    assert!(offset_of!(TextMetric16Wire, styles) == 16);
    assert!(offset_of!(TextMetric16Wire, extra) == 25);
};
