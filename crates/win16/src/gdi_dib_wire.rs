//! Private fixed-prefix representations for guest DIB headers.

use zerocopy::byteorder::little_endian::{I32, U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

// The common size field selects a fixed prefix and supplies its variable
// extension length, so its offset is named separately for the scalar probe.
pub(super) const HEADER_SIZE_OFFSET: usize = 0;

// These named guest offsets are checked against the wire structs below; the
// byteorder wrappers keep repr(C) fields aligned to one byte on every host.
mod core_offsets {
    pub(super) const SIZE: usize = 0;
    pub(super) const WIDTH: usize = 4;
    pub(super) const HEIGHT: usize = 6;
    pub(super) const PLANES: usize = 8;
    pub(super) const BITS_PER_PIXEL: usize = 10;
}

mod info_offsets {
    pub(super) const SIZE: usize = 0;
    pub(super) const WIDTH: usize = 4;
    pub(super) const HEIGHT: usize = 8;
    pub(super) const PLANES: usize = 12;
    pub(super) const BITS_PER_PIXEL: usize = 14;
    pub(super) const COMPRESSION: usize = 16;
    pub(super) const IMAGE_SIZE: usize = 20;
    pub(super) const X_PELS_PER_METER: usize = 24;
    pub(super) const Y_PELS_PER_METER: usize = 28;
    pub(super) const COLORS_USED: usize = 32;
    pub(super) const COLORS_IMPORTANT: usize = 36;
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct BitmapCoreHeader12Wire {
    pub(super) size: U32,
    pub(super) width: U16,
    pub(super) height: U16,
    pub(super) planes: U16,
    pub(super) bits_per_pixel: U16,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct BitmapInfoHeader40Wire {
    pub(super) size: U32,
    pub(super) width: I32,
    pub(super) height: I32,
    pub(super) planes: U16,
    pub(super) bits_per_pixel: U16,
    pub(super) compression: U32,
    pub(super) image_size: U32,
    pub(super) _x_pels_per_meter: I32,
    pub(super) _y_pels_per_meter: I32,
    pub(super) colors_used: U32,
    pub(super) _colors_important: U32,
}

const _: () = {
    use super::{BITMAPCOREHEADER16_SIZE, BITMAPINFOHEADER16_MIN_SIZE};

    assert!(core::mem::size_of::<BitmapCoreHeader12Wire>() == BITMAPCOREHEADER16_SIZE);
    assert!(core::mem::align_of::<BitmapCoreHeader12Wire>() == 1);
    assert!(core::mem::offset_of!(BitmapCoreHeader12Wire, size) == core_offsets::SIZE);
    assert!(core::mem::offset_of!(BitmapCoreHeader12Wire, width) == core_offsets::WIDTH);
    assert!(core::mem::offset_of!(BitmapCoreHeader12Wire, height) == core_offsets::HEIGHT);
    assert!(core::mem::offset_of!(BitmapCoreHeader12Wire, planes) == core_offsets::PLANES);
    assert!(core::mem::offset_of!(BitmapCoreHeader12Wire, bits_per_pixel) == core_offsets::BITS_PER_PIXEL);

    assert!(core::mem::size_of::<BitmapInfoHeader40Wire>() == BITMAPINFOHEADER16_MIN_SIZE);
    assert!(core::mem::align_of::<BitmapInfoHeader40Wire>() == 1);
    assert!(core::mem::offset_of!(BitmapInfoHeader40Wire, size) == info_offsets::SIZE);
    assert!(core::mem::offset_of!(BitmapInfoHeader40Wire, width) == info_offsets::WIDTH);
    assert!(core::mem::offset_of!(BitmapInfoHeader40Wire, height) == info_offsets::HEIGHT);
    assert!(core::mem::offset_of!(BitmapInfoHeader40Wire, planes) == info_offsets::PLANES);
    assert!(core::mem::offset_of!(BitmapInfoHeader40Wire, bits_per_pixel) == info_offsets::BITS_PER_PIXEL);
    assert!(core::mem::offset_of!(BitmapInfoHeader40Wire, compression) == info_offsets::COMPRESSION);
    assert!(core::mem::offset_of!(BitmapInfoHeader40Wire, image_size) == info_offsets::IMAGE_SIZE);
    assert!(core::mem::offset_of!(BitmapInfoHeader40Wire, _x_pels_per_meter) == info_offsets::X_PELS_PER_METER);
    assert!(core::mem::offset_of!(BitmapInfoHeader40Wire, _y_pels_per_meter) == info_offsets::Y_PELS_PER_METER);
    assert!(core::mem::offset_of!(BitmapInfoHeader40Wire, colors_used) == info_offsets::COLORS_USED);
    assert!(core::mem::offset_of!(BitmapInfoHeader40Wire, _colors_important) == info_offsets::COLORS_IMPORTANT);
};
