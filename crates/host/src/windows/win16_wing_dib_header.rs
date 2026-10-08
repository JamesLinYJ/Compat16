//! Fixed Win32 `BITMAPINFOHEADER` wire codec shared by WinG producers.
//!
//! The `windows-sys` binding has no zerocopy traits, so this private LE mirror
//! serializes its fixed 40-byte header. It does not replace the guest parser,
//! which must continue to validate variable `biSize`, masks, and ranges.

use core::mem::{align_of, offset_of, size_of};
use windows_sys::Win32::Graphics::Gdi::BITMAPINFOHEADER;
use zerocopy::byteorder::little_endian::{I32, U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub(super) const BITMAPINFOHEADER_SIZE: usize = 40;

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct BitmapInfoHeaderWire {
    size: U32,
    width: I32,
    height: I32,
    planes: U16,
    bit_count: U16,
    compression: U32,
    image_size: U32,
    x_pixels_per_meter: I32,
    y_pixels_per_meter: I32,
    colors_used: U32,
    colors_important: U32,
}

impl BitmapInfoHeaderWire {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        size: u32,
        width: i32,
        height: i32,
        planes: u16,
        bit_count: u16,
        compression: u32,
        image_size: u32,
        x_pixels_per_meter: i32,
        y_pixels_per_meter: i32,
        colors_used: u32,
        colors_important: u32,
    ) -> Self {
        Self {
            size: U32::new(size),
            width: I32::new(width),
            height: I32::new(height),
            planes: U16::new(planes),
            bit_count: U16::new(bit_count),
            compression: U32::new(compression),
            image_size: U32::new(image_size),
            x_pixels_per_meter: I32::new(x_pixels_per_meter),
            y_pixels_per_meter: I32::new(y_pixels_per_meter),
            colors_used: U32::new(colors_used),
            colors_important: U32::new(colors_important),
        }
    }

    pub(super) fn from_native(header: &BITMAPINFOHEADER) -> Self {
        Self::new(
            header.biSize,
            header.biWidth,
            header.biHeight,
            header.biPlanes,
            header.biBitCount,
            header.biCompression,
            header.biSizeImage,
            header.biXPelsPerMeter,
            header.biYPelsPerMeter,
            header.biClrUsed,
            header.biClrImportant,
        )
    }

    pub(super) fn into_bytes(self) -> [u8; BITMAPINFOHEADER_SIZE] {
        zerocopy::transmute!(self)
    }
}

const _: () = {
    assert!(size_of::<BitmapInfoHeaderWire>() == BITMAPINFOHEADER_SIZE);
    assert!(align_of::<BitmapInfoHeaderWire>() == 1);
    assert!(size_of::<BITMAPINFOHEADER>() == BITMAPINFOHEADER_SIZE);
    assert!(align_of::<BITMAPINFOHEADER>() == 4);

    assert!(offset_of!(BitmapInfoHeaderWire, size) == 0);
    assert!(offset_of!(BitmapInfoHeaderWire, size) == offset_of!(BITMAPINFOHEADER, biSize));
    assert!(offset_of!(BitmapInfoHeaderWire, width) == 4);
    assert!(offset_of!(BitmapInfoHeaderWire, width) == offset_of!(BITMAPINFOHEADER, biWidth));
    assert!(offset_of!(BitmapInfoHeaderWire, height) == 8);
    assert!(offset_of!(BitmapInfoHeaderWire, height) == offset_of!(BITMAPINFOHEADER, biHeight));
    assert!(offset_of!(BitmapInfoHeaderWire, planes) == 12);
    assert!(offset_of!(BitmapInfoHeaderWire, planes) == offset_of!(BITMAPINFOHEADER, biPlanes));
    assert!(offset_of!(BitmapInfoHeaderWire, bit_count) == 14);
    assert!(
        offset_of!(BitmapInfoHeaderWire, bit_count) == offset_of!(BITMAPINFOHEADER, biBitCount)
    );
    assert!(offset_of!(BitmapInfoHeaderWire, compression) == 16);
    assert!(
        offset_of!(BitmapInfoHeaderWire, compression)
            == offset_of!(BITMAPINFOHEADER, biCompression)
    );
    assert!(offset_of!(BitmapInfoHeaderWire, image_size) == 20);
    assert!(
        offset_of!(BitmapInfoHeaderWire, image_size) == offset_of!(BITMAPINFOHEADER, biSizeImage)
    );
    assert!(offset_of!(BitmapInfoHeaderWire, x_pixels_per_meter) == 24);
    assert!(
        offset_of!(BitmapInfoHeaderWire, x_pixels_per_meter)
            == offset_of!(BITMAPINFOHEADER, biXPelsPerMeter)
    );
    assert!(offset_of!(BitmapInfoHeaderWire, y_pixels_per_meter) == 28);
    assert!(
        offset_of!(BitmapInfoHeaderWire, y_pixels_per_meter)
            == offset_of!(BITMAPINFOHEADER, biYPelsPerMeter)
    );
    assert!(offset_of!(BitmapInfoHeaderWire, colors_used) == 32);
    assert!(
        offset_of!(BitmapInfoHeaderWire, colors_used) == offset_of!(BITMAPINFOHEADER, biClrUsed)
    );
    assert!(offset_of!(BitmapInfoHeaderWire, colors_important) == 36);
    assert!(
        offset_of!(BitmapInfoHeaderWire, colors_important)
            == offset_of!(BITMAPINFOHEADER, biClrImportant)
    );
};
