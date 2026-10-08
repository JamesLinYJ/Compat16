//! Fixed-layout Win16 USER service structures.
//!
//! The guest declarations use Win16-sized handles, signed 16-bit coordinates,
//! and one-byte packing. These codecs operate on bytes only; guest far
//! pointers must be resolved and range-checked by the caller before reading or
//! writing a structure. No host pointer or native structure layout is exposed.

pub use crate::window_geometry::Rect16;

use zerocopy::byteorder::{I16, LittleEndian, U16};

/// Byte offsets in the packed, 32-byte Win16 `PAINTSTRUCT` representation.
pub mod paintstruct16_offsets {
    pub const HDC: usize = 0;
    pub const F_ERASE: usize = 2;
    pub const RC_PAINT: usize = 4;
    pub const F_RESTORE: usize = 12;
    pub const F_INC_UPDATE: usize = 14;
    pub const RGB_RESERVED: usize = 16;
    pub const RGB_RESERVED_SIZE: usize = 16;
    pub const SIZE: usize = 32;
}

/// Logical fields of the packed Win16 `PAINTSTRUCT` passed to BeginPaint and
/// EndPaint. BOOL16 members remain signed words so their guest representation
/// is retained exactly while translating to native `BOOL` semantics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct PaintStruct16 {
    pub hdc: u16,
    pub f_erase: i16,
    pub rc_paint: Rect16,
    pub f_restore: i16,
    pub f_inc_update: i16,
    pub rgb_reserved: [u8; paintstruct16_offsets::RGB_RESERVED_SIZE],
}

/// Byte-exact wire layouts for these packed guest structures. Byte-order
/// wrappers keep the layout alignment at one while retaining explicit little
/// endian semantics on every host architecture.
mod wire {
    use super::{I16, LittleEndian, U16};
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};
    pub(super) use crate::user_abi::wire::Rect16Wire;

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub(super) struct LogFont16Wire {
        pub(super) height: I16<LittleEndian>,
        pub(super) width: I16<LittleEndian>,
        pub(super) escapement: I16<LittleEndian>,
        pub(super) orientation: I16<LittleEndian>,
        pub(super) weight: I16<LittleEndian>,
        pub(super) italic: u8,
        pub(super) underline: u8,
        pub(super) strike_out: u8,
        pub(super) char_set: u8,
        pub(super) out_precision: u8,
        pub(super) clip_precision: u8,
        pub(super) quality: u8,
        pub(super) pitch_and_family: u8,
        pub(super) face_name: [u8; 32],
    }

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub(super) struct MouseParameters16Wire {
        pub(super) threshold_1: I16<LittleEndian>,
        pub(super) threshold_2: I16<LittleEndian>,
        pub(super) acceleration: I16<LittleEndian>,
    }

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub(super) struct PaintStruct16Wire {
        pub(super) hdc: U16<LittleEndian>,
        pub(super) f_erase: I16<LittleEndian>,
        pub(super) rc_paint: Rect16Wire,
        pub(super) f_restore: I16<LittleEndian>,
        pub(super) f_inc_update: I16<LittleEndian>,
        pub(super) rgb_reserved: [u8; 16],
    }
}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    use wire::{LogFont16Wire, MouseParameters16Wire, PaintStruct16Wire, Rect16Wire};

    assert!(size_of::<LogFont16Wire>() == logfont16_offsets::SIZE);
    assert!(align_of::<LogFont16Wire>() == 1);
    assert!(offset_of!(LogFont16Wire, height) == logfont16_offsets::HEIGHT);
    assert!(offset_of!(LogFont16Wire, width) == logfont16_offsets::WIDTH);
    assert!(offset_of!(LogFont16Wire, escapement) == logfont16_offsets::ESCAPEMENT);
    assert!(offset_of!(LogFont16Wire, orientation) == logfont16_offsets::ORIENTATION);
    assert!(offset_of!(LogFont16Wire, weight) == logfont16_offsets::WEIGHT);
    assert!(offset_of!(LogFont16Wire, italic) == logfont16_offsets::ITALIC);
    assert!(offset_of!(LogFont16Wire, underline) == logfont16_offsets::UNDERLINE);
    assert!(offset_of!(LogFont16Wire, strike_out) == logfont16_offsets::STRIKE_OUT);
    assert!(offset_of!(LogFont16Wire, char_set) == logfont16_offsets::CHAR_SET);
    assert!(offset_of!(LogFont16Wire, out_precision) == logfont16_offsets::OUT_PRECISION);
    assert!(offset_of!(LogFont16Wire, clip_precision) == logfont16_offsets::CLIP_PRECISION);
    assert!(offset_of!(LogFont16Wire, quality) == logfont16_offsets::QUALITY);
    assert!(offset_of!(LogFont16Wire, pitch_and_family) == logfont16_offsets::PITCH_AND_FAMILY);
    assert!(offset_of!(LogFont16Wire, face_name) == logfont16_offsets::FACE_NAME);

    assert!(size_of::<MouseParameters16Wire>() == MouseParameters16::SIZE);
    assert!(align_of::<MouseParameters16Wire>() == 1);
    assert!(offset_of!(MouseParameters16Wire, threshold_1) == 0);
    assert!(offset_of!(MouseParameters16Wire, threshold_2) == 2);
    assert!(offset_of!(MouseParameters16Wire, acceleration) == 4);

    assert!(size_of::<Rect16Wire>() == Rect16::SIZE);
    assert!(align_of::<Rect16Wire>() == 1);
    assert!(offset_of!(Rect16Wire, left) == 0);
    assert!(offset_of!(Rect16Wire, top) == 2);
    assert!(offset_of!(Rect16Wire, right) == 4);
    assert!(offset_of!(Rect16Wire, bottom) == 6);

    assert!(size_of::<PaintStruct16Wire>() == paintstruct16_offsets::SIZE);
    assert!(align_of::<PaintStruct16Wire>() == 1);
    assert!(offset_of!(PaintStruct16Wire, hdc) == paintstruct16_offsets::HDC);
    assert!(offset_of!(PaintStruct16Wire, f_erase) == paintstruct16_offsets::F_ERASE);
    assert!(offset_of!(PaintStruct16Wire, rc_paint) == paintstruct16_offsets::RC_PAINT);
    assert!(offset_of!(PaintStruct16Wire, f_restore) == paintstruct16_offsets::F_RESTORE);
    assert!(offset_of!(PaintStruct16Wire, f_inc_update) == paintstruct16_offsets::F_INC_UPDATE);
    assert!(offset_of!(PaintStruct16Wire, rgb_reserved) == paintstruct16_offsets::RGB_RESERVED);
};

/// Byte offsets and total size of the packed Win16 `LOGFONT` structure.
pub mod logfont16_offsets {
    pub const HEIGHT: usize = 0;
    pub const WIDTH: usize = 2;
    pub const ESCAPEMENT: usize = 4;
    pub const ORIENTATION: usize = 6;
    pub const WEIGHT: usize = 8;
    pub const ITALIC: usize = 10;
    pub const UNDERLINE: usize = 11;
    pub const STRIKE_OUT: usize = 12;
    pub const CHAR_SET: usize = 13;
    pub const OUT_PRECISION: usize = 14;
    pub const CLIP_PRECISION: usize = 15;
    pub const QUALITY: usize = 16;
    pub const PITCH_AND_FAMILY: usize = 17;
    pub const FACE_NAME: usize = 18;
    pub const FACE_NAME_SIZE: usize = 32;
    pub const SIZE: usize = FACE_NAME + FACE_NAME_SIZE;
}

/// Packed Win16 LOGFONT payload. It is converted field-by-field to the native
/// 32-bit LOGFONTA structure at the Windows adapter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct LogFont16 {
    pub height: i16,
    pub width: i16,
    pub escapement: i16,
    pub orientation: i16,
    pub weight: i16,
    pub italic: u8,
    pub underline: u8,
    pub strike_out: u8,
    pub char_set: u8,
    pub out_precision: u8,
    pub clip_precision: u8,
    pub quality: u8,
    pub pitch_and_family: u8,
    pub face_name: [u8; logfont16_offsets::FACE_NAME_SIZE],
}

impl LogFont16 {
    pub const SIZE: usize = logfont16_offsets::SIZE;

    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        let wire: wire::LogFont16Wire = zerocopy::transmute!(*bytes);
        Self {
            height: wire.height.get(),
            width: wire.width.get(),
            escapement: wire.escapement.get(),
            orientation: wire.orientation.get(),
            weight: wire.weight.get(),
            italic: wire.italic,
            underline: wire.underline,
            strike_out: wire.strike_out,
            char_set: wire.char_set,
            out_precision: wire.out_precision,
            clip_precision: wire.clip_precision,
            quality: wire.quality,
            pitch_and_family: wire.pitch_and_family,
            face_name: wire.face_name,
        }
    }

    pub fn encode(self) -> [u8; Self::SIZE] {
        let wire = wire::LogFont16Wire {
            height: I16::new(self.height),
            width: I16::new(self.width),
            escapement: I16::new(self.escapement),
            orientation: I16::new(self.orientation),
            weight: I16::new(self.weight),
            italic: self.italic,
            underline: self.underline,
            strike_out: self.strike_out,
            char_set: self.char_set,
            out_precision: self.out_precision,
            clip_precision: self.clip_precision,
            quality: self.quality,
            pitch_and_family: self.pitch_and_family,
            face_name: self.face_name,
        };
        zerocopy::transmute!(wire)
    }
}

/// The SPI_GETMOUSE/SPI_SETMOUSE array contains three Win16 `int` values.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct MouseParameters16(pub [i16; 3]);

impl MouseParameters16 {
    pub const SIZE: usize = 6;

    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        let wire: wire::MouseParameters16Wire = zerocopy::transmute!(*bytes);
        Self([
            wire.threshold_1.get(),
            wire.threshold_2.get(),
            wire.acceleration.get(),
        ])
    }

    pub fn encode(self) -> [u8; Self::SIZE] {
        let wire = wire::MouseParameters16Wire {
            threshold_1: I16::new(self.0[0]),
            threshold_2: I16::new(self.0[1]),
            acceleration: I16::new(self.0[2]),
        };
        zerocopy::transmute!(wire)
    }
}

impl PaintStruct16 {
    pub const SIZE: usize = paintstruct16_offsets::SIZE;

    /// Decodes exactly one packed Win16 `PAINTSTRUCT` byte sequence.
    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        let wire: wire::PaintStruct16Wire = zerocopy::transmute!(*bytes);
        Self {
            hdc: wire.hdc.get(),
            f_erase: wire.f_erase.get(),
            rc_paint: Rect16 {
                left: wire.rc_paint.left.get(),
                top: wire.rc_paint.top.get(),
                right: wire.rc_paint.right.get(),
                bottom: wire.rc_paint.bottom.get(),
            },
            f_restore: wire.f_restore.get(),
            f_inc_update: wire.f_inc_update.get(),
            rgb_reserved: wire.rgb_reserved,
        }
    }

    /// Encodes this value as exactly 32 guest-format bytes.
    pub fn encode(self) -> [u8; Self::SIZE] {
        let wire = wire::PaintStruct16Wire {
            hdc: U16::new(self.hdc),
            f_erase: I16::new(self.f_erase),
            rc_paint: wire::Rect16Wire {
                left: I16::new(self.rc_paint.left),
                top: I16::new(self.rc_paint.top),
                right: I16::new(self.rc_paint.right),
                bottom: I16::new(self.rc_paint.bottom),
            },
            f_restore: I16::new(self.f_restore),
            f_inc_update: I16::new(self.f_inc_update),
            rgb_reserved: self.rgb_reserved,
        };
        zerocopy::transmute!(wire)
    }
}
