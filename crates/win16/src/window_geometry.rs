//! Checked fixed-layout codecs for common Win16 USER geometry structures.
//!
//! Field order and 16-bit widths retain the fixed Win16 guest ABI. Microsoft
//! Learn's [`RECT`], [`MINMAXINFO`], and [`WINDOWPOS`] documentation describes
//! the corresponding field meanings. Private byte-aligned wire types use explicit
//! little-endian fields, with sizes and offsets checked against the named ABI
//! offsets at compile time.
//!
//! [`RECT`]: https://learn.microsoft.com/en-us/windows/win32/api/windef/ns-windef-rect
//! [`MINMAXINFO`]: https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-minmaxinfo
//! [`WINDOWPOS`]: https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-windowpos

use crate::Point16;
use crate::user_abi::wire::{MinMaxInfo16Wire, Rect16Wire, WindowPos16Wire};

/// Byte offsets in a packed Win16 `RECT16`.
pub mod rect16_offsets {
    pub const LEFT: usize = 0;
    pub const TOP: usize = 2;
    pub const RIGHT: usize = 4;
    pub const BOTTOM: usize = 6;
    pub const SIZE: usize = 8;
}

/// Byte offsets in a Win16 `MINMAXINFO16` containing five `POINT16` values.
pub mod minmaxinfo16_offsets {
    pub const PT_RESERVED_X: usize = 0;
    pub const PT_RESERVED_Y: usize = 2;
    pub const PT_MAX_SIZE_X: usize = 4;
    pub const PT_MAX_SIZE_Y: usize = 6;
    pub const PT_MAX_POSITION_X: usize = 8;
    pub const PT_MAX_POSITION_Y: usize = 10;
    pub const PT_MIN_TRACK_SIZE_X: usize = 12;
    pub const PT_MIN_TRACK_SIZE_Y: usize = 14;
    pub const PT_MAX_TRACK_SIZE_X: usize = 16;
    pub const PT_MAX_TRACK_SIZE_Y: usize = 18;
    pub const SIZE: usize = 20;
}

/// Byte offsets in the packed Win16 `WINDOWPOS16` ABI representation.
pub mod windowpos16_offsets {
    pub const HWND: usize = 0;
    pub const HWND_INSERT_AFTER: usize = 2;
    pub const X: usize = 4;
    pub const Y: usize = 6;
    pub const CX: usize = 8;
    pub const CY: usize = 10;
    pub const FLAGS: usize = 12;
    pub const SIZE: usize = 14;
}

/// The four signed 16-bit edges of a Win16 rectangle.
///
/// The field meanings mirror Win32 `RECT`: left/top are the upper-left corner,
/// and right/bottom are the lower-right corner.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct Rect16 {
    pub left: i16,
    pub top: i16,
    pub right: i16,
    pub bottom: i16,
}

impl Rect16 {
    pub const SIZE: usize = rect16_offsets::SIZE;

    /// Decodes exactly one 8-byte Win16 `RECT16` representation.
    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        let wire: Rect16Wire = zerocopy::transmute!(*bytes);

        Self {
            left: wire.left.get(),
            top: wire.top.get(),
            right: wire.right.get(),
            bottom: wire.bottom.get(),
        }
    }

    /// Encodes this value as exactly eight guest-format bytes.
    pub fn encode(self) -> [u8; Self::SIZE] {
        use zerocopy::byteorder::little_endian::I16;

        let wire = Rect16Wire {
            left: I16::new(self.left),
            top: I16::new(self.top),
            right: I16::new(self.right),
            bottom: I16::new(self.bottom),
        };
        zerocopy::transmute!(wire)
    }
}

/// Window maximized position/size and minimum/maximum tracking limits.
///
/// This is the 20-byte Win16 structure used by `WM_GETMINMAXINFO`. The reserved
/// point must be retained as received; the remaining points describe maximized
/// size, maximized position, minimum tracking size, and maximum tracking size.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct MinMaxInfo16 {
    pub pt_reserved: Point16,
    pub pt_max_size: Point16,
    pub pt_max_position: Point16,
    pub pt_min_track_size: Point16,
    pub pt_max_track_size: Point16,
}

impl MinMaxInfo16 {
    pub const SIZE: usize = minmaxinfo16_offsets::SIZE;

    /// Decodes exactly one 20-byte Win16 `MINMAXINFO16` representation.
    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        let wire: MinMaxInfo16Wire = zerocopy::transmute!(*bytes);

        Self {
            pt_reserved: Point16 {
                x: wire.pt_reserved_x.get(),
                y: wire.pt_reserved_y.get(),
            },
            pt_max_size: Point16 {
                x: wire.pt_max_size_x.get(),
                y: wire.pt_max_size_y.get(),
            },
            pt_max_position: Point16 {
                x: wire.pt_max_position_x.get(),
                y: wire.pt_max_position_y.get(),
            },
            pt_min_track_size: Point16 {
                x: wire.pt_min_track_size_x.get(),
                y: wire.pt_min_track_size_y.get(),
            },
            pt_max_track_size: Point16 {
                x: wire.pt_max_track_size_x.get(),
                y: wire.pt_max_track_size_y.get(),
            },
        }
    }

    /// Encodes this value as exactly 20 guest-format bytes.
    pub fn encode(self) -> [u8; Self::SIZE] {
        use zerocopy::byteorder::little_endian::I16;

        let wire = MinMaxInfo16Wire {
            pt_reserved_x: I16::new(self.pt_reserved.x),
            pt_reserved_y: I16::new(self.pt_reserved.y),
            pt_max_size_x: I16::new(self.pt_max_size.x),
            pt_max_size_y: I16::new(self.pt_max_size.y),
            pt_max_position_x: I16::new(self.pt_max_position.x),
            pt_max_position_y: I16::new(self.pt_max_position.y),
            pt_min_track_size_x: I16::new(self.pt_min_track_size.x),
            pt_min_track_size_y: I16::new(self.pt_min_track_size.y),
            pt_max_track_size_x: I16::new(self.pt_max_track_size.x),
            pt_max_track_size_y: I16::new(self.pt_max_track_size.y),
        };
        zerocopy::transmute!(wire)
    }
}

/// Window handle references and proposed position/size for `WINDOWPOS16`.
///
/// Both handles remain raw 16-bit guest `HWND16` values. `hwnd_insert_after`
/// describes the Z-order position or a guest special value; translating either
/// value to a host handle belongs to the caller.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct WindowPos16 {
    pub hwnd: u16,
    pub hwnd_insert_after: u16,
    pub x: i16,
    pub y: i16,
    pub cx: i16,
    pub cy: i16,
    pub flags: u16,
}

impl WindowPos16 {
    pub const SIZE: usize = windowpos16_offsets::SIZE;

    /// Decodes exactly one 14-byte Win16 `WINDOWPOS16` representation.
    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        let wire: WindowPos16Wire = zerocopy::transmute!(*bytes);

        Self {
            hwnd: wire.hwnd.get(),
            hwnd_insert_after: wire.hwnd_insert_after.get(),
            x: wire.x.get(),
            y: wire.y.get(),
            cx: wire.cx.get(),
            cy: wire.cy.get(),
            flags: wire.flags.get(),
        }
    }

    /// Encodes this value as exactly 14 guest-format bytes.
    pub fn encode(self) -> [u8; Self::SIZE] {
        use zerocopy::byteorder::little_endian::{I16, U16};

        let wire = WindowPos16Wire {
            hwnd: U16::new(self.hwnd),
            hwnd_insert_after: U16::new(self.hwnd_insert_after),
            x: I16::new(self.x),
            y: I16::new(self.y),
            cx: I16::new(self.cx),
            cy: I16::new(self.cy),
            flags: U16::new(self.flags),
        };
        zerocopy::transmute!(wire)
    }
}
