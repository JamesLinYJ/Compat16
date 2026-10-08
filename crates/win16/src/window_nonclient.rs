//! Fixed Win16 non-client message structure codecs.
//!
//! The Windows 3.1 SDK 3.10 Disk 3 `INC/WINDOWS.H` defaults `WINVER` to
//! `0x030a` (lines 81–84). In that branch, `WINDOWPOS` is declared at lines
//! 3221–3231 and `NCCALCSIZE_PARAMS` at lines 3474–3478; `RECT` is lines
//! 1070–1078. Source: `work/reference/windows-sdk/3.1/files/expanded/Disk 3
//! (050-151-053)/INC/WINDOWS.H` (SHA-256
//! `0e26530e07a6b6d6e6c6442d4a5092a186ca94520ddcf43f95387712c1330738`).
//!
//! For `WM_NCCALCSIZE` with `wParam == FALSE`, callers must use only the
//! leading `Rect16` codec. This 28-byte codec is for the three-rectangle
//! branch; it must not be used to read the false branch's trailing bytes.
//! The `lppos` field remains raw guest FAR bits. Resolving it and decoding a
//! separate `WindowPos16` are caller responsibilities after guest-memory
//! validation.

use crate::user_abi::wire::Rect16Wire;
use crate::window_geometry::{windowpos16_offsets, Rect16, WindowPos16};
use crate::Win16Error;
use zerocopy::byteorder::little_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Byte offsets in the Windows 3.1 `NCCALCSIZE_PARAMS` true-branch layout.
pub mod nonclient_calc_size16_offsets {
    use crate::window_geometry::Rect16;

    pub const RGRC0: usize = 0;
    pub const RGRC1: usize = RGRC0 + Rect16::SIZE;
    pub const RGRC2: usize = RGRC1 + Rect16::SIZE;
    pub const LPPOS: usize = RGRC2 + Rect16::SIZE;
    pub const SIZE: usize = LPPOS + 4;
}

// The SDK's Win16 outer structure is not provided by a general layout crate.
// Use one packed zerocopy wire type while reusing the established RECT16 wire;
// the raw FAR word is copied without interpreting it as a host pointer.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct NonClientCalcSize16Wire {
    rgrc: [Rect16Wire; 3],
    lppos: U32,
}

/// Logical fields of the Windows 3.1 `NCCALCSIZE_PARAMS` true branch.
///
/// The `rgrc` array keeps the guest's original indices. No source/destination
/// interpretation is assigned to `rgrc[1]` or `rgrc[2]` here.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct NonClientCalcSize16 {
    pub rgrc: [Rect16; 3],
    /// Raw 32-bit guest FAR pointer bits for a separate `WindowPos16`.
    pub lppos: u32,
}

impl NonClientCalcSize16 {
    pub const SIZE: usize = nonclient_calc_size16_offsets::SIZE;
    pub const LPPOS_OFFSET: usize = nonclient_calc_size16_offsets::LPPOS;

    /// Decodes exactly one 28-byte Win16 `NCCALCSIZE_PARAMS` record.
    pub fn decode(bytes: &[u8]) -> Result<Self, Win16Error> {
        let bytes: &[u8; Self::SIZE] = bytes.try_into().map_err(|_| Win16Error::InvalidSize)?;
        let wire: NonClientCalcSize16Wire = zerocopy::transmute!(*bytes);
        let rect0: [u8; Rect16::SIZE] = zerocopy::transmute!(wire.rgrc[0]);
        let rect1: [u8; Rect16::SIZE] = zerocopy::transmute!(wire.rgrc[1]);
        let rect2: [u8; Rect16::SIZE] = zerocopy::transmute!(wire.rgrc[2]);
        Ok(Self {
            rgrc: [
                Rect16::decode(&rect0),
                Rect16::decode(&rect1),
                Rect16::decode(&rect2),
            ],
            lppos: wire.lppos.get(),
        })
    }

    /// Encodes the record as exactly 28 guest-format bytes.
    pub fn encode(self) -> [u8; Self::SIZE] {
        let wire = NonClientCalcSize16Wire {
            rgrc: [
                zerocopy::transmute!(self.rgrc[0].encode()),
                zerocopy::transmute!(self.rgrc[1].encode()),
                zerocopy::transmute!(self.rgrc[2].encode()),
            ],
            lppos: U32::new(self.lppos),
        };
        zerocopy::transmute!(wire)
    }
}

const _: () = {
    use nonclient_calc_size16_offsets as nccalc;

    assert!(core::mem::size_of::<Rect16Wire>() == Rect16::SIZE);
    assert!(core::mem::align_of::<Rect16Wire>() == 1);
    assert!(core::mem::size_of::<NonClientCalcSize16Wire>() == nccalc::SIZE);
    assert!(core::mem::align_of::<NonClientCalcSize16Wire>() == 1);
    assert!(core::mem::offset_of!(NonClientCalcSize16Wire, rgrc) == nccalc::RGRC0);
    assert!(core::mem::offset_of!(NonClientCalcSize16Wire, lppos) == nccalc::LPPOS);
    assert!(nccalc::RGRC0 == 0);
    assert!(nccalc::RGRC1 == 8);
    assert!(nccalc::RGRC2 == 16);
    assert!(nccalc::LPPOS == 24);
    assert!(nccalc::SIZE == 28);
    assert!(nccalc::RGRC1 == nccalc::RGRC0 + Rect16::SIZE);
    assert!(nccalc::RGRC2 == nccalc::RGRC1 + Rect16::SIZE);
    assert!(nccalc::LPPOS == nccalc::RGRC2 + Rect16::SIZE);
    assert!(nccalc::SIZE == nccalc::LPPOS + 4);
    assert!(WindowPos16::SIZE == windowpos16_offsets::SIZE);
    assert!(WindowPos16::SIZE == 14);
};
