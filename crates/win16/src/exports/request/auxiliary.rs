//! Windows 3.1 auxiliary-audio requests. Device ids and FAR values stay
//! guest integers; this module does not turn them into host pointers.

use zerocopy::byteorder::little_endian::{U16, U32};
use zerocopy::{Immutable, IntoBytes, KnownLayout, Unaligned};

/// Packed Windows 3.1 `AUXCAPS`. `VERSION` and `UINT` are 16-bit, `szPname`
/// is `MAXPNAMELEN` (32) ANSI bytes, and `dwSupport` follows `wTechnology`
/// with no Win32 `wReserved1` padding word.
pub const AUXCAPS16_SIZE: usize = 44;
pub const AUXCAPS_CDAUDIO: u16 = 1;
pub const AUXCAPS_AUXIN: u16 = 2;
pub const AUXCAPS_VOLUME: u32 = 0x0001;
pub const AUXCAPS_LRVOLUME: u32 = 0x0002;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16AuxCapabilities16 {
    pub manufacturer_id: u16,
    pub product_id: u16,
    pub driver_version: u16,
    pub product_name: [u8; 32],
    pub technology: u16,
    pub support: u32,
}

#[repr(C)]
#[derive(Clone, Copy, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct AuxCapabilities16Wire {
    manufacturer_id: U16,
    product_id: U16,
    driver_version: U16,
    product_name: [u8; 32],
    technology: U16,
    support: U32,
}

const _: () = {
    assert!(core::mem::size_of::<AuxCapabilities16Wire>() == AUXCAPS16_SIZE);
    assert!(core::mem::align_of::<AuxCapabilities16Wire>() == 1);
    assert!(core::mem::offset_of!(AuxCapabilities16Wire, manufacturer_id) == 0);
    assert!(core::mem::offset_of!(AuxCapabilities16Wire, product_id) == 2);
    assert!(core::mem::offset_of!(AuxCapabilities16Wire, driver_version) == 4);
    assert!(core::mem::offset_of!(AuxCapabilities16Wire, product_name) == 6);
    assert!(core::mem::offset_of!(AuxCapabilities16Wire, technology) == 38);
    assert!(core::mem::offset_of!(AuxCapabilities16Wire, support) == 40);
};

impl Win16AuxCapabilities16 {
    pub fn encode(self) -> [u8; AUXCAPS16_SIZE] {
        let wire = AuxCapabilities16Wire {
            manufacturer_id: U16::new(self.manufacturer_id),
            product_id: U16::new(self.product_id),
            driver_version: U16::new(self.driver_version),
            product_name: self.product_name,
            technology: U16::new(self.technology),
            support: U32::new(self.support),
        };
        let mut bytes = [0; AUXCAPS16_SIZE];
        bytes.copy_from_slice(wire.as_bytes());
        bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16AuxRequest {
    GetNumDevs,
    GetDevCaps {
        device: u16,
        output: u32,
        size: u16,
    },
    GetVolume {
        device: u16,
        output: u32,
    },
    SetVolume {
        device: u16,
        value: u32,
    },
    /// `dw1` and `dw2` stay the guest DWORD bits. A message whose parameter
    /// is a structure pointer is not loaded here.
    OutMessage {
        device: u16,
        message: u16,
        parameter1: u32,
        parameter2: u32,
    },
}
