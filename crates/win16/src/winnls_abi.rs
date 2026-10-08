//! Checked Win16 WINNLS profile records.

use zerocopy::byteorder::little_endian::U16;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub const IMEPRO16_SIZE: usize = 176;
pub const IMEPRO16_WINDOW_OFFSET: usize = 0;
pub const IMEPRO16_DATE_OFFSET: usize = 2;
pub const IMEPRO16_VERSION_OFFSET: usize = 14;
pub const IMEPRO16_DESCRIPTION_OFFSET: usize = 16;
pub const IMEPRO16_NAME_OFFSET: usize = 66;
pub const IMEPRO16_OPTIONS_OFFSET: usize = 146;
pub const IMEPRO16_NAME_SIZE: usize = 80;

/// Owned values from the fixed Win16 `IMEPRO16` record.
///
/// These values are intentionally distinct from the native Windows profile
/// structure: the guest HWND and version are both 16-bit, and the fixed text
/// fields retain their original bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImeProfile16 {
    pub hwnd: u16,
    pub date: [u16; 6],
    pub version: u16,
    pub description: [u8; 50],
    pub name: [u8; 80],
    pub options: [u8; 30],
}

// The Win16 fixed record needs explicit little-endian, byte-aligned fields;
// host HWND/version widths and native struct alignment do not describe it.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct ImeProfile16Wire {
    hwnd: U16,
    date: [U16; 6],
    version: U16,
    description: [u8; 50],
    name: [u8; 80],
    options: [u8; 30],
}

const _: () = {
    assert!(core::mem::size_of::<ImeProfile16Wire>() == IMEPRO16_SIZE);
    assert!(core::mem::align_of::<ImeProfile16Wire>() == 1);
    assert!(core::mem::offset_of!(ImeProfile16Wire, hwnd) == IMEPRO16_WINDOW_OFFSET);
    assert!(core::mem::offset_of!(ImeProfile16Wire, date) == IMEPRO16_DATE_OFFSET);
    assert!(core::mem::offset_of!(ImeProfile16Wire, version) == IMEPRO16_VERSION_OFFSET);
    assert!(core::mem::offset_of!(ImeProfile16Wire, description) == IMEPRO16_DESCRIPTION_OFFSET);
    assert!(core::mem::offset_of!(ImeProfile16Wire, name) == IMEPRO16_NAME_OFFSET);
    assert!(core::mem::offset_of!(ImeProfile16Wire, options) == IMEPRO16_OPTIONS_OFFSET);
};

/// Encodes the exact fixed Win16 `IMEPRO16` byte layout.
pub fn encode_ime_profile16(profile: &ImeProfile16) -> [u8; IMEPRO16_SIZE] {
    let wire = ImeProfile16Wire {
        hwnd: U16::new(profile.hwnd),
        date: profile.date.map(U16::new),
        version: U16::new(profile.version),
        description: profile.description,
        name: profile.name,
        options: profile.options,
    };
    let mut bytes = [0; IMEPRO16_SIZE];
    bytes.copy_from_slice(wire.as_bytes());
    bytes
}
