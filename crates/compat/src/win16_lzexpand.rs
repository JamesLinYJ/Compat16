//! Signed Win16 `HFILE` rules shared by LZEXPAND bridge operations.
//!
//! LZEXPAND does not own a separate guest handle namespace. Its routines accept
//! ordinary DOS/Win16 file handles as well as the handles returned by
//! `LZOpenFile` and `LZInit`; the runtime resolves every value through its
//! single task file table before asking the host adapter to perform an LZ call.

/// A usable guest file number. The Win16 API returns `-1` as `HFILE_ERROR`;
/// valid positive file numbers must remain representable by its signed INT16
/// return and parameter slots.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16LzFileHandle(i16);

/// Byte size of the Win16 `OFSTRUCT` layout used by LZOpenFile.
pub const OFSTRUCT_BYTES: usize = 136;

impl Win16LzFileHandle {
    pub const ERROR: i16 = -1;

    pub const fn from_signed(value: i16) -> Option<Self> {
        if value < 0 { None } else { Some(Self(value)) }
    }

    pub const fn from_guest_word(value: u16) -> Option<Self> {
        if value <= i16::MAX as u16 { Some(Self(value as i16)) } else { None }
    }

    pub const fn signed(self) -> i16 {
        self.0
    }

    pub const fn guest_word(self) -> u16 {
        self.0 as u16
    }
}
