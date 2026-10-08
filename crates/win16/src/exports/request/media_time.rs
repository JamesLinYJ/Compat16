//! Synchronous Win16 multimedia timer requests.

use zerocopy::byteorder::little_endian::U16;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub const MMTIME16_SIZE: usize = 8;
pub const TIMECAPS16_SIZE: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16Mmtime16 {
    pub kind: u16,
    pub value: [u8; 6],
}

impl Win16Mmtime16 {
    pub fn encode(self) -> [u8; MMTIME16_SIZE] {
        zerocopy::transmute!(Mmtime16Wire {
            kind: U16::new(self.kind),
            value: self.value,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16TimeCaps16 {
    pub minimum_period: u16,
    pub maximum_period: u16,
}

impl Win16TimeCaps16 {
    pub fn encode(self) -> [u8; TIMECAPS16_SIZE] {
        zerocopy::transmute!(Timecaps16Wire {
            minimum_period: U16::new(self.minimum_period),
            maximum_period: U16::new(self.maximum_period),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16MediaTimeRequest {
    GetSystemTime { time: u32, size: u16 },
    GetDevCaps { caps: u32, size: u16 },
    BeginPeriod { period: u16 },
    EndPeriod { period: u16 },
    GetTime,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct Mmtime16Wire {
    pub(crate) kind: U16,
    pub(crate) value: [u8; 6],
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct Timecaps16Wire {
    pub(crate) minimum_period: U16,
    pub(crate) maximum_period: U16,
}

const _: () = {
    assert!(core::mem::size_of::<Mmtime16Wire>() == MMTIME16_SIZE);
    assert!(core::mem::align_of::<Mmtime16Wire>() == 1);
    assert!(core::mem::offset_of!(Mmtime16Wire, kind) == 0);
    assert!(core::mem::offset_of!(Mmtime16Wire, value) == 2);
    assert!(core::mem::size_of::<Timecaps16Wire>() == TIMECAPS16_SIZE);
    assert!(core::mem::align_of::<Timecaps16Wire>() == 1);
    assert!(core::mem::offset_of!(Timecaps16Wire, minimum_period) == 0);
    assert!(core::mem::offset_of!(Timecaps16Wire, maximum_period) == 2);
};
