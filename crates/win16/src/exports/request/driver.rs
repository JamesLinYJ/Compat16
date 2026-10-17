//! Decoded arguments for driver and deferred-device exports.
//!
//! Far values stay guest 16:16 dwords. They are not host pointers.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16DriverArg {
    Word(u16),
    Dword(u32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16DriverCall {
    pub arguments: Vec<Win16DriverArg>,
}
