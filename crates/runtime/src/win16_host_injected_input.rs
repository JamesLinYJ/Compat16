//! Scalar synthesized input passed to the host.
//!
//! `extra_info` remains the guest DWORD. It is not a host pointer.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16InjectedKey {
    pub virtual_key: u8,
    pub scan: u8,
    pub flags: u32,
    pub extra_info: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16InjectedMouse {
    pub flags: u16,
    pub dx: i32,
    pub dy: i32,
    pub buttons: u16,
    pub extra_info: u32,
}
