//! Owned legacy IME profiles crossing the guest/native boundary.

use crate::Win16HostWindow;

#[derive(Clone, Debug)]
pub struct Win16HostImeProfile {
    pub window: Option<Win16HostWindow>,
    pub date: [u16; 6],
    pub version: u32,
    pub description: [u8; 50],
    pub name: [u8; 80],
    pub options: [u8; 30],
}

#[derive(Clone, Debug)]
pub enum Win16HostImeProfileCall {
    Query { name: [u8; 80] },
    Get,
    Set { name: [u8; 80] },
}

#[derive(Clone, Debug)]
pub enum Win16HostImeProfileResult {
    Profile(Option<Win16HostImeProfile>),
    Status(bool),
}
