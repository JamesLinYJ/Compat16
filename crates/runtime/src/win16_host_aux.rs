//! Pointer-free auxiliary-audio host contract.
//!
//! Device ids are guest words. Capability and volume bytes are owned copies.
//! Nothing in this contract is a host audio device or a host pointer.

pub const MMSYSERR_NOERROR: u32 = 0;
pub const MMSYSERR_BADDEVICEID: u32 = 2;
pub const MMSYSERR_INVALPARAM: u32 = 11;

/// Owned Windows 3.1 `AUXCAPS` fields. `product_name` is 32 ANSI bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostAuxCapabilities {
    pub manufacturer_id: u16,
    pub product_id: u16,
    pub driver_version: u16,
    pub product_name: [u8; 32],
    pub technology: u16,
    pub support: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostAuxOperation {
    GetNumDevs,
    GetDevCaps {
        device: u16,
    },
    GetVolume {
        device: u16,
    },
    SetVolume {
        device: u16,
        value: u32,
    },
    OutMessage {
        device: u16,
        message: u16,
        parameter1: u32,
        parameter2: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostAuxResult {
    Count(u16),
    Capabilities {
        result: u32,
        capabilities: Option<Win16HostAuxCapabilities>,
    },
    Volume {
        result: u32,
        value: Option<u32>,
    },
    Status(u32),
}
