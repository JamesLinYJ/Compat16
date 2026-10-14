//! Owned classic WMF values at the runtime/host boundary.
//!
//! Guest HMETAFILE is HGLOBAL-backed bytes. Native HMETAFILE never crosses
//! this boundary and is released within the synchronous host operation.

use crate::{Win16GuestPath, Win16HostDc};

#[derive(Clone, Debug)]
pub enum Win16HostMetafileOperation {
    Get { path: Win16GuestPath, maximum_bytes: u32 },
    CopyToFile { bits: Vec<u8>, path: Win16GuestPath, maximum_bytes: u32 },
    Play { dc: Win16HostDc, bits: Vec<u8> },
}

#[derive(Clone, Debug)]
pub enum Win16HostMetafileResult {
    Bits(Option<Vec<u8>>),
    Played(bool),
}
