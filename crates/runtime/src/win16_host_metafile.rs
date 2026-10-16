//! Owned classic WMF values at the runtime/host boundary.
//!
//! Guest HMETAFILE is HGLOBAL-backed bytes. Native HMETAFILE never crosses
//! this boundary and is released within the synchronous host operation.

use crate::{Win16GuestPath, Win16HostDc};

#[derive(Clone, Debug)]
pub enum Win16HostMetafileOperation {
    Create { path: Option<Win16GuestPath> },
    Close { dc: Win16HostDc, maximum_bytes: u32 },
    Get { path: Win16GuestPath, maximum_bytes: u32 },
    CopyToFile { bits: Vec<u8>, path: Win16GuestPath, maximum_bytes: u32 },
    Play { dc: Win16HostDc, bits: Vec<u8> },
    CallbackTable { callback: crate::Win16HostCallback },
    CommitCallbackTable { callback: crate::Win16HostCallback, objects: Vec<Option<crate::Win16HostGdiObject>> },
    /// A copied METARECORD and opaque, process-owned object identities.
    PlayRecord { dc: Win16HostDc, callback: Option<crate::Win16HostCallback>, record: Vec<u8>, objects: Vec<Option<crate::Win16HostGdiObject>> },
}

#[derive(Clone, Debug)]
pub enum Win16HostMetafileResult {
    Created(Option<Win16HostDc>),
    Closed { consumed: bool, bits: Option<Vec<u8>> },
    Bits(Option<Vec<u8>>),
    Played(bool),
    Table(Vec<Option<crate::Win16HostGdiObject>>),
    TableCommitted,
    Record { success: bool, objects: Vec<Option<crate::Win16HostGdiObject>>,
        retired: Vec<crate::Win16HostGdiObject> },
}
