//! Pointer-free bridge for the USER/WFW Win16 network redirector.
//!
//! Guest byte strings cross this boundary as owned data. Native WNet handles,
//! pointers, and UTF-16 buffers stay in the Windows adapter.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostNetworkRedirectorCall {
    AddConnection {
        remote_name: Vec<u8>,
        password: Option<Vec<u8>>,
        local_name: Option<Vec<u8>>,
    },
    CancelConnection {
        local_name: Vec<u8>,
        force: bool,
    },
    GetConnection {
        local_name: Vec<u8>,
    },
    GetUser,
    GetLastError,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostNetworkRedirectorValue {
    None,
    /// Full guest-encoded text without a trailing NUL.
    Text(Vec<u8>),
    /// The native error and provider message from `WNetGetLastErrorW`.
    LastError {
        code: u32,
        message: Vec<u8>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16HostNetworkRedirectorResult {
    /// Native WNet status returned by the host API.
    pub status: u32,
    pub value: Win16HostNetworkRedirectorValue,
}
