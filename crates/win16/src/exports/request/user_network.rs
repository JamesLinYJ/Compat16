//! Checked USER/WFW network redirector requests.
//!
//! All strings and buffers owned here are copies of guest bytes. The runtime
//! validates FAR pointers before copying and performs output writes only
//! after the native redirector has returned.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16UserNetworkBuffer {
    pub far_pointer: u32,
    pub capacity: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16UserNetworkRequest {
    /// WNetErrorText returns BOOL, so an invalid output must project FALSE.
    ErrorTextBadPointer,
    BadPointer,
    ErrorText {
        error: u16,
        output: Win16UserNetworkBuffer,
    },
    OpenJob {
        queue: Vec<u8>,
        /// NULL asks the provider to choose the optional document title.
        job_name: Option<Vec<u8>>,
        copies: u16,
        hfile_output: u32,
    },
    CloseJob {
        hfile: u16,
        job_id_output: u32,
        queue_name_output: u32,
    },
    AbortJob {
        queue: Vec<u8>,
        hfile: u16,
    },
    HoldJob {
        queue: Vec<u8>,
        job_id: u16,
    },
    ReleaseJob {
        queue: Vec<u8>,
        job_id: u16,
    },
    CancelJob {
        queue: Vec<u8>,
        job_id: u16,
    },
    SetJobCopies {
        queue: Vec<u8>,
        job_id: u16,
        copies: u16,
    },
    WatchQueue {
        owner: u16,
        /// WNetWatchQueue's redirected local device name (for example LPT1:).
        local_device: Vec<u8>,
        user: Option<Vec<u8>>,
        /// The Win16 notification's queue number, echoed in WPARAM.
        n_queue: u16,
    },
    UnwatchQueue {
        local_device: Vec<u8>,
    },
    LockQueueData {
        queue: Vec<u8>,
        user: Option<Vec<u8>>,
        output: u32,
    },
    UnlockQueueData {
        queue: Vec<u8>,
    },
    GetConnection {
        local_name: Vec<u8>,
        output: Win16UserNetworkBuffer,
        length_output: u32,
    },
    GetCaps {
        index: u16,
    },
    DeviceMode {
        owner: u16,
    },
    BrowseDialog {
        owner: u16,
        resource_type: u16,
        path_output: u32,
    },
    GetUser {
        output: Win16UserNetworkBuffer,
        length_output: u32,
    },
    AddConnection {
        remote_name: Vec<u8>,
        password: Option<Vec<u8>>,
        local_name: Option<Vec<u8>>,
    },
    CancelConnection {
        local_name: Vec<u8>,
        force: bool,
    },
    GetError {
        error_output: u32,
    },
    GetErrorText {
        error: u16,
        output: Win16UserNetworkBuffer,
        length_output: u32,
    },
    Enable,
    Disable,
    Initialize,
    RestoreConnection {
        owner: u16,
        local_name: Option<Vec<u8>>,
    },
    WriteJob {
        hfile: u16,
        /// Retained as guest FAR values only. WFW/NTVDM sources confirm the
        /// pointer types but do not establish the LPINT direction or length
        /// contract, so the decoder must not dereference either pointer.
        data_far: u32,
        length_far: u32,
    },
    ConnectDialog {
        owner: u16,
        resource_type: u16,
    },
    DisconnectDialog {
        owner: u16,
        resource_type: u16,
    },
    ConnectionDialog {
        owner: u16,
        resource_type: u16,
    },
    ViewQueueDialog {
        owner: u16,
        queue: Vec<u8>,
    },
    PropertyDialog {
        owner: u16,
        button: u16,
        property: u16,
        name: Vec<u8>,
        resource_type: u16,
    },
    GetDirectoryType {
        path: Vec<u8>,
        type_output: u32,
    },
    DirectoryNotify {
        owner: u16,
        path: Vec<u8>,
        notification: u16,
    },
    GetPropertyText {
        button: u16,
        property: u16,
        name: Vec<u8>,
        button_name_output: Win16UserNetworkBuffer,
        resource_type: u16,
    },
}
