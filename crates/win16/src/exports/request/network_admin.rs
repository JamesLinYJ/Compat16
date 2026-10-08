//! Owned Win16 NDDEAPI/NETAPI calls with known inventory signatures.
//! Unknown-signature exports are deliberately absent from these request types.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16NetworkAdminBuffer {
    pub far_pointer: u32,
    pub capacity: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16NddeRequest {
    ShareAdd { server: Option<Vec<u8>>, level: u16, info: Vec<u8>, declared_size: u32 },
    ShareDelete { server: Option<Vec<u8>>, share: Option<Vec<u8>>, reserved: u16 },
    ShareEnum { server: Option<Vec<u8>>, level: u16, output: Win16NetworkAdminBuffer, entries_read: u32, total_entries: u32 },
    ShareGetInfo { server: Option<Vec<u8>>, share: Option<Vec<u8>>, level: u16, output: Win16NetworkAdminBuffer, entries_read: u32, total_entries: u32 },
    ShareSetInfo { server: Option<Vec<u8>>, share: Option<Vec<u8>>, level: u16, info: Vec<u8>, declared_size: u32, reserved: u16 },
    GetClientInfo { level: u16, client_name: Win16NetworkAdminBuffer, user_name: Win16NetworkAdminBuffer },
    GetNodeName { output: Win16NetworkAdminBuffer },
    GetErrorString { error: u16, output: Win16NetworkAdminBuffer },
    ConnectionEnum { server: Option<Vec<u8>>, share: Option<Vec<u8>>, user: u32, level: u16, output: Win16NetworkAdminBuffer, entries_read: u32, total_entries: u32 },
    IsValidShareName(Option<Vec<u8>>),
    IsValidPassword(Option<Vec<u8>>),
    IsValidTopic(Option<Vec<u8>>),
    SessionEnum { server: Option<Vec<u8>>, level: u16, output: Win16NetworkAdminBuffer, entries_read: u32, total_entries: u32 },
    SessionClose { server: Option<Vec<u8>>, client: Option<Vec<u8>>, session: u32 },
    GetWindow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16NetworkAdminRequest {
    Ndde(Win16NddeRequest),
    NetWkstaGetInfo {
        server: Option<Vec<u8>>,
        level: u16,
        output: Win16NetworkAdminBuffer,
        bytes_read_output: u32,
    },
}

