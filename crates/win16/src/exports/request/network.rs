//! Owned requests for the Win16 Winsock 1.x export family.
//!
//! Far pointers are either checked and copied during decoding or retained as
//! guest addresses for a later transactional runtime write. They never become
//! native pointers in this crate.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16GuestBuffer {
    pub far_pointer: u32,
    pub capacity: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16GuestInOutBuffer {
    pub buffer_far: u32,
    pub length_pointer: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16SocketSetInput {
    Null,
    Encoded { far_pointer: u32, bytes: Vec<u8> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16SelectInput {
    pub nfds: i16,
    pub read: Win16SocketSetInput,
    pub write: Win16SocketSetInput,
    pub except: Win16SocketSetInput,
    pub timeout: Option<[u8; 8]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostQuery {
    HostByAddress { address: Vec<u8>, address_type: i16 },
    HostByName(Vec<u8>),
    ProtocolByName(Vec<u8>),
    ProtocolByNumber(i16),
    ServiceByName { name: Vec<u8>, protocol: Option<Vec<u8>> },
    ServiceByPort { port_network_order: u16, protocol: Option<Vec<u8>> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16AsyncLookup {
    HostByAddress { address: Vec<u8>, address_type: i16 },
    HostByName(Vec<u8>),
    ProtocolByName(Vec<u8>),
    ProtocolByNumber(i16),
    ServiceByName { name: Vec<u8>, protocol: Option<Vec<u8>> },
    ServiceByPort { port_network_order: u16, protocol: Option<Vec<u8>> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16WinsockRequest {
    DecodeFailure { ordinal: u16, failure: Win16WinsockDecodeFailure },
    Accept { socket: u16, address: Option<Win16GuestInOutBuffer> },
    Bind { socket: u16, address: Vec<u8> },
    CloseSocket { socket: u16 },
    Connect { socket: u16, address: Vec<u8> },
    GetPeerName { socket: u16, address: Win16GuestInOutBuffer },
    GetSocketName { socket: u16, address: Win16GuestInOutBuffer },
    GetSocketOption { socket: u16, level: i16, option: i16, value: Win16GuestInOutBuffer },
    HostToNetworkLong(u32),
    HostToNetworkShort(u16),
    InetAddress(Vec<u8>),
    InetName(u32),
    IoctlSocket { socket: u16, command: u32, value_pointer: u32 },
    Listen { socket: u16, backlog: i16 },
    NetworkToHostLong(u32),
    NetworkToHostShort(u16),
    Receive { socket: u16, output: Win16GuestBuffer, flags: i16 },
    ReceiveFrom { socket: u16, output: Win16GuestBuffer, flags: i16, address: Option<Win16GuestInOutBuffer> },
    Select(Win16SelectInput),
    Send { socket: u16, bytes: Vec<u8>, flags: i16 },
    SendTo { socket: u16, bytes: Vec<u8>, flags: i16, address: Vec<u8> },
    SetSocketOption { socket: u16, level: i16, option: i16, value: Vec<u8> },
    Shutdown { socket: u16, how: i16 },
    CreateSocket { address_family: i16, socket_type: i16, protocol: i16 },
    Query(Win16HostQuery),
    AsyncQuery {
        window: u16,
        message: u16,
        lookup: Win16AsyncLookup,
        output: Win16GuestBuffer,
    },
    GetHostName { output: Win16GuestBuffer },
    AsyncSelect { socket: u16, window: u16, message: u16, events: u32 },
    CancelAsyncRequest { task: u16 },
    SetBlockingHook { callback: u32 },
    UnhookBlockingHook,
    GetLastError,
    SetLastError(u16),
    CancelBlockingCall,
    IsBlocking,
    Startup { version: u16, output: Win16GuestBuffer },
    Cleanup,
    IsSocketInSet { socket: u16, set: Vec<u8> },
    ReceiveEx { socket: u16, output: Win16GuestBuffer, flags_output: u32 },
    /// Export ordinal 2000 is a known empty-argument declaration. Its role as
    /// a default blocking hook remains a callback-architecture concern.
    DefaultHook,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16WinsockDecodeFailure { PointerFault, InvalidArgument }
