//! Pointer-free request and result values exchanged with the native Winsock
//! adapter. Native `SOCKET` values and native resolver pointers stay inside
//! the host implementation; guest handles are mapped by `win16_network`.

use compat_services::win16_network::{HostEntryOwned, ProtocolEntryOwned, ServiceEntryOwned, WsaData16};
use guest_core::OwnerId;
use crate::{RuntimeError, Win16GuestNotificationSource, Win16HostWindow};

/// Opaque host socket identity. Windows SOCKET values never appear in guest state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostSocket(pub u64);

/// Opaque host async request identity, distinct from the guest's WORD task ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostAsyncTask(pub u64);

/// Exact host owner identity for one accepted resolver request. The source
/// id joins the shared Win16 notification namespace; the generation binds the
/// completion and cancellation to the captured runtime request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostAsyncRequest {
    pub task: Win16HostAsyncTask,
    pub source_id: u64,
    pub generation: u64,
}

/// Shared async registration identity returned for an accepted socket that
/// inherited its listener's `WSAAsyncSelect` route.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16HostAcceptedAsyncRegistration {
    pub source_id: u64,
    pub generation: u64,
    pub inherited_source_id: u64,
    pub inherited_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostSocketRetirementPhase {
    GuestClose,
    GuestCleanupReferenceReleased,
    RuntimeTeardown,
    FinalHostShutdown,
}

/// Native close failures carry the host's first typed cause across every
/// retry. Runtime keeps this same Arc while it owns the guest-facing token.
#[derive(Clone, Debug)]
pub struct Win16HostSocketRetirementFailure {
    pub socket: Win16HostSocket,
    pub owner: Win16NetworkTaskIdentity,
    pub phase: Win16HostSocketRetirementPhase,
    pub wsa_error: i32,
    pub first_cause: std::sync::Arc<RuntimeError>,
}

/// Receipt for the irreversible process Winsock reference release. Socket
/// close failures are separate and cannot be projected as Cleanup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostNetworkReferenceRelease {
    pub owner: Win16NetworkTaskIdentity,
    pub task_final: bool,
}

/// Exact Win16 task incarnation captured when an asynchronous request is
/// accepted. The guest HTASK word alone may be recycled after task teardown.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Win16NetworkTaskIdentity {
    pub owner: OwnerId,
    pub guest_htask: u16,
    pub selector_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostNetworkNameQuery {
    HostByAddress { address: Vec<u8>, address_type: i16 },
    HostByName(Vec<u8>),
    ProtocolByName(Vec<u8>),
    ProtocolByNumber(i16),
    ServiceByName { name: Vec<u8>, protocol: Option<Vec<u8>> },
    ServiceByPort { port_network_order: u16, protocol: Option<Vec<u8>> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostNetworkNameResult {
    Host(HostEntryOwned),
    Protocol(ProtocolEntryOwned),
    Service(ServiceEntryOwned),
    HostName(Vec<u8>),
    NotFound,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostSocketOptionInput {
    Win16SignedInt(i16),
    Opaque(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostSocketOptionEncoding { Win16SignedInt, Opaque }

/// Exact host-owned SO_ERROR read whose guest get-and-clear phase has not yet
/// committed. The guest output transaction must succeed before this token is
/// acknowledged; the native value is never reread to retry that transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostSocketErrorReadToken {
    pub socket: Win16HostSocket,
    pub generation: u64,
    pub connect_attempt: Option<u64>,
}

/// Complete pointer-free operation set for the 49 declared WINSOCK exports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostNetworkCall {
    Startup { task: Win16NetworkTaskIdentity, version: u16 },
    Cleanup { task: Win16NetworkTaskIdentity, task_final: bool },
    CreateSocket { task: Win16NetworkTaskIdentity, address_family: i16, socket_type: i16, protocol: i16 },
    CloseSocket { socket: Win16HostSocket, owner: Win16NetworkTaskIdentity },
    RetireSocket { socket: Win16HostSocket, owner: Win16NetworkTaskIdentity },
    Bind { socket: Win16HostSocket, address: Vec<u8> },
    Accept {
        task: Win16NetworkTaskIdentity,
        socket: Win16HostSocket,
        address_capacity: Option<i16>,
        inherited_registration_generation: Option<u64>,
    },
    Connect { socket: Win16HostSocket, address: Vec<u8> },
    GetPeerName { socket: Win16HostSocket, address_capacity: i16 },
    GetSocketName { socket: Win16HostSocket, address_capacity: i16 },
    GetSocketOption {
        socket: Win16HostSocket, level: i16, option: i16, capacity: i16,
        encoding: Win16HostSocketOptionEncoding,
    },
    AcknowledgeSocketError { token: Win16HostSocketErrorReadToken },
    SetSocketOption {
        socket: Win16HostSocket, level: i16, option: i16, value: Win16HostSocketOptionInput,
    },
    IoctlSocket { socket: Win16HostSocket, command: u32, value: u32 },
    Listen { socket: Win16HostSocket, backlog: i16 },
    Shutdown { socket: Win16HostSocket, how: i16 },
    Receive { socket: Win16HostSocket, capacity: i16, flags: i16 },
    ReceiveFrom { socket: Win16HostSocket, capacity: i16, flags: i16, address_capacity: Option<i16> },
    RearmAsyncEvent {
        socket: Win16HostSocket,
        source_id: u64,
        registration_generation: u64,
        events: u32,
    },
    Send { socket: Win16HostSocket, bytes: Vec<u8>, flags: i16 },
    SendTo { socket: Win16HostSocket, bytes: Vec<u8>, flags: i16, address: Vec<u8> },
    Select {
        read: Option<Vec<Win16HostSocket>>,
        write: Option<Vec<Win16HostSocket>>,
        except: Option<Vec<Win16HostSocket>>,
        timeout: Option<[u8; 8]>,
    },
    HostToNetworkLong(u32),
    HostToNetworkShort(u16),
    NetworkToHostLong(u32),
    NetworkToHostShort(u16),
    InetAddress(Vec<u8>),
    InetName(u32),
    Query(Win16HostNetworkNameQuery),
    GetHostName { capacity: i16 },
    AsyncSelect {
        socket: Win16HostSocket,
        task: Win16NetworkTaskIdentity,
        window: Win16HostWindow,
        guest_hwnd: u16,
        message: u16,
        events: u32,
        registration_generation: u64,
        expected_source_id: Option<u64>,
    },
    AsyncQuery {
        task: Win16NetworkTaskIdentity,
        window: Win16HostWindow,
        guest_hwnd: u16,
        message: u16,
        query: Win16HostNetworkNameQuery,
        capacity: i16,
        request_generation: u64,
    },
    CancelAsyncRequest { request: Win16HostAsyncRequest, owner: Win16NetworkTaskIdentity },
    CancelBlockingCall,
    IsBlocking,
    IsSocketInSet { socket: Win16HostSocket, set: Vec<Win16HostSocket> },
    ReceiveEx { socket: Win16HostSocket, capacity: i16 },
}

#[derive(Clone, Debug)]
pub enum Win16HostNetworkValue {
    None,
    Cleanup {
        reference_release: Win16HostNetworkReferenceRelease,
        socket_retire_failures: Vec<Win16HostSocketRetirementFailure>,
    },
    SocketRetirementFailure(Win16HostSocketRetirementFailure),
    Signed(i32),
    Unsigned(u32),
    Socket(Option<Win16HostSocket>),
    AsyncTask(Option<Win16HostAsyncRequest>),
    AsyncRegistration { source_id: u64, generation: u64 },
    Bytes { bytes: Vec<u8>, count: i32 },
    Accepted {
        socket: Win16HostSocket,
        address: Vec<u8>,
        required: i32,
        async_registration: Option<Win16HostAcceptedAsyncRegistration>,
    },
    ReceivedFrom { bytes: Vec<u8>, count: i32, address: Vec<u8>, required: i32 },
    ReceiveEx { bytes: Vec<u8>, count: i32, flags: u16 },
    Address { bytes: Vec<u8>, required: i32 },
    SocketOption { bytes: Vec<u8>, required: i32 },
    SocketOptionPendingRead {
        bytes: Vec<u8>, required: i32, token: Win16HostSocketErrorReadToken,
    },
    Selected {
        ready_count: i32,
        read: Option<Vec<Win16HostSocket>>,
        write: Option<Vec<Win16HostSocket>>,
        except: Option<Vec<Win16HostSocket>>,
    },
    NameQuery(Option<Win16HostNetworkNameResult>),
    HostName(Vec<u8>),
    InetText(Vec<u8>),
    Startup(WsaData16),
    IoctlValue(u32),
}

/// Asynchronous host notifications are copied before crossing into runtime.
/// The runtime maps the opaque host token to a guest socket/task and a guest
/// message target; native SOCKET values never enter WPARAM or LPARAM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostNetworkEvent {
    SocketReady {
        source: Win16GuestNotificationSource,
        socket: Win16HostSocket,
        task: Win16NetworkTaskIdentity,
        registration_generation: u64,
        window: Win16HostWindow,
        guest_hwnd: u16,
        message: u16,
        event: u16,
        error: u16,
    },
    AsyncQueryComplete {
        source: Win16GuestNotificationSource,
        task: Win16HostAsyncTask,
        owner: Win16NetworkTaskIdentity,
        window: Win16HostWindow,
        guest_hwnd: u16,
        message: u16,
        capacity: i16,
        request_generation: u64,
        result: Result<Win16HostNetworkNameResult, i32>,
    },
}

/// Winsock errors remain ordinary guest-visible results, separate from runtime
/// protocol failures. The runtime stores this code for WSAGetLastError.
#[derive(Clone, Debug)]
pub struct Win16HostNetworkResult {
    pub value: Win16HostNetworkValue,
    pub wsa_error: i32,
}
