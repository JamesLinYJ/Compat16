//! WinSock 1.x guest bridge.
//!
//! Guest FAR inputs and outputs are captured before native calls, and
//! asynchronous work is owned by the host until runtime safe-point delivery
//! and exact source ACK. Blocking-call callback pumping remains a separately
//! tracked compatibility gap until network calls have resumable continuations.

use compat_services::win16_network::{
    WSAEFAULT, WSAEINVAL, WSAENOBUFS, WSAENOTSOCK, WSAEOPNOTSUPP,
    WSADATA16_SIZE, WSANOTINITIALISED,
};
use guest_core::memory::Memory;
use win16_abi::{
    Access, Win16GuestInOutBuffer, Win16WinsockDecodeFailure, Win16WinsockRequest,
};

use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostNetworkCall, Win16HostNetworkResult, Win16HostNetworkValue, Win16HostSocket,
    Win16HostSocketOptionEncoding, Win16HostSocketOptionInput, Win16NetworkTaskIdentity,
};
use super::{guest_ranges::{commit_guest_writes, GuestOutputRange}, Win16State};

#[path = "win16_runtime_network_io.rs"]
mod io;
#[path = "win16_runtime_network_lifecycle.rs"]
mod lifecycle;
#[path = "win16_runtime_network_cleanup.rs"]
mod cleanup;
#[path = "win16_runtime_network_resolver.rs"]
mod resolver;
#[path = "win16_runtime_network_async.rs"]
mod async_ops;
#[path = "win16_runtime_network_events.rs"]
mod events;
#[path = "win16_runtime_network_sockets.rs"]
mod sockets;
#[path = "win16_runtime_network_startup.rs"]
mod startup;

const SOCKET_ERROR_WORD: u32 = u16::MAX as u32;
const GLOBAL_MOVEABLE_ZEROINIT: u16 = 0x0042;
const SOL_SOCKET_WORD: u16 = 0xffff;
// Winsock FIONBIO: _IOW('f', 126, u_long).
const WIN16_FIONBIO: u32 = 0x8004_667e;

#[derive(Debug)]
struct NativeWinsockError(i32);

impl std::fmt::Display for NativeWinsockError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "native Winsock error {}", self.0)
    }
}

impl std::error::Error for NativeWinsockError {}

struct PreparedInOut {
    buffer: GuestOutputRange,
    length: GuestOutputRange,
    capacity: i16,
}

struct PreparedFdSet {
    range: Option<GuestOutputRange>,
    sockets: Option<Vec<Win16HostSocket>>,
}

enum SetPrepareError {
    Winsock(i32),
    Runtime(RuntimeError),
}

impl Win16State {
    pub(crate) fn winsock_api(
        &mut self,
        request: Win16WinsockRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let task = self.current_task_handle()?;
        let task_identity = self.winsock_task_identity(task)?;
        self.network.bind_task_identity(task, task_identity);
        if Self::requires_guest_startup(&request)
            && self.network.startup_references_for_task(task_identity) == 0
        {
            return Ok(self.fail_request(task, &request, WSANOTINITIALISED));
        }
        match request {
            Win16WinsockRequest::DecodeFailure { ordinal, failure } =>
                self.winsock_decode_failure(task, ordinal, failure, None, host),
            Win16WinsockRequest::Startup { version, output } => {
                self.winsock_startup(task, task_identity, version, output.far_pointer, memory, host)
            }
            Win16WinsockRequest::Cleanup => self.winsock_cleanup(task, task_identity, host),
        Win16WinsockRequest::CreateSocket { address_family, socket_type, protocol } =>
                self.winsock_create_socket(task, task_identity, address_family, socket_type, protocol, host),
            Win16WinsockRequest::CloseSocket { socket } => self.winsock_close_socket(task, socket, host),
            Win16WinsockRequest::Bind { socket, address } => self.winsock_signed(
                task, match self.host_socket(socket) {
                    Some(host_socket) => Win16HostNetworkCall::Bind { socket: host_socket, address },
                    None => return Ok(self.fail_int(task, WSAENOTSOCK)),
                }, host,
            ),
            Win16WinsockRequest::Connect { socket, address } => self.winsock_signed(
                task, match self.host_socket(socket) {
                    Some(host_socket) => Win16HostNetworkCall::Connect { socket: host_socket, address },
                    None => return Ok(self.fail_int(task, WSAENOTSOCK)),
                }, host,
            ),
            Win16WinsockRequest::Accept { socket, address } =>
                self.winsock_accept(task, task_identity, socket, address, memory, host),
            Win16WinsockRequest::GetPeerName { socket, address } =>
                self.winsock_get_address(task, socket, address, true, memory, host),
            Win16WinsockRequest::GetSocketName { socket, address } =>
                self.winsock_get_address(task, socket, address, false, memory, host),
            Win16WinsockRequest::GetSocketOption { socket, level, option, value } =>
                self.winsock_get_option(task, socket, level, option, value, memory, host),
            Win16WinsockRequest::SetSocketOption { socket, level, option, value } => {
                let host_socket = match self.host_socket(socket) {
                    Some(value) => value,
                    None => return Ok(self.fail_int(task, WSAENOTSOCK)),
                };
                let input = match Self::socket_option_encoding(level, option) {
                    Some(_) if value.len() != 2 => return Ok(self.fail_int(task, WSAEINVAL)),
                    Some(_) => Win16HostSocketOptionInput::Win16SignedInt(i16::from_le_bytes(
                        [value[0], value[1]])),
                    None => Win16HostSocketOptionInput::Opaque(value),
                };
                self.winsock_signed(task, Win16HostNetworkCall::SetSocketOption {
                    socket: host_socket, level, option, value: input,
                }, host)
            }
            Win16WinsockRequest::IoctlSocket { socket, command, value_pointer } =>
                self.winsock_ioctl(task, socket, command, value_pointer, memory, host),
            Win16WinsockRequest::Listen { socket, backlog } => {
                let host_socket = match self.host_socket(socket) {
                    Some(value) => value,
                    None => return Ok(self.fail_int(task, WSAENOTSOCK)),
                };
                self.winsock_signed(task, Win16HostNetworkCall::Listen { socket: host_socket, backlog }, host)
            }
            Win16WinsockRequest::Shutdown { socket, how } => {
                let host_socket = match self.host_socket(socket) {
                    Some(value) => value,
                    None => return Ok(self.fail_int(task, WSAENOTSOCK)),
                };
                self.winsock_signed(task, Win16HostNetworkCall::Shutdown { socket: host_socket, how }, host)
            }
            Win16WinsockRequest::Receive { socket, output, flags } =>
                self.winsock_receive(task, socket, output.far_pointer, output.capacity, flags, memory, host),
            Win16WinsockRequest::ReceiveFrom { socket, output, flags, address } =>
                self.winsock_receive_from(task, socket, output.far_pointer, output.capacity, flags, address, memory, host),
            Win16WinsockRequest::Select(input) => self.winsock_select(task, input, memory, host),
            Win16WinsockRequest::Send { socket, bytes, flags } => {
                let host_socket = match self.host_socket(socket) {
                    Some(value) => value,
                    None => return Ok(self.fail_int(task, WSAENOTSOCK)),
                };
                if bytes.len() > i16::MAX as usize { return Ok(self.fail_int(task, WSAEINVAL)); }
                self.winsock_signed(task, Win16HostNetworkCall::Send { socket: host_socket, bytes, flags }, host)
            }
            Win16WinsockRequest::SendTo { socket, bytes, flags, address } => {
                let host_socket = match self.host_socket(socket) {
                    Some(value) => value,
                    None => return Ok(self.fail_int(task, WSAENOTSOCK)),
                };
                if bytes.len() > i16::MAX as usize { return Ok(self.fail_int(task, WSAEINVAL)); }
                self.winsock_signed(task, Win16HostNetworkCall::SendTo {
                    socket: host_socket, bytes, flags, address,
                }, host)
            }
            Win16WinsockRequest::HostToNetworkLong(value) => self.winsock_unsigned(
                task, Win16HostNetworkCall::HostToNetworkLong(value), host,
            ),
            Win16WinsockRequest::HostToNetworkShort(value) => self.winsock_unsigned(
                task, Win16HostNetworkCall::HostToNetworkShort(value), host,
            ),
            Win16WinsockRequest::NetworkToHostLong(value) => self.winsock_unsigned(
                task, Win16HostNetworkCall::NetworkToHostLong(value), host,
            ),
            Win16WinsockRequest::NetworkToHostShort(value) => self.winsock_unsigned(
                task, Win16HostNetworkCall::NetworkToHostShort(value), host,
            ),
            Win16WinsockRequest::InetAddress(address) => self.winsock_unsigned(
                task, Win16HostNetworkCall::InetAddress(address), host,
            ),
            Win16WinsockRequest::InetName(address) => self.winsock_inet_name(task, address, memory, host),
            Win16WinsockRequest::Query(query) => self.winsock_query(task, query, memory, host),
            Win16WinsockRequest::GetHostName { output } =>
                self.winsock_hostname(task, output.far_pointer, output.capacity, memory, host),
            Win16WinsockRequest::AsyncSelect { socket, window, message, events } =>
                self.winsock_async_select(task, socket, window, message, events, host),
            Win16WinsockRequest::AsyncQuery { window, message, lookup, output } =>
                self.winsock_async_query(task, window, message, lookup, output, memory, host),
            Win16WinsockRequest::CancelAsyncRequest { task: guest_task } =>
                self.winsock_cancel_async_request(task, guest_task, host),
            Win16WinsockRequest::SetBlockingHook { .. } => Ok(self.unsupported(task, 109, "WSASetBlockingHook", 0, host)),
            Win16WinsockRequest::UnhookBlockingHook => Ok(self.unsupported(
                task, 110, "WSAUnhookBlockingHook", SOCKET_ERROR_WORD, host,
            )),
            Win16WinsockRequest::GetLastError => Ok(u32::from(self.network.last_error(task))),
            Win16WinsockRequest::SetLastError(error) => { self.network.set_last_error(task, error); Ok(0) }
            Win16WinsockRequest::CancelBlockingCall => Ok(self.unsupported(task, 113, "WSACancelBlockingCall", SOCKET_ERROR_WORD, host)),
            Win16WinsockRequest::IsBlocking => Ok(u32::from(self.network.is_blocking(task))),
            Win16WinsockRequest::IsSocketInSet { socket, set } => Ok(self.winsock_is_set(task, socket, &set)),
            Win16WinsockRequest::ReceiveEx { socket, output, flags_output } =>
                self.winsock_receive_ex(task, socket, output.far_pointer, output.capacity, flags_output, memory, host),
            Win16WinsockRequest::DefaultHook => Ok(self.unsupported(task, 2000, "default blocking hook", 0, host)),
        }
    }
}

impl Win16State {
    fn host_socket(&self, guest: u16) -> Option<Win16HostSocket> { self.network.host_socket(guest) }

    /// Winsock 1.1's standard scalar socket options use C `int`/`BOOL` values;
    /// the Win16 SDK ABI stores those as signed 16-bit `int`. SO_LINGER is a
    /// separate two-WORD structure, and provider-specific values stay opaque.
    fn socket_option_encoding(level: i16, option: i16) -> Option<Win16HostSocketOptionEncoding> {
        let level = level as u16;
        let option = option as u16;
        let scalar = (level == SOL_SOCKET_WORD && matches!(option,
            0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0040 | 0x0100
            | 0x1001 | 0x1002 | 0x1003 | 0x1004 | 0x1005 | 0x1006 | 0x1007 | 0x1008
            | 0x2003 | 0xff7f))
            || (level == 6 && option == 1); // IPPROTO_TCP / TCP_NODELAY
        scalar.then_some(Win16HostSocketOptionEncoding::Win16SignedInt)
    }

    fn requires_guest_startup(request: &Win16WinsockRequest) -> bool {
        !matches!(request,
            Win16WinsockRequest::Startup { .. } | Win16WinsockRequest::Cleanup
            | Win16WinsockRequest::GetLastError | Win16WinsockRequest::SetLastError(_)
            | Win16WinsockRequest::HostToNetworkLong(_) | Win16WinsockRequest::HostToNetworkShort(_)
            | Win16WinsockRequest::NetworkToHostLong(_) | Win16WinsockRequest::NetworkToHostShort(_)
            | Win16WinsockRequest::InetAddress(_)
            | Win16WinsockRequest::IsSocketInSet { .. } | Win16WinsockRequest::DefaultHook
            | Win16WinsockRequest::DecodeFailure { ordinal: 8..=10 | 14..=15 | 111..=112 | 115..=116, .. }
            | Win16WinsockRequest::DecodeFailure { ordinal: 151, .. }
        )
    }

    fn fail_request(&mut self, task: u16, request: &Win16WinsockRequest, error: i32) -> u32 {
        match request {
            Win16WinsockRequest::Query(_) | Win16WinsockRequest::InetName(_)
            | Win16WinsockRequest::AsyncQuery { .. }
            | Win16WinsockRequest::SetBlockingHook { .. }
            | Win16WinsockRequest::IsBlocking
            | Win16WinsockRequest::DecodeFailure { ordinal: 11 | 51..=56 | 102..=107 | 109 | 114, .. } =>
                self.fail_pointer(task, error),
            Win16WinsockRequest::DecodeFailure { ordinal: 10, .. } => {
                self.network.record_host_error(task, error);
                u32::MAX
            }
            _ => self.fail_int(task, error),
        }
    }

    fn winsock_decode_failure(
        &mut self,
        task: u16,
        ordinal: u16,
        failure: Win16WinsockDecodeFailure,
        socket: Option<u16>,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let error = match failure {
            Win16WinsockDecodeFailure::PointerFault => WSAEFAULT,
            Win16WinsockDecodeFailure::InvalidArgument => WSAEINVAL,
        };
        if let Some(guest_socket) = socket {
            let events = match ordinal {
                1 => 0x0008,
                16 | 17 | 1107 => 0x0001 | 0x0004,
                _ => 0,
            };
            if events != 0
                && let Some(host_socket) = self.network.host_socket(guest_socket)
                && let Err(rearm_error) = self.rearm_async_events(
                    guest_socket, host_socket, events, host,
                )
            {
                host.report_diagnostic(rearm_error.diagnostic());
            }
        }
        match ordinal {
            10 => {
                self.network.record_host_error(task, error);
                Ok(u32::MAX)
            }
            51..=56 | 11 | 102..=107 => Ok(self.fail_pointer(task, error)),
            // WSAFDIsSet is an inline BOOL helper. Malformed input has no
            // SOCKET_ERROR sentinel; preserve its false return shape.
            151 => {
                self.network.record_host_error(task, error);
                Ok(0)
            }
            115 => Ok(u32::from(error as u16)),
            _ => Ok(self.fail_int(task, error)),
        }
    }

    fn fail_int(&mut self, task: u16, error: i32) -> u32 {
        self.network.record_host_error(task, error);
        SOCKET_ERROR_WORD
    }

    fn fail_pointer(&mut self, task: u16, error: i32) -> u32 {
        self.network.record_host_error(task, error);
        0
    }

    fn unsupported(
        &mut self,
        task: u16,
        ordinal: u16,
        name: &str,
        failure: u32,
        host: &mut impl RuntimeHost,
    ) -> u32 {
        self.network.set_last_error(task, WSAEOPNOTSUPP as u16);
        if self.network.mark_unsupported_warned(ordinal) {
            host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                format!("WinSock {name} is disabled until the guest callback path is available")));
        }
        failure
    }

    fn report_host_failure(&mut self, task: u16, error: i32) {
        if error != 0 { self.network.record_host_error(task, error); }
    }

    fn capture_network_output(
        &self,
        memory: &Memory,
        far: u32,
        length: usize,
    ) -> Result<Option<GuestOutputRange>, RuntimeError> {
        if far == 0 && length == 0 { return Ok(None); }
        let pointer = self.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
        self.selectors.translate(pointer, Access::Write, length, memory).map_err(crate::runtime_error)?;
        GuestOutputRange::capture(self, memory, pointer, length).map(Some)
    }

    fn capture_inout(
        &self,
        memory: &Memory,
        buffer_far: u32,
        length_far: u32,
    ) -> Result<PreparedInOut, RuntimeError> {
        if buffer_far == 0 || length_far == 0 {
            return Err(RuntimeError::new(Kind::GuestFault, "WinSock in/out FAR pointer is null"));
        }
        let length = self.capture_network_output(memory, length_far, 2)?.ok_or_else(||
            RuntimeError::new(Kind::GuestFault, "WinSock length output is null"))?;
        let bytes = length.read(self, memory)?;
        let raw = u16::from_le_bytes([bytes[0], bytes[1]]);
        let capacity = raw as i16;
        if capacity < 0 {
            return Err(RuntimeError::new(Kind::InvalidInput, "WinSock buffer capacity is a negative Win16 int"));
        }
        let buffer = self.capture_network_output(memory, buffer_far, usize::try_from(capacity).unwrap_or(0))?
            .ok_or_else(|| RuntimeError::new(Kind::GuestFault, "WinSock buffer output is null"))?;
        Ok(PreparedInOut { buffer, length, capacity })
    }

    fn capture_buffer(
        &self,
        memory: &Memory,
        far: u32,
        raw_capacity: u16,
    ) -> Result<(i16, Option<GuestOutputRange>), RuntimeError> {
        let capacity = raw_capacity as i16;
        if capacity < 0 {
            return Err(RuntimeError::new(Kind::InvalidInput, "WinSock buffer capacity is a negative Win16 int"));
        }
        let range = self.capture_network_output(memory, far, usize::try_from(capacity).unwrap_or(0))?;
        Ok((capacity, range))
    }

    fn map_range_error(error: RuntimeError) -> Result<i32, RuntimeError> {
        match error.kind() {
            Kind::GuestFault => Ok(WSAEFAULT),
            Kind::InvalidInput => Ok(WSAEINVAL),
            _ => Err(error),
        }
    }

    fn commit_outputs(
        &self,
        memory: &mut Memory,
        writes: Vec<(GuestOutputRange, Vec<u8>)>,
    ) -> Result<(), RuntimeError> {
        commit_guest_writes(self, memory, writes)
    }

    fn int_return(value: i32) -> u32 { u32::from(value as u16) }

    fn result_error(&mut self, task: u16, error: i32, failure: u32) -> u32 {
        self.report_host_failure(task, error);
        failure
    }

    fn expect_signed(result: Win16HostNetworkValue) -> Result<i32, RuntimeError> {
        match result {
            Win16HostNetworkValue::Signed(value) => Ok(value),
            _ => Err(RuntimeError::new(Kind::InternalInvariant, "WinSock host returned a mismatched signed result")),
        }
    }

    fn expect_unsigned(result: Win16HostNetworkValue) -> Result<u32, RuntimeError> {
        match result {
            Win16HostNetworkValue::Unsigned(value) => Ok(value),
            _ => Err(RuntimeError::new(Kind::InternalInvariant, "WinSock host returned a mismatched unsigned result")),
        }
    }

    /// Mark only synchronous operations that can wait on socket readiness or
    /// a resolver. Callback-hook pumping remains unsupported; this flag keeps
    /// WSAIsBlocking accurate while the host call is in progress.
    pub(super) fn win16_network_call_with_blocking(
        &mut self,
        task: u16,
        call: Win16HostNetworkCall,
        host: &mut impl RuntimeHost,
    ) -> Result<Win16HostNetworkResult, RuntimeError> {
        let socket_is_blocking = |socket: Win16HostSocket| {
            self.network
                .host_socket_nonblocking(socket)
                .map_or(true, |nonblocking| !nonblocking)
        };
        let may_block = match &call {
            Win16HostNetworkCall::Accept { socket, .. }
            | Win16HostNetworkCall::Connect { socket, .. }
            | Win16HostNetworkCall::Receive { socket, .. }
            | Win16HostNetworkCall::ReceiveFrom { socket, .. }
            | Win16HostNetworkCall::ReceiveEx { socket, .. }
            | Win16HostNetworkCall::Send { socket, .. }
            | Win16HostNetworkCall::SendTo { socket, .. } => socket_is_blocking(*socket),
            Win16HostNetworkCall::Query(_) => true,
            Win16HostNetworkCall::Select { timeout, .. } => timeout
                .map_or(true, |value| value.iter().any(|byte| *byte != 0)),
            _ => false,
        };
        let mark_blocking = may_block && !self.network.is_blocking(task);
        if mark_blocking {
            self.network.set_blocking(task, true);
        }
        let result = host.win16_network(call);
        if mark_blocking {
            let _ = self.network.clear_blocking(task);
        }
        result
    }

    fn winsock_signed(
        &mut self,
        task: u16,
        call: Win16HostNetworkCall,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let result = self.win16_network_call_with_blocking(task, call, host)?;
        if result.wsa_error != 0 { return Ok(self.result_error(task, result.wsa_error, SOCKET_ERROR_WORD)); }
        Ok(Self::int_return(Self::expect_signed(result.value)?))
    }

    fn winsock_unsigned(
        &mut self,
        task: u16,
        call: Win16HostNetworkCall,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let result = host.win16_network(call)?;
        if result.wsa_error != 0 { return Ok(self.result_error(task, result.wsa_error, 0)); }
        Self::expect_unsigned(result.value)
    }

    fn winsock_accept(
        &mut self,
        task: u16,
        task_identity: Win16NetworkTaskIdentity,
        guest_socket: u16,
        address: Option<Win16GuestInOutBuffer>,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(socket) = self.network.host_socket(guest_socket) else {
            return Ok(self.fail_int(task, WSAENOTSOCK));
        };
        let Some(listener_nonblocking) = self.network.socket_nonblocking(guest_socket) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock listener mode disappeared while its host socket remained live"));
        };
        if !self.network.has_free_guest_socket()
            || self.network.reserve_orphan_sockets(1).is_err()
        {
            if let Err(rearm) = self.rearm_async_events(guest_socket, socket, 0x0008, host) {
                host.report_diagnostic(rearm.diagnostic());
            }
            return Ok(self.fail_int(task, WSAENOBUFS));
        }
        let inherited_route = self.network.async_select_route(guest_socket);
        let inherited_generation = if inherited_route.is_some() {
            let Some(generation) = self.network.reserve_async_generation() else {
                if let Err(rearm) = self.rearm_async_events(guest_socket, socket, 0x0008, host) {
                    host.report_diagnostic(rearm.diagnostic());
                }
                return Ok(self.fail_int(task, WSAENOBUFS));
            };
            if self.network.reserve_async_select().is_err() {
                if let Err(rearm) = self.rearm_async_events(guest_socket, socket, 0x0008, host) {
                    host.report_diagnostic(rearm.diagnostic());
                }
                return Ok(self.fail_int(task, WSAENOBUFS));
            }
            Some(generation)
        } else {
            None
        };
        let prepared = match address {
            Some(value) => match self.capture_inout(memory, value.buffer_far, value.length_pointer) {
                Ok(value) => Some(value),
                Err(error) => {
                    let wsa_error = Self::map_range_error(error)?;
                    if let Err(rearm) = self.rearm_async_events(guest_socket, socket, 0x0008, host) {
                        host.report_diagnostic(rearm.diagnostic());
                    }
                    return Ok(self.fail_int(task, wsa_error));
                }
            },
            None => None,
        };
        let result = self.win16_network_call_with_blocking(task, Win16HostNetworkCall::Accept {
            task: task_identity, socket,
            address_capacity: prepared.as_ref().map(|value| value.capacity),
            inherited_registration_generation: inherited_generation,
        }, host)?;
        if result.wsa_error != 0 { return Ok(self.result_error(task, result.wsa_error, SOCKET_ERROR_WORD)); }
        let Win16HostNetworkValue::Accepted {
            socket: accepted, address, required, async_registration,
        } = result.value else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock accept returned an unexpected host result"));
        };
        let inherited_registration = match (inherited_route, inherited_generation, async_registration) {
            (None, None, None) => None,
            (Some(route), Some(generation), Some(registration))
                if registration.source_id != 0
                    && registration.source_id != u64::MAX
                    && registration.generation == generation
                    && registration.inherited_source_id == route.source_id
                    && registration.inherited_generation == route.registration_generation
                    && self.network.async_select_route(guest_socket) == Some(route) =>
            {
                let mut inherited = route;
                inherited.socket = accepted;
                inherited.registration_generation = generation;
                inherited.source_id = registration.source_id;
                inherited.last_event_sequence = 0;
                Some(inherited)
            }
            _ => {
                if !self.retire_unpublished_socket(task_identity, accepted, host) {
                    host.report_diagnostic(&Diagnostic::warning(Kind::HostFailure,
                        "WinSock accepted-socket async inheritance could not be validated and native rollback remains owned for teardown"));
                }
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "WinSock accepted-socket async route did not match the exact listener registration"));
            }
        };
        let accepted_nonblocking = listener_nonblocking || inherited_route.is_some();
        let Some(guest_accepted) = self.network.add_socket_with_mode(
            accepted, task_identity, accepted_nonblocking,
        ) else {
            if !self.retire_unpublished_socket(task_identity, accepted, host) {
                host.report_diagnostic(&Diagnostic::warning(Kind::HostFailure,
                    "WinSock accepted a socket without a guest handle and native rollback remains owned for teardown"));
            }
            return Ok(self.fail_int(task, WSAENOBUFS));
        };
        if let Some(route) = inherited_registration
            && !self.network.set_async_select(guest_accepted, Some(route))
        {
            let _ = self.network.close_socket(guest_accepted)?;
            if !self.retire_unpublished_socket(task_identity, accepted, host) {
                host.report_diagnostic(&Diagnostic::warning(Kind::HostFailure,
                    "WinSock accepted-socket async route publication failed and native rollback remains owned for teardown"));
            }
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock accepted socket disappeared before inherited async route publication"));
        }
        if let Some(prepared) = prepared {
            let writes = match Self::inout_writes(prepared, address, required) {
                Ok(writes) => writes,
                Err(error) => {
                    let _ = self.network.close_socket(guest_accepted)?;
                    if !self.retire_unpublished_socket(task_identity, accepted, host) {
                        host.report_diagnostic(&Diagnostic::warning(Kind::HostFailure,
                            "WinSock accepted-socket rollback remains owned for teardown after invalid host address data"));
                    }
                    return Err(error);
                }
            };
            if let Err(error) = self.commit_outputs(memory, writes) {
                let _ = self.network.close_socket(guest_accepted)?;
                if !self.retire_unpublished_socket(task_identity, accepted, host) {
                    host.report_diagnostic(&Diagnostic::warning(Kind::HostFailure,
                        "WinSock accepted-socket rollback remains owned for teardown after guest output failure"));
                }
                return Ok(self.fail_int(task, Self::map_range_error(error)?));
            }
        }
        Ok(u32::from(guest_accepted))
    }

    fn retire_unpublished_socket(
        &mut self,
        owner: Win16NetworkTaskIdentity,
        socket: Win16HostSocket,
        host: &mut impl RuntimeHost,
    ) -> bool {
        match host.win16_network(Win16HostNetworkCall::RetireSocket { socket, owner }) {
            Ok(result) if result.wsa_error == 0
                && matches!(result.value, Win16HostNetworkValue::Signed(0)) => true,
            outcome => {
                let cause: std::sync::Arc<RuntimeError> = match outcome {
                    Ok(result) => {
                        let wsa_error = result.wsa_error;
                        match result.value {
                            Win16HostNetworkValue::SocketRetirementFailure(failure)
                                if failure.socket == socket && failure.owner == owner
                                    && failure.wsa_error != 0 => failure.first_cause,
                            _ if wsa_error != 0 => std::sync::Arc::new(RuntimeError::with_source(
                                Kind::HostFailure,
                                "retiring an unpublished WinSock socket failed",
                                NativeWinsockError(wsa_error),
                            )),
                            _ => std::sync::Arc::new(RuntimeError::new(Kind::InternalInvariant,
                                "unpublished WinSock socket retirement returned an unexpected result")),
                        }
                    }
                    Err(error) => std::sync::Arc::new(error),
                };
                self.network.retain_orphan_socket(
                    socket, owner, crate::win16_network::Win16NetworkSocketRetirementPhase::UnpublishedRollback,
                    cause,
                );
                false
            }
        }
    }

    fn winsock_get_address(
        &mut self,
        task: u16,
        guest_socket: u16,
        address: Win16GuestInOutBuffer,
        peer: bool,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(socket) = self.network.host_socket(guest_socket) else {
            return Ok(self.fail_int(task, WSAENOTSOCK));
        };
        let prepared = match self.capture_inout(memory, address.buffer_far, address.length_pointer) {
            Ok(value) => value,
            Err(error) => return Ok(self.fail_int(task, Self::map_range_error(error)?)),
        };
        let call = if peer {
            Win16HostNetworkCall::GetPeerName { socket, address_capacity: prepared.capacity }
        } else {
            Win16HostNetworkCall::GetSocketName { socket, address_capacity: prepared.capacity }
        };
        let result = host.win16_network(call)?;
        if result.wsa_error != 0 { return Ok(self.result_error(task, result.wsa_error, SOCKET_ERROR_WORD)); }
        let Win16HostNetworkValue::Address { bytes, required } = result.value else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock name lookup returned an unexpected host result"));
        };
        let writes = Self::inout_writes(prepared, bytes, required)?;
        if let Err(error) = self.commit_outputs(memory, writes) {
            return Ok(self.fail_int(task, Self::map_range_error(error)?));
        }
        Ok(0)
    }

    fn winsock_get_option(
        &mut self,
        task: u16,
        guest_socket: u16,
        level: i16,
        option: i16,
        value: Win16GuestInOutBuffer,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(socket) = self.network.host_socket(guest_socket) else {
            return Ok(self.fail_int(task, WSAENOTSOCK));
        };
        let prepared = match self.capture_inout(memory, value.buffer_far, value.length_pointer) {
            Ok(value) => value,
            Err(error) => return Ok(self.fail_int(task, Self::map_range_error(error)?)),
        };
        let is_so_error = level as u16 == SOL_SOCKET_WORD && option as u16 == 0x1007;
        // The host read clears SO_ERROR. Reserve all small output containers
        // before that effect so an allocation failure cannot strand a value
        // after the native provider has consumed it.
        let mut staged_outputs = if is_so_error {
            let mut value_bytes = Vec::new();
            value_bytes.try_reserve_exact(2).map_err(|error| RuntimeError::with_source(
                Kind::ResourceExhausted, "reserve WinSock SO_ERROR guest value before native read", error))?;
            let mut length_bytes = Vec::new();
            length_bytes.try_reserve_exact(2).map_err(|error| RuntimeError::with_source(
                Kind::ResourceExhausted, "reserve WinSock SO_ERROR guest length before native read", error))?;
            let mut writes = Vec::new();
            writes.try_reserve_exact(2).map_err(|error| RuntimeError::with_source(
                Kind::ResourceExhausted, "reserve WinSock SO_ERROR write set before native read", error))?;
            Some((value_bytes, length_bytes, writes))
        } else { None };
        let result = host.win16_network(Win16HostNetworkCall::GetSocketOption {
            socket, level, option, capacity: prepared.capacity,
            encoding: Self::socket_option_encoding(level, option)
                .unwrap_or(Win16HostSocketOptionEncoding::Opaque),
        })?;
        if result.wsa_error != 0 { return Ok(self.result_error(task, result.wsa_error, SOCKET_ERROR_WORD)); }
        let (bytes, required) = match result.value {
            Win16HostNetworkValue::SocketOptionPendingRead { bytes, required, token } => {
                if !is_so_error || required != 4 || bytes.len() != 4 {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "staged WinSock SO_ERROR result violated its native int shape"));
                }
                let raw = i32::from_ne_bytes(bytes.as_slice().try_into().map_err(|_| RuntimeError::new(
                    Kind::InternalInvariant, "staged WinSock SO_ERROR value is not four bytes"))?);
                let Ok(guest_value) = i16::try_from(raw) else {
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                        "native SO_ERROR value cannot be represented by the Win16 signed int ABI"));
                    return Ok(self.fail_int(task, WSAEINVAL));
                };
                let Some((mut value_bytes, mut length_bytes, mut writes)) = staged_outputs.take() else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "staged SO_ERROR output capacity was not reserved before native read"));
                };
                value_bytes.extend_from_slice(&guest_value.to_le_bytes());
                length_bytes.extend_from_slice(&2i16.to_le_bytes());
                writes.push((prepared.buffer, value_bytes));
                writes.push((prepared.length, length_bytes));
                if let Err(error) = self.commit_outputs(memory, writes) {
                    return Ok(self.fail_int(task, Self::map_range_error(error)?));
                }
                let ack = host.win16_network(Win16HostNetworkCall::AcknowledgeSocketError { token })?;
                if ack.wsa_error != 0 || !matches!(ack.value, Win16HostNetworkValue::Signed(0)) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "committed WinSock SO_ERROR output could not retire its exact read token"));
                }
                return Ok(0);
            }
            Win16HostNetworkValue::SocketOption { .. } if is_so_error => {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "WinSock SO_ERROR bypassed its staged read owner"));
            }
            Win16HostNetworkValue::SocketOption { bytes, required } => (bytes, required),
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock option lookup returned an unexpected host result")),
        };
        let (bytes, required) = if Self::socket_option_encoding(level, option).is_some() {
            // Ordinary provider scalar options are 32-bit C ints while the
            // guest SDK stores `int` in 16 bits. SO_ERROR took the staged-token
            // path above and cannot reach this generic projection.
            if required != 4 || bytes.len() != 4 {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "native scalar socket option was not returned as one 32-bit int"));
            }
            let raw = i32::from_ne_bytes(bytes.as_slice().try_into().map_err(|_| RuntimeError::new(
                Kind::InternalInvariant, "native scalar socket option is not four bytes"))?);
            let Ok(value) = i16::try_from(raw) else {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    "native socket option value cannot be represented by the Win16 signed int ABI"));
                return Ok(self.fail_int(task, WSAEINVAL));
            };
            (value.to_le_bytes().to_vec(), 2)
        } else { (bytes, required) };
        let writes = Self::inout_writes(prepared, bytes, required)?;
        if let Err(error) = self.commit_outputs(memory, writes) {
            return Ok(self.fail_int(task, Self::map_range_error(error)?));
        }
        Ok(0)
    }

    fn inout_writes(
        prepared: PreparedInOut,
        bytes: Vec<u8>,
        required: i32,
    ) -> Result<Vec<(GuestOutputRange, Vec<u8>)>, RuntimeError> {
        if bytes.len() > usize::try_from(prepared.capacity).unwrap_or(0) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock host output exceeded the captured native capacity"));
        }
        let length = i16::try_from(required).map_err(|error| RuntimeError::with_source(
            Kind::InternalInvariant, "WinSock output length does not fit guest int16", error))?;
        Ok(vec![(prepared.buffer, bytes), (prepared.length, length.to_le_bytes().to_vec())])
    }

    fn winsock_ioctl(
        &mut self,
        task: u16,
        guest_socket: u16,
        command: u32,
        value_far: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(socket) = self.network.host_socket(guest_socket) else {
            return Ok(self.fail_int(task, WSAENOTSOCK));
        };
        let output = match self.capture_network_output(memory, value_far, 4) {
            Ok(Some(range)) => range,
            Ok(None) => return Ok(self.fail_int(task, WSAEFAULT)),
            Err(error) => return Ok(self.fail_int(task, Self::map_range_error(error)?)),
        };
        let bytes = output.read(self, memory)?;
        let value = u32::from_le_bytes(bytes.try_into().map_err(|_| RuntimeError::new(
            Kind::InternalInvariant, "WinSock ioctl input was not four bytes"))?);
        let result = host.win16_network(Win16HostNetworkCall::IoctlSocket { socket, command, value })?;
        if result.wsa_error != 0 { return Ok(self.result_error(task, result.wsa_error, SOCKET_ERROR_WORD)); }
        if command == WIN16_FIONBIO
            && !self.network.set_socket_nonblocking(guest_socket, value != 0)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock socket identity disappeared after a successful FIONBIO operation"));
        }
        let Win16HostNetworkValue::IoctlValue(value) = result.value else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock ioctl returned an unexpected host result"));
        };
        if let Err(error) = self.commit_outputs(memory, vec![(output, value.to_le_bytes().to_vec())]) {
            return Ok(self.fail_int(task, Self::map_range_error(error)?));
        }
        Ok(0)
    }

}
