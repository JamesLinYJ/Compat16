//! Native Winsock 1.x adapter. Guest socket WORDs, fd_set values, and
//! name-service records are converted by the runtime; native SOCKET values
//! remain private to this owner. Async work is retained in typed host sources.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::ptr;
use std::sync::{Arc, atomic::AtomicU64};

use compat_services::win16_network::{
    FD_SETSIZE_16, HostEntryOwned, ProtocolEntryOwned, SOCKADDR_MAX_16, ServiceEntryOwned,
    WsaData16,
};
use runtime::{
    DiagnosticKind, RuntimeError, Win16GuestNotificationSource, Win16HostNetworkCall,
    Win16HostNetworkEvent, Win16HostNetworkNameQuery, Win16HostNetworkNameResult,
    Win16HostNetworkReferenceRelease, Win16HostNetworkResult, Win16HostNetworkValue,
    Win16HostSocket, Win16HostSocketOptionInput, Win16HostSocketRetirementFailure,
    Win16HostSocketRetirementPhase, Win16NetworkTaskIdentity,
};
use windows_sys::Win32::Networking::WinSock::*;

#[path = "win16_network_async.rs"]
mod async_ops;
use super::win16_network_wake::NetworkWakeHub;
use async_ops::{NetworkAsyncState, allocate_source_id};
#[path = "win16_network_retirement.rs"]
mod retirement;
use retirement::{NetworkRetirementOwner, NetworkRetirementTicket};
#[path = "win16_network_lifecycle.rs"]
mod lifecycle;
#[path = "win16_network_socket_options.rs"]
mod socket_options;

#[derive(Clone, Debug)]
pub(super) struct NetworkReferenceFailure {
    pub current_wsa_error: i32,
    pub first_cause: Arc<RuntimeError>,
}

/// Native socket ownership for the Win16 network family.
#[derive(Debug)]
pub struct Win16NetworkHost {
    sockets: BTreeMap<Win16HostSocket, SOCKET>,
    socket_tokens: BTreeMap<SOCKET, Win16HostSocket>,
    socket_owners: BTreeMap<Win16HostSocket, Win16NetworkTaskIdentity>,
    socket_types: BTreeMap<Win16HostSocket, i32>,
    socket_retirement_failures: HashMap<Win16HostSocket, Win16HostSocketRetirementFailure>,
    listening_sockets: HashSet<Win16HostSocket>,
    next_socket: u64,
    guest_startup_references: u32,
    startup_references_by_task: BTreeMap<Win16NetworkTaskIdentity, u32>,
    startup_release_failures: BTreeMap<Win16NetworkTaskIdentity, Option<NetworkReferenceFailure>>,
    host_anchor_reference: bool,
    host_anchor_first_cause: Option<Arc<RuntimeError>>,
    host_anchor_last_wsa_error: Option<i32>,
    identity_source: Arc<AtomicU64>,
    async_state: NetworkAsyncState,
    async_shutdown_receipt: Option<async_ops::AsyncShutdownReceipt>,
    retirement_ticket: NetworkRetirementTicket,
    retirement_started: bool,
}

impl Win16NetworkHost {
    /// Reserve one producer identity from the same namespace as Win16 USER,
    /// WAVE, MIDI, MCI and Winsock notification sources.
    pub fn reserve_notification_source_id(&self) -> Result<u64, RuntimeError> {
        allocate_source_id(&self.identity_source).ok_or_else(|| {
            RuntimeError::new(
                DiagnosticKind::ResourceExhausted,
                "shared Win16 notification source identities are exhausted",
            )
        })
    }

    pub fn ensure_printer_watch_polling(&self) -> Result<(), RuntimeError> {
        self.async_state.ensure_external_polling()
    }

    pub fn set_printer_watch_poll_demand(&mut self, count: usize) {
        self.async_state.set_external_poll_demand(count);
    }

    pub fn new(
        identity_source: Arc<AtomicU64>,
        wake: super::multimedia_wake::MultimediaWakeSender,
    ) -> Result<Self, RuntimeError> {
        let retirement_ticket = NetworkRetirementTicket::reserve()?;
        Ok(Self {
            sockets: BTreeMap::new(),
            socket_tokens: BTreeMap::new(),
            socket_owners: BTreeMap::new(),
            socket_types: BTreeMap::new(),
            socket_retirement_failures: HashMap::new(),
            listening_sockets: HashSet::new(),
            next_socket: 1,
            guest_startup_references: 0,
            startup_references_by_task: BTreeMap::new(),
            startup_release_failures: BTreeMap::new(),
            host_anchor_reference: false,
            host_anchor_first_cause: None,
            host_anchor_last_wsa_error: None,
            identity_source,
            async_state: NetworkAsyncState::new(NetworkWakeHub::new(wake)),
            async_shutdown_receipt: None,
            retirement_ticket,
            retirement_started: false,
        })
    }

    /// Execute one typed request. A Winsock error is returned as an ordinary
    /// guest result; malformed host protocol values are rejected by callers.
    pub fn execute(&mut self, call: Win16HostNetworkCall) -> Win16HostNetworkResult {
        match call {
            Win16HostNetworkCall::Startup { task, version } => self.startup(task, version),
            Win16HostNetworkCall::Cleanup { task, task_final } => self.cleanup(task, task_final),
            Win16HostNetworkCall::CreateSocket {
                task,
                address_family,
                socket_type,
                protocol,
            } => {
                if !self.can_allocate_socket_token()
                    || !self.startup_owner_live(task)
                    || self.reserve_socket_owner_capacity().is_err()
                {
                    return fail(WSAENOBUFS, Win16HostNetworkValue::Socket(None));
                }
                // SAFETY: socket creates a socket from integer domain, type, and protocol.
                let raw = unsafe {
                    socket(
                        i32::from(address_family),
                        i32::from(socket_type),
                        i32::from(protocol),
                    )
                };
                if raw == INVALID_SOCKET {
                    return fail(
                        crate::windows::win32_safe::wsa_last_error(),
                        Win16HostNetworkValue::Socket(None),
                    );
                }
                match self.insert_socket(raw, task, i32::from(socket_type), false) {
                    Some(token) => ok(Win16HostNetworkValue::Socket(Some(token))),
                    None => {
                        // SAFETY: closesocket closes a socket this owner opened.
                        unsafe {
                            closesocket(raw);
                        }
                        fail(WSAENOBUFS, Win16HostNetworkValue::Socket(None))
                    }
                }
            }
            Win16HostNetworkCall::CloseSocket {
                socket: token,
                owner,
            } => {
                let Some(raw) = self.sockets.get(&token).copied() else {
                    return fail(WSAENOTSOCK, Win16HostNetworkValue::Signed(SOCKET_ERROR));
                };
                if self.socket_owners.get(&token) != Some(&owner) {
                    return fail(WSAEINVAL, Win16HostNetworkValue::Signed(SOCKET_ERROR));
                }
                // SAFETY: closesocket closes a socket this owner opened.
                let result = unsafe { closesocket(raw) };
                if result == SOCKET_ERROR {
                    let error = crate::windows::win32_safe::wsa_last_error();
                    let failure = self.record_socket_retirement_failure(
                        token,
                        owner,
                        Win16HostSocketRetirementPhase::GuestClose,
                        error,
                    );
                    fail(
                        error,
                        Win16HostNetworkValue::SocketRetirementFailure(failure),
                    )
                } else {
                    self.remove_socket(token);
                    ok(Win16HostNetworkValue::Signed(result))
                }
            }
            Win16HostNetworkCall::RetireSocket {
                socket: token,
                owner,
            } => {
                let Some(raw) = self.sockets.get(&token).copied() else {
                    return fail(WSAENOTSOCK, Win16HostNetworkValue::Signed(SOCKET_ERROR));
                };
                if self.socket_owners.get(&token) != Some(&owner) {
                    return fail(WSAEINVAL, Win16HostNetworkValue::Signed(SOCKET_ERROR));
                }
                match self.retire_socket(
                    token,
                    raw,
                    owner,
                    Win16HostSocketRetirementPhase::RuntimeTeardown,
                ) {
                    Ok(()) => ok(Win16HostNetworkValue::Signed(0)),
                    Err(failure) => fail(
                        failure.wsa_error,
                        Win16HostNetworkValue::SocketRetirementFailure(failure),
                    ),
                }
            }
            Win16HostNetworkCall::Bind {
                socket: token,
                address,
            } => {
                let Some(raw) = self.socket(token) else {
                    return fail(WSAENOTSOCK, signed_error());
                };
                let Some(length) = valid_sockaddr(&address) else {
                    return fail(WSAEINVAL, signed_error());
                };
                // SAFETY: bind reads a caller-owned sockaddr of the length passed with it.
                let result = unsafe { bind(raw, address.as_ptr().cast(), length) };
                if result == 0 {
                    self.async_state.note_bind(token);
                }
                self.socket_result(result)
            }
            Win16HostNetworkCall::Accept {
                task,
                socket: token,
                address_capacity,
                inherited_registration_generation,
            } => {
                let Some(raw) = self.socket(token) else {
                    return fail(WSAENOTSOCK, Win16HostNetworkValue::Socket(None));
                };
                if !self.can_allocate_socket_token()
                    || !self.startup_owner_live(task)
                    || self.reserve_socket_owner_capacity().is_err()
                {
                    return fail(WSAENOBUFS, Win16HostNetworkValue::Socket(None));
                }
                let inherited = match self.async_state.reserve_accept_registration(
                    &self.identity_source,
                    token,
                    inherited_registration_generation,
                ) {
                    Ok(reservation) => reservation,
                    Err(error) => return fail(error, Win16HostNetworkValue::Socket(None)),
                };
                let Some(socket_type) = self.socket_types.get(&token).copied() else {
                    return fail(WSAENOTSOCK, Win16HostNetworkValue::Socket(None));
                };
                let mut address = [0u8; SOCKADDR_MAX_16];
                let Some(mut address_length) = address_capacity.map_or(Some(0), nonnegative_length)
                else {
                    return fail(WSAEINVAL, Win16HostNetworkValue::Socket(None));
                };
                address_length = address_length.min(SOCKADDR_MAX_16 as i32);
                let address_ptr = address_capacity
                    .map_or(ptr::null_mut(), |_| address.as_mut_ptr().cast::<SOCKADDR>());
                let length_ptr = address_capacity.map_or(ptr::null_mut(), |_| &mut address_length);
                // SAFETY: accept writes an optional caller-owned sockaddr.
                let accepted = unsafe { accept(raw, address_ptr, length_ptr) };
                // Winsock re-enables FD_ACCEPT after every accept attempt,
                // including WSAEWOULDBLOCK, so poll the listening condition
                // again when the native event source is revisited.
                self.async_state.note_accept(token);
                if accepted == INVALID_SOCKET {
                    return fail(
                        crate::windows::win32_safe::wsa_last_error(),
                        Win16HostNetworkValue::Socket(None),
                    );
                }
                let Some(accepted_token) = self.insert_socket(accepted, task, socket_type, true)
                else {
                    // SAFETY: closesocket closes a socket this owner opened.
                    unsafe {
                        closesocket(accepted);
                    }
                    return fail(WSAENOBUFS, Win16HostNetworkValue::Socket(None));
                };
                let async_registration = inherited.map(|reservation| {
                    self.async_state
                        .inherit_accept_registration(reservation, accepted_token)
                });
                let copied = address_length.clamp(0, SOCKADDR_MAX_16 as i32) as usize;
                ok(Win16HostNetworkValue::Accepted {
                    socket: accepted_token,
                    address: address[..copied].to_vec(),
                    required: address_length.max(0),
                    async_registration,
                })
            }
            Win16HostNetworkCall::Connect {
                socket: token,
                address,
            } => {
                let Some(raw) = self.socket(token) else {
                    return fail(WSAENOTSOCK, signed_error());
                };
                let Some(length) = valid_sockaddr(&address) else {
                    return fail(WSAEINVAL, signed_error());
                };
                let (attempt_id, notice) = match self.async_state.reserve_connect_attempt(token) {
                    Ok(reservation) => reservation,
                    Err(error) => return fail(error, signed_error()),
                };
                // SAFETY: connect reads a caller-owned sockaddr of the length passed with it.
                let result = unsafe { connect(raw, address.as_ptr().cast(), length) };
                let error =
                    (result == SOCKET_ERROR).then(|| crate::windows::win32_safe::wsa_last_error());
                self.async_state
                    .note_connect(token, attempt_id, notice, result, error);
                self.async_state
                    .finish_connect_notification(notice, result, error);
                match error {
                    Some(code) => fail(code, Win16HostNetworkValue::Signed(result)),
                    None => ok(Win16HostNetworkValue::Signed(result)),
                }
            }
            Win16HostNetworkCall::GetPeerName {
                socket: token,
                address_capacity,
            } => self.get_socket_name(token, address_capacity, true),
            Win16HostNetworkCall::GetSocketName {
                socket: token,
                address_capacity,
            } => self.get_socket_name(token, address_capacity, false),
            Win16HostNetworkCall::GetSocketOption {
                socket: token,
                level,
                option,
                capacity,
                encoding,
            } => self.get_socket_option(token, level, option, capacity, encoding),
            Win16HostNetworkCall::AcknowledgeSocketError { token } => {
                self.acknowledge_socket_error(token)
            }
            Win16HostNetworkCall::SetSocketOption {
                socket: token,
                level,
                option,
                value,
            } => {
                let Some(raw) = self.socket(token) else {
                    return fail(WSAENOTSOCK, signed_error());
                };
                let scalar: [u8; 4];
                let bytes: &[u8] = match &value {
                    Win16HostSocketOptionInput::Win16SignedInt(value) => {
                        scalar = i32::from(*value).to_ne_bytes();
                        &scalar
                    }
                    Win16HostSocketOptionInput::Opaque(value) => value.as_slice(),
                };
                let Some(length) = i32::try_from(bytes.len()).ok() else {
                    return fail(WSAEINVAL, signed_error());
                };
                let value_ptr = if bytes.is_empty() {
                    ptr::null()
                } else {
                    bytes.as_ptr().cast()
                };
                // SAFETY: setsockopt reads a caller-owned option buffer of the length passed with it.
                let result = unsafe {
                    setsockopt(
                        raw,
                        i32::from(level as u16),
                        i32::from(option),
                        value_ptr,
                        length,
                    )
                };
                self.socket_result(result)
            }
            Win16HostNetworkCall::IoctlSocket {
                socket: token,
                command,
                value,
            } => {
                let Some(raw) = self.socket(token) else {
                    return fail(WSAENOTSOCK, Win16HostNetworkValue::IoctlValue(value));
                };
                if command as i32 == FIONBIO
                    && value == 0
                    && self.async_state.has_registration(token)
                {
                    return fail(WSAEINVAL, Win16HostNetworkValue::IoctlValue(value));
                }
                let mut value = value;
                // SAFETY: ioctlsocket reads or writes a caller-owned integer argument.
                let result = unsafe { ioctlsocket(raw, command as i32, &mut value) };
                if result == SOCKET_ERROR {
                    fail(
                        crate::windows::win32_safe::wsa_last_error(),
                        Win16HostNetworkValue::IoctlValue(value),
                    )
                } else {
                    ok(Win16HostNetworkValue::IoctlValue(value))
                }
            }
            Win16HostNetworkCall::Listen {
                socket: token,
                backlog,
            } => {
                let Some(raw) = self.socket(token) else {
                    return fail(WSAENOTSOCK, signed_error());
                };
                if self.listening_sockets.try_reserve(1).is_err() {
                    return fail(WSAENOBUFS, signed_error());
                }
                // SAFETY: listen marks a socket this owner opened.
                let result = unsafe { listen(raw, i32::from(backlog)) };
                let response = self.socket_result(result);
                if response.wsa_error == 0 {
                    self.listening_sockets.insert(token);
                    self.async_state.note_listen(token, true);
                }
                response
            }
            Win16HostNetworkCall::Shutdown { socket: token, how } => {
                let Some(raw) = self.socket(token) else {
                    return fail(WSAENOTSOCK, signed_error());
                };
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                let result = unsafe { shutdown(raw, i32::from(how)) };
                if result == 0 {
                    self.async_state.note_shutdown(token, how);
                }
                self.socket_result(result)
            }
            Win16HostNetworkCall::Receive {
                socket: token,
                capacity,
                flags,
            } => {
                let Some(raw) = self.socket(token) else {
                    return fail(WSAENOTSOCK, bytes_empty());
                };
                let (result, bytes) = self.receive(raw, capacity, flags);
                self.async_state.note_receive(token, result, capacity);
                if result == SOCKET_ERROR {
                    fail(crate::windows::win32_safe::wsa_last_error(), bytes)
                } else {
                    ok(bytes)
                }
            }
            Win16HostNetworkCall::ReceiveFrom {
                socket: token,
                capacity,
                flags,
                address_capacity,
            } => {
                let Some(raw) = self.socket(token) else {
                    return fail(WSAENOTSOCK, bytes_empty());
                };
                let requested = capacity;
                let Some(capacity) = nonnegative_length(capacity) else {
                    return fail(WSAEINVAL, bytes_empty());
                };
                let has_address = address_capacity.is_some();
                let Some(address_capacity_value) =
                    address_capacity.map_or(Some(0), nonnegative_length)
                else {
                    return fail(WSAEINVAL, bytes_empty());
                };
                let mut bytes = vec![0u8; capacity as usize];
                let mut address = [0u8; SOCKADDR_MAX_16];
                let mut address_length = address_capacity_value.min(SOCKADDR_MAX_16 as i32);
                let buffer = if bytes.is_empty() {
                    ptr::null_mut()
                } else {
                    bytes.as_mut_ptr().cast()
                };
                let address_ptr = if has_address {
                    address.as_mut_ptr().cast()
                } else {
                    ptr::null_mut()
                };
                let length_ptr = if has_address {
                    &mut address_length
                } else {
                    ptr::null_mut()
                };
                // SAFETY: recvfrom writes into caller-owned byte and sockaddr buffers.
                let result = unsafe {
                    recvfrom(
                        raw,
                        buffer,
                        capacity,
                        i32::from(flags),
                        address_ptr,
                        length_ptr,
                    )
                };
                self.async_state.note_receive(token, result, requested);
                if result == SOCKET_ERROR {
                    return fail(crate::windows::win32_safe::wsa_last_error(), bytes_empty());
                }
                bytes.truncate(result.max(0) as usize);
                let copied = address_length.clamp(0, SOCKADDR_MAX_16 as i32) as usize;
                ok(Win16HostNetworkValue::ReceivedFrom {
                    bytes,
                    count: result.max(0),
                    address: address[..copied].to_vec(),
                    required: address_length.max(0),
                })
            }
            Win16HostNetworkCall::RearmAsyncEvent {
                socket: token,
                source_id,
                registration_generation,
                events,
            } => self
                .async_state
                .rearm_event(token, source_id, registration_generation, events),
            Win16HostNetworkCall::Send {
                socket: token,
                bytes,
                flags,
            } => {
                let Some(raw) = self.socket(token) else {
                    return fail(WSAENOTSOCK, signed_error());
                };
                let Some(length) = i32::try_from(bytes.len()).ok() else {
                    return fail(WSAEMSGSIZE, signed_error());
                };
                let buffer = if bytes.is_empty() {
                    ptr::null()
                } else {
                    bytes.as_ptr().cast()
                };
                // SAFETY: send reads a caller-owned byte span.
                let result = unsafe { send(raw, buffer, length, i32::from(flags)) };
                let error =
                    (result == SOCKET_ERROR).then(|| crate::windows::win32_safe::wsa_last_error());
                self.async_state.note_send(token, result, error);
                match error {
                    Some(code) => fail(code, Win16HostNetworkValue::Signed(result)),
                    None => ok(Win16HostNetworkValue::Signed(result)),
                }
            }
            Win16HostNetworkCall::SendTo {
                socket: token,
                bytes,
                flags,
                address,
            } => {
                let Some(raw) = self.socket(token) else {
                    return fail(WSAENOTSOCK, signed_error());
                };
                let Some(length) = i32::try_from(bytes.len()).ok() else {
                    return fail(WSAEMSGSIZE, signed_error());
                };
                let Some(address_length) = valid_sockaddr(&address) else {
                    return fail(WSAEINVAL, signed_error());
                };
                let buffer = if bytes.is_empty() {
                    ptr::null()
                } else {
                    bytes.as_ptr().cast()
                };
                // SAFETY: sendto reads a caller-owned byte span and sockaddr.
                let result = unsafe {
                    sendto(
                        raw,
                        buffer,
                        length,
                        i32::from(flags),
                        address.as_ptr().cast(),
                        address_length,
                    )
                };
                let error =
                    (result == SOCKET_ERROR).then(|| crate::windows::win32_safe::wsa_last_error());
                self.async_state.note_send(token, result, error);
                match error {
                    Some(code) => fail(code, Win16HostNetworkValue::Signed(result)),
                    None => ok(Win16HostNetworkValue::Signed(result)),
                }
            }
            Win16HostNetworkCall::Select {
                read,
                write,
                except,
                timeout,
            } => self.select(read, write, except, timeout),
            // SAFETY: htonl converts an integer and takes no pointers.
            Win16HostNetworkCall::HostToNetworkLong(value) => {
                ok(Win16HostNetworkValue::Unsigned(unsafe { htonl(value) }))
            }
            // SAFETY: htons converts an integer and takes no pointers.
            Win16HostNetworkCall::HostToNetworkShort(value) => {
                ok(Win16HostNetworkValue::Unsigned(u32::from(unsafe {
                    htons(value)
                })))
            }
            // SAFETY: ntohl converts an integer and takes no pointers.
            Win16HostNetworkCall::NetworkToHostLong(value) => {
                ok(Win16HostNetworkValue::Unsigned(unsafe { ntohl(value) }))
            }
            // SAFETY: ntohs converts an integer and takes no pointers.
            Win16HostNetworkCall::NetworkToHostShort(value) => {
                ok(Win16HostNetworkValue::Unsigned(u32::from(unsafe {
                    ntohs(value)
                })))
            }
            Win16HostNetworkCall::InetAddress(value) => self.inet_address(value),
            Win16HostNetworkCall::InetName(value) => self.inet_name(value),
            Win16HostNetworkCall::Query(query) => self.query(query),
            Win16HostNetworkCall::GetHostName { capacity } => self.hostname(capacity),
            Win16HostNetworkCall::AsyncSelect {
                socket: token,
                task,
                window,
                guest_hwnd,
                message,
                events,
                registration_generation,
                expected_source_id,
            } => {
                if !self.startup_owner_live(task) {
                    return fail(WSANOTINITIALISED, signed_error());
                }
                self.async_state.async_select(
                    &self.identity_source,
                    &self.sockets,
                    token,
                    task,
                    window,
                    guest_hwnd,
                    message,
                    events,
                    registration_generation,
                    expected_source_id,
                )
            }
            Win16HostNetworkCall::AsyncQuery {
                task,
                window,
                guest_hwnd,
                message,
                query,
                capacity,
                request_generation,
            } => {
                if !self.startup_owner_live(task) {
                    return fail(WSANOTINITIALISED, Win16HostNetworkValue::AsyncTask(None));
                }
                self.async_state.start_async_query(
                    &self.identity_source,
                    task,
                    window,
                    guest_hwnd,
                    message,
                    query,
                    capacity,
                    request_generation,
                )
            }
            Win16HostNetworkCall::CancelAsyncRequest { request, owner } => {
                self.async_state.cancel_async_request(request, owner)
            }
            Win16HostNetworkCall::CancelBlockingCall => fail(WSAEOPNOTSUPP, signed_error()),
            Win16HostNetworkCall::IsBlocking => {
                fail(WSAEOPNOTSUPP, Win16HostNetworkValue::Unsigned(0))
            }
            Win16HostNetworkCall::IsSocketInSet { socket: token, set } => ok(
                Win16HostNetworkValue::Unsigned(u32::from(set.contains(&token))),
            ),
            Win16HostNetworkCall::ReceiveEx {
                socket: token,
                capacity,
            } => {
                let Some(raw) = self.socket(token) else {
                    return fail(WSAENOTSOCK, receive_ex_empty());
                };
                let Some(native_capacity) = nonnegative_length(capacity) else {
                    return fail(WSAEINVAL, receive_ex_empty());
                };
                let mut bytes = vec![0u8; native_capacity as usize];
                let mut flags = 0i32;
                let buffer = if bytes.is_empty() {
                    ptr::null_mut()
                } else {
                    bytes.as_mut_ptr().cast()
                };
                // SAFETY: `WSARecvEx` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
                let result = unsafe { WSARecvEx(raw, buffer, native_capacity, &mut flags) };
                self.async_state.note_receive(token, result, capacity);
                if result == SOCKET_ERROR {
                    return fail(
                        crate::windows::win32_safe::wsa_last_error(),
                        receive_ex_empty(),
                    );
                }
                bytes.truncate(result.max(0) as usize);
                ok(Win16HostNetworkValue::ReceiveEx {
                    bytes,
                    count: result.max(0),
                    flags: flags as u16,
                })
            }
        }
    }

    pub fn peek_network_event(
        &mut self,
    ) -> Result<Option<Win16HostNetworkEvent>, runtime::RuntimeError> {
        self.async_state.peek_event(&self.sockets)
    }

    pub fn ack_network_event(
        &mut self,
        source: Win16GuestNotificationSource,
    ) -> Result<(), runtime::RuntimeError> {
        self.async_state.ack_event(source)
    }

    /// Stop callbacks/wake work before WindowsHost drops the USER worker that
    /// owns the shared no-payload wake event. Its exact query/event owners move
    /// to the process-lifetime receipt instead of being cleared on shutdown.
    pub fn shutdown_async_sources(&mut self) {
        if self.async_shutdown_receipt.is_none() {
            self.async_shutdown_receipt = Some(self.async_state.shutdown_and_join());
        }
    }

    /// Attempt one exact native retirement step, then transfer every remaining
    /// socket/reference/source owner to its pre-reserved process-lifetime slot.
    pub fn shutdown_and_quarantine(&mut self) {
        if self.retirement_started {
            return;
        }
        self.shutdown_async_sources();
        let mut owner = NetworkRetirementOwner {
            sockets: std::mem::take(&mut self.sockets),
            socket_owners: std::mem::take(&mut self.socket_owners),
            socket_types: std::mem::take(&mut self.socket_types),
            socket_retirement_failures: std::mem::take(&mut self.socket_retirement_failures),
            startup_references: std::mem::take(&mut self.startup_references_by_task),
            startup_release_failures: std::mem::take(&mut self.startup_release_failures),
            host_anchor_reference: self.host_anchor_reference,
            host_anchor_first_cause: self.host_anchor_first_cause.take(),
            host_anchor_last_wsa_error: self.host_anchor_last_wsa_error,
            resolver_sources: self.async_shutdown_receipt.take().unwrap_or_default(),
            socket_retry_cursor: None,
            startup_retry_cursor: None,
            invariant_failure: None,
        };
        self.socket_tokens.clear();
        self.listening_sockets.clear();
        self.guest_startup_references = 0;
        self.host_anchor_reference = false;
        let done = owner.progress_once();
        if done {
            self.retirement_ticket.release();
        } else {
            self.retirement_ticket.retain(owner);
        }
        self.retirement_started = true;
    }

    fn socket(&self, token: Win16HostSocket) -> Option<SOCKET> {
        self.sockets.get(&token).copied()
    }

    fn socket_result(&self, result: i32) -> Win16HostNetworkResult {
        if result == SOCKET_ERROR {
            fail(
                crate::windows::win32_safe::wsa_last_error(),
                Win16HostNetworkValue::Signed(result),
            )
        } else {
            ok(Win16HostNetworkValue::Signed(result))
        }
    }

    fn receive(&self, raw: SOCKET, capacity: i16, flags: i16) -> (i32, Win16HostNetworkValue) {
        let Some(capacity) = nonnegative_length(capacity) else {
            return (SOCKET_ERROR, bytes_empty());
        };
        let mut bytes = vec![0u8; capacity as usize];
        let buffer = if bytes.is_empty() {
            ptr::null_mut()
        } else {
            bytes.as_mut_ptr().cast()
        };
        // SAFETY: recv writes into a caller-owned byte span.
        let result = unsafe { recv(raw, buffer, capacity, i32::from(flags)) };
        if result >= 0 {
            bytes.truncate(result as usize);
            (
                result,
                Win16HostNetworkValue::Bytes {
                    bytes,
                    count: result,
                },
            )
        } else {
            (result, bytes_empty())
        }
    }

    fn get_socket_name(
        &self,
        token: Win16HostSocket,
        capacity: i16,
        peer: bool,
    ) -> Win16HostNetworkResult {
        let Some(raw) = self.socket(token) else {
            return fail(WSAENOTSOCK, address_empty());
        };
        let Some(capacity) = nonnegative_length(capacity) else {
            return fail(WSAEINVAL, address_empty());
        };
        let mut address = [0u8; SOCKADDR_MAX_16];
        let mut length = capacity.min(SOCKADDR_MAX_16 as i32);
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        let result = unsafe {
            if peer {
                getpeername(raw, address.as_mut_ptr().cast(), &mut length)
            } else {
                getsockname(raw, address.as_mut_ptr().cast(), &mut length)
            }
        };
        if result == SOCKET_ERROR {
            return fail(
                crate::windows::win32_safe::wsa_last_error(),
                address_empty(),
            );
        }
        let copied = length.clamp(0, capacity.min(SOCKADDR_MAX_16 as i32)) as usize;
        ok(Win16HostNetworkValue::Address {
            bytes: address[..copied].to_vec(),
            required: length.max(0),
        })
    }

    fn select(
        &self,
        read: Option<Vec<Win16HostSocket>>,
        write: Option<Vec<Win16HostSocket>>,
        except: Option<Vec<Win16HostSocket>>,
        timeout: Option<[u8; 8]>,
    ) -> Win16HostNetworkResult {
        let mut native_read = match self.native_fd_set(read.as_deref()) {
            Ok(value) => value,
            Err(code) => return fail(code, selected_empty()),
        };
        let mut native_write = match self.native_fd_set(write.as_deref()) {
            Ok(value) => value,
            Err(code) => return fail(code, selected_empty()),
        };
        let mut native_except = match self.native_fd_set(except.as_deref()) {
            Ok(value) => value,
            Err(code) => return fail(code, selected_empty()),
        };
        let timeval = timeout.map(|bytes| TIMEVAL {
            tv_sec: i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            tv_usec: i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        });
        if timeval.is_some_and(|value| {
            value.tv_sec < 0 || value.tv_usec < 0 || value.tv_usec >= 1_000_000
        }) {
            return fail(WSAEINVAL, selected_empty());
        }
        // SAFETY: select reads and writes caller-owned fd sets that stay live for the call.
        let result = unsafe {
            select(
                0,
                read.as_ref().map_or(ptr::null_mut(), |_| &mut native_read),
                write
                    .as_ref()
                    .map_or(ptr::null_mut(), |_| &mut native_write),
                except
                    .as_ref()
                    .map_or(ptr::null_mut(), |_| &mut native_except),
                timeval
                    .as_ref()
                    .map_or(ptr::null(), |value| value as *const TIMEVAL),
            )
        };
        if result == SOCKET_ERROR {
            return fail(
                crate::windows::win32_safe::wsa_last_error(),
                selected_empty(),
            );
        }
        ok(Win16HostNetworkValue::Selected {
            ready_count: result,
            read: self.guest_fd_set(read, native_read),
            write: self.guest_fd_set(write, native_write),
            except: self.guest_fd_set(except, native_except),
        })
    }

    fn native_fd_set(&self, values: Option<&[Win16HostSocket]>) -> Result<FD_SET, i32> {
        let mut set = FD_SET::default();
        let Some(values) = values else {
            return Ok(set);
        };
        if values.len() > FD_SETSIZE_16 {
            return Err(WSAEINVAL);
        }
        for (index, token) in values.iter().enumerate() {
            let Some(raw) = self.socket(*token) else {
                return Err(WSAENOTSOCK);
            };
            set.fd_array[index] = raw;
        }
        set.fd_count = values.len() as u32;
        Ok(set)
    }

    fn guest_fd_set(
        &self,
        original: Option<Vec<Win16HostSocket>>,
        native: FD_SET,
    ) -> Option<Vec<Win16HostSocket>> {
        original.map(|_| {
            native.fd_array[..(native.fd_count as usize).min(FD_SETSIZE_16)]
                .iter()
                .filter_map(|raw| self.socket_tokens.get(raw).copied())
                .collect()
        })
    }

    fn inet_address(&self, address: Vec<u8>) -> Win16HostNetworkResult {
        let Ok(address) = CString::new(address) else {
            return fail(WSAEINVAL, Win16HostNetworkValue::Unsigned(u32::MAX));
        };
        // SAFETY: inet_addr reads a caller-owned NUL-terminated address string.
        let value = unsafe { inet_addr(address.as_ptr().cast()) };
        ok(Win16HostNetworkValue::Unsigned(value))
    }

    fn inet_name(&self, address: u32) -> Win16HostNetworkResult {
        let mut native = IN_ADDR::default();
        native.S_un.S_addr = address;
        // SAFETY: inet_ntoa returns a pointer to a static dotted-quad buffer that stays live for the process.
        let result = unsafe { inet_ntoa(native) };
        if result.is_null() {
            return fail(
                crate::windows::win32_safe::wsa_last_error(),
                Win16HostNetworkValue::InetText(Vec::new()),
            );
        }
        // SAFETY: inet_ntoa returned a non-null static dotted-quad string.
        let text = unsafe { copy_c_string(result.cast()) };
        ok(Win16HostNetworkValue::InetText(text))
    }

    fn query(&self, query: Win16HostNetworkNameQuery) -> Win16HostNetworkResult {
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        let result = unsafe { query_native(&query) };
        match result {
            Some(result) => ok(Win16HostNetworkValue::NameQuery(Some(result))),
            None => fail(
                crate::windows::win32_safe::wsa_last_error(),
                Win16HostNetworkValue::NameQuery(None),
            ),
        }
    }

    fn hostname(&self, capacity: i16) -> Win16HostNetworkResult {
        let Some(capacity) = nonnegative_length(capacity) else {
            return fail(WSAEINVAL, Win16HostNetworkValue::HostName(Vec::new()));
        };
        let mut bytes = vec![0u8; capacity as usize];
        let output = if bytes.is_empty() {
            ptr::null_mut()
        } else {
            bytes.as_mut_ptr().cast()
        };
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        let result = unsafe { gethostname(output, capacity) };
        if result == SOCKET_ERROR {
            return fail(
                crate::windows::win32_safe::wsa_last_error(),
                Win16HostNetworkValue::HostName(Vec::new()),
            );
        }
        if let Some(end) = bytes.iter().position(|value| *value == 0) {
            bytes.truncate(end + 1);
        }
        ok(Win16HostNetworkValue::HostName(bytes))
    }
}

impl Drop for Win16NetworkHost {
    fn drop(&mut self) {
        self.shutdown_and_quarantine();
    }
}

fn abortive_close_socket(raw: SOCKET, socket_type: i32) -> Result<(), i32> {
    if socket_type == SOCK_STREAM {
        let mut peer = SOCKADDR_STORAGE::default();
        let mut peer_length =
            i32::try_from(std::mem::size_of::<SOCKADDR_STORAGE>()).map_err(|_| WSAEINVAL)?;
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        let connected = unsafe {
            getpeername(
                raw,
                (&mut peer as *mut SOCKADDR_STORAGE).cast(),
                &mut peer_length,
            )
        };
        if connected == SOCKET_ERROR {
            let error = crate::windows::win32_safe::wsa_last_error();
            if error != WSAENOTCONN {
                return Err(error);
            }
        } else {
            // Winsock 1.1 requires final task cleanup to reset open connected
            // SOCK_STREAM sockets. The host anchor prevents native WSACleanup
            // from performing that task-local close, so request RST explicitly.
            let linger = LINGER {
                l_onoff: 1,
                l_linger: 0,
            };
            // SAFETY: setsockopt reads a caller-owned option buffer of the length passed with it.
            let result = unsafe {
                setsockopt(
                    raw,
                    SOL_SOCKET,
                    SO_LINGER,
                    (&linger as *const LINGER).cast(),
                    i32::try_from(std::mem::size_of::<LINGER>()).map_err(|_| WSAEINVAL)?,
                )
            };
            if result == SOCKET_ERROR {
                return Err(crate::windows::win32_safe::wsa_last_error());
            }
        }
    }
    // SAFETY: closesocket closes a socket this owner opened.
    if unsafe { closesocket(raw) } == SOCKET_ERROR {
        return Err(crate::windows::win32_safe::wsa_last_error());
    }
    Ok(())
}

fn valid_sockaddr(bytes: &[u8]) -> Option<i32> {
    if !(2..=SOCKADDR_MAX_16).contains(&bytes.len()) {
        return None;
    }
    i32::try_from(bytes.len()).ok()
}

fn nonnegative_length(value: i16) -> Option<i32> {
    (value >= 0).then_some(i32::from(value))
}

fn ok(value: Win16HostNetworkValue) -> Win16HostNetworkResult {
    Win16HostNetworkResult {
        value,
        wsa_error: 0,
    }
}
fn fail(error: i32, value: Win16HostNetworkValue) -> Win16HostNetworkResult {
    Win16HostNetworkResult {
        value,
        wsa_error: error,
    }
}
fn unit() -> Win16HostNetworkValue {
    Win16HostNetworkValue::None
}
fn signed_error() -> Win16HostNetworkValue {
    Win16HostNetworkValue::Signed(SOCKET_ERROR)
}
fn bytes_empty() -> Win16HostNetworkValue {
    Win16HostNetworkValue::Bytes {
        bytes: Vec::new(),
        count: 0,
    }
}
fn address_empty() -> Win16HostNetworkValue {
    Win16HostNetworkValue::Address {
        bytes: Vec::new(),
        required: 0,
    }
}
fn socket_option_empty() -> Win16HostNetworkValue {
    Win16HostNetworkValue::SocketOption {
        bytes: Vec::new(),
        required: 0,
    }
}
fn selected_empty() -> Win16HostNetworkValue {
    Win16HostNetworkValue::Selected {
        ready_count: SOCKET_ERROR,
        read: None,
        write: None,
        except: None,
    }
}
fn receive_ex_empty() -> Win16HostNetworkValue {
    Win16HostNetworkValue::ReceiveEx {
        bytes: Vec::new(),
        count: 0,
        flags: 0,
    }
}

fn array_string(value: &[i8]) -> Vec<u8> {
    value
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| *byte as u8)
        .collect()
}

// SAFETY: Callers uphold the pointer and lifetime invariant required by this function. Pointers are host addresses, not guest addresses.
unsafe fn query_native(query: &Win16HostNetworkNameQuery) -> Option<Win16HostNetworkNameResult> {
    match query {
        Win16HostNetworkNameQuery::HostByAddress {
            address,
            address_type,
        } => {
            let length = i32::try_from(address.len()).ok()?;
            // SAFETY: gethostbyaddr reads a caller-owned address of the length passed with it.
            let entry =
                unsafe { gethostbyaddr(address.as_ptr().cast(), length, i32::from(*address_type)) };
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            unsafe { copy_host_entry(entry) }.map(Win16HostNetworkNameResult::Host)
        }
        Win16HostNetworkNameQuery::HostByName(name) => {
            let name = CString::new(name.as_slice()).ok()?;
            // SAFETY: gethostbyname reads a caller-owned NUL-terminated name. The returned record is copied before another resolver call.
            let entry = unsafe { gethostbyname(name.as_ptr().cast()) };
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            unsafe { copy_host_entry(entry) }.map(Win16HostNetworkNameResult::Host)
        }
        Win16HostNetworkNameQuery::ProtocolByName(name) => {
            let name = CString::new(name.as_slice()).ok()?;
            // SAFETY: getprotobyname reads a caller-owned NUL-terminated name.
            let entry = unsafe { getprotobyname(name.as_ptr().cast()) };
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            unsafe { copy_protocol_entry(entry) }.map(Win16HostNetworkNameResult::Protocol)
        }
        Win16HostNetworkNameQuery::ProtocolByNumber(number) => {
            // SAFETY: getprotobynumber takes a protocol number.
            let entry = unsafe { getprotobynumber(i32::from(*number)) };
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            unsafe { copy_protocol_entry(entry) }.map(Win16HostNetworkNameResult::Protocol)
        }
        Win16HostNetworkNameQuery::ServiceByName { name, protocol } => {
            let name = CString::new(name.as_slice()).ok()?;
            let protocol = protocol.as_deref().map(CString::new).transpose().ok()?;
            let protocol: *const u8 = protocol
                .as_ref()
                .map_or(ptr::null(), |value| value.as_ptr().cast());
            // SAFETY: getservbyname reads caller-owned name and protocol strings.
            let entry = unsafe { getservbyname(name.as_ptr().cast(), protocol) };
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            unsafe { copy_service_entry(entry) }.map(Win16HostNetworkNameResult::Service)
        }
        Win16HostNetworkNameQuery::ServiceByPort {
            port_network_order,
            protocol,
        } => {
            let protocol = protocol.as_deref().map(CString::new).transpose().ok()?;
            let protocol: *const u8 = protocol
                .as_ref()
                .map_or(ptr::null(), |value| value.as_ptr().cast());
            // SAFETY: getservbyport reads an optional caller-owned protocol string.
            let entry = unsafe { getservbyport(i32::from(*port_network_order), protocol) };
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            unsafe { copy_service_entry(entry) }.map(Win16HostNetworkNameResult::Service)
        }
    }
}

// SAFETY: Callers uphold the pointer and lifetime invariant required by this function. Pointers are host addresses, not guest addresses.
unsafe fn copy_host_entry(entry: *mut HOSTENT) -> Option<HostEntryOwned> {
    let entry = unsafe { entry.as_ref() }?;
    let address_length = u16::try_from(entry.h_length).ok()?;
    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
    let addresses =
        unsafe { copy_binary_pointer_array(entry.h_addr_list, 64, usize::from(address_length)) };
    Some(HostEntryOwned {
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        name: unsafe { copy_c_string(entry.h_name) },
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        aliases: unsafe { copy_pointer_array(entry.h_aliases, 256) },
        address_type: entry.h_addrtype as u16,
        address_length,
        addresses,
    })
}

// SAFETY: Callers uphold the pointer and lifetime invariant required by this function. Pointers are host addresses, not guest addresses.
unsafe fn copy_protocol_entry(entry: *mut PROTOENT) -> Option<ProtocolEntryOwned> {
    let entry = unsafe { entry.as_ref() }?;
    Some(ProtocolEntryOwned {
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        name: unsafe { copy_c_string(entry.p_name) },
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        aliases: unsafe { copy_pointer_array(entry.p_aliases, 256) },
        protocol: entry.p_proto as u16,
    })
}

// SAFETY: Callers uphold the pointer and lifetime invariant required by this function. Pointers are host addresses, not guest addresses.
unsafe fn copy_service_entry(entry: *mut SERVENT) -> Option<ServiceEntryOwned> {
    let entry = unsafe { entry.as_ref() }?;
    Some(ServiceEntryOwned {
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        name: unsafe { copy_c_string(entry.s_name) },
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        aliases: unsafe { copy_pointer_array(entry.s_aliases, 256) },
        port_network_order: entry.s_port as u16,
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        protocol: unsafe { copy_c_string(entry.s_proto) },
    })
}

// SAFETY: Callers uphold the pointer and lifetime invariant required by this function. Pointers are host addresses, not guest addresses.
unsafe fn copy_pointer_array(mut array: *mut *mut i8, maximum: usize) -> Vec<Vec<u8>> {
    if array.is_null() {
        return Vec::new();
    }
    let mut copied = Vec::new();
    for _ in 0..maximum {
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        let item = unsafe { *array };
        if item.is_null() {
            break;
        }
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        copied.push(unsafe { copy_c_string(item.cast()) });
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        array = unsafe { array.add(1) };
    }
    copied
}

/// `HOSTENT::h_addr_list` is a NULL-terminated pointer vector whose entries
/// are binary addresses of exactly `h_length` bytes, not C strings. Resolver
/// storage is copied here before another Winsock resolver call can invalidate
/// it; the list is bounded in case a provider omits its terminator.
// SAFETY: Callers uphold the pointer and lifetime invariant required by this function. Pointers are host addresses, not guest addresses.
unsafe fn copy_binary_pointer_array(
    mut array: *mut *mut i8,
    maximum: usize,
    address_length: usize,
) -> Vec<Vec<u8>> {
    if array.is_null() {
        return Vec::new();
    }
    let mut copied = Vec::new();
    for _ in 0..maximum {
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        let item = unsafe { *array };
        if item.is_null() {
            break;
        }
        // A resolver address is a binary sockaddr, not an unbounded buffer.
        // Longer lengths are not copied: reading them would walk off the provider allocation.
        if address_length > MAX_RESOLVER_ADDRESS {
            break;
        }
        // SAFETY: `item` is non-null and `address_length` is capped at a sockaddr-sized bound.
        let bytes = unsafe { std::slice::from_raw_parts(item.cast::<u8>(), address_length) };
        copied.push(bytes.to_vec());
        array = unsafe { array.add(1) };
    }
    copied
}

// Winsock resolver names are far shorter than this. The cap stops a missing
// terminator from reading past the provider buffer. A terminated name at or
// below the cap is copied without its NUL, matching `CStr::to_bytes`.
const MAX_RESOLVER_STRING: usize = 2048;
const MAX_RESOLVER_ADDRESS: usize = 256;

// SAFETY: Callers uphold the pointer and lifetime invariant required by this function. Pointers are host addresses, not guest addresses.
unsafe fn copy_c_string(value: *const u8) -> Vec<u8> {
    if value.is_null() {
        return Vec::new();
    }
    let mut length = 0usize;
    while length < MAX_RESOLVER_STRING {
        // SAFETY: `value` is non-null. The scan stops at the first NUL or at
        // MAX_RESOLVER_STRING, so it cannot walk an unbounded provider buffer.
        if unsafe { *value.add(length) } == 0 {
            break;
        }
        length += 1;
    }
    // SAFETY: the preceding loop read exactly `length` initialized bytes.
    unsafe { std::slice::from_raw_parts(value, length) }.to_vec()
}
