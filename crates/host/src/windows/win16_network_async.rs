//! Owned WinSock asynchronous request and event sources.
//!
//! Native resolver work runs away from the guest execution thread and copies
//! resolver records before returning. Socket readiness is sampled at runtime
//! safe points. Both event kinds remain in this owner until an exact source
//! ACK; native callbacks never enter guest code.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex, atomic::AtomicU64};

use runtime::{
    DiagnosticKind, RuntimeError, Win16GuestNotificationSource, Win16HostAsyncTask,
    Win16HostNetworkEvent, Win16HostNetworkNameResult, Win16HostNetworkValue, Win16HostSocket,
    Win16NetworkTaskIdentity,
};
use windows_sys::Win32::Networking::WinSock::*;

use super::super::win16_network_wake::NetworkWakeHub;
use super::{fail, ok};
use helpers::{event_source, network_invariant, signed_error};
#[path = "win16_network_async_helpers.rs"]
mod helpers;
#[path = "win16_network_async_lifecycle.rs"]
mod lifecycle;
#[path = "win16_network_async_poll.rs"]
mod poll;
#[path = "win16_network_resolver_work.rs"]
mod resolver_work;
use poll::pollable_events;
use resolver_work::ResolverWorkLease;

pub(super) fn allocate_source_id(identity_source: &AtomicU64) -> Option<u64> {
    helpers::allocate_source_id(identity_source)
}

const FD_READ_16: u32 = 0x0001;
const FD_WRITE_16: u32 = 0x0002;
const FD_OOB_16: u32 = 0x0004;
const FD_ACCEPT_16: u32 = 0x0008;
const FD_CONNECT_16: u32 = 0x0010;
const FD_CLOSE_16: u32 = 0x0020;
const FD_MASK_16: u32 = 0x003f;
#[derive(Debug)]
enum ResolverWorkerState {
    Queued,
    Running,
    Completed(Result<Win16HostNetworkNameResult, i32>),
    CancelledBeforeStart,
    CancelledRunning,
    CancelledAfterRun,
    Panicked,
}

#[derive(Debug)]
struct AsyncQueryOwner {
    owner: Win16NetworkTaskIdentity,
    window: runtime::Win16HostWindow,
    guest_hwnd: u16,
    message: u16,
    capacity: i16,
    request_generation: u64,
    source_id: u64,
    worker_state: Arc<Mutex<ResolverWorkerState>>,
    work: Option<ResolverWorkLease>,
    work_retirement_succeeded: Option<bool>,
    worker_failure_reported: bool,
    event_source: Option<Win16GuestNotificationSource>,
}

/// Exact async owners moved out of NetworkAsyncState after shutdown. Keeping
/// this receipt alive retains unACKed FIFO sources and copied resolver results.
#[derive(Debug, Default)]
pub(super) struct AsyncShutdownReceipt {
    queries: HashMap<Win16HostAsyncTask, AsyncQueryOwner>,
    registrations: HashMap<Win16HostSocket, AsyncSocketRegistration>,
    sockets: HashMap<Win16HostSocket, NativeSocketState>,
    events: VecDeque<Win16HostNetworkEvent>,
    panicked_workers: usize,
}

impl AsyncShutdownReceipt {
    pub(super) fn retire_socket(&mut self, socket: Win16HostSocket) {
        self.registrations.remove(&socket);
        self.sockets.remove(&socket);
    }

    pub(super) fn is_quiescent(&self) -> bool {
        self.queries.is_empty()
            && self.events.is_empty()
            && self.registrations.is_empty()
            && self.sockets.is_empty()
            && self.panicked_workers == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AsyncSocketRegistration {
    socket: Win16HostSocket,
    owner: Win16NetworkTaskIdentity,
    window: runtime::Win16HostWindow,
    guest_hwnd: u16,
    message: u16,
    events: u32,
    armed: u32,
    generation: u64,
    source_id: u64,
    next_sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ConnectNotificationReservation {
    route: AsyncSocketRegistration,
    sequence: u64,
    attempt_id: u64,
}

impl ConnectNotificationReservation {
    fn source(self) -> Win16GuestNotificationSource {
        Win16GuestNotificationSource {
            id: self.route.source_id,
            generation: self.route.generation,
            sequence: self.sequence,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct AcceptRegistrationReservation {
    listener: AsyncSocketRegistration,
    source_id: u64,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct NativeSocketState {
    socket_type: i32,
    connected: bool,
    connect_pending: bool,
    connect_attempt: Option<u64>,
    connect_notice: Option<ConnectNotificationReservation>,
    connect_result: Option<CachedConnectTerminal>,
    next_socket_error_generation: u64,
    socket_error_read: Option<CachedSocketErrorRead>,
    last_socket_error_ack_generation: u64,
    last_socket_error_ack_connect_attempt: Option<u64>,
    bound: bool,
    listening: bool,
    receive_eof: bool,
    local_receive_shutdown: bool,
    local_send_shutdown: bool,
    close_event_queued: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CachedConnectTerminal {
    attempt_id: u64,
    error: i32,
    notice: Option<ConnectNotificationReservation>,
    read_generation: u64,
    guest_error_pending: bool,
    event_pending: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CachedSocketErrorRead {
    generation: u64,
    connect_attempt: Option<u64>,
    error: i32,
}

#[derive(Debug)]
pub(super) struct NetworkAsyncState {
    wake: NetworkWakeHub,
    /// Active native printer watches reuse this existing safe-point wake
    /// producer instead of creating a parallel USER wake namespace.
    external_poll_demand: usize,
    next_task: u64,
    next_connect_attempt: u64,
    poll_cursor: Option<Win16HostSocket>,
    queries: HashMap<Win16HostAsyncTask, AsyncQueryOwner>,
    registrations: HashMap<Win16HostSocket, AsyncSocketRegistration>,
    sockets: HashMap<Win16HostSocket, NativeSocketState>,
    events: VecDeque<Win16HostNetworkEvent>,
}

impl NetworkAsyncState {
    pub(super) fn new(wake: NetworkWakeHub) -> Self {
        Self {
            wake,
            external_poll_demand: 0,
            next_task: 1,
            next_connect_attempt: 1,
            poll_cursor: None,
            queries: HashMap::new(),
            registrations: HashMap::new(),
            sockets: HashMap::new(),
            events: VecDeque::new(),
        }
    }

    pub(super) fn ensure_external_polling(&self) -> Result<(), RuntimeError> {
        self.wake.ensure_started()
    }

    pub(super) fn set_external_poll_demand(&mut self, count: usize) {
        self.external_poll_demand = count;
        self.sync_poll_demand();
    }

    pub(super) fn has_registration(&self, socket: Win16HostSocket) -> bool {
        self.registrations.contains_key(&socket)
    }

    pub(super) fn rearm_event(
        &mut self,
        socket: Win16HostSocket,
        source_id: u64,
        generation: u64,
        events: u32,
    ) -> runtime::Win16HostNetworkResult {
        let Some(route) = self.registrations.get_mut(&socket) else {
            return fail(WSAEINVAL, signed_error());
        };
        if route.source_id != source_id
            || route.generation != generation
            || events == 0
            || events & !route.events != 0
        {
            return fail(WSAEINVAL, signed_error());
        }
        let state = self.sockets.get(&socket).copied().unwrap_or_default();
        let mut rearmed = events;
        if state.receive_eof || state.local_receive_shutdown {
            rearmed &= !(FD_READ_16 | FD_OOB_16);
        }
        if state.local_send_shutdown {
            rearmed &= !FD_WRITE_16;
        }
        if state.close_event_queued {
            rearmed &= !FD_CLOSE_16;
        }
        route.armed |= rearmed;
        self.sync_poll_demand();
        ok(Win16HostNetworkValue::Signed(0))
    }

    pub(super) fn reserve_accept_registration(
        &mut self,
        identity_source: &Arc<AtomicU64>,
        listener: Win16HostSocket,
        generation: Option<u64>,
    ) -> Result<Option<AcceptRegistrationReservation>, i32> {
        let Some(route) = self.registrations.get(&listener).copied() else {
            return if generation.is_none() {
                Ok(None)
            } else {
                Err(WSAEINVAL)
            };
        };
        let Some(generation) = generation.filter(|generation| *generation != 0) else {
            return Err(WSAEINVAL);
        };
        self.registrations.try_reserve(1).map_err(|_| WSAENOBUFS)?;
        if route.events & FD_WRITE_16 != 0 {
            self.events.try_reserve(1).map_err(|_| WSAENOBUFS)?;
        }
        let Some(source_id) = allocate_source_id(identity_source) else {
            return Err(WSAENOBUFS);
        };
        Ok(Some(AcceptRegistrationReservation {
            listener: route,
            source_id,
            generation,
        }))
    }

    pub(super) fn inherit_accept_registration(
        &mut self,
        reservation: AcceptRegistrationReservation,
        accepted: Win16HostSocket,
    ) -> runtime::Win16HostAcceptedAsyncRegistration {
        let listener = reservation.listener;
        let route = AsyncSocketRegistration {
            socket: accepted,
            owner: listener.owner,
            window: listener.window,
            guest_hwnd: listener.guest_hwnd,
            message: listener.message,
            events: listener.events,
            armed: listener.events,
            generation: reservation.generation,
            source_id: reservation.source_id,
            next_sequence: 1,
        };
        // FD_WRITE is initially signalled on accept. Keep it armed until the
        // runtime publishes the accepted guest SOCKET; the safe-point poll
        // will queue it once the connected socket is writable.
        self.registrations.insert(accepted, route);
        self.sync_poll_demand();
        runtime::Win16HostAcceptedAsyncRegistration {
            source_id: route.source_id,
            generation: route.generation,
            inherited_source_id: listener.source_id,
            inherited_generation: listener.generation,
        }
    }

    pub(super) fn async_select(
        &mut self,
        identity_source: &Arc<AtomicU64>,
        sockets: &BTreeMap<Win16HostSocket, SOCKET>,
        socket: Win16HostSocket,
        owner: Win16NetworkTaskIdentity,
        window: runtime::Win16HostWindow,
        guest_hwnd: u16,
        message: u16,
        events: u32,
        generation: u64,
        expected_source_id: Option<u64>,
    ) -> runtime::Win16HostNetworkResult {
        let Some(raw) = sockets.get(&socket).copied() else {
            return fail(WSAENOTSOCK, signed_error());
        };
        if events & !FD_MASK_16 != 0 {
            return fail(WSAEINVAL, signed_error());
        }
        if events == 0 {
            if generation == 0 {
                if self.registrations.contains_key(&socket) || expected_source_id.is_some() {
                    return fail(WSAEINVAL, signed_error());
                }
            } else {
                let Some(route) = self.registrations.get(&socket) else {
                    return fail(WSAEINVAL, signed_error());
                };
                if route.generation != generation
                    || route.owner != owner
                    || expected_source_id != Some(route.source_id)
                {
                    return fail(WSAEINVAL, signed_error());
                }
            }
            // WSAAsyncSelect changes socket mode even when clearing its event
            // record. Keep the old route until this native operation succeeds.
            let mut nonblocking = 1u32;
            if unsafe { ioctlsocket(raw, FIONBIO, &mut nonblocking) } == SOCKET_ERROR {
                return fail(unsafe { WSAGetLastError() }, signed_error());
            }
            let queued_connect_source = self
                .sockets
                .get(&socket)
                .and_then(|state| state.connect_result)
                .and_then(|terminal| terminal.notice.map(ConnectNotificationReservation::source))
                .is_some_and(|source| {
                    self.events
                        .iter()
                        .any(|event| event_source(event) == source)
                });
            self.registrations.remove(&socket);
            if let Some(state) = self.sockets.get_mut(&socket) {
                state.connect_notice = None;
                if let Some(mut terminal) = state.connect_result {
                    if terminal.event_pending && !queued_connect_source {
                        // WSAAsyncSelect cancellation revokes only a source
                        // that has not entered the FIFO; the guest SO_ERROR
                        // value remains owned until its separate commit ACK.
                        terminal.event_pending = false;
                        terminal.notice = None;
                    }
                    if !terminal.event_pending && !terminal.guest_error_pending {
                        state.connect_result = None;
                        state.connect_attempt = None;
                    } else {
                        state.connect_result = Some(terminal);
                    }
                }
            }
            self.sync_poll_demand();
            return ok(Win16HostNetworkValue::AsyncRegistration {
                source_id: 0,
                generation,
            });
        }
        if generation == 0 || expected_source_id.is_some() {
            return fail(WSAEINVAL, signed_error());
        }
        if self.registrations.try_reserve(1).is_err() {
            return fail(WSAENOBUFS, signed_error());
        }
        if self.wake.ensure_started().is_err() {
            return fail(WSAENOBUFS, signed_error());
        }
        let initial_connect = events & FD_CONNECT_16 != 0
            && self.sockets.get(&socket).is_some_and(|state| {
                state.connected
                    && !state.connect_pending
                    && !state
                        .connect_result
                        .is_some_and(|terminal| terminal.event_pending)
            });
        let pending_attempt = self.sockets.get(&socket).and_then(|state| {
            (state.connect_pending && events & FD_CONNECT_16 != 0)
                .then_some(state.connect_attempt)
                .flatten()
        });
        if (initial_connect || pending_attempt.is_some()) && self.events.try_reserve(1).is_err() {
            return fail(WSAENOBUFS, signed_error());
        }
        let Some(source_id) = allocate_source_id(identity_source) else {
            return fail(WSAENOBUFS, signed_error());
        };
        let route = AsyncSocketRegistration {
            socket,
            owner,
            window,
            guest_hwnd,
            message,
            events,
            armed: if initial_connect {
                events & !FD_CONNECT_16
            } else {
                events
            },
            generation,
            source_id,
            next_sequence: if initial_connect { 2 } else { 1 },
        };
        let connect_notice = pending_attempt.map(|attempt_id| ConnectNotificationReservation {
            route,
            sequence: 1,
            attempt_id,
        });

        // WinSock changes the native socket to nonblocking before accepting a
        // nonzero event mask. The registration is visible only after this
        // native operation succeeds.
        let mut nonblocking = 1u32;
        if unsafe { ioctlsocket(raw, FIONBIO, &mut nonblocking) } == SOCKET_ERROR {
            return fail(unsafe { WSAGetLastError() }, signed_error());
        }
        let queued_connect_source = self
            .sockets
            .get(&socket)
            .and_then(|state| state.connect_result)
            .and_then(|terminal| terminal.notice.map(ConnectNotificationReservation::source))
            .is_some_and(|source| {
                self.events
                    .iter()
                    .any(|event| event_source(event) == source)
            });
        if let Some(state) = self.sockets.get_mut(&socket)
            && let Some(mut terminal) = state.connect_result
        {
            let route_replaced = terminal.notice.is_some_and(|notice| notice.route != route);
            if route_replaced && terminal.event_pending && !queued_connect_source {
                // A new WSAAsyncSelect route cannot inherit an unposted source
                // reserved for the old registration. Keep the independently
                // cached guest SO_ERROR result until its exact read ACK.
                terminal.event_pending = false;
                terminal.notice = None;
            }
            if !terminal.event_pending && !terminal.guest_error_pending {
                state.connect_result = None;
                state.connect_attempt = None;
            } else {
                state.connect_result = Some(terminal);
            }
        }
        self.registrations.remove(&socket);
        self.registrations.insert(socket, route);
        if let Some(state) = self.sockets.get_mut(&socket) {
            state.connect_notice = connect_notice;
        }
        if initial_connect {
            self.events.push_back(Win16HostNetworkEvent::SocketReady {
                source: Win16GuestNotificationSource {
                    id: route.source_id,
                    generation: route.generation,
                    sequence: 1,
                },
                socket: route.socket,
                task: route.owner,
                registration_generation: route.generation,
                window: route.window,
                guest_hwnd: route.guest_hwnd,
                message: route.message,
                event: FD_CONNECT_16 as u16,
                error: 0,
            });
        }
        self.sync_poll_demand();
        if initial_connect {
            self.wake.request_poll();
        }
        ok(Win16HostNetworkValue::AsyncRegistration {
            source_id,
            generation,
        })
    }

    /// Reserve queue and sequence capacity before invoking a nonblocking
    /// native connect. A completed connect with FD_CONNECT interest can then
    /// publish its exact source without allocation after the native effect.
    pub(super) fn reserve_connect_attempt(
        &mut self,
        socket: Win16HostSocket,
    ) -> Result<(u64, Option<ConnectNotificationReservation>), i32> {
        let Some(state) = self.sockets.get(&socket) else {
            return Err(WSAENOTSOCK);
        };
        let async_completion_route = self
            .registrations
            .get(&socket)
            .is_some_and(|route| route.events & !FD_ACCEPT_16 != 0);
        if state.connect_result.is_some()
            || state.socket_error_read.is_some()
            || (state.connect_pending && async_completion_route)
        {
            return Err(WSAEALREADY);
        }
        let attempt_id = self.next_connect_attempt;
        let Some(next_attempt) = attempt_id.checked_add(1).filter(|next| *next != 0) else {
            return Err(WSAENOBUFS);
        };
        let Some(mut route) = self
            .registrations
            .get(&socket)
            .copied()
            .filter(|route| route.events & FD_CONNECT_16 != 0)
        else {
            self.next_connect_attempt = next_attempt;
            return Ok((attempt_id, None));
        };
        if route.next_sequence == 0 || route.next_sequence.checked_add(1).is_none() {
            return Err(WSAENOBUFS);
        }
        self.events.try_reserve(1).map_err(|_| WSAENOBUFS)?;
        // A new native connect attempt reenables the registered FD_CONNECT
        // source even after the previous attempt's event was queued.
        route.armed |= FD_CONNECT_16;
        if let Some(current) = self.registrations.get_mut(&socket) {
            if current.source_id != route.source_id
                || current.generation != route.generation
                || current.next_sequence != route.next_sequence
            {
                return Err(WSAEINVAL);
            }
            current.armed |= FD_CONNECT_16;
        } else {
            return Err(WSAENOTSOCK);
        }
        self.next_connect_attempt = next_attempt;
        Ok((
            attempt_id,
            Some(ConnectNotificationReservation {
                route,
                sequence: route.next_sequence,
                attempt_id,
            }),
        ))
    }

    pub(super) fn finish_connect_notification(
        &mut self,
        reservation: Option<ConnectNotificationReservation>,
        result: i32,
        error: Option<i32>,
    ) {
        let Some(reservation) = reservation else {
            return;
        };
        let pending = matches!(error, Some(WSAEWOULDBLOCK | WSAEINPROGRESS | WSAEALREADY));
        if pending {
            return;
        }
        let route = reservation.route;
        self.events.push_back(Win16HostNetworkEvent::SocketReady {
            source: Win16GuestNotificationSource {
                id: route.source_id,
                generation: route.generation,
                sequence: reservation.sequence,
            },
            socket: route.socket,
            task: route.owner,
            registration_generation: route.generation,
            window: route.window,
            guest_hwnd: route.guest_hwnd,
            message: route.message,
            event: FD_CONNECT_16 as u16,
            error: error.unwrap_or(if result == 0 { 0 } else { WSAEINVAL }) as u16,
        });
        if let Some(current) = self.registrations.get_mut(&route.socket)
            && current.source_id == route.source_id
            && current.generation == route.generation
            && current.next_sequence == reservation.sequence
            && current.armed & FD_CONNECT_16 != 0
        {
            current.next_sequence = reservation.sequence + 1;
            current.armed &= !FD_CONNECT_16;
        }
        self.sync_poll_demand();
        self.wake.request_poll();
    }

    pub(super) fn register_socket(
        &mut self,
        socket: Win16HostSocket,
        socket_type: i32,
        connected: bool,
    ) {
        self.sockets.insert(
            socket,
            NativeSocketState {
                socket_type,
                connected,
                next_socket_error_generation: 1,
                ..NativeSocketState::default()
            },
        );
    }

    pub(super) fn note_bind(&mut self, socket: Win16HostSocket) {
        if let Some(state) = self.sockets.get_mut(&socket) {
            state.bound = true;
        }
        self.sync_poll_demand();
    }

    pub(super) fn note_receive(&mut self, socket: Win16HostSocket, result: i32, requested: i16) {
        if result == 0
            && requested > 0
            && let Some(state) = self.sockets.get_mut(&socket)
            && state.socket_type == SOCK_STREAM
        {
            state.receive_eof = true;
        }
        if let Some(route) = self.registrations.get_mut(&socket) {
            if !self
                .sockets
                .get(&socket)
                .is_some_and(|state| state.receive_eof || state.local_receive_shutdown)
            {
                route.armed |= route.events & FD_READ_16;
                route.armed |= route.events & FD_OOB_16;
            }
        }
        self.sync_poll_demand();
    }

    pub(super) fn note_accept(&mut self, socket: Win16HostSocket) {
        if let Some(route) = self.registrations.get_mut(&socket) {
            route.armed |= route.events & FD_ACCEPT_16;
        }
        self.sync_poll_demand();
    }

    pub(super) fn note_send(&mut self, socket: Win16HostSocket, result: i32, error: Option<i32>) {
        if result >= 0 {
            if let Some(state) = self.sockets.get_mut(&socket)
                && state.socket_type == SOCK_DGRAM
            {
                // A successful sendto implicitly binds an unbound datagram
                // socket, making later FD_READ polling meaningful.
                state.bound = true;
            }
        }
        if error == Some(WSAEWOULDBLOCK) {
            if !self
                .sockets
                .get(&socket)
                .is_some_and(|state| state.local_send_shutdown)
                && let Some(route) = self.registrations.get_mut(&socket)
            {
                route.armed |= route.events & FD_WRITE_16;
            }
        }
        let _ = result;
        self.sync_poll_demand();
    }

    pub(super) fn note_connect(
        &mut self,
        socket: Win16HostSocket,
        attempt_id: u64,
        notice: Option<ConnectNotificationReservation>,
        result: i32,
        error: Option<i32>,
    ) {
        let has_async_route = self
            .registrations
            .get(&socket)
            .is_some_and(|route| route.events & !FD_ACCEPT_16 != 0);
        if let Some(state) = self.sockets.get_mut(&socket) {
            if result == 0 {
                state.connected = true;
                state.connect_pending = false;
                state.connect_attempt = None;
                state.connect_notice = None;
            } else if matches!(error, Some(WSAEWOULDBLOCK | WSAEINPROGRESS | WSAEALREADY))
                && state.connect_pending
                && !has_async_route
            {
                // Without an async completion route, let native connect and
                // the guest's select/SO_ERROR sequence decide whether this
                // old attempt is still pending; don't replace its identity
                // when native reports WSAEALREADY again.
            } else if matches!(error, Some(WSAEWOULDBLOCK | WSAEINPROGRESS | WSAEALREADY)) {
                state.connect_pending = true;
                state.connected = false;
                state.connect_attempt = Some(attempt_id);
                state.connect_notice = notice;
            } else {
                state.connect_pending = false;
                state.connected = false;
                state.connect_attempt = None;
                state.connect_notice = None;
            }
        }
        if result == 0 {
            if let Some(route) = self.registrations.get_mut(&socket) {
                route.armed |= route.events & FD_WRITE_16;
            }
        }
        self.sync_poll_demand();
    }

    pub(super) fn note_shutdown(&mut self, socket: Win16HostSocket, how: i16) {
        if let Some(state) = self.sockets.get_mut(&socket) {
            // SD_RECEIVE and SD_SEND close independent directions; SD_BOTH
            // closes both, while peer EOF alone does not disable FD_WRITE.
            if how == 0 || how == 2 {
                state.local_receive_shutdown = true;
            }
            if how == 1 || how == 2 {
                state.local_send_shutdown = true;
            }
        }
        self.sync_poll_demand();
    }

    pub(super) fn note_listen(&mut self, socket: Win16HostSocket, listening: bool) {
        if let Some(state) = self.sockets.get_mut(&socket) {
            state.listening = listening;
        }
        if listening {
            if let Some(route) = self.registrations.get_mut(&socket) {
                route.armed |= route.events & FD_ACCEPT_16;
            }
        }
        self.sync_poll_demand();
    }

    pub(super) fn remove_socket(&mut self, socket: Win16HostSocket) {
        self.registrations.remove(&socket);
        self.sockets.remove(&socket);
        self.sync_poll_demand();
    }
}
