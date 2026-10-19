//! Serialized nonblocking readiness probe for owned async-select routes.

use std::collections::BTreeMap;

use runtime::{
    DiagnosticKind, RuntimeError, Win16GuestNotificationSource, Win16HostNetworkEvent,
    Win16HostSocket,
};
use windows_sys::Win32::Networking::WinSock::*;

use super::helpers::SocketProbeError;
use super::helpers::{network_invariant, socket_error, socket_peek_status};
use super::{CachedConnectTerminal, NativeSocketState, NetworkAsyncState};
use super::{FD_ACCEPT_16, FD_CLOSE_16, FD_CONNECT_16, FD_OOB_16, FD_READ_16, FD_WRITE_16};

impl NetworkAsyncState {
    /// WinSock SO_ERROR is destructive. This single per-socket cache owns the
    /// native read until the runtime commits both guest output ranges and
    /// acknowledges this exact generation. FD_CONNECT has a separate FIFO ACK.
    pub(in super::super) fn read_socket_error(
        &mut self,
        socket: Win16HostSocket,
        raw: SOCKET,
    ) -> Result<(i32, runtime::Win16HostSocketErrorReadToken), i32> {
        let Some(snapshot) = self.sockets.get(&socket).copied() else {
            return Err(WSAENOTSOCK);
        };
        if let Some(read) = snapshot.socket_error_read {
            return Ok((
                read.error,
                socket_error_token(socket, read.generation, read.connect_attempt),
            ));
        }
        if let Some(terminal) = snapshot.connect_result
            && terminal.guest_error_pending
        {
            return Ok((
                terminal.error,
                socket_error_token(socket, terminal.read_generation, Some(terminal.attempt_id)),
            ));
        }

        let attempt = snapshot.connect_attempt;
        let was_connect_pending = snapshot.connect_pending;
        if was_connect_pending && attempt.is_none() {
            return Err(WSAEINVAL);
        }
        let ready = if was_connect_pending {
            connect_ready(raw)?
        } else {
            false
        };
        let notice = if was_connect_pending {
            if let Some(route) = self.registrations.get(&socket).copied() {
                let attempt_id = attempt.ok_or(WSAEINVAL)?;
                self.reserve_connect_completion(route, attempt_id)
                    .map_err(|_| WSAENOBUFS)?
            } else {
                None
            }
        } else {
            None
        };
        let generation =
            reserve_socket_error_generation(self.sockets.get_mut(&socket).ok_or(WSAENOTSOCK)?)?;
        if let Some(notice) = notice {
            if let Some(state) = self.sockets.get_mut(&socket) {
                state.connect_notice = Some(notice);
            }
        }

        // A zero SO_ERROR while select still reports a pending connect is a
        // real guest read, but not proof of completion. Cache it separately;
        // after its guest ACK, readiness polling may read a later terminal
        // result once. A nonzero SO_ERROR is itself the consumed terminal.
        let error = socket_error(raw)?;
        if was_connect_pending && (ready || error != 0) {
            let attempt_id = attempt.ok_or(WSAEINVAL)?;
            let terminal = CachedConnectTerminal {
                attempt_id,
                error,
                notice,
                read_generation: generation,
                guest_error_pending: true,
                event_pending: notice.is_some(),
            };
            if let Some(state) = self.sockets.get_mut(&socket) {
                state.connect_pending = false;
                state.connected = error == 0;
                state.connect_notice = None;
                state.connect_result = Some(terminal);
            }
            if let Some(notice) = notice {
                self.publish_cached_connect(notice.route, terminal)
                    .map_err(|_| WSAENOBUFS)?;
            }
        } else if let Some(state) = self.sockets.get_mut(&socket) {
            state.socket_error_read = Some(super::CachedSocketErrorRead {
                generation,
                connect_attempt: attempt,
                error,
            });
        }
        self.sync_poll_demand();
        if was_connect_pending && (ready || error != 0) && notice.is_some() {
            self.wake.request_poll();
        }
        Ok((error, socket_error_token(socket, generation, attempt)))
    }

    pub(in super::super) fn acknowledge_socket_error(
        &mut self,
        token: runtime::Win16HostSocketErrorReadToken,
    ) -> runtime::Win16HostNetworkResult {
        let Some(state) = self.sockets.get_mut(&token.socket) else {
            return super::fail(WSAENOTSOCK, super::signed_error());
        };
        if token.generation == 0 {
            return super::fail(WSAEINVAL, super::signed_error());
        }
        if state.last_socket_error_ack_generation == token.generation
            && state.last_socket_error_ack_connect_attempt == token.connect_attempt
        {
            return super::ok(runtime::Win16HostNetworkValue::Signed(0));
        }
        let mut retired_terminal = false;
        if let Some(mut terminal) = state.connect_result
            && terminal.read_generation == token.generation
            && Some(terminal.attempt_id) == token.connect_attempt
            && terminal.guest_error_pending
        {
            terminal.guest_error_pending = false;
            if !terminal.event_pending {
                state.connect_result = None;
                state.connect_attempt = None;
                retired_terminal = true;
            } else {
                state.connect_result = Some(terminal);
            }
        } else if state.socket_error_read.is_some_and(|read| {
            read.generation == token.generation && read.connect_attempt == token.connect_attempt
        }) {
            state.socket_error_read = None;
        } else {
            return super::fail(WSAEINVAL, super::signed_error());
        }
        state.last_socket_error_ack_generation = token.generation;
        state.last_socket_error_ack_connect_attempt = token.connect_attempt;
        let retry_poll = state.connect_pending || retired_terminal;
        self.sync_poll_demand();
        if retry_poll {
            self.wake.request_poll();
        }
        super::ok(runtime::Win16HostNetworkValue::Signed(0))
    }

    pub(super) fn poll_one_socket_event(
        &mut self,
        sockets: &BTreeMap<Win16HostSocket, SOCKET>,
    ) -> Result<(), RuntimeError> {
        if let Some((route, terminal)) = self
            .sockets
            .values()
            .filter_map(|state| {
                state
                    .connect_result
                    .filter(|terminal| terminal.event_pending)
                    .and_then(|terminal| terminal.notice.map(|notice| (notice.route, terminal)))
            })
            .min_by_key(|(_, terminal)| terminal.attempt_id)
        {
            let source = terminal
                .notice
                .map(super::ConnectNotificationReservation::source)
                .ok_or_else(|| {
                    network_invariant("cached connect event lost its reserved source")
                })?;
            if !self
                .events
                .iter()
                .any(|event| super::helpers::event_source(event) == source)
            {
                self.publish_cached_connect(route, terminal)?;
            }
            return Ok(());
        }
        if !self.events.is_empty() {
            return Ok(());
        }
        let mut routes = Vec::new();
        routes
            .try_reserve_exact(self.registrations.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    DiagnosticKind::ResourceExhausted,
                    "reserve WinSock async socket poll order",
                    error,
                )
            })?;
        routes.extend(self.registrations.values().copied().filter(|route| {
            let state = self.sockets.get(&route.socket).copied().unwrap_or_default();
            pollable_events(route.armed, state) != 0
        }));
        routes.sort_by_key(|route| route.socket);
        let route = match self.poll_cursor {
            Some(cursor) => routes
                .iter()
                .copied()
                .find(|route| route.socket > cursor)
                .or_else(|| routes.first().copied()),
            None => routes.first().copied(),
        };
        let Some(route) = route else {
            return Ok(());
        };
        self.poll_cursor = Some(route.socket);
        let Some(raw) = sockets.get(&route.socket).copied() else {
            self.registrations.remove(&route.socket);
            self.sync_poll_demand();
            return Ok(());
        };

        let mut socket_state = self.sockets.get(&route.socket).copied().unwrap_or_default();
        if let Some(terminal) = socket_state.connect_result {
            if terminal.event_pending {
                return Ok(());
            }
        }
        if socket_state.connect_pending && socket_state.socket_error_read.is_some() {
            return Ok(());
        }

        let mut read_set = FD_SET::default();
        let mut write_set = FD_SET::default();
        let mut except_set = FD_SET::default();
        read_set.fd_array[0] = raw;
        read_set.fd_count = 1;
        write_set.fd_array[0] = raw;
        write_set.fd_count = 1;
        except_set.fd_array[0] = raw;
        except_set.fd_count = 1;
        let mut timeout = TIMEVAL {
            tv_sec: 0,
            tv_usec: 0,
        };
        // SAFETY: select reads and writes caller-owned fd sets that stay live for the call.
        let result = unsafe {
            select(
                0,
                &mut read_set,
                &mut write_set,
                &mut except_set,
                &mut timeout,
            )
        };
        if result == SOCKET_ERROR {
            let code = crate::windows::win32_safe::wsa_last_error();
            if code == WSAENOTSOCK {
                self.registrations.remove(&route.socket);
                self.sync_poll_demand();
                return Ok(());
            }
            return Err(RuntimeError::new(
                DiagnosticKind::HostFailure,
                format!("poll WinSock async socket readiness failed with WSA error {code}"),
            ));
        }
        let is_readable = read_set.fd_count != 0;
        let is_writable = write_set.fd_count != 0;
        let is_exceptional = except_set.fd_count != 0;

        if socket_state.connect_pending && !(is_writable || is_exceptional) {
            // Other event interests may remain armed during connect, but none
            // can be published until the attempt's readiness resolves. This
            // keeps the reserved FD_CONNECT sequence stable when requested.
            self.sync_poll_demand();
            return Ok(());
        }

        // SO_ERROR clears the native connect result. The cached attempt is
        // published before any later select and remains owned on reserve or
        // sequence failure until the exact source can be created.
        if socket_state.connect_pending && (is_writable || is_exceptional) {
            let attempt_id = socket_state.connect_attempt.ok_or_else(|| {
                network_invariant("pending WinSock connect has no reserved attempt identity")
            })?;
            // Reserve the exact FD_CONNECT source before SO_ERROR consumes its
            // native terminal result, including when the route was registered
            // after connect began.
            let notice = self.reserve_connect_completion(route, attempt_id)?;
            let read_generation = reserve_socket_error_generation(
                self.sockets
                    .get_mut(&route.socket)
                    .ok_or_else(|| network_invariant("pending connect lost its socket owner"))?,
            )
            .map_err(|_| {
                RuntimeError::new(
                    DiagnosticKind::ResourceExhausted,
                    "WinSock SO_ERROR read generation space is exhausted",
                )
            })?;
            let error = socket_error(raw).map_err(|code| {
                RuntimeError::with_source(
                    DiagnosticKind::HostFailure,
                    "read the completed WinSock connect SO_ERROR",
                    SocketProbeError(code),
                )
            })?;
            let terminal = CachedConnectTerminal {
                attempt_id,
                error,
                notice,
                read_generation,
                guest_error_pending: true,
                event_pending: notice.is_some(),
            };
            if let Some(state) = self.sockets.get_mut(&route.socket) {
                state.connect_pending = false;
                state.connected = error == 0;
                state.connect_notice = None;
                state.connect_result = Some(terminal);
            }
            if notice.is_some() {
                self.publish_cached_connect(notice.expect("checked notice").route, terminal)?;
                return Ok(());
            }
            socket_state = self.sockets.get(&route.socket).copied().unwrap_or_default();
        }

        let active_mask = pollable_events(route.armed, socket_state);
        let mut ready: Vec<(u16, u16)> = Vec::new();
        ready.try_reserve_exact(4).map_err(|error| {
            RuntimeError::with_source(
                DiagnosticKind::ResourceExhausted,
                "reserve WinSock readiness result slots before inspecting socket status",
                error,
            )
        })?;
        if socket_state.listening && is_readable && active_mask & FD_ACCEPT_16 != 0 {
            ready.push((FD_ACCEPT_16 as u16, 0));
        } else if !socket_state.listening && is_readable {
            if socket_state.socket_type == SOCK_DGRAM {
                // select's read set already proves a queued datagram. A one
                // byte MSG_PEEK reports WSAEMSGSIZE for larger packets.
                if active_mask & FD_READ_16 != 0 {
                    ready.push((FD_READ_16 as u16, 0));
                }
            } else if socket_state.socket_type == SOCK_STREAM {
                match socket_peek_status(raw) {
                    Ok(Some(0)) => {
                        if let Some(state) = self.sockets.get_mut(&route.socket) {
                            state.receive_eof = true;
                        }
                        if active_mask & FD_CLOSE_16 != 0 && !socket_state.close_event_queued {
                            ready.push((FD_CLOSE_16 as u16, 0));
                        }
                        socket_state.receive_eof = true;
                    }
                    Ok(Some(count)) if count > 0 && active_mask & FD_READ_16 != 0 => {
                        ready.push((FD_READ_16 as u16, 0));
                    }
                    Err(error)
                        if active_mask & FD_CLOSE_16 != 0 && !socket_state.close_event_queued =>
                    {
                        ready.push((FD_CLOSE_16 as u16, error as u16));
                    }
                    _ => {}
                }
            }
        }
        if socket_state.socket_type == SOCK_STREAM && is_exceptional && active_mask & FD_OOB_16 != 0
        {
            ready.push((FD_OOB_16 as u16, 0));
        }
        if is_writable
            && !socket_state.local_send_shutdown
            && (socket_state.connected || socket_state.socket_type == SOCK_DGRAM)
            && active_mask & FD_WRITE_16 != 0
        {
            ready.push((FD_WRITE_16 as u16, 0));
        }
        if ready.is_empty() {
            self.sync_poll_demand();
            return Ok(());
        }
        self.events.try_reserve(ready.len()).map_err(|error| {
            RuntimeError::with_source(
                DiagnosticKind::ResourceExhausted,
                "reserve WinSock socket event sources",
                error,
            )
        })?;
        let event_count = ready
            .iter()
            .filter(|(event, _)| route.armed & u32::from(*event) != 0)
            .count();
        let Some(next_sequence) = route
            .next_sequence
            .checked_add(event_count as u64)
            .filter(|next| *next != 0)
        else {
            return Err(RuntimeError::new(
                DiagnosticKind::ResourceExhausted,
                "WinSock notification source sequence space is exhausted",
            ));
        };
        if route.next_sequence == u64::MAX {
            return Err(RuntimeError::new(
                DiagnosticKind::ResourceExhausted,
                "WinSock notification source sequence space is exhausted",
            ));
        }
        let mut sequence = route.next_sequence;
        let current = self.registrations.get_mut(&route.socket).ok_or_else(|| {
            network_invariant("WinSock async route disappeared during readiness poll")
        })?;
        if current.source_id != route.source_id
            || current.generation != route.generation
            || current.next_sequence != route.next_sequence
        {
            return Err(network_invariant(
                "WinSock route identity changed during readiness poll",
            ));
        }
        for (event, error) in ready {
            let event_mask = u32::from(event);
            if current.armed & event_mask == 0 {
                continue;
            }
            self.events.push_back(Win16HostNetworkEvent::SocketReady {
                source: Win16GuestNotificationSource {
                    id: current.source_id,
                    generation: current.generation,
                    sequence,
                },
                socket: current.socket,
                task: current.owner,
                registration_generation: current.generation,
                window: current.window,
                guest_hwnd: current.guest_hwnd,
                message: current.message,
                event,
                error,
            });
            current.armed &= !event_mask;
            if event == FD_CLOSE_16 as u16
                && let Some(state) = self.sockets.get_mut(&route.socket)
            {
                state.close_event_queued = true;
            }
            sequence += 1;
        }
        current.next_sequence = next_sequence;
        self.sync_poll_demand();
        Ok(())
    }

    fn publish_cached_connect(
        &mut self,
        route: super::AsyncSocketRegistration,
        terminal: CachedConnectTerminal,
    ) -> Result<(), RuntimeError> {
        let state = self.sockets.get(&route.socket).copied().ok_or_else(|| {
            network_invariant("cached WinSock connect result lost its socket owner")
        })?;
        if state.connect_pending
            || state.connect_attempt != Some(terminal.attempt_id)
            || !terminal.event_pending
            || state.connect_result != Some(terminal)
        {
            return Err(network_invariant(
                "cached WinSock SO_ERROR no longer matches its connect attempt",
            ));
        }
        let notice = terminal.notice.ok_or_else(|| {
            network_invariant("cached WinSock connect notification lost its reserved source")
        })?;
        let current = self
            .registrations
            .get(&route.socket)
            .copied()
            .ok_or_else(|| {
                network_invariant("cached WinSock connect result lost its notification route")
            })?;
        if current != route
            || current != notice.route
            || current.source_id != route.source_id
            || current.generation != route.generation
            || current.next_sequence != notice.sequence
            || current.armed & FD_CONNECT_16 == 0
        {
            return Err(network_invariant(
                "cached WinSock connect result changed route before publication",
            ));
        }
        let Some(next_sequence) = notice.sequence.checked_add(1).filter(|value| *value != 0) else {
            return Err(RuntimeError::new(
                DiagnosticKind::ResourceExhausted,
                "WinSock connect notification sequence space is exhausted",
            ));
        };
        self.events.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                DiagnosticKind::ResourceExhausted,
                "reserve cached WinSock connect source",
                error,
            )
        })?;
        let error = u16::try_from(terminal.error).map_err(|_| {
            network_invariant("WinSock SO_ERROR does not fit the Win16 FD_CONNECT error word")
        })?;
        self.events.push_back(Win16HostNetworkEvent::SocketReady {
            source: Win16GuestNotificationSource {
                id: current.source_id,
                generation: current.generation,
                sequence: notice.sequence,
            },
            socket: current.socket,
            task: current.owner,
            registration_generation: current.generation,
            window: current.window,
            guest_hwnd: current.guest_hwnd,
            message: current.message,
            event: FD_CONNECT_16 as u16,
            error,
        });
        if let Some(current) = self.registrations.get_mut(&route.socket) {
            current.armed &= !FD_CONNECT_16;
            current.next_sequence = next_sequence;
        }
        if let Some(state) = self.sockets.get_mut(&route.socket) {
            if let Some(mut cached) = state.connect_result {
                cached.event_pending = true;
                state.connect_result = Some(cached);
            }
        }
        self.sync_poll_demand();
        Ok(())
    }

    fn reserve_connect_completion(
        &mut self,
        route: super::AsyncSocketRegistration,
        attempt_id: u64,
    ) -> Result<Option<super::ConnectNotificationReservation>, RuntimeError> {
        if let Some(notice) = self
            .sockets
            .get(&route.socket)
            .and_then(|state| state.connect_notice)
        {
            if notice.attempt_id != attempt_id {
                return Err(network_invariant(
                    "reserved WinSock connect notification belongs to another attempt",
                ));
            }
            let current = self
                .registrations
                .get(&route.socket)
                .copied()
                .ok_or_else(|| {
                    network_invariant("reserved WinSock connect route disappeared before SO_ERROR")
                })?;
            if current != route || current != notice.route {
                return Err(network_invariant(
                    "reserved WinSock connect route changed before SO_ERROR",
                ));
            }
            self.events.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    DiagnosticKind::ResourceExhausted,
                    "preserve reserved WinSock connect event before reading SO_ERROR",
                    error,
                )
            })?;
            return Ok(Some(notice));
        }
        if route.armed & FD_CONNECT_16 == 0 {
            return Ok(None);
        }
        let current = self
            .registrations
            .get(&route.socket)
            .copied()
            .ok_or_else(|| {
                network_invariant("FD_CONNECT route disappeared before SO_ERROR reservation")
            })?;
        if current != route
            || current.source_id != route.source_id
            || current.generation != route.generation
            || current.armed & FD_CONNECT_16 == 0
        {
            return Err(network_invariant(
                "FD_CONNECT route changed before SO_ERROR reservation",
            ));
        }
        let Some(next) = route
            .next_sequence
            .checked_add(1)
            .filter(|value| *value != 0)
        else {
            return Err(RuntimeError::new(
                DiagnosticKind::ResourceExhausted,
                "WinSock connect notification sequence space is exhausted",
            ));
        };
        let _ = next;
        self.events.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                DiagnosticKind::ResourceExhausted,
                "reserve WinSock connect event before reading SO_ERROR",
                error,
            )
        })?;
        Ok(Some(super::ConnectNotificationReservation {
            route,
            sequence: route.next_sequence,
            attempt_id,
        }))
    }
}

fn socket_error_token(
    socket: Win16HostSocket,
    generation: u64,
    connect_attempt: Option<u64>,
) -> runtime::Win16HostSocketErrorReadToken {
    runtime::Win16HostSocketErrorReadToken {
        socket,
        generation,
        connect_attempt,
    }
}

fn reserve_socket_error_generation(state: &mut NativeSocketState) -> Result<u64, i32> {
    let generation = state.next_socket_error_generation;
    let Some(next) = generation.checked_add(1).filter(|next| *next != 0) else {
        return Err(WSAENOBUFS);
    };
    state.next_socket_error_generation = next;
    Ok(generation)
}

fn connect_ready(raw: SOCKET) -> Result<bool, i32> {
    let mut writable = FD_SET::default();
    let mut exceptional = FD_SET::default();
    writable.fd_array[0] = raw;
    writable.fd_count = 1;
    exceptional.fd_array[0] = raw;
    exceptional.fd_count = 1;
    let mut timeout = TIMEVAL {
        tv_sec: 0,
        tv_usec: 0,
    };
    // SAFETY: select reads and writes caller-owned fd sets that stay live for the call.
    let result = unsafe {
        select(
            0,
            std::ptr::null_mut(),
            &mut writable,
            &mut exceptional,
            &mut timeout,
        )
    };
    if result == SOCKET_ERROR {
        return Err(crate::windows::win32_safe::wsa_last_error());
    }
    Ok(writable.fd_count != 0 || exceptional.fd_count != 0)
}

pub(super) fn pollable_events(armed: u32, state: NativeSocketState) -> u32 {
    if state.listening {
        armed & FD_ACCEPT_16
    } else if state.connect_pending {
        // A nonblocking connect has one reserved terminal source. Do not let
        // pre-connect READ/WRITE/CLOSE events advance that sequence before
        // SO_ERROR is consumed. If FD_CONNECT was not requested, other
        // interests still drive the readiness probe and are evaluated only
        // after the connect attempt becomes terminal.
        if armed & FD_CONNECT_16 != 0 {
            armed & FD_CONNECT_16
        } else {
            armed & !FD_ACCEPT_16
        }
    } else if state.socket_type == SOCK_DGRAM && (state.connected || state.bound) {
        let mut events = armed
            & (FD_READ_16
                | if state.local_send_shutdown {
                    0
                } else {
                    FD_WRITE_16
                });
        if state.local_receive_shutdown {
            events &= !FD_READ_16;
        }
        events
    } else if state.connected {
        let mut events = armed & !(FD_CONNECT_16 | FD_ACCEPT_16);
        if state.receive_eof || state.local_receive_shutdown {
            events &= !(FD_READ_16 | FD_OOB_16);
        }
        if state.local_send_shutdown {
            events &= !FD_WRITE_16;
        }
        if state.close_event_queued {
            events &= !FD_CLOSE_16;
        }
        events
    } else {
        0
    }
}
