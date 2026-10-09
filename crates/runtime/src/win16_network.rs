//! Win16 Winsock guest state, including sockets, resolver buffers, and
//! asynchronous source owners.

use std::{collections::{BTreeMap, BTreeSet, HashMap}, sync::Arc};
use win16_abi::GlobalHandle;
use crate::{
    RuntimeError,
    Win16GuestNotification, Win16HostNetworkEvent, Win16HostWindow,
    Win16WindowOperationStartedFailure, Win16WindowSourceRetiredProof,
    win16_host_network::{Win16HostAsyncRequest, Win16HostAsyncTask, Win16HostSocket, Win16NetworkTaskIdentity},
    win16_runtime::guest_ranges::GuestOutputRange,
};

#[derive(Clone, Debug)]
pub(crate) struct StaticResultBlock {
    pub guest_handle: u16,
    pub identity: GlobalHandle,
    retirement_cause: Option<Arc<RuntimeError>>,
}

impl StaticResultBlock {
    pub(crate) fn new(guest_handle: u16, identity: GlobalHandle) -> Self {
        Self { guest_handle, identity, retirement_cause: None }
    }

    fn remember_retirement_failure(&mut self, error: RuntimeError) -> RuntimeError {
        if let Some(cause) = &self.retirement_cause {
            return RuntimeError::with_source(
                cause.kind().with_cleanup(error.kind()),
                "WinSock resolver owner retry retained its first typed cleanup cause",
                Arc::clone(cause),
            ).with_cleanup("retrying WinSock resolver owner retirement", error);
        }
        let cause = Arc::new(error);
        let report = RuntimeError::with_source(
            cause.kind(),
            "WinSock resolver owner retained its initial typed cleanup cause",
            Arc::clone(&cause),
        );
        self.retirement_cause = Some(cause);
        report
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketRecord {
    host: Win16HostSocket,
    owner: Win16NetworkTaskIdentity,
    nonblocking: bool,
}

#[derive(Clone, Debug)]
struct AsyncRecord { host: Option<Win16HostAsyncRequest>, route: Win16AsyncGuestRoute }

#[derive(Clone, Debug)]
pub(crate) struct Win16AsyncGuestRoute {
    pub window: u16,
    pub host_window: Win16HostWindow,
    pub message: u16,
    pub task: Win16NetworkTaskIdentity,
    pub lookup: win16_abi::Win16AsyncLookup,
    pub output: GuestOutputRange,
    pub output_capacity: u16,
    pub request_generation: u64,
    pub source_id: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Win16AsyncSelectRoute {
    pub socket: Win16HostSocket,
    pub window: u16,
    pub host_window: Win16HostWindow,
    pub message: u16,
    pub events: u32,
    pub task: Win16NetworkTaskIdentity,
    pub registration_generation: u64,
    pub source_id: u64,
    pub last_event_sequence: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RetiredAsyncSelectRoute {
    pub guest_socket: u16,
    pub route: Win16AsyncSelectRoute,
}

#[derive(Clone, Debug)]
pub(crate) struct OrphanSocketOwner {
    pub socket: Win16HostSocket,
    pub owner: Win16NetworkTaskIdentity,
    pub first_phase: Win16NetworkSocketRetirementPhase,
    pub phase: Win16NetworkSocketRetirementPhase,
    pub first_cause: Arc<crate::RuntimeError>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Win16NetworkSocketRetirementPhase {
    UnpublishedRollback,
    GuestCleanupReferenceReleased,
    RuntimeTeardown,
}

#[derive(Debug)]
pub(crate) struct PreparedAsyncGuestOutput {
    pub range: GuestOutputRange,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Default)]
pub(crate) struct Win16NetworkEventProgress {
    pub notification: Option<Win16GuestNotification>,
    pub identity_validated: bool,
    pub target_abandoned: bool,
    pub output: Option<PreparedAsyncGuestOutput>,
    pub output_projected: bool,
    pub output_error: Option<u16>,
    pub required_output_bytes: u16,
    pub post_started: bool,
    pub post_proof: Option<Arc<Win16WindowSourceRetiredProof>>,
    pub posted: Option<bool>,
    pub post_proof_read_back: bool,
    pub post_proof_consumed: bool,
    pub retry_not_before: Option<std::time::Instant>,
    pub started_failure: Option<Arc<Win16WindowOperationStartedFailure>>,
    pub terminal_user_acknowledged: bool,
    pub network_source_acknowledged: bool,
    pub runtime_owner_retired: bool,
    pub failure_reported: bool,
}

#[derive(Debug)]
pub(crate) struct PendingNetworkEvent {
    pub event: Win16HostNetworkEvent,
    pub progress: Win16NetworkEventProgress,
    pub first_cause: Option<Arc<crate::RuntimeError>>,
}

/// Per-Win16-process socket IDs and per-task Winsock error values. Host tokens
/// are mapped at this layer; guest code only sees a WORD socket/task ID.
#[derive(Debug, Default)]
pub struct Win16NetworkState {
    sockets: BTreeMap<u16, SocketRecord>,
    async_tasks: HashMap<u16, AsyncRecord>,
    async_selects: HashMap<u16, Win16AsyncSelectRoute>,
    retired_async_selects: Vec<RetiredAsyncSelectRoute>,
    orphan_sockets: Vec<OrphanSocketOwner>,
    // Runtime network event delivery and task teardown live in sibling modules.
    pub(crate) pending_event: Option<PendingNetworkEvent>,
    producer_quiescing: bool,
    producers_quiesced: bool,
    event_poll_failure: Option<Arc<RuntimeError>>,
    event_poll_failure_reported: bool,
    task_identity_by_handle: BTreeMap<u16, Win16NetworkTaskIdentity>,
    last_error_by_task: BTreeMap<Win16NetworkTaskIdentity, u16>,
    next_socket: u16,
    next_async_task: u16,
    next_async_generation: u64,
    startup_references_by_task: BTreeMap<Win16NetworkTaskIdentity, u32>,
    total_startup_references: u64,
    result_blocks_by_task: BTreeMap<u16, Vec<StaticResultBlock>>,
    blocking_by_task: BTreeMap<u16, bool>,
    warned_unsupported: BTreeSet<u16>,
}

impl Win16NetworkState {
    pub fn new() -> Self {
        Self { next_socket: 1, next_async_task: 1, next_async_generation: 1, ..Self::default() }
    }

    pub(crate) fn needs_scheduler_progress(&self) -> bool {
        !self.sockets.is_empty()
            || !self.async_tasks.is_empty()
            || !self.async_selects.is_empty()
            || !self.retired_async_selects.is_empty()
            || !self.orphan_sockets.is_empty()
            || self.pending_event.is_some()
            || self.event_poll_failure.is_some()
            || (self.producer_quiescing && !self.producers_quiesced)
            || self.result_blocks_by_task.values().any(|blocks| {
                blocks.iter().any(|block| block.retirement_cause.is_some())
            })
    }

    pub(crate) fn native_sources_quiescent(&self) -> bool {
        self.sockets.is_empty() && self.async_tasks.is_empty()
            && self.async_selects.is_empty() && self.retired_async_selects.is_empty()
            && self.orphan_sockets.is_empty() && self.pending_event.is_none()
            && self.result_blocks_by_task.values().all(Vec::is_empty)
            && self.startup_references_by_task.is_empty()
            && self.total_startup_references == 0
    }

    pub(crate) fn begin_producer_quiescence(&mut self) {
        // Stop the only Runtime path that can turn a native network event into
        // a new guest USER operation before asking the provider to disable routes.
        self.producer_quiescing = true;
    }

    pub(crate) fn producers_quiesced(&self) -> bool { self.producers_quiesced }

    pub(crate) fn clear_event_poll_failure(&mut self) {
        self.event_poll_failure = None;
        self.event_poll_failure_reported = false;
    }

    /// Keep the first poll failure and return it for reporting only once.
    pub(crate) fn retain_event_poll_failure(&mut self, error: RuntimeError) -> Option<Arc<RuntimeError>> {
        if self.event_poll_failure.is_none() { self.event_poll_failure = Some(Arc::new(error)); }
        if self.event_poll_failure_reported { return None; }
        self.event_poll_failure_reported = true;
        self.event_poll_failure.as_ref().map(Arc::clone)
    }

    pub(crate) fn producer_quiescing(&self) -> bool { self.producer_quiescing }

    pub(crate) fn mark_producers_quiesced(&mut self) {
        self.producer_quiescing = true;
        self.producers_quiesced = true;
    }

    pub fn host_socket(&self, guest: u16) -> Option<Win16HostSocket> {
        self.sockets.get(&guest).map(|record| record.host)
    }

    pub fn socket_nonblocking(&self, guest: u16) -> Option<bool> {
        self.sockets.get(&guest).map(|record| record.nonblocking)
    }

    pub fn host_socket_nonblocking(&self, socket: Win16HostSocket) -> Option<bool> {
        self.sockets.values().find_map(|record| {
            (record.host == socket).then_some(record.nonblocking)
        })
    }

    pub fn set_socket_nonblocking(&mut self, guest: u16, nonblocking: bool) -> bool {
        let Some(record) = self.sockets.get_mut(&guest) else { return false; };
        record.nonblocking = nonblocking;
        true
    }

    pub fn try_sockets_snapshot(
        &self,
    ) -> Result<Vec<(u16, Win16HostSocket, Win16NetworkTaskIdentity)>, std::collections::TryReserveError> {
        let mut sockets = Vec::new();
        sockets.try_reserve_exact(self.sockets.len())?;
        sockets.extend(self.sockets.iter().map(|(guest, record)| (*guest, record.host, record.owner)));
        Ok(sockets)
    }

    pub fn sockets_for_task(&self, task: Win16NetworkTaskIdentity) -> Vec<(u16, Win16HostSocket)> {
        self.sockets.iter().filter_map(|(&guest, record)|
            (record.owner == task).then_some((guest, record.host))).collect()
    }

    pub fn try_sockets_for_task(
        &self,
        task: Win16NetworkTaskIdentity,
    ) -> Result<Vec<(u16, Win16HostSocket)>, std::collections::TryReserveError> {
        let mut sockets = Vec::new();
        sockets.try_reserve_exact(self.socket_count_for_task(task))?;
        sockets.extend(self.sockets.iter().filter_map(|(&guest, record)| {
            (record.owner == task).then_some((guest, record.host))
        }));
        Ok(sockets)
    }

    pub fn try_async_select_routes_snapshot(
        &self,
    ) -> Result<Vec<(u16, Win16AsyncSelectRoute)>, std::collections::TryReserveError> {
        let mut routes = Vec::new();
        routes.try_reserve_exact(self.async_selects.len())?;
        routes.extend(self.async_selects.iter().map(|(&guest, &route)| (guest, route)));
        Ok(routes)
    }

    pub fn try_async_task_cancellation_snapshot(
        &self,
    ) -> Result<Vec<(u16, Option<Win16HostAsyncRequest>, Win16NetworkTaskIdentity, u64, Option<u64>)>,
        std::collections::TryReserveError> {
        let mut requests = Vec::new();
        requests.try_reserve_exact(self.async_tasks.len())?;
        requests.extend(self.async_tasks.iter().map(|(&guest, record)| {
            (guest, record.host, record.route.task,
                record.route.request_generation, record.route.source_id)
        }));
        Ok(requests)
    }

    pub fn remove_async_task_if_matches(
        &mut self,
        guest: u16,
        request: Win16HostAsyncRequest,
        owner: Win16NetworkTaskIdentity,
    ) -> bool {
        if !matches!(self.async_tasks.get(&guest), Some(record)
            if record.host == Some(request) && record.route.task == owner)
        {
            return false;
        }
        self.async_tasks.remove(&guest).is_some()
    }

    pub fn socket_count_for_task(&self, task: Win16NetworkTaskIdentity) -> usize {
        self.sockets.values().filter(|record| record.owner == task).count()
    }

    pub fn socket_owner(&self, guest: u16) -> Option<Win16NetworkTaskIdentity> {
        self.sockets.get(&guest).map(|record| record.owner)
    }

    pub fn guest_socket(&self, host: Win16HostSocket) -> Option<u16> {
        self.sockets.iter().find_map(|(guest, record)| (record.host == host).then_some(*guest))
    }

    pub fn has_free_guest_socket(&self) -> bool { self.next_free_word(true).is_some() }

    pub fn reserve_orphan_sockets(&mut self, count: usize)
        -> Result<(), crate::RuntimeError> {
        self.orphan_sockets.try_reserve(count).map_err(|error|
            crate::RuntimeError::with_source(crate::DiagnosticKind::ResourceExhausted,
                "reserve WinSock orphan socket ownership", error))
    }

    pub fn retain_orphan_socket(
        &mut self,
        socket: Win16HostSocket,
        owner: Win16NetworkTaskIdentity,
        phase: Win16NetworkSocketRetirementPhase,
        first_cause: Arc<crate::RuntimeError>,
    ) -> bool {
        if let Some(existing) = self.orphan_sockets.iter_mut().find(|item| item.socket == socket) {
            if existing.owner != owner { return false; }
            existing.phase = phase;
            return true;
        }
        self.orphan_sockets.push(OrphanSocketOwner {
            socket, owner, first_phase: phase, phase, first_cause,
        });
        true
    }

    pub fn orphan_sockets_snapshot(&self) -> Result<Vec<OrphanSocketOwner>, crate::RuntimeError> {
        let mut sockets = Vec::new();
        sockets.try_reserve_exact(self.orphan_sockets.len()).map_err(|error|
            crate::RuntimeError::with_source(crate::DiagnosticKind::ResourceExhausted,
                "snapshot WinSock orphan socket owners", error))?;
        sockets.extend(self.orphan_sockets.iter().cloned());
        Ok(sockets)
    }

    pub fn remove_orphan_socket(&mut self, socket: Win16HostSocket) {
        self.orphan_sockets.retain(|owner| owner.socket != socket);
    }

    pub fn set_orphan_socket_phase(
        &mut self,
        socket: Win16HostSocket,
        owner: Win16NetworkTaskIdentity,
        phase: Win16NetworkSocketRetirementPhase,
    ) -> bool {
        let Some(record) = self.orphan_sockets.iter_mut()
            .find(|record| record.socket == socket && record.owner == owner) else {
            return false;
        };
        record.phase = phase;
        true
    }

    pub fn socket_is_owned_by_task(&self, socket: Win16HostSocket, task: Win16NetworkTaskIdentity) -> bool {
        self.sockets.values().any(|record| record.host == socket && record.owner == task)
    }

    pub fn orphan_socket_is_owned_by_task(&self, socket: Win16HostSocket, task: Win16NetworkTaskIdentity) -> bool {
        self.orphan_sockets.iter().any(|record| record.socket == socket && record.owner == task)
    }

    pub fn add_socket(&mut self, host: Win16HostSocket, owner: Win16NetworkTaskIdentity) -> Option<u16> {
        self.add_socket_with_mode(host, owner, false)
    }

    pub fn add_socket_with_mode(
        &mut self,
        host: Win16HostSocket,
        owner: Win16NetworkTaskIdentity,
        nonblocking: bool,
    ) -> Option<u16> {
        let id = self.next_free_word(true)?;
        self.sockets.insert(id, SocketRecord { host, owner, nonblocking });
        self.next_socket = id.wrapping_add(1).max(1);
        Some(id)
    }

    pub fn close_socket(&mut self, guest: u16) -> Result<Option<Win16HostSocket>, crate::RuntimeError> {
        if self.async_selects.contains_key(&guest) {
            self.reserve_retired_async_selects(1)?;
        }
        if let Some(route) = self.async_selects.remove(&guest) {
            self.retired_async_selects.push(RetiredAsyncSelectRoute {
                guest_socket: guest,
                route,
            });
        }
        Ok(self.sockets.remove(&guest).map(|record| record.host))
    }

    /// Forget socket identities after the final successful Winsock cleanup.
    /// The native cleanup has already retired the process's Winsock sockets.
    pub fn clear_sockets(&mut self) -> Result<(), crate::RuntimeError> {
        self.reserve_retired_async_selects(self.async_selects.len())?;
        for (guest, route) in std::mem::take(&mut self.async_selects) {
            self.retired_async_selects.push(RetiredAsyncSelectRoute {
                guest_socket: guest,
                route,
            });
        }
        self.sockets.clear();
        Ok(())
    }

    /// Drop one task's guest socket identities after its final successful
    /// WSACleanup. Native closure/reset is performed by the host owner first.
    pub fn retire_task_sockets(&mut self, task: Win16NetworkTaskIdentity) -> Result<(), crate::RuntimeError> {
        let sockets = self.sockets_for_task(task);
        self.retire_task_sockets_from_snapshot(task, &sockets)
    }

    pub fn retire_task_sockets_from_snapshot(
        &mut self,
        task: Win16NetworkTaskIdentity,
        sockets: &[(u16, Win16HostSocket)],
    ) -> Result<(), crate::RuntimeError> {
        let routes = sockets.iter().filter(|(guest, _)| self.async_selects.contains_key(guest)).count();
        self.reserve_retired_async_selects(routes)?;
        for (guest, socket) in sockets {
            if self.socket_owner(*guest) != Some(task) || self.host_socket(*guest) != Some(*socket) {
                return Err(crate::RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                    "WinSock task socket identity changed before exact runtime retirement"));
            }
            if self.close_socket(*guest)? != Some(*socket) {
                return Err(crate::RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                    "WinSock task socket disappeared during exact runtime retirement"));
            }
        }
        Ok(())
    }

    pub fn reserve_task_socket_retirements(&mut self, task: Win16NetworkTaskIdentity)
        -> Result<(), crate::RuntimeError> {
        let routes = self.async_selects.keys().filter(|guest| {
            self.sockets.get(guest).is_some_and(|socket| socket.owner == task)
        }).count();
        self.reserve_retired_async_selects(routes)
    }

    pub fn reserve_async_task(&mut self, route: Win16AsyncGuestRoute)
        -> Result<Option<u16>, crate::RuntimeError> {
        self.async_tasks.try_reserve(1).map_err(|error| crate::RuntimeError::with_source(
            crate::DiagnosticKind::ResourceExhausted,
            "reserve WinSock asynchronous task owner", error))?;
        let Some(id) = self.next_free_word(false) else { return Ok(None); };
        self.async_tasks.insert(id, AsyncRecord { host: None, route });
        self.next_async_task = id.wrapping_add(1).max(1);
        Ok(Some(id))
    }

    pub fn bind_async_task(&mut self, guest: u16, host: Win16HostAsyncRequest) -> bool {
        let Some(record) = self.async_tasks.get_mut(&guest) else { return false; };
        if record.host.is_some()
            || host.source_id == 0
            || host.source_id == u64::MAX
            || host.generation == 0
            || host.generation != record.route.request_generation
        { return false; }
        record.route.source_id = Some(host.source_id);
        record.host = Some(host);
        true
    }

    pub fn remove_async_task_reservation(&mut self, guest: u16) -> bool {
        matches!(self.async_tasks.get(&guest), Some(record) if record.host.is_none())
            && self.async_tasks.remove(&guest).is_some()
    }

    pub fn host_async_task(&self, guest: u16) -> Option<Win16HostAsyncRequest> {
        self.async_tasks.get(&guest).and_then(|record| record.host)
    }

    pub fn async_task_record(&self, guest: u16)
        -> Option<(Option<Win16HostAsyncRequest>, Win16AsyncGuestRoute)> {
        self.async_tasks.get(&guest).map(|record| (record.host, record.route.clone()))
    }

    pub fn event_owner_for_query(
        &self,
        host_task: Win16HostAsyncTask,
    ) -> Option<(u16, Win16AsyncGuestRoute)> {
        self.async_tasks.iter().find_map(|(&guest, record)| {
            (record.host.is_some_and(|request| request.task == host_task))
                .then(|| (guest, record.route.clone()))
        })
    }

    pub fn reserve_async_select(&mut self) -> Result<(), crate::RuntimeError> {
        self.async_selects.try_reserve(1).map_err(|error| crate::RuntimeError::with_source(
            crate::DiagnosticKind::ResourceExhausted,
            "reserve WinSock asynchronous socket route", error))
    }

    pub fn reserve_retired_async_selects(&mut self, count: usize)
        -> Result<(), crate::RuntimeError> {
        self.retired_async_selects.try_reserve(count).map_err(|error| crate::RuntimeError::with_source(
            crate::DiagnosticKind::ResourceExhausted,
            "reserve retired WinSock notification routes",
            error))
    }

    pub fn set_async_select(&mut self, socket: u16, route: Option<Win16AsyncSelectRoute>) -> bool {
        let Some(record) = self.sockets.get_mut(&socket) else { return false; };
        // Successful WSAAsyncSelect calls leave the native socket nonblocking,
        // including calls that unregister the last event route.
        record.nonblocking = true;
        if let Some(previous) = self.async_selects.remove(&socket) {
            self.retired_async_selects.push(RetiredAsyncSelectRoute {
                guest_socket: socket,
                route: previous,
            });
        }
        if let Some(route) = route { self.async_selects.insert(socket, route); }
        true
    }

    pub fn async_select_route_for_event(
        &self,
        socket: Win16HostSocket,
        generation: u64,
    ) -> Option<(u16, Win16AsyncSelectRoute, bool)> {
        if let Some((&guest, &route)) = self.async_selects.iter().find(|(_, route)| {
            route.socket == socket && route.registration_generation == generation
        }) {
            return Some((guest, route, true));
        }
        self.retired_async_selects.iter().find_map(|retired| {
            (retired.route.socket == socket
                && retired.route.registration_generation == generation)
                .then_some((retired.guest_socket, retired.route, false))
        })
    }

    pub fn record_async_select_event_ack(
        &mut self,
        socket: Win16HostSocket,
        generation: u64,
        sequence: u64,
    ) -> bool {
        if let Some(route) = self.async_selects.values_mut().find(|route| {
            route.socket == socket && route.registration_generation == generation
        }) {
            if sequence <= route.last_event_sequence { return false; }
            route.last_event_sequence = sequence;
            return true;
        }
        if let Some(retired) = self.retired_async_selects.iter_mut().find(|retired| {
            retired.route.socket == socket
                && retired.route.registration_generation == generation
        }) {
            if sequence <= retired.route.last_event_sequence { return false; }
            retired.route.last_event_sequence = sequence;
            return true;
        }
        false
    }

    /// Retired routes survive every unrelated FIFO head. `clear_retired_routes`
    /// is called only after the host proves its retained source FIFO is empty.
    pub fn clear_retired_routes(&mut self) { self.retired_async_selects.clear(); }

    pub fn async_select_route(&self, socket: u16) -> Option<Win16AsyncSelectRoute> {
        self.async_selects.get(&socket).copied()
    }

    pub fn async_select_route_count(&self) -> usize { self.async_selects.len() }

    pub fn async_task_count(&self) -> usize { self.async_tasks.len() }

    pub fn can_note_startup(&self, task: Win16NetworkTaskIdentity) -> bool {
        self.startup_references_by_task.get(&task).copied().unwrap_or(0).checked_add(1).is_some()
            && self.total_startup_references.checked_add(1).is_some()
    }

    pub fn take_async_task(&mut self, guest: u16) -> Option<Win16HostAsyncRequest> {
        self.async_tasks.remove(&guest).and_then(|record| record.host)
    }

    pub fn reserve_async_generation(&mut self) -> Option<u64> {
        let current = self.next_async_generation;
        let next = current.checked_add(1).filter(|value| *value != 0)?;
        self.next_async_generation = next;
        Some(current)
    }

    pub fn last_error(&self, task: u16) -> u16 {
        self.task_identity_by_handle.get(&task)
            .and_then(|identity| self.last_error_by_task.get(identity))
            .copied().unwrap_or(0)
    }

    pub fn set_last_error(&mut self, task: u16, error: u16) {
        if let Some(identity) = self.task_identity_by_handle.get(&task).copied() {
            self.last_error_by_task.insert(identity, error);
        }
    }

    pub fn bind_task_identity(&mut self, task: u16, identity: Win16NetworkTaskIdentity) {
        if let Some(previous) = self.task_identity_by_handle.insert(task, identity)
            && previous != identity
        {
            self.last_error_by_task.remove(&previous);
        }
    }

    pub fn record_host_error(&mut self, task: u16, error: i32) {
        self.set_last_error(task, error as u16);
    }

    pub fn note_startup(&mut self, task: Win16NetworkTaskIdentity) -> bool {
        let references = self.startup_references_by_task.entry(task).or_default();
        let Some(next_task) = references.checked_add(1) else { return false; };
        let Some(next_total) = self.total_startup_references.checked_add(1) else { return false; };
        *references = next_task;
        self.total_startup_references = next_total;
        true
    }

    pub fn note_cleanup(&mut self, task: Win16NetworkTaskIdentity) -> bool {
        let Some(references) = self.startup_references_by_task.get_mut(&task) else { return false; };
        if *references == 0 || self.total_startup_references == 0 { return false; }
        *references -= 1;
        if *references == 0 { self.startup_references_by_task.remove(&task); }
        self.total_startup_references -= 1;
        true
    }

    pub fn startup_references(&self) -> u64 { self.total_startup_references }

    pub fn startup_references_for_task(&self, task: Win16NetworkTaskIdentity) -> u32 {
        self.startup_references_by_task.get(&task).copied().unwrap_or(0)
    }

    pub fn try_startup_snapshot(
        &self,
    ) -> Result<Vec<(Win16NetworkTaskIdentity, u32)>, std::collections::TryReserveError> {
        let mut snapshot = Vec::new();
        snapshot.try_reserve_exact(self.startup_references_by_task.len())?;
        snapshot.extend(self.startup_references_by_task.iter().map(|(&task, &count)| (task, count)));
        Ok(snapshot)
    }

    pub fn retire_task_orphans_absent_from_receipt(
        &mut self,
        task: Win16NetworkTaskIdentity,
        failures: &[crate::Win16HostSocketRetirementFailure],
    ) {
        self.orphan_sockets.retain(|orphan| {
            orphan.owner != task || failures.iter().any(|failure| {
                failure.owner == task && failure.socket == orphan.socket
            })
        });
    }

    /// Track each task's static resolver block together with its heap
    /// generation. A recycled HGLOBAL WORD is never sufficient authority to
    /// free a guest allocation during a later query or task cleanup.
    pub fn track_result_block(&mut self, task: u16, block: StaticResultBlock) {
        self.result_blocks_by_task.entry(task).or_default().push(block);
    }

    pub fn reserve_result_block(
        &mut self,
        task: u16,
    ) -> Result<(), std::collections::TryReserveError> {
        self.result_blocks_by_task.entry(task).or_default().try_reserve(1)
    }

    pub fn try_result_blocks_for_task(
        &self,
        task: u16,
    ) -> Result<Vec<StaticResultBlock>, std::collections::TryReserveError> {
        let mut blocks = Vec::new();
        if let Some(owned) = self.result_blocks_by_task.get(&task) {
            blocks.try_reserve_exact(owned.len())?;
            blocks.extend_from_slice(owned);
        }
        Ok(blocks)
    }

    pub fn try_all_result_blocks(
        &self,
    ) -> Result<Vec<(u16, StaticResultBlock)>, std::collections::TryReserveError> {
        let mut result = Vec::new();
        for (&task, blocks) in &self.result_blocks_by_task {
            result.try_reserve(blocks.len())?;
        result.extend(blocks.iter().cloned().map(|block| (task, block)));
        }
        Ok(result)
    }

    pub fn remove_result_block(&mut self, task: u16, guest_handle: u16, identity: GlobalHandle) {
        let mut remove_task = false;
        if let Some(blocks) = self.result_blocks_by_task.get_mut(&task) {
            blocks.retain(|candidate| candidate.guest_handle != guest_handle
                || candidate.identity != identity);
            remove_task = blocks.is_empty();
        }
        if remove_task { self.result_blocks_by_task.remove(&task); }
    }

    pub fn record_result_block_failure(
        &mut self,
        task: u16,
        guest_handle: u16,
        identity: GlobalHandle,
        error: RuntimeError,
    ) -> RuntimeError {
        let Some(block) = self.result_blocks_by_task.get_mut(&task)
            .and_then(|blocks| blocks.iter_mut().find(|block|
                block.guest_handle == guest_handle && block.identity == identity))
        else {
            return RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "WinSock resolver cleanup lost its exact owner record")
                .with_cleanup("preserving failed WinSock resolver owner", error);
        };
        block.remember_retirement_failure(error)
    }

    pub fn set_blocking(&mut self, task: u16, blocking: bool) {
        self.blocking_by_task.insert(task, blocking);
    }

    pub fn is_blocking(&self, task: u16) -> bool {
        self.blocking_by_task.get(&task).copied().unwrap_or(false)
    }

    pub fn clear_blocking(&mut self, task: u16) { self.blocking_by_task.remove(&task); }

    /// Emit only the first warning for a permanently unsupported export.
    pub fn mark_unsupported_warned(&mut self, ordinal: u16) -> bool {
        self.warned_unsupported.insert(ordinal)
    }

    fn next_free_word(&self, socket_ids: bool) -> Option<u16> {
        let start = if socket_ids { self.next_socket } else { self.next_async_task };
        let occupied = |candidate| {
            candidate == 0 || candidate == u16::MAX || if socket_ids {
                self.sockets.contains_key(&candidate)
            } else { self.async_tasks.contains_key(&candidate) }
        };
        let mut candidate = start.max(1);
        for _ in 1..u16::MAX {
            if !occupied(candidate) { return Some(candidate); }
            candidate = candidate.wrapping_add(1).max(1);
        }
        None
    }
}
