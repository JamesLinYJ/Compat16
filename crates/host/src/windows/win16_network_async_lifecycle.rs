use std::sync::atomic::AtomicU64;

use runtime::{Win16HostAsyncRequest, Win16HostNetworkNameQuery};

use super::*;

impl NetworkAsyncState {
    pub(in super::super) fn start_async_query(
        &mut self,
        identity_source: &Arc<AtomicU64>,
        owner: Win16NetworkTaskIdentity,
        window: runtime::Win16HostWindow,
        guest_hwnd: u16,
        message: u16,
        query: Win16HostNetworkNameQuery,
        capacity: i16,
        request_generation: u64,
    ) -> runtime::Win16HostNetworkResult {
        if capacity <= 0 || request_generation == 0 {
            return fail(WSAEINVAL, Win16HostNetworkValue::AsyncTask(None));
        }
        if self.wake.ensure_started().is_err() {
            return fail(WSAENOBUFS, Win16HostNetworkValue::AsyncTask(None));
        }
        let Some(next_task) = self.next_task.checked_add(1).filter(|value| *value != 0) else {
            return fail(WSAENOBUFS, Win16HostNetworkValue::AsyncTask(None));
        };
        if self.queries.try_reserve(1).is_err() {
            return fail(WSAENOBUFS, Win16HostNetworkValue::AsyncTask(None));
        }
        let Some(source_id) = allocate_source_id(identity_source) else {
            return fail(WSAENOBUFS, Win16HostNetworkValue::AsyncTask(None));
        };
        let task = Win16HostAsyncTask(self.next_task);
        let worker_state = Arc::new(Mutex::new(ResolverWorkerState::Queued));
        let work =
            match ResolverWorkLease::submit(query, Arc::clone(&worker_state), self.wake.clone()) {
                Ok(work) => work,
                Err(_) => return fail(WSAENOBUFS, Win16HostNetworkValue::AsyncTask(None)),
            };
        self.next_task = next_task;
        self.queries.insert(
            task,
            AsyncQueryOwner {
                owner,
                window,
                guest_hwnd,
                message,
                capacity,
                request_generation,
                source_id,
                worker_state,
                work: Some(work),
                work_retirement_succeeded: None,
                worker_failure_reported: false,
                event_source: None,
            },
        );
        ok(Win16HostNetworkValue::AsyncTask(Some(
            Win16HostAsyncRequest {
                task,
                source_id,
                generation: request_generation,
            },
        )))
    }

    pub(in super::super) fn cancel_async_request(
        &mut self,
        request: Win16HostAsyncRequest,
        owner: Win16NetworkTaskIdentity,
    ) -> runtime::Win16HostNetworkResult {
        let Some(record) = self.queries.get_mut(&request.task) else {
            return fail(WSAEINVAL, signed_error());
        };
        if record.owner != owner
            || record.request_generation != request.generation
            || record.source_id != request.source_id
        {
            return fail(WSAEINVAL, signed_error());
        }
        if record.event_source.is_some() {
            return fail(WSAEALREADY, signed_error());
        }
        let mut wake = false;
        let result = {
            let Ok(mut state) = record.worker_state.lock() else {
                return fail(WSASYSCALLFAILURE, signed_error());
            };
            let current = std::mem::replace(&mut *state, ResolverWorkerState::Panicked);
            match current {
                ResolverWorkerState::Queued => {
                    *state = ResolverWorkerState::CancelledBeforeStart;
                    wake = true;
                    ok(Win16HostNetworkValue::Signed(0))
                }
                ResolverWorkerState::Running => {
                    *state = ResolverWorkerState::CancelledRunning;
                    ok(Win16HostNetworkValue::Signed(0))
                }
                ResolverWorkerState::Completed(result) => {
                    *state = ResolverWorkerState::Completed(result);
                    fail(WSAEALREADY, signed_error())
                }
                current @ (ResolverWorkerState::CancelledBeforeStart
                | ResolverWorkerState::CancelledRunning
                | ResolverWorkerState::CancelledAfterRun
                | ResolverWorkerState::Panicked) => {
                    *state = current;
                    fail(WSAEINVAL, signed_error())
                }
            }
        };
        if wake {
            self.wake.request_poll();
        }
        result
    }
}

impl NetworkAsyncState {
    pub(in super::super) fn peek_event(
        &mut self,
        sockets: &std::collections::BTreeMap<Win16HostSocket, SOCKET>,
    ) -> Result<Option<Win16HostNetworkEvent>, RuntimeError> {
        if let Some(error) = self.wake.take_failure() {
            return Err(error);
        }
        self.reap_cancelled_queries()?;
        self.report_panicked_query()?;
        if let Err(error) = self.publish_one_completed_query() {
            // Keep an owned resolver result and retry source admission on a later safe point.
            self.wake.request_poll();
            return Err(error);
        }
        self.poll_one_socket_event(sockets)?;
        Ok(self.events.front().cloned())
    }

    fn publish_one_completed_query(&mut self) -> Result<(), RuntimeError> {
        if !self.events.is_empty() {
            return Ok(());
        }
        let mut task = None;
        for (&candidate, owner) in &self.queries {
            if owner.event_source.is_some() {
                continue;
            }
            let state = owner.worker_state.lock().map_err(|_| {
                network_invariant("WinSock resolver worker state mutex was poisoned")
            })?;
            if matches!(*state, ResolverWorkerState::Completed(_)) {
                task = Some(candidate);
                break;
            }
        }
        let Some(task) = task else {
            return Ok(());
        };
        let Some(owner) = self.queries.get(&task) else {
            return Ok(());
        };
        let state = owner
            .worker_state
            .lock()
            .map_err(|_| network_invariant("WinSock resolver worker state mutex was poisoned"))?;
        let ResolverWorkerState::Completed(result) = &*state else {
            return Ok(());
        };
        let result = result.clone();
        drop(state);
        self.events.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                DiagnosticKind::ResourceExhausted,
                "reserve WinSock query completion source",
                error,
            )
        })?;
        let source = Win16GuestNotificationSource {
            id: owner.source_id,
            generation: owner.request_generation,
            sequence: 1,
        };
        let event = Win16HostNetworkEvent::AsyncQueryComplete {
            source,
            task,
            owner: owner.owner,
            window: owner.window,
            guest_hwnd: owner.guest_hwnd,
            message: owner.message,
            capacity: owner.capacity,
            request_generation: owner.request_generation,
            result,
        };
        let owner = self.queries.get_mut(&task).ok_or_else(|| {
            network_invariant("WinSock query owner disappeared while publishing completion")
        })?;
        owner.event_source = Some(source);
        self.events.push_back(event);
        self.sync_poll_demand();
        Ok(())
    }

    fn reap_cancelled_queries(&mut self) -> Result<(), RuntimeError> {
        let ready: Vec<_> = self
            .queries
            .iter()
            .filter_map(|(&task, owner)| {
                let cancelled = owner.worker_state.lock().ok().is_some_and(|state| {
                    matches!(
                        *state,
                        ResolverWorkerState::CancelledBeforeStart
                            | ResolverWorkerState::CancelledAfterRun
                    )
                });
                cancelled.then_some(task)
            })
            .collect();
        let changed = !ready.is_empty();
        for task in ready {
            let Some(owner) = self.queries.get_mut(&task) else {
                continue;
            };
            retire_work(owner, true)?;
            self.queries.remove(&task);
        }
        if changed {
            self.sync_poll_demand();
        }
        Ok(())
    }

    fn report_panicked_query(&mut self) -> Result<(), RuntimeError> {
        let task = self.queries.iter().find_map(|(&task, owner)| {
            if owner.worker_failure_reported {
                return None;
            }
            owner
                .worker_state
                .lock()
                .ok()
                .is_some_and(|state| matches!(*state, ResolverWorkerState::Panicked))
                .then_some(task)
        });
        let Some(task) = task else {
            return Ok(());
        };
        let owner = self.queries.get_mut(&task).ok_or_else(|| {
            network_invariant("panicked WinSock resolver lost its owner before retirement")
        })?;
        let error = retire_work(owner, false).err().unwrap_or_else(|| {
            network_invariant("WinSock resolver callback panicked before publishing a completion")
        });
        owner.worker_failure_reported = true;
        self.sync_poll_demand();
        Err(error)
    }

    pub(in super::super) fn shutdown_and_join(&mut self) -> AsyncShutdownReceipt {
        for owner in self.queries.values_mut() {
            let mut state = owner
                .worker_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let current = std::mem::replace(&mut *state, ResolverWorkerState::CancelledBeforeStart);
            match current {
                ResolverWorkerState::Queued | ResolverWorkerState::CancelledBeforeStart => {}
                ResolverWorkerState::Running => *state = ResolverWorkerState::CancelledRunning,
                current => *state = current,
            }
        }
        let mut panicked_workers = 0usize;
        for owner in self.queries.values_mut() {
            if owner.work_retirement_succeeded == Some(false) {
                panicked_workers = panicked_workers.saturating_add(1);
            } else if owner.work.is_some() && retire_work(owner, true).is_err() {
                panicked_workers = panicked_workers.saturating_add(1);
            }
        }
        self.wake.shutdown();
        AsyncShutdownReceipt {
            queries: std::mem::take(&mut self.queries),
            registrations: std::mem::take(&mut self.registrations),
            sockets: std::mem::take(&mut self.sockets),
            events: std::mem::take(&mut self.events),
            panicked_workers,
        }
    }
}

fn retire_work(owner: &mut AsyncQueryOwner, cancel_pending: bool) -> Result<(), RuntimeError> {
    match owner.work_retirement_succeeded {
        Some(true) => return Ok(()),
        Some(false) => {
            return Err(network_invariant(
                "WinSock resolver work callback previously panicked before retirement",
            ));
        }
        None => {}
    }
    let Some(mut work) = owner.work.take() else {
        owner.work_retirement_succeeded = Some(false);
        return Err(network_invariant(
            "WinSock resolver work lease disappeared before callback retirement",
        ));
    };
    work.retire(cancel_pending);
    let state = owner
        .worker_state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let retired = matches!(
        *state,
        ResolverWorkerState::Completed(_)
            | ResolverWorkerState::CancelledBeforeStart
            | ResolverWorkerState::CancelledAfterRun
    );
    let panicked = matches!(*state, ResolverWorkerState::Panicked);
    drop(state);
    owner.work_retirement_succeeded = Some(retired);
    if retired {
        Ok(())
    } else if panicked {
        Err(network_invariant(
            "WinSock resolver callback panicked before source retirement",
        ))
    } else {
        Err(network_invariant(
            "WinSock resolver work lease retired before its callback reached a terminal state",
        ))
    }
}

impl NetworkAsyncState {
    pub(super) fn sync_poll_demand(&self) {
        let armed_routes = self
            .registrations
            .values()
            .filter(|route| {
                let state = self.sockets.get(&route.socket).copied().unwrap_or_default();
                pollable_events(route.armed, state) != 0
            })
            .count();
        // Retained sources need safe points for USER-post retry, and completed
        // resolver results must keep demand while an earlier FIFO item blocks.
        let retained_event = usize::from(!self.events.is_empty());
        let completed_queries = self
            .queries
            .values()
            .filter(|owner| {
                if owner.event_source.is_some() {
                    return false;
                }
                owner
                    .worker_state
                    .lock()
                    .map_or(true, |state| match &*state {
                        ResolverWorkerState::Completed(_)
                        | ResolverWorkerState::CancelledBeforeStart
                        | ResolverWorkerState::CancelledAfterRun => true,
                        ResolverWorkerState::Panicked => !owner.worker_failure_reported,
                        ResolverWorkerState::Queued
                        | ResolverWorkerState::Running
                        | ResolverWorkerState::CancelledRunning => false,
                    })
            })
            .count();
        let cached_connect_events = self
            .sockets
            .values()
            .filter(|state| {
                state.connect_result.is_some_and(|terminal| {
                    terminal.event_pending
                        && terminal.notice.is_some_and(|notice| {
                            !self
                                .events
                                .iter()
                                .any(|event| event_source(event) == notice.source())
                        })
                })
            })
            .count();
        self.wake.set_poll_demands(
            armed_routes
                .saturating_add(retained_event)
                .saturating_add(completed_queries)
                .saturating_add(cached_connect_events)
                .saturating_add(self.external_poll_demand),
        );
    }

    pub(in super::super) fn ack_event(
        &mut self,
        source: runtime::Win16GuestNotificationSource,
    ) -> Result<(), RuntimeError> {
        let Some(event) = self.events.front() else {
            return Err(network_invariant(
                "WinSock event ACK has no retained source",
            ));
        };
        if event_source(event) != source {
            return Err(network_invariant(
                "WinSock event ACK did not match the exact retained source",
            ));
        }
        let terminal_socket = match event {
            Win16HostNetworkEvent::SocketReady { socket, .. } => Some(*socket),
            Win16HostNetworkEvent::AsyncQueryComplete { .. } => None,
        };
        match event {
            Win16HostNetworkEvent::SocketReady { .. } => {}
            Win16HostNetworkEvent::AsyncQueryComplete { task, .. } => {
                let Some(owner) = self.queries.get_mut(task) else {
                    return Err(network_invariant(
                        "WinSock query source lost its request owner before ACK",
                    ));
                };
                if owner.event_source != Some(source) {
                    return Err(network_invariant(
                        "WinSock query ACK changed its request source identity",
                    ));
                }
                retire_work(owner, false)?;
                let task = *task;
                self.events.pop_front();
                self.queries.remove(&task);
                self.sync_poll_demand();
                return Ok(());
            }
        }
        self.events.pop_front();
        if let Some(socket) = terminal_socket
            && let Some(state) = self.sockets.get_mut(&socket)
            && let Some(mut terminal) = state.connect_result
            && terminal
                .notice
                .is_some_and(|notice| notice.source() == source)
        {
            terminal.event_pending = false;
            terminal.notice = None;
            if !terminal.guest_error_pending {
                state.connect_result = None;
                state.connect_attempt = None;
            } else {
                state.connect_result = Some(terminal);
            }
        }
        self.sync_poll_demand();
        Ok(())
    }
}
