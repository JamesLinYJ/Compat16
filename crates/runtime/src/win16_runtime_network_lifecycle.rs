//! Teardown of owned Winsock references and per-task resolver globals.

use guest_core::memory::Memory;
use compat_services::win16_network::WSAEALREADY;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostNetworkCall,
    Win16HostNetworkValue, Win16NativeWindowOperationKind, Win16WindowAbortReceipt,
    Win16WindowTerminalSourceTop,
};
use crate::win16_network::StaticResultBlock;
use crate::win16_runtime::global_memory::GlobalTeardownResult;
use super::Win16State;

impl Win16State {
    pub(super) fn free_result_owner(
        &mut self,
        block: &StaticResultBlock,
    ) -> Result<GlobalTeardownResult, RuntimeError> {
        self.free_runtime_global_on_teardown(block.identity)
    }

    pub(super) fn free_result_blocks_for_task(&mut self, task: u16) -> Result<(), RuntimeError> {
        let mut first_error = None;
        let blocks = self.network.try_result_blocks_for_task(task).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve WinSock result-owner snapshot", error))?;
        for block in blocks {
            match self.free_result_owner(&block) {
                Ok(GlobalTeardownResult::Freed) => self.network.remove_result_block(
                    task, block.guest_handle, block.identity,
                ),
                Ok(retained @ GlobalTeardownResult::Retained { .. }) => {
                    let error = retained.retained_error("WinSock result").unwrap_or_else(||
                        RuntimeError::new(Kind::InternalInvariant,
                            "Retained WinSock cleanup result lost its typed cause"));
                    let error = self.network.record_result_block_failure(
                        task, block.guest_handle, block.identity, error,
                    );
                    remember_network_cleanup_failure(&mut first_error, error);
                }
                Err(error) => {
                    let error = self.network.record_result_block_failure(
                        task, block.guest_handle, block.identity, error,
                    );
                    remember_network_cleanup_failure(&mut first_error, error);
                }
            }
        }
        if let Some(error) = first_error { Err(error) } else { Ok(()) }
    }

    /// Stop routes that can create new socket sources and cancel only resolver
    /// requests that have not yet crossed their host-owned completion point.
    /// Existing FIFO events remain owned until the post-abort exact ACK phase.
    pub(crate) fn quiesce_network_producers(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if self.network.producers_quiesced() { return Ok(()); }
        self.network.begin_producer_quiescence();

        // Snapshot and validate every identity, and reserve all Runtime route
        // storage, before disabling the first native producer.
        let routes = self.network.try_async_select_routes_snapshot().map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve WinSock route quiescence snapshot", error))?;
        let requests = self.network.try_async_task_cancellation_snapshot().map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve WinSock resolver quiescence snapshot", error))?;
        self.network.reserve_retired_async_selects(routes.len())?;
        for (guest, route) in &routes {
            if route.source_id == 0 || route.source_id == u64::MAX
                || route.registration_generation == 0
                || self.network.async_select_route(*guest) != Some(*route)
                || self.network.socket_owner(*guest) != Some(route.task)
                || self.network.host_socket(*guest) != Some(route.socket)
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "WinSock route changed before exact producer quiescence"));
            }
        }
        for (guest, request, owner, generation, source_id) in &requests {
            let Some(request) = request else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "WinSock async request reservation has no accepted host identity"));
            };
            if request.task.0 == 0 || request.source_id == 0 || request.source_id == u64::MAX
                || request.generation == 0 || request.generation != *generation
                || *source_id != Some(request.source_id) || owner.selector_generation == 0
                || self.network.host_async_task(*guest) != Some(*request)
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "WinSock resolver owner changed before exact producer quiescence"));
            }
        }

        for (guest, route) in routes {
            let result = host.win16_network(Win16HostNetworkCall::AsyncSelect {
                socket: route.socket,
                task: route.task,
                window: route.host_window,
                guest_hwnd: route.window,
                message: route.message,
                events: 0,
                registration_generation: route.registration_generation,
                expected_source_id: Some(route.source_id),
            })?;
            if result.wsa_error != 0 {
                return Err(RuntimeError::with_source(
                    Kind::HostFailure,
                    "disabling the exact WinSock asynchronous socket route failed",
                    WinsockCleanupError(result.wsa_error),
                ));
            }
            if !self.network.set_socket_nonblocking(guest, true) {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "WinSock socket disappeared after successful route disable"));
            }
            if !matches!(&result.value, Win16HostNetworkValue::AsyncRegistration {
                source_id: 0, generation,
            } if *generation == route.registration_generation) {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "WinSock route quiescence returned a different registration identity"));
            }
            if !self.network.set_async_select(guest, None) {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "WinSock route owner disappeared after native route disable"));
            }
        }

        for (guest, request, owner, _, _) in requests {
            let request = request.ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "WinSock resolver owner lost its prevalidated request identity"))?;
            let result = host.win16_network(Win16HostNetworkCall::CancelAsyncRequest {
                request,
                owner,
            })?;
            match result {
                result if result.wsa_error == 0
                    && matches!(&result.value, Win16HostNetworkValue::Signed(0)) => {
                    if !self.network.remove_async_task_if_matches(guest, request, owner) {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "cancelled WinSock resolver owner changed before exact Runtime retirement"));
                    }
                }
                result if result.wsa_error == WSAEALREADY => {
                    // Completed resolver work is an accepted source even if
                    // it has not reached the retained FIFO yet; keep its row.
                }
                result if result.wsa_error != 0 => return Err(RuntimeError::with_source(
                    Kind::HostFailure,
                    "cancelling unpublished WinSock resolver work failed",
                    WinsockCleanupError(result.wsa_error),
                )),
                _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                    "WinSock resolver cancellation returned an unexpected success value")),
            }
        }
        self.network.mark_producers_quiesced();
        Ok(())
    }

    pub(crate) fn owns_terminal_network_post_source(
        &self,
        top: &Win16WindowTerminalSourceTop,
    ) -> Result<bool, RuntimeError> {
        let Some(pending) = self.network.pending_event.as_ref() else { return Ok(false); };
        let Some(failure) = pending.progress.started_failure.as_ref() else { return Ok(false); };
        Ok(matches!(top,
            Win16WindowTerminalSourceTop::User {
                operation, kind, state, worker_generation,
            } if failure.operation.kind == Win16NativeWindowOperationKind::PostGuestNotification
                && *operation == failure.operation.operation_id
                && *kind == failure.operation.kind
                && *state == failure.state
                && *worker_generation == failure.worker_generation))
    }

    pub(crate) fn retire_network_terminal_post_source(
        &mut self,
        receipt: &Win16WindowAbortReceipt,
        top: &Win16WindowTerminalSourceTop,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if !self.network.producers_quiesced() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock USER POST retirement started before producer quiescence"));
        }
        if !self.owns_terminal_network_post_source(top)? { return Ok(false); }
        let failure = self.network.pending_event.as_ref()
            .and_then(|pending| pending.progress.started_failure.as_ref())
            .cloned().ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "WinSock terminal POST owner disappeared before exact ACK"))?;
        let already_acknowledged = self.network.pending_event.as_ref().is_some_and(|pending|
            pending.progress.terminal_user_acknowledged);
        let cached_receipt = self.window_abort_receipt.as_ref().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant,
            "WinSock terminal POST lost the cached USER abort receipt",
        ))?;
        if cached_receipt.request_id != receipt.request_id
            || cached_receipt.worker_generation != receipt.worker_generation
            || receipt.worker_generation != failure.worker_generation
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "WinSock USER POST source does not match the exact cached abort receipt"));
        }
        if !matches!(top, Win16WindowTerminalSourceTop::User {
            operation, kind, state, worker_generation,
        } if *operation == failure.operation.operation_id
            && *kind == failure.operation.kind
            && *state == failure.state
            && *worker_generation == failure.worker_generation)
        {
            return Err(RuntimeError::new(Kind::HostFailure,
                "WinSock USER POST is not the exact shared source-stack top"));
        }
        self.acknowledge_started_post_failure(&failure, host)?;
        let ack = crate::Win16WindowTerminalAck {
            worker_generation: failure.worker_generation,
            operation: failure.operation,
            state: failure.state,
            callbacks: Vec::new(),
            modals: Vec::new(),
        };
        if !host.win16_window_terminal_acknowledged(receipt, &ack)? {
            return Err(RuntimeError::new(Kind::HostFailure,
                "WinSock USER POST ACK has no exact native tombstone readback"));
        }
        if already_acknowledged { return Ok(true); }
        let pending = self.network.pending_event.as_mut().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "WinSock event owner disappeared after USER terminal ACK"))?;
        let retained = pending.progress.started_failure.as_ref().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "WinSock USER failure proof disappeared after terminal ACK"))?;
        if !std::sync::Arc::ptr_eq(retained, &failure) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock USER failure proof changed during exact terminal ACK"));
        }
        pending.progress.terminal_user_acknowledged = true;
        Ok(true)
    }

    pub(crate) fn close_network(
        &mut self,
        _memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let mut first_error = None;
        if !self.network.producers_quiesced() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock cleanup started before native event producers were quiesced"));
        }
        // Keep this retry set to owners that predated this teardown attempt.
        // A close failure discovered below must retain its first cause and
        // wait for the next cleanup pass instead of issuing a second native
        // close immediately in the same pass.
        let retry_orphans = self.network.orphan_sockets_snapshot()?;
        let preflight_sockets = self.network.try_sockets_snapshot().map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve WinSock orphan capacity before native teardown", error))?;
        self.network.reserve_orphan_sockets(preflight_sockets.len())?;
        let startup = self.network.try_startup_snapshot().map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve WinSock startup-reference teardown snapshot", error))?;

        // Retire all retained USER and network events before closing sockets.
        // Socket removal also removes provider-side readiness state, so it is
        // not a substitute for acknowledging a queued event source.
        self.retire_network_events_after_windows(host)?;
        if self.network.pending_event.is_some() || self.network.async_task_count() != 0 {
            return Err(RuntimeError::new(Kind::HostFailure,
                "accepted WinSock network source remains after terminal FIFO drain"));
        }
        if self.network.async_select_route_count() != 0 {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "active WinSock async-select route remains after producer quiescence"));
        }

        let blocks = self.network.try_all_result_blocks().map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve WinSock resolver result-owner teardown snapshot", error))?;
        for (task, block) in blocks {
            match self.free_result_owner(&block) {
                Ok(GlobalTeardownResult::Freed) => self.network.remove_result_block(
                    task, block.guest_handle, block.identity,
                ),
                Ok(retained @ GlobalTeardownResult::Retained { .. }) => {
                    let error = retained.retained_error("WinSock result").unwrap_or_else(||
                        RuntimeError::new(Kind::InternalInvariant,
                            "Retained WinSock cleanup result lost its typed cause"));
                    let error = self.network.record_result_block_failure(
                        task, block.guest_handle, block.identity, error,
                    );
                    remember_network_cleanup_failure(&mut first_error, error);
                }
                Err(error) => {
                    let error = self.network.record_result_block_failure(
                        task, block.guest_handle, block.identity, error,
                    );
                    remember_network_cleanup_failure(&mut first_error, error);
                }
            }
        }

        for &(task, startup_refs) in &startup {
            let task_sockets = self.network.try_sockets_for_task(task).map_err(|error|
                RuntimeError::with_source(Kind::ResourceExhausted,
                    "reserve exact WinSock task socket teardown snapshot", error))?;
            for _ in 0..startup_refs {
                let task_final = self.network.startup_references_for_task(task) == 1;
                if task_final && (self.network.reserve_orphan_sockets(task_sockets.len()).is_err()
                    || self.network.reserve_task_socket_retirements(task).is_err())
                {
                    remember_network_cleanup_failure(&mut first_error, RuntimeError::new(
                        Kind::ResourceExhausted,
                        "reserving exact WinSock socket owners before final host cleanup"));
                    break;
                }
                match host.win16_network(Win16HostNetworkCall::Cleanup { task, task_final }) {
                    Ok(result) if result.wsa_error == 0 => {
                        let (reference_release, failures) = match result.value {
                            Win16HostNetworkValue::Cleanup { reference_release, socket_retire_failures } =>
                                (reference_release, socket_retire_failures),
                            _ => {
                                if first_error.is_none() {
                                    first_error = Some(RuntimeError::new(Kind::InternalInvariant,
                                        "native WinSock Cleanup omitted its retirement receipt"));
                                }
                                break;
                            }
                        };
                        if reference_release.owner != task {
                            if first_error.is_none() {
                                first_error = Some(RuntimeError::new(Kind::InternalInvariant,
                                    "native WinSock Cleanup released a reference for a different task incarnation"));
                            }
                            break;
                        }
                        if !self.network.note_cleanup(task) {
                            remember_network_cleanup_failure(&mut first_error,
                                RuntimeError::new(Kind::InternalInvariant,
                                    "WinSock startup reference disappeared after native Cleanup succeeded"));
                            break;
                        }
                        let retention = self.retain_cleanup_failures(task, &failures);
                        if reference_release.task_final != task_final {
                            remember_network_cleanup_failure(&mut first_error, RuntimeError::new(
                                Kind::InternalInvariant,
                                "WinSock Cleanup released a different task-reference phase than Runtime reserved"));
                        }
                        if task_final && reference_release.task_final && retention.is_ok() {
                            if let Err(error) = self.network.retire_task_sockets_from_snapshot(
                                task, &task_sockets,
                            ) {
                                remember_network_cleanup_failure(&mut first_error, error);
                            } else {
                                self.network.retire_task_orphans_absent_from_receipt(task, &failures);
                            }
                        }
                        if let Err(error) = retention {
                            remember_network_cleanup_failure(&mut first_error, error);
                        }
                    }
                    Ok(result) if result.wsa_error != 0 => {
                        remember_network_cleanup_failure(&mut first_error, RuntimeError::with_source(
                            Kind::HostFailure,
                            "releasing native WinSock startup reference",
                            WinsockCleanupError(result.wsa_error),
                        ));
                    },
                    Ok(_) => {
                        remember_network_cleanup_failure(&mut first_error, RuntimeError::new(
                            Kind::InternalInvariant,
                            "native WinSock cleanup returned an unexpected success value during teardown"));
                    },
                    Err(error) => remember_network_cleanup_failure(&mut first_error, error),
                }
            }
        }

        // A previous failed cleanup may leave an active Runtime socket row
        // after its startup reference has already been released. Retire only
        // that exact token/owner and move a structured close failure to the
        // typed orphan owner before dropping the guest WORD mapping.
        let sockets = self.network.try_sockets_snapshot().map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve residual WinSock socket teardown snapshot", error))?;
        self.network.reserve_orphan_sockets(sockets.len())?;
        for (guest, socket, owner) in sockets {
            if self.network.startup_references_for_task(owner) != 0 {
                continue;
            }
            match host.win16_network(Win16HostNetworkCall::RetireSocket { socket, owner }) {
                Ok(result) if result.wsa_error == 0
                    && matches!(&result.value, Win16HostNetworkValue::Signed(0)) => {
                    match self.network.close_socket(guest) {
                        Ok(Some(closed)) if closed == socket => {}
                        Ok(_) => remember_network_cleanup_failure(&mut first_error,
                            RuntimeError::new(Kind::InternalInvariant,
                                "WinSock socket identity changed during teardown")),
                        Err(error) => remember_network_cleanup_failure(&mut first_error, error),
                    }
                }
                Ok(result) if result.wsa_error != 0 => {
                    match result.value {
                        Win16HostNetworkValue::SocketRetirementFailure(failure)
                            if failure.socket == socket && failure.owner == owner
                                && failure.wsa_error == result.wsa_error
                                && failure.phase == crate::Win16HostSocketRetirementPhase::RuntimeTeardown =>
                        {
                            if !self.network.retain_orphan_socket(
                                socket, owner,
                                crate::win16_network::Win16NetworkSocketRetirementPhase::RuntimeTeardown,
                                std::sync::Arc::clone(&failure.first_cause),
                            ) {
                                remember_network_cleanup_failure(&mut first_error,
                                    RuntimeError::new(Kind::InternalInvariant,
                                        "WinSock residual socket orphan identity changed"));
                                continue;
                            }
                            if self.network.close_socket(guest)? != Some(socket) {
                                remember_network_cleanup_failure(&mut first_error,
                                    RuntimeError::new(Kind::InternalInvariant,
                                        "WinSock residual socket lost its exact guest owner"));
                            }
                        }
                        _ => remember_network_cleanup_failure(&mut first_error,
                            RuntimeError::with_source(Kind::HostFailure,
                                "retiring residual native WinSock socket",
                                WinsockCleanupError(result.wsa_error))),
                    }
                }
                Ok(_) => remember_network_cleanup_failure(&mut first_error,
                    RuntimeError::new(Kind::InternalInvariant,
                        "native WinSock retirement returned an unexpected success value")),
                Err(error) => remember_network_cleanup_failure(&mut first_error, error),
            }
        }

        for orphan in retry_orphans {
            if !self.network.orphan_socket_is_owned_by_task(orphan.socket, orphan.owner) {
                continue;
            }
            // The host's exact final WSACleanup receipt already attempted all
            // sockets for every startup owner present at this entry point.
            // A failed socket from that receipt belongs to the next pass.
            if startup.iter().any(|(task, refs)| *task == orphan.owner && *refs != 0) {
                continue;
            }
            self.network.set_orphan_socket_phase(
                orphan.socket, orphan.owner,
                crate::win16_network::Win16NetworkSocketRetirementPhase::RuntimeTeardown,
            );
            match host.win16_network(Win16HostNetworkCall::RetireSocket {
                socket: orphan.socket, owner: orphan.owner,
            }) {
                Ok(result) if result.wsa_error == 0
                    && matches!(&result.value, Win16HostNetworkValue::Signed(0)) => {
                    self.network.remove_orphan_socket(orphan.socket);
                }
                Ok(result) if result.wsa_error != 0 => {
                    let retry = match result.value {
                        Win16HostNetworkValue::SocketRetirementFailure(failure)
                            if failure.socket == orphan.socket && failure.owner == orphan.owner
                                && failure.phase == crate::Win16HostSocketRetirementPhase::RuntimeTeardown
                                && failure.wsa_error == result.wsa_error =>
                            RuntimeError::with_source(Kind::HostFailure,
                                "retrying orphaned native WinSock socket retirement",
                                WinsockCleanupError(result.wsa_error)),
                        _ => RuntimeError::new(Kind::InternalInvariant,
                            "orphan socket retry did not return its exact typed owner"),
                    };
                    remember_network_cleanup_failure(&mut first_error,
                        owned_socket_retry_error(
                            &orphan.first_cause, orphan.first_phase, retry,
                        ));
                }
                Ok(_) => remember_network_cleanup_failure(&mut first_error,
                    owned_socket_retry_error(&orphan.first_cause, orphan.first_phase,
                        RuntimeError::new(Kind::InternalInvariant,
                            "orphaned WinSock socket retirement returned an unexpected result"))),
                Err(error) => remember_network_cleanup_failure(&mut first_error,
                    owned_socket_retry_error(&orphan.first_cause, orphan.first_phase, error)),
            }
        }

        if self.network.startup_references() != 0 {
            remember_network_cleanup_failure(&mut first_error, RuntimeError::new(
                Kind::HostFailure, "WinSock startup references remain after teardown retry"));
        }
        if self.network.async_task_count() != 0 || self.network.async_select_route_count() != 0
            || self.network.pending_event.is_some()
        {
            remember_network_cleanup_failure(&mut first_error, RuntimeError::new(
                Kind::InternalInvariant, "WinSock event owner remains after terminal cleanup"));
        }
        if !self.network.try_sockets_snapshot().map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "verify residual WinSock socket owners", error))?.is_empty()
            || !self.network.orphan_sockets_snapshot()?.is_empty()
        {
            remember_network_cleanup_failure(&mut first_error, RuntimeError::new(
                Kind::HostFailure, "native WinSock socket ownership remains after teardown retry"));
        }
        if !self.network.try_all_result_blocks().map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "verify residual WinSock resolver owners", error))?.is_empty()
        {
            remember_network_cleanup_failure(&mut first_error, RuntimeError::new(
                Kind::HostFailure, "WinSock resolver result ownership remains after teardown retry"));
        }
        if let Some(error) = first_error { Err(error) } else { Ok(()) }
    }
}

fn remember_network_cleanup_failure(
    slot: &mut Option<RuntimeError>,
    error: RuntimeError,
) {
    *slot = Some(match slot.take() {
        None => error,
        Some(primary) => primary.with_cleanup("multiple WinSock task cleanup failures", error),
    });
}

#[derive(Debug)]
struct WinsockCleanupError(i32);

impl std::fmt::Display for WinsockCleanupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Winsock error {}", self.0)
    }
}

impl std::error::Error for WinsockCleanupError {}

fn owned_socket_retry_error(
    first: &std::sync::Arc<RuntimeError>,
    first_phase: crate::win16_network::Win16NetworkSocketRetirementPhase,
    retry: RuntimeError,
) -> RuntimeError {
    let first_context = match first_phase {
        crate::win16_network::Win16NetworkSocketRetirementPhase::UnpublishedRollback =>
            "original socket retirement failure during unpublished rollback remains retained",
        crate::win16_network::Win16NetworkSocketRetirementPhase::GuestCleanupReferenceReleased =>
            "original socket retirement failure after guest cleanup reference release remains retained",
        crate::win16_network::Win16NetworkSocketRetirementPhase::RuntimeTeardown =>
            "original socket retirement failure during runtime teardown remains retained",
    };
    RuntimeError::with_source(first.kind(), first_context, std::sync::Arc::clone(first))
        .with_cleanup("retrying the same native WinSock socket identity", retry)
}
