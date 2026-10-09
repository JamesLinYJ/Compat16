//! Safe-point delivery for owned WinSock notification sources.
//!
//! Native work is copied into the host's retained event queue. This module
//! validates the exact socket/request incarnation, projects any async lookup
//! into its captured guest range, posts through USER's source-aware API, and
//! retires the WINSOCK source only after the independent USER source proof.

use compat_services::win16_network::{
    WSAEFAULT, WSAENOBUFS, WSAEINVAL,
};
use guest_core::memory::Memory;
use win16_abi::Win16AsyncLookup;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostNetworkCall,
    Win16HostNetworkValue,
    Win16GuestNotification, Win16GuestNotificationTarget,
    Win16HostNetworkEvent, Win16HostNetworkNameResult,
    Win16NativeWindowOperationKind, Win16NativeWindowOperationProof,
    Win16NativeWindowOperationState, Win16WindowOperation, Win16WindowResult,
    Win16WindowStep, Win16HostWindowLiveness,
};
use crate::win16_network::{PendingNetworkEvent, PreparedAsyncGuestOutput};
use super::Win16State;

// WinSock 1.1 WSAHOST_NOT_FOUND is 11001; the shared compat set currently
// exports the 100xx socket errors but not the resolver error range.
const WSAHOST_NOT_FOUND: i32 = 11_001;

#[path = "win16_runtime_network_events_retirement.rs"]
mod retirement;

impl Win16State {
    /// Returns true only after an exact source event finishes advancing.
    pub(in crate::win16_runtime) fn poll_network_events(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if self.network.producer_quiescing() { return Ok(false); }
        if self.network.pending_event.is_none() {
            match host.win16_peek_network_event() {
                Ok(Some(event)) => {
                    self.network.pending_event = Some(PendingNetworkEvent {
                        event,
                        progress: Default::default(),
                        first_cause: None,
                    });
                    self.network.clear_event_poll_failure();
                }
                Ok(None) => {
                    self.network.clear_retired_routes();
                    self.network.clear_event_poll_failure();
                    return Ok(false);
                }
                Err(error) => {
                    if let Some(error) = self.network.retain_event_poll_failure(error) {
                        host.report_diagnostic(error.diagnostic());
                    }
                    return Ok(false);
                }
            }
        }

        let Some(mut pending) = self.network.pending_event.take() else { return Ok(false); };
        match self.advance_network_event(&mut pending, memory, host) {
            Ok(true) => Ok(true),
            Ok(false) => {
                self.network.pending_event = Some(pending);
                Ok(false)
            }
            Err(error) => {
                let cause = std::sync::Arc::new(error);
                if pending.first_cause.is_none() {
                    pending.first_cause = Some(std::sync::Arc::clone(&cause));
                }
                self.network.pending_event = Some(pending);
                Err(RuntimeError::with_source(
                    cause.kind(),
                    "WinSock event processing failed; original typed cause is retained",
                    cause,
                ))
            }
        }
    }

    fn advance_network_event(
        &mut self,
        pending: &mut PendingNetworkEvent,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        if !pending.progress.identity_validated {
            self.validate_network_event_identity(&pending.event)?;
            pending.progress.identity_validated = true;
        }
        if let Some(retry_not_before) = pending.progress.retry_not_before {
            if std::time::Instant::now() < retry_not_before {
                return Ok(false);
            }
            pending.progress.retry_not_before = None;
        }
        if pending.progress.network_source_acknowledged {
            if let Some(proof) = pending.progress.post_proof.as_ref().cloned()
                && !pending.progress.post_proof_consumed
            {
                match host.win16_window_source_retirement_consumed(&proof) {
                    Ok(()) => pending.progress.post_proof_consumed = true,
                    Err(error) => {
                        self.report_pending_failure(pending, host, std::sync::Arc::new(error));
                        return Ok(false);
                    }
                }
            }
            self.finish_runtime_event_owner(pending)?;
            return Ok(pending.progress.runtime_owner_retired
                && (pending.progress.post_proof.is_none()
                    || pending.progress.post_proof_consumed));
        }

        if matches!(&pending.event, Win16HostNetworkEvent::SocketReady { .. }) {
            self.prepare_socket_notification(pending)?;
        } else {
            self.prepare_query_notification(pending, memory)?;
        }

        let task_identity = match &pending.event {
            Win16HostNetworkEvent::SocketReady { task, .. } => *task,
            Win16HostNetworkEvent::AsyncQueryComplete { owner, .. } => *owner,
        };
        if !self.task_identity_is_live(task_identity) {
            pending.progress.target_abandoned = true;
            if pending.first_cause.is_none() {
                pending.first_cause = Some(std::sync::Arc::new(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "WinSock notification belongs to a retired guest task")));
            }
        } else if !self.is_current_task(task_identity) {
            return Ok(false);
        }

        if let Some(cause) = pending.first_cause.as_ref().cloned() {
            self.report_pending_failure(pending, host, cause);
        }

        if !pending.progress.target_abandoned && pending.progress.notification.is_none() {
            return Ok(false);
        }

        if let Some(cause) = pending.progress.started_failure.as_ref()
            .map(|failure| std::sync::Arc::clone(&failure.cause))
        {
            self.report_pending_failure(pending, host, cause);
            // A started USER failure is terminally acknowledged only after
            // close_windows has retained the shared abort receipt.
            return Ok(false);
        }

        if pending.progress.target_abandoned {
            if let Some(proof) = pending.progress.post_proof.as_ref().cloned()
                && !pending.progress.post_proof_read_back
            {
                match host.win16_window_source_retirement(
                    proof.operation, proof.worker_generation,
                ) {
                    Ok(Some(read_back)) if std::sync::Arc::ptr_eq(&proof, &read_back) => {
                        pending.progress.post_proof_read_back = true;
                    }
                    Ok(Some(_)) => return Err(RuntimeError::new(Kind::InternalInvariant,
                        "WinSock USER POST returned a different source-retirement proof")),
                    Ok(None) => {
                        self.report_pending_failure(pending, host, std::sync::Arc::new(
                            RuntimeError::new(Kind::CompatibilityGap,
                                "WinSock USER POST source proof is not yet readable")));
                        return Ok(false);
                    }
                    Err(error) => {
                        self.report_pending_failure(pending, host, std::sync::Arc::new(error));
                        return Ok(false);
                    }
                }
            }
            self.retire_abandoned_socket_route(pending, host)?;
            self.ack_network_source(pending, host)?;
            if !pending.progress.network_source_acknowledged { return Ok(false); }
            if let Some(proof) = pending.progress.post_proof.as_ref().cloned()
                && !pending.progress.post_proof_consumed
            {
                match host.win16_window_source_retirement_consumed(&proof) {
                    Ok(()) => pending.progress.post_proof_consumed = true,
                    Err(error) => {
                        self.report_pending_failure(pending, host, std::sync::Arc::new(error));
                        return Ok(false);
                    }
                }
            }
            self.finish_runtime_event_owner(pending)?;
            return Ok(pending.progress.runtime_owner_retired
                && pending.progress.post_proof.as_ref().is_none_or(|_| {
                    pending.progress.post_proof_consumed
                }));
        }

        if pending.progress.post_proof.is_none() && pending.progress.posted.is_none() {
            let notification = pending.progress.notification.ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "WinSock event has no prepared guest notification"))?;
            match self.ensure_user_queue(host) {
                Ok(Some(_)) => {}
                Ok(None) => {
                    self.report_pending_failure(pending, host, std::sync::Arc::new(
                        RuntimeError::new(Kind::CompatibilityGap,
                            "WinSock notification has no live USER task queue")));
                    return Ok(false);
                }
                Err(error) => {
                    self.report_pending_failure(pending, host, std::sync::Arc::new(error));
                    return Ok(false);
                }
            }
            if !self.validate_guest_notification_target(notification.target) {
                self.report_pending_failure(pending, host, std::sync::Arc::new(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "WinSock notification target no longer names its captured Win16 window/task")));
                // A stale or reused guest HWND alias is not proof that the
                // opaque native window token retired. Keep the exact event
                // until USER supplies liveness evidence or task teardown.
                return Ok(false);
            }
            match host.win16_window_begin(Win16WindowOperation::PostGuestNotification(notification)) {
                Ok(step) => self.accept_post_step(pending, step)?,
                Err(error) => {
                    // USER defines a plain Err as a known pre-enqueue failure.
                    // Keep the same notification and event source for retry.
                    self.report_pending_failure(pending, host, std::sync::Arc::new(error));
                    return Ok(false);
                }
            }
        }

        if pending.progress.started_failure.is_some() {
            return Ok(false);
        }
        let Some(proof) = pending.progress.post_proof.as_ref().cloned() else {
            return Ok(false);
        };
        if !pending.progress.post_proof_read_back {
            match host.win16_window_source_retirement(
                proof.operation, proof.worker_generation,
            ) {
                Ok(Some(read_back)) if std::sync::Arc::ptr_eq(&proof, &read_back) => {
                    pending.progress.post_proof_read_back = true;
                }
                Ok(Some(_)) => return Err(RuntimeError::new(Kind::InternalInvariant,
                    "WinSock USER POST returned a different source-retirement proof")),
                Ok(None) => {
                    self.report_pending_failure(pending, host, std::sync::Arc::new(
                        RuntimeError::new(Kind::CompatibilityGap,
                            "WinSock USER POST source proof is not yet readable")));
                    return Ok(false);
                }
                Err(error) => {
                    self.report_pending_failure(pending, host, std::sync::Arc::new(error));
                    return Ok(false);
                }
            }
        }

        // WinSock 1.1 requires a provider to retry a failed PostMessage while
        // the exact destination window still exists. Each USER attempt has
        // its own retired source proof; consume that proof first, retain the
        // same WINSOCK event/notification/output owner, and schedule at most
        // one new POST on the next guest safe point.
        if pending.progress.posted == Some(false) {
            if !pending.progress.post_proof_consumed {
                match host.win16_window_source_retirement_consumed(&proof) {
                    Ok(()) => pending.progress.post_proof_consumed = true,
                    Err(error) => {
                        self.report_pending_failure(pending, host, std::sync::Arc::new(error));
                        return Ok(false);
                    }
                }
            }
            let notification = pending.progress.notification.ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "WinSock failed POST has no retained owned notification"))?;
            let crate::Win16GuestNotificationTarget::Window { window, guest_hwnd } =
                notification.target else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "WinSock async notification lost its captured window target"));
                };
            if self.window_handles.get(&guest_hwnd) != Some(&window) {
                self.report_pending_failure(pending, host, std::sync::Arc::new(
                    RuntimeError::new(Kind::CompatibilityGap,
                        "WinSock target alias no longer names the captured window token")));
                // A reused guest WORD cannot prove retirement of the captured
                // host token. Do not query the new incarnation or ACK this
                // event on an unknown alias/liveness result.
                return Ok(false);
            }
            match host.win16_host_window_liveness(window) {
                Ok(Win16HostWindowLiveness::Live) => {
                    // Keep `notification`, the native event, and any async
                    // query's already committed result block. The next call
                    // to this method is a distinct safe point and therefore a
                    // distinct USER POST attempt.
                    pending.progress.post_started = false;
                    pending.progress.post_proof = None;
                    pending.progress.posted = None;
                    pending.progress.post_proof_read_back = false;
                    pending.progress.post_proof_consumed = false;
                    pending.progress.retry_not_before = Some(
                        std::time::Instant::now() + std::time::Duration::from_millis(50));
                    return Ok(false);
                }
                Ok(Win16HostWindowLiveness::Retired) => {
                    pending.progress.target_abandoned = true;
                    self.retire_abandoned_socket_route(pending, host)?;
                    self.ack_network_source(pending, host)?;
                    if !pending.progress.network_source_acknowledged { return Ok(false); }
                    self.finish_runtime_event_owner(pending)?;
                    return Ok(pending.progress.runtime_owner_retired);
                }
                Err(error) => {
                    self.report_pending_failure(pending, host, std::sync::Arc::new(error));
                    return Ok(false);
                }
            }
        }

        self.ack_network_source(pending, host)?;
        if !pending.progress.network_source_acknowledged { return Ok(false); }
        if !pending.progress.post_proof_consumed {
            match host.win16_window_source_retirement_consumed(&proof) {
                Ok(()) => pending.progress.post_proof_consumed = true,
                Err(error) => {
                    self.report_pending_failure(pending, host, std::sync::Arc::new(error));
                    return Ok(false);
                }
            }
        }
        self.finish_runtime_event_owner(pending)?;
        Ok(pending.progress.runtime_owner_retired && pending.progress.post_proof_consumed)
    }

    fn retire_abandoned_socket_route(
        &mut self,
        pending: &PendingNetworkEvent,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let Win16HostNetworkEvent::SocketReady {
            socket, registration_generation, ..
        } = &pending.event else { return Ok(()); };
        let Some((guest_socket, route, active)) = self.network.async_select_route_for_event(
            *socket, *registration_generation,
        ) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "abandoned WinSock socket event lost its exact registration route"));
        };
        if !active { return Ok(()); }
        if self.network.host_socket(guest_socket) != Some(*socket)
            || self.network.async_select_route(guest_socket) != Some(route)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "abandoned WinSock route changed before exact host retirement"));
        }
        self.network.reserve_retired_async_selects(1)?;
        let result = host.win16_network(Win16HostNetworkCall::AsyncSelect {
            socket: *socket,
            task: route.task,
            window: route.host_window,
            guest_hwnd: route.window,
            message: route.message,
            events: 0,
            registration_generation: route.registration_generation,
            expected_source_id: Some(route.source_id),
        })?;
        if result.wsa_error != 0 {
            return Err(RuntimeError::new(Kind::HostFailure,
                format!("retiring abandoned WinSock async route failed with WSA error {}",
                    result.wsa_error)));
        }
        if !self.network.set_socket_nonblocking(guest_socket, true) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock socket disappeared after successful abandoned-route retirement"));
        }
        if !matches!(result.value, Win16HostNetworkValue::AsyncRegistration {
            source_id: 0, generation,
        } if generation == route.registration_generation) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock async route retirement returned the wrong source proof"));
        }
        if !self.network.set_async_select(guest_socket, None) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock guest socket disappeared after exact async route retirement"));
        }
        Ok(())
    }

    fn prepare_socket_notification(
        &mut self,
        pending: &mut PendingNetworkEvent,
    ) -> Result<(), RuntimeError> {
        let Win16HostNetworkEvent::SocketReady {
            source, socket, task, registration_generation, window,
            guest_hwnd, message, event, error,
        } = &pending.event else { return Ok(()); };
        if pending.progress.target_abandoned { return Ok(()); }
        let Some((guest_socket, route, _active)) = self.network.async_select_route_for_event(
            *socket, *registration_generation,
        ) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock socket event has no active or retired exact registration"));
        };
        let bit = u32::from(*event);
        if source.id != route.source_id
            || source.generation != route.registration_generation
            || *task != route.task || *window != route.host_window
            || *guest_hwnd != route.window || *message != route.message
            || bit.count_ones() != 1 || bit & route.events == 0
            || source.sequence == 0
            || route.last_event_sequence.checked_add(1) != Some(source.sequence)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock socket event identity does not match its retained registration"));
        }
        pending.progress.identity_validated = true;
        if !self.task_identity_is_live(route.task) {
            if pending.first_cause.is_none() {
                pending.first_cause = Some(std::sync::Arc::new(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "WinSock socket event belongs to a retired guest task")));
            }
            pending.progress.target_abandoned = true;
            return Ok(());
        }
        if !self.is_current_task(route.task) { return Ok(()); }
        if pending.progress.notification.is_some() { return Ok(()); }
        pending.progress.notification = Some(Win16GuestNotification {
            target: Win16GuestNotificationTarget::Window {
                window: route.host_window,
                guest_hwnd: route.window,
            },
            source: *source,
            message: route.message,
            w_param: guest_socket,
            l_param: u32::from(*event) | (u32::from(*error) << 16),
        });
        Ok(())
    }

    fn prepare_query_notification(
        &mut self,
        pending: &mut PendingNetworkEvent,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let Win16HostNetworkEvent::AsyncQueryComplete {
            source, task, owner, window, guest_hwnd, message, capacity,
            request_generation, result,
        } = &pending.event else { return Ok(()); };
        if pending.progress.target_abandoned { return Ok(()); }
        let Some((guest_task, route)) = self.network.event_owner_for_query(*task) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock async completion has no retained guest request"));
        };
        let Some(request) = self.network.host_async_task(guest_task) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock async completion request has no exact host identity"));
        };
        if route.source_id != Some(source.id) || request.source_id != source.id
            || request.task != *task || request.generation != *request_generation
            || source.generation != *request_generation || source.sequence != 1
            || route.request_generation != *request_generation
            || route.task != *owner || route.host_window != *window
            || route.window != *guest_hwnd || route.message != *message
            || i16::try_from(route.output_capacity).ok() != Some(*capacity)
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock async completion identity does not match its captured request"));
        }
        pending.progress.identity_validated = true;
        if !self.task_identity_is_live(route.task) {
            if pending.first_cause.is_none() {
                pending.first_cause = Some(std::sync::Arc::new(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "WinSock async completion belongs to a retired guest task")));
            }
            pending.progress.target_abandoned = true;
            return Ok(());
        }
        if !self.is_current_task(route.task) { return Ok(()); }
        if pending.progress.notification.is_some() { return Ok(()); }

        if !pending.progress.output_projected {
            match result {
                Err(error) => {
                    if *error == 0 {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "WinSock async resolver failure carried a success error code"));
                    }
                    let error = u16::try_from(*error).map_err(|cause| RuntimeError::with_source(
                        Kind::InternalInvariant,
                        "WinSock async resolver returned an invalid Win16 error code", cause))?;
                    pending.progress.output_error = Some(error);
                    pending.progress.output_projected = true;
                }
                Ok(Win16HostNetworkNameResult::NotFound) => {
                    pending.progress.output_error = Some(WSAHOST_NOT_FOUND as u16);
                    pending.progress.output_projected = true;
                }
                Ok(value) => {
                    if !lookup_accepts_result(&route.lookup, value) {
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "WinSock async resolver result does not match its lookup family"));
                    }
                    if let Err(error) = route.output.is_live(self, memory) {
                        match error.kind() {
                            Kind::GuestFault => {
                                pending.progress.output_error = Some(WSAEFAULT as u16);
                                pending.progress.output_projected = true;
                            }
                            Kind::InvalidInput => {
                                pending.progress.output_error = Some(WSAEINVAL as u16);
                                pending.progress.output_projected = true;
                            }
                            Kind::ResourceExhausted => {
                                if pending.first_cause.is_none() {
                                    pending.first_cause = Some(std::sync::Arc::new(error));
                                }
                                return Ok(());
                            }
                            _ => return Err(error),
                        }
                    } else {
                        let start = route.output.start();
                        let base = compat_services::win16_network::GuestFarBase16 {
                            selector: start.selector().raw().0,
                            offset: start.offset(),
                        };
                        let bytes = match super::resolver::encode_name_result_at(value, base) {
                            Ok(bytes) => bytes,
                            Err(_) => {
                                pending.progress.output_error = Some(WSAENOBUFS as u16);
                                pending.progress.output_projected = true;
                                Vec::new()
                            }
                        };
                        if !pending.progress.output_projected {
                            if bytes.len() > usize::from(route.output_capacity) {
                                pending.progress.output_error = Some(WSAENOBUFS as u16);
                                pending.progress.required_output_bytes = u16::try_from(bytes.len())
                                    .unwrap_or(u16::MAX);
                                pending.progress.output_projected = true;
                            } else {
                                pending.progress.output = Some(
                                    PreparedAsyncGuestOutput {
                                        range: route.output.try_clone()?,
                                        bytes,
                                    },
                                );
                            }
                        }
                    }
                }
            }
        }
        if !pending.progress.output_projected {
            if let Some(output) = pending.progress.output.as_ref() {
                let range = output.range.try_clone()?;
                let bytes = output.bytes.clone();
                match self.commit_outputs(memory, vec![(range, bytes)]) {
                    Ok(()) => pending.progress.output_projected = true,
                    Err(error) => match error.kind() {
                        Kind::GuestFault => {
                            pending.progress.output_error = Some(WSAEFAULT as u16);
                            pending.progress.output_projected = true;
                        }
                        Kind::InvalidInput => {
                            pending.progress.output_error = Some(WSAEINVAL as u16);
                            pending.progress.output_projected = true;
                        }
                        Kind::ResourceExhausted => {
                            if pending.first_cause.is_none() {
                                pending.first_cause = Some(std::sync::Arc::new(error));
                            }
                            return Ok(());
                        }
                        _ => return Err(error.with_context(
                            "WinSock async resolver output could not be committed transactionally")),
                    },
                }
            }
        }
        if pending.progress.output_projected {
            let error = pending.progress.output_error.unwrap_or(0);
            let required = if error == WSAENOBUFS as u16 {
                pending.progress.required_output_bytes
            } else { 0 };
            pending.progress.notification = Some(Win16GuestNotification {
                target: Win16GuestNotificationTarget::Window {
                    window: route.host_window,
                    guest_hwnd: route.window,
                },
                source: *source,
                message: route.message,
                w_param: guest_task,
                l_param: (u32::from(error) << 16) | u32::from(required),
            });
        }
        Ok(())
    }

    fn accept_post_step(
        &mut self,
        pending: &mut PendingNetworkEvent,
        step: Win16WindowStep,
    ) -> Result<(), RuntimeError> {
        match step {
            Win16WindowStep::StartedFailure(failure) => {
                pending.progress.post_started = true;
                self.validate_post_failure(&failure)?;
                pending.progress.started_failure = Some(failure);
            }
            Win16WindowStep::Started {
                operation_id, worker_generation, kind, step,
            } => {
                pending.progress.post_started = true;
                if kind != Win16NativeWindowOperationKind::PostGuestNotification {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "WinSock USER call started a non-POST operation"));
                }
                let operation = Win16NativeWindowOperationProof { operation_id, kind };
                match *step {
                    Win16WindowStep::StartedFailure(failure) => {
                        if failure.operation != operation
                            || failure.worker_generation != worker_generation
                        {
                            return Err(RuntimeError::new(Kind::InternalInvariant,
                                "WinSock USER POST failure changed its operation identity"));
                        }
                        self.validate_post_failure(&failure)?;
                        pending.progress.started_failure = Some(failure);
                    }
                    Win16WindowStep::SourceRetired { proof, result } => {
                        if proof.operation != operation
                            || proof.worker_generation != worker_generation
                            || proof.state != Win16NativeWindowOperationState::Returned
                        {
                            return Err(RuntimeError::new(Kind::InternalInvariant,
                                "WinSock USER POST returned a mismatched source proof"));
                        }
                        let posted = match *result {
                            Win16WindowStep::Complete(Win16WindowResult::NotificationPosted(posted)) => posted,
                            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                                "WinSock USER POST proof did not carry NotificationPosted")),
                        };
                        pending.progress.post_proof = Some(proof);
                        pending.progress.posted = Some(posted);
                    }
                    _ => return Err(RuntimeError::new(Kind::CompatibilityGap,
                        "WinSock USER POST did not return a terminal source proof")),
                }
            }
            Win16WindowStep::SourceRetired { proof, result } => {
                pending.progress.post_started = true;
                if proof.operation.kind != Win16NativeWindowOperationKind::PostGuestNotification
                    || proof.state != Win16NativeWindowOperationState::Returned
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "WinSock USER POST returned an invalid terminal proof"));
                }
                let posted = match *result {
                    Win16WindowStep::Complete(Win16WindowResult::NotificationPosted(posted)) => posted,
                    _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                        "WinSock USER POST proof did not carry NotificationPosted")),
                };
                pending.progress.post_proof = Some(proof);
                pending.progress.posted = Some(posted);
            }
            _ => return Err(RuntimeError::new(Kind::CompatibilityGap,
                "WinSock USER POST did not return a recognized terminal source phase")),
        }
        Ok(())
    }

    fn validate_post_failure(
        &self,
        failure: &std::sync::Arc<crate::Win16WindowOperationStartedFailure>,
    ) -> Result<(), RuntimeError> {
        if failure.operation.kind != Win16NativeWindowOperationKind::PostGuestNotification
            || failure.worker_generation == 0
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock USER POST failure has an invalid operation proof"));
        }
        Ok(())
    }

}

fn lookup_accepts_result(
    lookup: &Win16AsyncLookup,
    result: &Win16HostNetworkNameResult,
) -> bool {
    matches!((lookup, result),
        (Win16AsyncLookup::HostByAddress { .. }, Win16HostNetworkNameResult::Host(_))
        | (Win16AsyncLookup::HostByName(_), Win16HostNetworkNameResult::Host(_))
        | (Win16AsyncLookup::ProtocolByName(_), Win16HostNetworkNameResult::Protocol(_))
        | (Win16AsyncLookup::ProtocolByNumber(_), Win16HostNetworkNameResult::Protocol(_))
        | (Win16AsyncLookup::ServiceByName { .. }, Win16HostNetworkNameResult::Service(_))
        | (Win16AsyncLookup::ServiceByPort { .. }, Win16HostNetworkNameResult::Service(_)))
}
