//! Exact cleanup of retained WinSock event and USER post sources.

use guest_core::Selector;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16HostNetworkEvent};
use super::{PendingNetworkEvent, Win16State};

impl Win16State {
    fn ack_started_failure(
        &mut self,
        pending: &mut PendingNetworkEvent,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if pending.progress.terminal_user_acknowledged { return Ok(()); }
        let failure = pending.progress.started_failure.as_ref().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "WinSock USER terminal ACK has no retained failure proof"))?;
        self.acknowledge_started_post_failure(failure, host)?;
        pending.progress.terminal_user_acknowledged = true;
        Ok(())
    }

    pub(in crate::win16_runtime) fn retire_network_events_after_windows(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        loop {
            if self.network.pending_event.is_none() {
                match host.win16_peek_network_event()? {
                    Some(event) => self.network.pending_event = Some(PendingNetworkEvent {
                        event,
                        progress: Default::default(),
                        first_cause: None,
                    }),
                None => {
                    self.network.clear_retired_routes();
                    return Ok(());
                }
                }
            }
            let Some(mut pending) = self.network.pending_event.take() else { continue; };
            let result = self.retire_network_event_after_windows(&mut pending, host);
            match result {
                Ok(()) => {}
                Err(error) => {
                    self.network.pending_event = Some(pending);
                    return Err(error);
                }
            }
        }
    }

    fn retire_network_event_after_windows(
        &mut self,
        pending: &mut PendingNetworkEvent,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if !pending.progress.identity_validated {
            self.validate_network_event_identity(&pending.event)?;
            pending.progress.identity_validated = true;
        }
        if pending.progress.started_failure.is_some() {
            self.ack_started_failure(pending, host)?;
            if !pending.progress.terminal_user_acknowledged {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "WinSock USER failure source remains unacknowledged after abort"));
            }
        } else if let Some(proof) = pending.progress.post_proof.as_ref().cloned() {
            if !pending.progress.post_proof_read_back {
                match host.win16_window_source_retirement(
                    proof.operation, proof.worker_generation,
                )? {
                    Some(read_back) if std::sync::Arc::ptr_eq(&proof, &read_back) => {
                        pending.progress.post_proof_read_back = true;
                    }
                    _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                        "WinSock USER POST proof changed during terminal cleanup")),
                }
            }
        } else if pending.progress.post_started {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock USER POST has an accepted operation without a terminal proof"));
        } else {
            // Teardown has closed the destination window. A queued but
            // unposted WINSOCK source has no USER source to acknowledge.
            pending.progress.target_abandoned = true;
        }
        self.ack_network_source(pending, host)?;
        if !pending.progress.network_source_acknowledged {
            return Err(RuntimeError::new(Kind::HostFailure,
                "WinSock event source remains retained during terminal cleanup"));
        }
        if let Some(proof) = pending.progress.post_proof.as_ref().cloned()
            && !pending.progress.post_proof_consumed
        {
            host.win16_window_source_retirement_consumed(&proof)?;
            pending.progress.post_proof_consumed = true;
        }
        self.finish_runtime_event_owner(pending)?;
        if !pending.progress.runtime_owner_retired {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "WinSock runtime owner remains after exact terminal source ACK"));
        }
        Ok(())
    }

    pub(super) fn validate_network_event_identity(
        &self,
        event: &Win16HostNetworkEvent,
    ) -> Result<(), RuntimeError> {
        match event {
            Win16HostNetworkEvent::SocketReady {
                source, socket, task, registration_generation, window,
                guest_hwnd, message, event, ..
            } => {
                let Some((_, route, _)) = self.network.async_select_route_for_event(
                    *socket, *registration_generation,
                ) else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "WinSock socket event has no exact retained registration"));
                };
                let bit = u32::from(*event);
                if source.id != route.source_id
                    || source.generation != route.registration_generation
                    || source.sequence == 0
                    || route.last_event_sequence.checked_add(1) != Some(source.sequence)
                    || *task != route.task || *window != route.host_window
                    || *guest_hwnd != route.window || *message != route.message
                    || bit.count_ones() != 1 || bit & route.events == 0
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "WinSock socket event source does not match its registration owner"));
                }
            }
            Win16HostNetworkEvent::AsyncQueryComplete {
                source, task, owner, window, guest_hwnd, message, capacity,
                request_generation, ..
            } => {
                let Some((guest, route)) = self.network.event_owner_for_query(*task) else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "WinSock async event has no exact guest request owner"));
                };
                let Some(request) = self.network.host_async_task(guest) else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "WinSock async event has no exact host request owner"));
                };
                if route.source_id != Some(source.id)
                    || request.task != *task || request.source_id != source.id
                    || request.generation != *request_generation
                    || source.generation != *request_generation || source.sequence != 1
                    || route.request_generation != *request_generation
                    || route.task != *owner || route.host_window != *window
                    || route.window != *guest_hwnd || route.message != *message
                    || i16::try_from(route.output_capacity).ok() != Some(*capacity)
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "WinSock async event source does not match its request owner"));
                }
            }
        }
        Ok(())
    }

    pub(super) fn ack_network_source(
        &mut self,
        pending: &mut PendingNetworkEvent,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if pending.progress.network_source_acknowledged { return Ok(()); }
        let source = match &pending.event {
            Win16HostNetworkEvent::SocketReady { source, .. }
            | Win16HostNetworkEvent::AsyncQueryComplete { source, .. } => *source,
        };
        match host.win16_ack_network_event(source) {
            Ok(()) => pending.progress.network_source_acknowledged = true,
            Err(error) => self.report_pending_failure(pending, host, std::sync::Arc::new(error)),
        }
        Ok(())
    }

    pub(super) fn finish_runtime_event_owner(
        &mut self,
        pending: &mut PendingNetworkEvent,
    ) -> Result<(), RuntimeError> {
        if pending.progress.runtime_owner_retired { return Ok(()); }
        match &pending.event {
            Win16HostNetworkEvent::SocketReady { source, socket, registration_generation, .. } => {
                let _active = self.network.async_select_route_for_event(
                    *socket, *registration_generation,
                ).map(|(_, _, active)| active).ok_or_else(|| RuntimeError::new(
                    Kind::InternalInvariant,
                    "WinSock socket event owner disappeared before source retirement"))?;
                if !self.network.record_async_select_event_ack(
                    *socket, *registration_generation, source.sequence,
                ) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "WinSock socket event sequence changed before source retirement"));
                }
            }
            Win16HostNetworkEvent::AsyncQueryComplete { task, source, .. } => {
                let Some((guest, route)) = self.network.event_owner_for_query(*task) else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "WinSock query owner disappeared before source retirement"));
                };
                let Some(request) = self.network.host_async_task(guest) else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "WinSock query request identity disappeared before source retirement"));
                };
                if request.task != *task || request.source_id != source.id
                    || route.request_generation != source.generation
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "WinSock query owner changed before exact source retirement"));
                }
                if self.network.take_async_task(guest) != Some(request) {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "WinSock query owner could not be retired after exact host ACK"));
                }
            }
        }
        pending.progress.runtime_owner_retired = true;
        Ok(())
    }

    pub(super) fn task_identity_is_live(&self, identity: crate::Win16NetworkTaskIdentity) -> bool {
        self.task_handles.get(&identity.owner) == Some(&identity.guest_htask)
            && self.selectors.reference(Selector(identity.guest_htask))
                .is_ok_and(|reference| reference.generation() == identity.selector_generation)
    }

    pub(super) fn is_current_task(&self, identity: crate::Win16NetworkTaskIdentity) -> bool {
        self.tasks.current() == Some(identity.owner) && self.task_identity_is_live(identity)
    }

    pub(super) fn report_pending_failure(
        &mut self,
        pending: &mut PendingNetworkEvent,
        host: &mut impl RuntimeHost,
        cause: std::sync::Arc<RuntimeError>,
    ) {
        if pending.first_cause.is_none() { pending.first_cause = Some(cause); }
        pending.progress.retry_not_before = Some(
            std::time::Instant::now() + std::time::Duration::from_millis(50));
        if !pending.progress.failure_reported {
            if let Some(cause) = pending.first_cause.as_ref() {
                host.report_diagnostic(cause.diagnostic());
            }
            pending.progress.failure_reported = true;
        }
    }
}
