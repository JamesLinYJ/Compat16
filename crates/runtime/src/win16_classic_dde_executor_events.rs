//! Classic DDE executor support for queued event publication and retirement.

use super::*;

impl Win16State {
    fn validate_committed_classic_dde_client_event(
        &self,
        event: &Win16HostClassicDdeEvent,
        event_id: crate::Win16ClassicDdeEventId,
    ) -> Result<(), RuntimeError> {
        if event_id != event.event_id {
            return Err(dde_invariant(
                "client DDE commit changed its exact queued EventId",
            ));
        }
        let committed = self
            .committed_ole1_client_dde_event(event.owner, event.endpoint, event_id)
            .ok_or_else(|| {
                dde_invariant("client DDE commit has no retained exact response journal")
            })?;
        if committed.event_id != event.event_id
            || committed.owner != event.owner
            || committed.endpoint != event.endpoint
            || committed.peer != event.peer
            || Some(committed.conversation) != event.conversation
            || committed.transaction != event.transaction
        {
            return Err(dde_invariant(
                "client DDE response journal changed queued event identity",
            ));
        }
        Ok(())
    }

    fn process_classic_dde_client_committed_event(
        &mut self,
        event: Win16HostClassicDdeEvent,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let Some((operation, disposition)) = self.process_ole1_client_dde_committed_event(
            event.clone(), cpu, dos, memory, host,
        )? else {
            return Ok(false);
        };
        if matches!(event.message, crate::Win16ClassicDdeMessage::Terminate) {
            // The termination journal already validated this peer, conversation
            // and EventId. Its ACK advances the close handshake, not an OLE
            // EXECUTE/POKE response stage retained by the same Release call.
            self.apply_client_terminal_disposition_ready(
                event.owner,
                operation,
                None,
                disposition,
                host,
            )?;
            return Ok(true);
        }
        self.apply_client_terminal_disposition(
            event.owner,
            operation,
            None,
            disposition,
            cpu,
            dos,
            memory,
            host,
        )?;
        Ok(true)
    }

    pub(super) fn publish_classic_dde_queued_event(
        &mut self,
        host_event: Win16HostClassicDdeEvent,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        self.classic_dde.event_tracker.admit(&host_event)?;
        let owns_publication = self.classic_dde.event_tracker.begin_publication(
            host_event.owner,
            host_event.endpoint,
            host_event.worker_generation,
            host_event.event_id,
        )?;
        if !owns_publication {
            // The exact event already has a published continuation. Its owner
            // journal, not another PollOwner pass, decides when it can resume.
            return Ok(());
        }
        let result = (|| -> Result<(), RuntimeError> {
            let materialized = match self.materialize_classic_dde_event_atoms(&host_event, host) {
                Ok(event) => event,
                Err(error) => return Err(error),
            };
            let mut event = materialized;
            self.materialize_classic_dde_event_global(&mut event, memory, host)?;

            let disposition = match self
                .route_classic_dde_queued_event(&event, cpu, dos, memory, host)?
            {
                Ole1ServerDdeDisposition::NotOwned => {
                    match self.commit_ole1_client_dde_event(event.clone())? {
                        Win16Ole1ClientDdeEventCommit::NotOwned(returned)
                        | Win16Ole1ClientDdeEventCommit::Ambiguous(returned) => {
                            if returned != event {
                                return Err(dde_invariant(
                                    "unclaimed classic DDE event changed its owned payload",
                                ));
                            }
                            self.retain_classic_dde_queued_event(event.clone())?;
                            self.retain_classic_dde_deferred_queued_event(event.clone())?;
                            self.classic_dde.event_tracker.publication_succeeded(
                                event.owner,
                                event.endpoint,
                                event.worker_generation,
                                event.event_id,
                            )?;
                            // Keep this exact mailbox entry for an owner-scoped
                            // retry. Ambiguity is not permission to acknowledge.
                            return Ok(());
                        }
                        Win16Ole1ClientDdeEventCommit::Committed(event_id)
                        | Win16Ole1ClientDdeEventCommit::AlreadyCommitted(event_id) => {
                            self.validate_committed_classic_dde_client_event(&event, event_id)?;
                            self.retain_classic_dde_queued_event(event.clone())?;
                            self.retain_classic_dde_deferred_queued_event(event.clone())?;
                            self.classic_dde.event_tracker.publication_succeeded(
                                event.owner,
                                event.endpoint,
                                event.worker_generation,
                                event.event_id,
                            )?;
                            // The exact client response remains retained until
                            // the OLE1 operation journal accepts its EventId.
                            if self.process_classic_dde_client_committed_event(
                                event.clone(), cpu, dos, memory, host,
                            )? {
                                self.remove_classic_dde_deferred_queued_event(&event)?;
                            }
                            return Ok(());
                        }
                    }
                }
                owned => owned,
            };

            self.retain_classic_dde_queued_event(event.clone())?;
            self.classic_dde.event_tracker.publication_succeeded(
                event.owner,
                event.endpoint,
                event.worker_generation,
                event.event_id,
            )?;
            self.apply_server_queued_disposition(disposition, event, cpu, dos, memory, host)
        })();
        if result.is_err() {
            let still_publishing = self.classic_dde.event_tracker.pending().any(|progress| {
                progress.owner == host_event.owner
                    && progress.endpoint == host_event.endpoint
                    && progress.worker_generation == host_event.worker_generation
                    && progress.event_id == host_event.event_id
                    && progress.phase == crate::Win16ClassicDdeEventPhase::Publishing
            });
            if still_publishing {
                self.classic_dde.event_tracker.publication_failed(
                    host_event.owner,
                    host_event.endpoint,
                    host_event.worker_generation,
                    host_event.event_id,
                )?;
            }
        }
        result
    }

    fn apply_server_queued_disposition(
        &mut self,
        disposition: Ole1ServerDdeDisposition,
        event: Win16HostClassicDdeEvent,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        match disposition {
            Ole1ServerDdeDisposition::BeginHostCall { call, continuation } => {
                self.begin_classic_dde_host_call(
                    call,
                    ClassicDdeOperationOwner::ServerDde { continuation },
                    None,
                    host,
                )?;
            }
            Ole1ServerDdeDisposition::GuestCallback {
                far,
                args,
                return_kind,
                continuation,
            } => {
                self.enter_classic_dde_guest_callback(
                    cpu,
                    dos,
                    memory,
                    far,
                    &args,
                    return_kind,
                    continuation,
                    host,
                )?;
            }
            Ole1ServerDdeDisposition::UnpublishedCleanupEvent { cleanup_id, event } => {
                self.begin_classic_dde_host_call(
                    Win16HostClassicDdeCall::AcknowledgeEvent {
                        owner: event.owner,
                        endpoint: event.endpoint,
                        event_id: event.event_id,
                    },
                    ClassicDdeOperationOwner::UnpublishedCleanupEvent { cleanup_id, event },
                    None,
                    host,
                )?;
            }
            Ole1ServerDdeDisposition::AwaitHostOperation { event, .. }
            | Ole1ServerDdeDisposition::DeferredEvent(event) => {
                self.retain_classic_dde_deferred_queued_event(event)?;
            }
            Ole1ServerDdeDisposition::Deferred => {
                self.retain_classic_dde_deferred_queued_event(event)?;
            }
            Ole1ServerDdeDisposition::ReleaseEndpointPending {
                event: origin,
                target: _,
                endpoint,
                pending_events,
            } => {
                if origin.owner != event.owner || pending_events.is_empty() {
                    return Err(dde_invariant(
                        "OLE1 release wait lost its owner or exact pending EventIds",
                    ));
                }
                self.retain_classic_dde_pending_endpoint_poll(
                    origin.owner,
                    endpoint,
                    &pending_events,
                )?;
            }
            Ole1ServerDdeDisposition::OwnedMessage(owned) => {
                self.retain_classic_dde_deferred_queued_event(owned)?;
            }
            Ole1ServerDdeDisposition::ProtocolResult {
                event: owned,
                status,
            } => {
                if owned != event {
                    return Err(dde_invariant(
                        "OLE1 protocol result changed the exact queued DDE event",
                    ));
                }
                self.begin_server_protocol_result(owned, status, None, host)?;
            }
            Ole1ServerDdeDisposition::NotOwned => {
                self.retain_classic_dde_deferred_queued_event(event)?;
            }
            Ole1ServerDdeDisposition::HostCall { .. }
            | Ole1ServerDdeDisposition::ResumeCallback { .. }
            | Ole1ServerDdeDisposition::ReleaseComplete => {
                return Err(dde_invariant(
                    "synchronous-only OLE1 DDE disposition reached queued-event routing",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn retain_classic_dde_queued_event(
        &mut self,
        event: Win16HostClassicDdeEvent,
    ) -> Result<(), RuntimeError> {
        if let Some(existing) = self.classic_dde.queued_events.iter().find(|record| {
            record.event.owner == event.owner
                && record.event.endpoint == event.endpoint
                && record.event.event_id == event.event_id
        }) {
            if existing.event != event {
                return Err(dde_invariant(
                    "classic DDE EventId was replayed with a changed owned snapshot",
                ));
            }
            return Ok(());
        }
        self.classic_dde
            .queued_events
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "retain exact classic DDE queued event snapshot",
                    error,
                )
            })?;
        // This list owns the materialized snapshot. Publication/ACK phases
        // remain in event_tracker and are advanced by their exact receipts.
        self.classic_dde.queued_events.push(ClassicDdeQueuedEvent { event });
        Ok(())
    }

    pub(super) fn retain_classic_dde_deferred_queued_event(
        &mut self,
        event: Win16HostClassicDdeEvent,
    ) -> Result<(), RuntimeError> {
        if self
            .classic_dde
            .deferred_queued_events
            .iter()
            .any(|existing| {
                existing.owner == event.owner
                    && existing.endpoint == event.endpoint
                    && existing.worker_generation == event.worker_generation
                    && existing.event_id == event.event_id
            })
        {
            if self
                .classic_dde
                .deferred_queued_events
                .iter()
                .any(|existing| {
                    existing.owner == event.owner
                        && existing.endpoint == event.endpoint
                        && existing.event_id == event.event_id
                        && existing != &event
                })
            {
                return Err(dde_invariant(
                    "deferred classic DDE EventId changed its retained snapshot",
                ));
            }
            return Ok(());
        }
        self.classic_dde
            .deferred_queued_events
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "retain deferred classic DDE EventId for exact reroute",
                    error,
                )
            })?;
        self.classic_dde.deferred_queued_events.push(event);
        Ok(())
    }

    fn remove_classic_dde_deferred_queued_event(
        &mut self,
        event: &Win16HostClassicDdeEvent,
    ) -> Result<(), RuntimeError> {
        let Some(index) = self
            .classic_dde
            .deferred_queued_events
            .iter()
            .position(|candidate| {
                candidate.owner == event.owner
                    && candidate.endpoint == event.endpoint
                    && candidate.worker_generation == event.worker_generation
                    && candidate.event_id == event.event_id
            })
        else {
            return Ok(());
        };
        if self.classic_dde.deferred_queued_events[index] != *event {
            return Err(dde_invariant(
                "classic DDE deferred reroute changed the exact event snapshot",
            ));
        }
        self.classic_dde.deferred_queued_events.remove(index);
        Ok(())
    }

    pub(super) fn retry_one_classic_dde_queued_event(
        &mut self,
        owner: OwnerId,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let Some(event) = self
            .classic_dde
            .deferred_queued_events
            .iter()
            .find(|event| event.owner == owner)
            .cloned()
        else {
            return Ok(false);
        };
        let disposition = self.route_classic_dde_queued_event(&event, cpu, dos, memory, host)?;
        match disposition {
            Ole1ServerDdeDisposition::NotOwned => {
                match self.commit_ole1_client_dde_event(event.clone())? {
                    Win16Ole1ClientDdeEventCommit::Committed(event_id)
                    | Win16Ole1ClientDdeEventCommit::AlreadyCommitted(event_id) => {
                        self.validate_committed_classic_dde_client_event(&event, event_id)?;
                        self.retain_classic_dde_queued_event(event.clone())?;
                        if self.process_classic_dde_client_committed_event(
                            event.clone(), cpu, dos, memory, host,
                        )? {
                            self.remove_classic_dde_deferred_queued_event(&event)?;
                            Ok(true)
                        } else {
                            Ok(false)
                        }
                    }
                    Win16Ole1ClientDdeEventCommit::NotOwned(_)
                    | Win16Ole1ClientDdeEventCommit::Ambiguous(_) => Ok(false),
                }
            }
            Ole1ServerDdeDisposition::AwaitHostOperation { .. }
            | Ole1ServerDdeDisposition::DeferredEvent(_)
            | Ole1ServerDdeDisposition::Deferred
            | Ole1ServerDdeDisposition::OwnedMessage(_)
            => Ok(false),
            actionable => {
                self.apply_server_queued_disposition(
                    actionable,
                    event.clone(),
                    cpu,
                    dos,
                    memory,
                    host,
                )?;
                self.remove_classic_dde_deferred_queued_event(&event)?;
                Ok(true)
            }
        }
    }

    /// Finish runtime-side retirement only after the exact host EventId ACK
    /// terminal. If any owner ledger or local lease refuses retirement, keep
    /// the event and HostAcknowledged phase so the same exact terminal can be
    /// retried without issuing a second host ACK.
    pub(super) fn finish_classic_dde_event_ack_local(
        &mut self,
        event: &Win16HostClassicDdeEvent,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let progress = self
            .classic_dde
            .event_tracker
            .pending()
            .find(|progress| {
                progress.owner == event.owner
                    && progress.endpoint == event.endpoint
                    && progress.worker_generation == event.worker_generation
                    && progress.event_id == event.event_id
            })
            .copied()
            .ok_or_else(|| {
                dde_invariant("classic DDE EventId ACK has no retained publication record")
            })?;
        match progress.phase {
            crate::Win16ClassicDdeEventPhase::AcknowledgementPending => {
                self.classic_dde
                    .event_tracker
                    .host_acknowledgement_succeeded(
                        event.owner,
                        event.endpoint,
                        event.worker_generation,
                        event.event_id,
                    )?;
            }
            crate::Win16ClassicDdeEventPhase::HostAcknowledged => {}
            _ => {
                return Err(dde_invariant(
                    "classic DDE EventId terminal is outside its pending ACK phase",
                ));
            }
        }

        let client_event = self
            .committed_ole1_client_dde_event(event.owner, event.endpoint, event.event_id)
            .is_some();
        if let Some(guest_global) = self.classic_dde_guest_global_for_event(event) {
            self.retire_classic_dde_guest_global_for_event(event, guest_global)?;
        }
        self.retire_classic_dde_event_atoms(event, host)?;

        // An API-owned Release wait is a different ledger from the DDE
        // protocol transaction and from a DDE-triggered release cascade.
        // Advance it only when this exact EventId was in its latest receipt.
        if let Some(wait) = self.pending_ole1_release_for_endpoint(event.owner, event.endpoint)? {
            if wait.worker_generation == event.worker_generation
                && wait.pending_events.contains(&event.event_id)
                && !self.acknowledge_release_event(wait.callback_id, event)?
            {
                return Err(dde_invariant(
                    "OLE1 API Release wait rejected an exact EventAcknowledged terminal",
                ));
            }
        }

        // Client ACK and TERMINATE responses retain their exact journal entry
        // until this EventId delivery acknowledgement has completed.
        if client_event {
            self.acknowledge_ole1_client_dde_event(event.owner, event.endpoint, event.event_id)
                .map_err(|_| {
                    dde_invariant(
                        "OLE1 client event journal has not committed its exact delivery retirement",
                    )
                })?;
        }

        self.classic_dde.event_tracker.acknowledge_succeeded(
            event.owner,
            event.endpoint,
            event.worker_generation,
            event.event_id,
        )?;
        self.remove_classic_dde_queued_event(event)?;
        self.remove_classic_dde_pending_endpoint_event(event);
        Ok(())
    }

    pub(super) fn acknowledged_classic_dde_event(
        &self,
        identity: Win16ClassicDdeOperationIdentity,
        step: &Win16HostClassicDdeStep,
    ) -> Result<Option<Win16HostClassicDdeEvent>, RuntimeError> {
        let Win16HostClassicDdeStep::Complete {
            operation, result, ..
        } = step
        else {
            return Ok(None);
        };
        let Win16HostClassicDdeResult::EventAcknowledged(event_id) = result else {
            return Ok(None);
        };
        if *operation != identity {
            return Err(dde_invariant(
                "classic DDE EventAcknowledged belongs to another host operation",
            ));
        }
        let Some(frame) = self.classic_dde.operations.last().filter(|frame| {
            frame.identity == identity
                && matches!(
                    &frame.call,
                    Win16HostClassicDdeCall::AcknowledgeEvent { .. }
                )
        }) else {
            return Ok(None);
        };
        let Win16HostClassicDdeCall::AcknowledgeEvent {
            owner,
            endpoint,
            event_id: requested,
        } = &frame.call
        else {
            return Ok(None);
        };
        if *requested != *event_id {
            return Err(dde_invariant(
                "classic DDE host acknowledged a different requested EventId",
            ));
        }
        let event = self
            .classic_dde
            .queued_events
            .iter()
            .find(|record| {
                record.event.owner == *owner
                    && record.event.endpoint == *endpoint
                    && record.event.event_id == *event_id
                    && record.event.worker_generation == identity.worker_generation
            })
            .ok_or_else(|| {
                dde_invariant("classic DDE EventAcknowledged lost its exact runtime event snapshot")
            })?;
        Ok(Some(event.event.clone()))
    }

    fn remove_classic_dde_queued_event(
        &mut self,
        event: &Win16HostClassicDdeEvent,
    ) -> Result<(), RuntimeError> {
        let Some(index) = self.classic_dde.queued_events.iter().position(|record| {
            record.event.owner == event.owner
                && record.event.endpoint == event.endpoint
                && record.event.worker_generation == event.worker_generation
                && record.event.event_id == event.event_id
        }) else {
            return Err(dde_invariant(
                "classic DDE EventId ACK lost its retained event snapshot",
            ));
        };
        if self.classic_dde.queued_events[index].event != *event {
            return Err(dde_invariant(
                "classic DDE EventId ACK changed its retained event contents",
            ));
        }
        self.classic_dde.queued_events.remove(index);
        Ok(())
    }

    fn remove_classic_dde_pending_endpoint_event(&mut self, event: &Win16HostClassicDdeEvent) {
        let mut index = 0usize;
        while index < self.classic_dde.pending_endpoint_polls.len() {
            let pending = &mut self.classic_dde.pending_endpoint_polls[index];
            if pending.owner == event.owner && pending.endpoint == event.endpoint {
                pending
                    .event_ids
                    .retain(|event_id| *event_id != event.event_id);
                if pending.event_ids.is_empty() {
                    self.classic_dde.pending_endpoint_polls.remove(index);
                    continue;
                }
            }
            index += 1;
        }
    }

    pub(super) fn pending_classic_dde_endpoint_poll(
        &self,
    ) -> Option<(
        OwnerId,
        Win16HostClassicDdeEndpoint,
        Vec<Win16ClassicDdeEventId>,
    )> {
        self.classic_dde
            .pending_endpoint_polls
            .first()
            .map(|pending| (pending.owner, pending.endpoint, pending.event_ids.clone()))
    }

    pub(super) fn pending_classic_dde_endpoint_poll_for(
        &self,
        owner: OwnerId,
    ) -> Option<(Win16HostClassicDdeEndpoint, Vec<Win16ClassicDdeEventId>)> {
        self.classic_dde
            .pending_endpoint_polls
            .iter()
            .find(|pending| pending.owner == owner)
            .map(|pending| (pending.endpoint, pending.event_ids.clone()))
    }

    pub(super) fn retain_classic_dde_pending_endpoint_poll(
        &mut self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        event_ids: &[Win16ClassicDdeEventId],
    ) -> Result<(), RuntimeError> {
        if event_ids.is_empty() {
            return Err(dde_invariant("pending endpoint poll has no exact EventIds"));
        }
        let mut unique = Vec::new();
        unique.try_reserve_exact(event_ids.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain pending classic DDE endpoint EventIds",
                error,
            )
        })?;
        for event_id in event_ids {
            if event_id.0 == 0 || unique.contains(event_id) {
                return Err(dde_invariant(
                    "pending endpoint EventIds are zero or duplicated",
                ));
            }
            unique.push(*event_id);
        }
        if let Some(existing) = self
            .classic_dde
            .pending_endpoint_polls
            .iter_mut()
            .find(|pending| pending.owner == owner && pending.endpoint == endpoint)
        {
            for event_id in unique {
                if !existing.event_ids.contains(&event_id) {
                    existing.event_ids.try_reserve(1).map_err(|error| {
                        RuntimeError::with_source(
                            Kind::ResourceExhausted,
                            "extend pending classic DDE endpoint EventIds",
                            error,
                        )
                    })?;
                    existing.event_ids.push(event_id);
                }
            }
            return Ok(());
        }
        self.classic_dde
            .pending_endpoint_polls
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "retain pending classic DDE endpoint poll",
                    error,
                )
            })?;
        self.classic_dde.pending_endpoint_polls.push(
            super::super::classic_dde_dispatch::ClassicDdePendingEndpointPoll {
                owner,
                endpoint,
                event_ids: unique,
            },
        );
        Ok(())
    }
}
