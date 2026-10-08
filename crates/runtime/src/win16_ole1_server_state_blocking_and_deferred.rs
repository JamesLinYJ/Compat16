impl Ole1ServerState {

    pub(crate) fn set_blocked(
        &mut self,
        owner: OwnerId,
        handle: Ole1ServerHandle,
    ) -> Result<(), Ole1Status> {
        let server = self.server_mut(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
        if server.state != Ole1RegistrationState::Active {
            return Err(OLE_ERROR_HANDLE);
        }
        // NTVDM OleBlockServer is idempotent and sets the flag unconditionally.
        server.blocked = true;
        Ok(())
    }

    fn termination_pending(
        &self,
        owner: OwnerId,
        target: Ole1TerminationTarget,
        conversation: Win16ClassicDdeConversationId,
    ) -> Result<&Ole1PendingTermination, Ole1Status> {
        match target {
            Ole1TerminationTarget::Server {
                handle,
                generation,
                endpoint,
                worker_generation,
            } => self
                .server(owner, handle)
                .filter(|record| {
                    record.generation == generation
                        && record.endpoint == endpoint
                        && record.endpoint_worker_generation == worker_generation
                })
                .ok_or(OLE_ERROR_HANDLE)?
                .pending_terminations
                .get(&conversation)
                .ok_or(OLE_ERROR_HANDLE),
            Ole1TerminationTarget::Document {
                handle,
                generation,
                endpoint,
                worker_generation,
            } => self
                .document(owner, handle)
                .filter(|record| {
                    record.generation == generation
                        && record.endpoint == endpoint
                        && record.endpoint_worker_generation == worker_generation
                })
                .ok_or(OLE_ERROR_HANDLE)?
                .pending_terminations
                .get(&conversation)
                .ok_or(OLE_ERROR_HANDLE),
        }
    }

    fn termination_pending_mut(
        &mut self,
        owner: OwnerId,
        target: Ole1TerminationTarget,
        conversation: Win16ClassicDdeConversationId,
    ) -> Result<&mut Ole1PendingTermination, Ole1Status> {
        match target {
            Ole1TerminationTarget::Server {
                handle,
                generation,
                endpoint,
                worker_generation,
            } => self
                .server_mut(owner, handle)
                .filter(|record| {
                    record.generation == generation
                        && record.endpoint == endpoint
                        && record.endpoint_worker_generation == worker_generation
                })
                .ok_or(OLE_ERROR_HANDLE)?
                .pending_terminations
                .get_mut(&conversation)
                .ok_or(OLE_ERROR_HANDLE),
            Ole1TerminationTarget::Document {
                handle,
                generation,
                endpoint,
                worker_generation,
            } => self
                .document_mut(owner, handle)
                .filter(|record| {
                    record.generation == generation
                        && record.endpoint == endpoint
                        && record.endpoint_worker_generation == worker_generation
                })
                .ok_or(OLE_ERROR_HANDLE)?
                .pending_terminations
                .get_mut(&conversation)
                .ok_or(OLE_ERROR_HANDLE),
        }
    }

    /// Update block state after the runtime processes at most one retained
    /// WM_DDE message. The caller computes `has_pending` from this server's
    /// exact queue, not from the process-wide message queue.
    pub(crate) fn unblock_step(
        &mut self,
        owner: OwnerId,
        handle: Ole1ServerHandle,
        has_pending: bool,
    ) -> Result<bool, Ole1Status> {
        let server = self.server_mut(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
        if server.state != Ole1RegistrationState::Active {
            return Err(OLE_ERROR_HANDLE);
        }
        if !has_pending {
            server.blocked = false;
            return Ok(false);
        }
        // The server remains blocked until the final queued message is drained.
        Ok(true)
    }

    pub(crate) fn defer_classic_dde_event(
        &mut self,
        owner: OwnerId,
        event: &Win16HostClassicDdeEvent,
        step: Arc<Win16HostClassicDdeCallbackStep>,
    ) -> Result<(), Ole1Status> {
        if event.owner != owner
            || step.owner != owner
            || step.event != *event
            || step.endpoint != event.endpoint
            || step.worker_generation != event.worker_generation
            || step.event.event_id != event.event_id
            || !matches!(
                event.delivery,
                crate::Win16ClassicDdeDeliveryKind::Synchronous { .. }
            )
        {
            return Err(OLE_ERROR_PROTOCOL);
        }
        let server_handle = self
            .server_for_endpoint(owner, event.endpoint)
            .map(|(handle, _)| handle)
            .or_else(|| {
                self.document_for_endpoint(owner, event.endpoint)
                    .map(|(_, document)| document.server)
            })
            .ok_or(OLE_ERROR_HANDLE)?;
        let server = self
            .server_mut(owner, server_handle)
            .ok_or(OLE_ERROR_HANDLE)?;
        if !server.blocked || server.processing_deferred_message {
            return Err(OLE_ERROR_PROTOCOL);
        }
        if let Some(existing) = server
            .deferred_events
            .iter()
            .chain(server.in_flight_deferred.iter())
            .find(|existing| existing.event.event_id == event.event_id)
        {
            return if existing.event == *event && existing.step.as_ref() == step.as_ref() {
                Ok(())
            } else {
                Err(OLE_ERROR_PROTOCOL)
            };
        }
        server
            .deferred_events
            .try_reserve(1)
            .map_err(|_| OLE_ERROR_MEMORY)?;
        server
            .deferred_events
            .push_back(Ole1DeferredClassicDdeEvent {
                event: event.clone(),
                step,
            });
        Ok(())
    }

    pub(crate) fn has_deferred_classic_dde_event(
        &self,
        owner: OwnerId,
        handle: Ole1ServerHandle,
    ) -> Result<bool, Ole1Status> {
        let server = self.server(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
        Ok(!server.deferred_events.is_empty())
    }

    /// The current OLESVR Unblock adapter implements only the synchronous
    /// INITIATE continuation. Inspect before dequeueing so unsupported
    /// Execute/Terminate/etc. messages remain owned and can be retried after
    /// a later dispatcher revision; never feed them to an INITIATE-only
    /// continuation or discard them as if delivery completed.
    pub(crate) fn deferred_front_is_initiate(
        &self,
        owner: OwnerId,
        handle: Ole1ServerHandle,
    ) -> Result<Option<bool>, Ole1Status> {
        let server = self.server(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
        Ok(server.deferred_events.front().map(|deferred| {
            matches!(
                deferred.event.message,
                crate::Win16ClassicDdeMessage::Initiate { .. }
            )
        }))
    }

    pub(crate) fn begin_unblock_classic_dde_event(
        &mut self,
        owner: OwnerId,
        handle: Ole1ServerHandle,
    ) -> Result<Option<Ole1DeferredClassicDdeEvent>, Ole1Status> {
        let server = self.server_mut(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
        if !server.blocked || server.processing_deferred_message {
            return Err(OLE_ERROR_HANDLE);
        }
        let Some(event) = server.deferred_events.pop_front() else {
            return Ok(None);
        };
        server.processing_deferred_message = true;
        server.in_flight_deferred = Some(event.clone());
        Ok(Some(event))
    }

    pub(crate) fn finish_unblock_classic_dde_event(
        &mut self,
        owner: OwnerId,
        handle: Ole1ServerHandle,
        event_id: crate::Win16ClassicDdeEventId,
    ) -> Result<(), Ole1Status> {
        let server = self.server_mut(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
        if !server.processing_deferred_message
            || server
                .in_flight_deferred
                .as_ref()
                .is_none_or(|event| event.event.event_id != event_id)
        {
            return Err(OLE_ERROR_PROTOCOL);
        }
        server.in_flight_deferred = None;
        server.processing_deferred_message = false;
        Ok(())
    }

    pub(crate) fn restore_unblock_classic_dde_event(
        &mut self,
        owner: OwnerId,
        handle: Ole1ServerHandle,
        event_id: crate::Win16ClassicDdeEventId,
    ) -> Result<(), Ole1Status> {
        let server = self.server_mut(owner, handle).ok_or(OLE_ERROR_HANDLE)?;
        if !server.processing_deferred_message {
            return Err(OLE_ERROR_PROTOCOL);
        }
        let event = server
            .in_flight_deferred
            .take()
            .filter(|event| event.event.event_id == event_id)
            .ok_or(OLE_ERROR_PROTOCOL)?;
        server.processing_deferred_message = false;
        server.deferred_events.push_front(event);
        Ok(())
    }
}
