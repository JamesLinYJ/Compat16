use super::*;

impl Win16State {
    pub(in crate::win16_runtime) fn prepare_ole1_client_dde_conversation_retirement(
        &mut self,
        operation: Win16Ole1OperationId,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        peer: Win16HostClassicDdePeer,
        conversation: Win16ClassicDdeConversationId,
    ) -> Result<Win16Ole1ClientDdeDisposition, RuntimeError> {
        self.ole1_client_documents
            .client_dde
            .prepare_client_conversation_retirement(operation, owner, endpoint, peer, conversation)
            .map_err(|message| RuntimeError::new(Kind::InvalidInput, message))
    }

    pub(in crate::win16_runtime) fn advance_ole1_client_dde_sequence(
        &mut self,
        owner: OwnerId,
        operation: Win16Ole1OperationId,
        disposition: Win16Ole1ClientDdeDisposition,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<Win16Ole1ClientDdeDisposition>, RuntimeError> {
        super::termination::note_conversation_retirement(self, owner, &disposition);
        if let Some(next) = super::super::dde_object_method::advance_sequence(
            self,
            owner,
            operation,
            disposition.clone(),
            cpu,
            dos,
            memory,
            host,
        )? {
            return Ok(Some(next));
        }
        super::super::creation_dde::advance_sequence(
            self,
            owner,
            operation,
            disposition,
            cpu,
            dos,
            memory,
            host,
        )
    }

    pub(in crate::win16_runtime) fn process_ole1_client_dde_committed_event(
        &mut self,
        event: Win16HostClassicDdeEvent,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<(Win16Ole1OperationId, Win16Ole1ClientDdeDisposition)>, RuntimeError> {
        if let Some(termination) = super::termination::process_committed_event(self, &event)? {
            return Ok(Some(termination));
        }
        if let Some(method) =
            super::super::dde_object_method::process_committed_event(self, event.clone())?
        {
            return Ok(Some(method));
        }
        super::super::creation_dde::process_committed_event(self, event, cpu, dos, memory, host)
    }

    pub(in crate::win16_runtime) fn advance_ole1_client_dde_event_ack(
        &mut self,
        owner: OwnerId,
        operation: Win16Ole1OperationId,
        event_id: crate::Win16ClassicDdeEventId,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<Win16Ole1ClientDdeDisposition>, RuntimeError> {
        if let Some(termination) = self
            .ole1_client_documents
            .client_dde
            .acknowledge_client_termination(owner, operation, event_id)?
        {
            return Ok(Some(termination));
        }
        if let Some(method) = super::super::dde_object_method::advance_event_ack(
            self, owner, operation, event_id, cpu, host,
        )? {
            return Ok(Some(method));
        }
        super::super::creation_dde::advance_event_ack(
            self, owner, operation, event_id, cpu, dos, memory, host,
        )
    }
}

impl Win16State {
    /// Exact classic-DDE shutdown inventory for one Win16 task owner. Items
    /// that cannot be proven to belong to this owner are surfaced as an
    /// invariant error instead of being treated as drained or charged to an
    /// unrelated owner.
    pub(in crate::win16_runtime) fn ole1_client_dde_owner_pending(
        &self,
        owner: OwnerId,
    ) -> Result<usize, RuntimeError> {
        owner_inventory::query(self, owner)
    }

    pub(in crate::win16_runtime) fn route_ole1_client_dde_callback_step(
        &mut self,
        step: &Win16HostClassicDdeCallbackStep,
    ) -> Result<Win16Ole1ClientDdeDisposition, RuntimeError> {
        self.ole1_client_documents
            .client_dde
            .route_callback_step(step)
    }

    pub(in crate::win16_runtime) fn bind_ole1_client_dde_host_operation(
        &mut self,
        operation: Win16Ole1OperationId,
        host: Win16ClassicDdeOperationIdentity,
    ) -> Result<(), &'static str> {
        self.ole1_client_documents
            .client_dde
            .bind_host_operation(operation, host)
    }

    pub(in crate::win16_runtime) fn bind_ole1_client_dde_initiate_operation(
        &mut self,
        operation: Win16Ole1OperationId,
        host: Win16ClassicDdeOperationIdentity,
    ) -> Result<(), &'static str> {
        self.ole1_client_documents
            .client_dde
            .bind_initiate_host_operation(operation, host)
    }

    pub(in crate::win16_runtime) fn route_ole1_client_dde_host_terminal(
        &mut self,
        host: Win16ClassicDdeOperationIdentity,
        terminal: Win16HostClassicDdeTerminal,
    ) -> Result<Win16Ole1ClientDdeDisposition, RuntimeError> {
        self.ole1_client_documents
            .client_dde
            .route_host_terminal(host, terminal)
    }

    pub(in crate::win16_runtime) fn commit_ole1_client_dde_event(
        &mut self,
        event: Win16HostClassicDdeEvent,
    ) -> Result<Win16Ole1ClientDdeEventCommit, RuntimeError> {
        self.ole1_client_documents
            .client_dde
            .commit_queued_event(event)
    }

    pub(in crate::win16_runtime) fn committed_ole1_client_dde_event(
        &self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        event_id: crate::Win16ClassicDdeEventId,
    ) -> Option<&Win16Ole1ClientDdeCommittedEvent> {
        self.ole1_client_documents
            .client_dde
            .committed_event(owner, endpoint, event_id)
    }

    pub(in crate::win16_runtime) fn ole1_client_dde_conversation_atoms(
        &self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        conversation: Win16ClassicDdeConversationId,
    ) -> Option<Win16Ole1ClientDdeConversationAtoms> {
        self.ole1_client_documents
            .client_dde
            .conversation_atoms(owner, endpoint, conversation)
    }

    pub(in crate::win16_runtime) fn acknowledge_ole1_client_dde_event(
        &mut self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        event_id: crate::Win16ClassicDdeEventId,
    ) -> Result<(), &'static str> {
        self.ole1_client_documents
            .client_dde
            .acknowledge_committed_event(owner, endpoint, event_id)
    }
}
