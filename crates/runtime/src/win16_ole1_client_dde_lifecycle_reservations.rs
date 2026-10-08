use super::*;

impl Win16Ole1ClientDdeJournal {
    /// Reserve the exact logical INITIATE before task-local GlobalAddAtom
    /// creates the references that will be serialized into the request.
    pub(in crate::win16_runtime) fn reserve_unmaterialized_initiate_attempt(
        &mut self,
        operation: Win16Ole1OperationId,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        application_name: &[u8],
        topic_name: &[u8],
        purpose: Win16Ole1InitiatePurpose,
    ) -> Result<(), &'static str> {
        if owner.0 == 0
            || endpoint.0 == 0
            || application_name.is_empty()
            || topic_name.is_empty()
            || application_name.contains(&0)
            || topic_name.contains(&0)
        {
            return Err("OLE1 INITIATE reservation has an invalid owner, endpoint, or name");
        }
        if self.endpoint_for_operation(operation, owner) != Some(endpoint) {
            return Err("OLE1 INITIATE reservation endpoint is not owned by this operation");
        }
        if let Some(existing) = self
            .initiate_attempts
            .iter()
            .find(|attempt| attempt.operation == operation && attempt.host.is_none())
        {
            if existing.owner == owner
                && existing.endpoint == endpoint
                && existing.purpose == purpose
                && existing.application_name == application_name
                && existing.topic_name == topic_name
                && existing.application_atom.is_none()
                && existing.topic_atom.is_none()
            {
                return Ok(());
            }
            return Err("OLE1 client operation already has a different unbound INITIATE attempt");
        }
        self.initiate_attempts
            .try_reserve(1)
            .map_err(|_| "OLE1 INITIATE attempt table cannot grow")?;
        self.initiate_attempts.push(Win16Ole1InitiateAttempt {
            operation,
            host: None,
            owner,
            endpoint,
            application_atom: None,
            topic_atom: None,
            application_name: copy_name(application_name)?,
            topic_name: copy_name(topic_name)?,
            purpose,
            first_responder: None,
            pending_first_responder: None,
            extra_responders: Vec::new(),
            pending_extra_responders: Vec::new(),
        });
        Ok(())
    }

    pub(in crate::win16_runtime) fn discard_unhosted_initiate_attempt(
        &mut self,
        operation: Win16Ole1OperationId,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
    ) -> Result<(), &'static str> {
        if let Some(attempt) = self
            .initiate_attempts
            .iter()
            .find(|attempt| attempt.operation == operation)
        {
            if attempt.owner != owner
                || attempt.endpoint != endpoint
                || attempt.host.is_some()
                || attempt.first_responder.is_some()
                || attempt.pending_first_responder.is_some()
                || !attempt.extra_responders.is_empty()
                || !attempt.pending_extra_responders.is_empty()
            {
                return Err("cannot discard a hosted or responder-bearing OLE1 INITIATE attempt");
            }
        }
        self.initiate_attempts
            .retain(|attempt| attempt.operation != operation);
        Ok(())
    }

    /// Bind actual atom WORDs only after the classic-DDE sidecar has retained
    /// their exact owner/endpoint/operation references.
    pub(in crate::win16_runtime) fn bind_initiate_attempt_atoms(
        &mut self,
        operation: Win16Ole1OperationId,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        application_atom: u16,
        topic_atom: u16,
    ) -> Result<(), &'static str> {
        if application_atom == 0 || topic_atom == 0 {
            return Err("OLE1 INITIATE atom binding contains a null WORD");
        }
        let Some(attempt) = self.initiate_attempts.iter_mut().find(|attempt| {
            attempt.operation == operation
                && attempt.host.is_none()
                && attempt.owner == owner
                && attempt.endpoint == endpoint
        }) else {
            return Err("OLE1 INITIATE atom binding has no exact unmaterialized attempt");
        };
        if attempt.application_atom.is_some() || attempt.topic_atom.is_some() {
            return Err("OLE1 INITIATE atom references were already bound");
        }
        attempt.application_atom = Some(application_atom);
        attempt.topic_atom = Some(topic_atom);
        Ok(())
    }
}
