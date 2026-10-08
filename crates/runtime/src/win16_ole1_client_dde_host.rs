use super::*;

#[path = "win16_ole1_client_dde_host_terminal.rs"]
mod terminal;

impl Win16Ole1ClientDdeJournal {
    pub(in crate::win16_runtime) fn route_callback_step(
        &mut self,
        step: &Win16HostClassicDdeCallbackStep,
    ) -> Result<Win16Ole1ClientDdeDisposition, RuntimeError> {
        let Win16ClassicDdeDeliveryKind::Synchronous {
            operation_id,
            callback,
            frame,
        } = step.event.delivery
        else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "classic DDE callback step does not contain a synchronous delivery",
            ));
        };
        if step.event.owner != step.owner
            || step.event.endpoint != step.endpoint
            || step.event.worker_generation != step.worker_generation
            || operation_id != step.operation_id
            || callback != step.callback
            || frame != step.frame
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "classic DDE callback step and embedded event identity differ",
            ));
        }
        if step
            .causal_parents
            .iter()
            .enumerate()
            .any(|(index, parent)| {
                parent.owner != step.owner
                    || parent.worker_generation != step.worker_generation
                    || parent.id == step.operation_id
                    || step.causal_parents[..index]
                        .iter()
                        .any(|previous| previous.id == parent.id)
            })
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "classic DDE callback causal chain crossed owner/generation or repeated the active operation",
            ));
        }

        match step.source {
            Win16ClassicDdeCallbackSource::ParkedUserWait => {
                // This callback belongs to the parked USER wait lifecycle,
                // which is not represented by the OLE1 host-operation journal.
                Ok(Win16Ole1ClientDdeDisposition::NotOwned)
            }
            Win16ClassicDdeCallbackSource::HostOperation => {
                let host = Win16ClassicDdeOperationIdentity {
                    owner: step.owner,
                    id: step.operation_id,
                    worker_generation: step.worker_generation,
                };
                let Some(operation) = self.client_operation_for_host(host) else {
                    return Ok(Win16Ole1ClientDdeDisposition::NotOwned);
                };
                match self
                    .observe_initiate_ack(&step.event, &step.causal_parents)
                    .map_err(|message| RuntimeError::new(Kind::ResourceExhausted, message))?
                {
                    Win16Ole1InitiateAckDecision::FirstResponder(candidate) => {
                        let call_candidate = match copy::clone_candidate(&candidate) {
                            Ok(candidate) => candidate,
                            Err(error) => {
                                self.rollback_pending_responder(&candidate);
                                return Err(error);
                            }
                        };
                        let call = match initiate::bind_initiate_responder(
                            operation,
                            step,
                            call_candidate,
                        ) {
                            Ok(call) => call,
                            Err(error) => {
                                self.rollback_pending_responder(&candidate);
                                return Err(error);
                            }
                        };
                        let action_candidate = match copy::clone_candidate(&candidate) {
                            Ok(candidate) => candidate,
                            Err(error) => {
                                self.rollback_pending_responder(&candidate);
                                return Err(error);
                            }
                        };
                        if let Err(message) =
                            self.queue_bind_action(operation, action_candidate, true)
                        {
                            self.rollback_pending_responder(&candidate);
                            return Err(RuntimeError::new(Kind::ResourceExhausted, message));
                        }
                        Ok(call)
                    }
                    Win16Ole1InitiateAckDecision::ExtraResponder(candidate) => {
                        let call_candidate = match copy::clone_candidate(&candidate) {
                            Ok(candidate) => candidate,
                            Err(error) => {
                                self.rollback_pending_responder(&candidate);
                                return Err(error);
                            }
                        };
                        let call = match initiate::bind_initiate_responder(
                            operation,
                            step,
                            call_candidate,
                        ) {
                            Ok(call) => call,
                            Err(error) => {
                                self.rollback_pending_responder(&candidate);
                                return Err(error);
                            }
                        };
                        let action_candidate = match copy::clone_candidate(&candidate) {
                            Ok(candidate) => candidate,
                            Err(error) => {
                                self.rollback_pending_responder(&candidate);
                                return Err(error);
                            }
                        };
                        if let Err(message) =
                            self.queue_bind_action(operation, action_candidate, false)
                        {
                            self.rollback_pending_responder(&candidate);
                            return Err(RuntimeError::new(Kind::ResourceExhausted, message));
                        }
                        Ok(call)
                    }
                    Win16Ole1InitiateAckDecision::BindingInProgress => {
                        Ok(Win16Ole1ClientDdeDisposition::Deferred)
                    }
                    Win16Ole1InitiateAckDecision::AtomIdentityPending => {
                        Ok(Win16Ole1ClientDdeDisposition::Deferred)
                    }
                    Win16Ole1InitiateAckDecision::DuplicateResponder => {
                        Ok(Win16Ole1ClientDdeDisposition::CallbackReply(
                            Win16HostClassicDdeCallbackResult::WindowProcedure(0),
                        ))
                    }
                    Win16Ole1InitiateAckDecision::NotOwned => {
                        Ok(Win16Ole1ClientDdeDisposition::NotOwned)
                    }
                }
            }
        }
    }

    /// Bind one returned host operation incarnation to its owning public
    /// client operation. A single client API may create several sequential
    /// host operations; each terminal must consume its own binding first.
    pub(in crate::win16_runtime) fn bind_host_operation(
        &mut self,
        operation: Win16Ole1OperationId,
        host: Win16ClassicDdeOperationIdentity,
    ) -> Result<(), &'static str> {
        if self.host_operations.iter().any(|entry| entry.host == host) {
            return Err("classic DDE host operation is already bound to an OLE1 client operation");
        }
        self.host_operations
            .try_reserve(1)
            .map_err(|_| "OLE1 client host-operation table cannot grow")?;
        let pending_action_index = self
            .pending_host_actions
            .iter()
            .position(|pending| pending.operation == operation);
        let action = if let Some(index) = pending_action_index {
            let pending = &self.pending_host_actions[index];
            let Some(expected_owner) = self.host_action_owner(operation, &pending.action) else {
                return Err("OLE1 client host action has no exact owner identity");
            };
            if host.owner != expected_owner {
                return Err("classic DDE host operation owner does not match its OLE1 action");
            }
            Some(self.pending_host_actions.remove(index).action)
        } else {
            None
        };
        self.host_operations.push(Win16Ole1ClientHostOperation {
            operation,
            host,
            action,
            terminal: None,
        });
        Ok(())
    }

    pub(super) fn host_action_owner(
        &self,
        operation: Win16Ole1OperationId,
        action: &Win16Ole1ClientHostAction,
    ) -> Option<OwnerId> {
        match action {
            Win16Ole1ClientHostAction::CreateEndpoint { owner }
            | Win16Ole1ClientHostAction::RetireEndpoint { owner, .. } => Some(*owner),
            Win16Ole1ClientHostAction::TerminateClientConversation { owner, .. }
            | Win16Ole1ClientHostAction::RetireClientConversation { owner, .. } => Some(*owner),
            Win16Ole1ClientHostAction::PostTransaction { owner, .. } => Some(*owner),
            Win16Ole1ClientHostAction::InitiateBroadcast => self
                .initiate_attempts
                .iter()
                .find(|attempt| attempt.operation == operation)
                .map(|attempt| attempt.owner),
            Win16Ole1ClientHostAction::BindFirstResponder { candidate, .. }
            | Win16Ole1ClientHostAction::BindExtraResponder { candidate, .. }
            | Win16Ole1ClientHostAction::TerminateExtraResponder { candidate, .. }
            | Win16Ole1ClientHostAction::RetireExtraResponder { candidate, .. } => {
                (candidate.operation == operation).then_some(candidate.source_operation.owner)
            }
        }
    }

    pub(super) fn queue_host_action(
        &mut self,
        operation: Win16Ole1OperationId,
        action: Win16Ole1ClientHostAction,
    ) -> Result<(), &'static str> {
        let owner = self
            .host_action_owner(operation, &action)
            .ok_or("OLE1 client host action has no exact owner identity")?;
        if owner.0 == 0 {
            return Err("OLE1 client host action has an invalid owner identity");
        }
        self.pending_host_actions
            .try_reserve(1)
            .map_err(|_| "OLE1 client host-action table cannot grow")?;
        self.pending_host_actions.push(Win16Ole1PendingHostAction {
            operation,
            owner,
            action,
        });
        Ok(())
    }

    fn queue_bind_action(
        &mut self,
        operation: Win16Ole1OperationId,
        candidate: Win16Ole1InitiateCandidate,
        first: bool,
    ) -> Result<(), &'static str> {
        let reply = candidate.callback_reply()?;
        self.queue_host_action(
            operation,
            if first {
                Win16Ole1ClientHostAction::BindFirstResponder {
                    candidate,
                    resume_callback: reply,
                }
            } else {
                Win16Ole1ClientHostAction::BindExtraResponder {
                    candidate,
                    resume_callback: reply,
                }
            },
        )
    }

    pub(in crate::win16_runtime) fn client_operation_for_host(
        &self,
        host: Win16ClassicDdeOperationIdentity,
    ) -> Option<Win16Ole1OperationId> {
        self.host_operations
            .iter()
            .find(|entry| entry.host == host)
            .map(|entry| entry.operation)
    }
}

impl Win16Ole1InitiateCandidate {
    pub(super) fn callback_reply(&self) -> Result<Win16HostClassicDdeCallbackReply, &'static str> {
        let mut causal_parents = Vec::new();
        causal_parents
            .try_reserve_exact(self.causal_parents.len())
            .map_err(|_| "OLE1 DDE callback reply causal chain cannot grow")?;
        causal_parents.extend_from_slice(&self.causal_parents);
        Ok(Win16HostClassicDdeCallbackReply {
            owner: self.source_operation.owner,
            endpoint: self.endpoint,
            operation_id: self.source_operation.id,
            worker_generation: self.source_operation.worker_generation,
            callback: self.callback,
            frame: self.frame,
            event_id: self.event_id,
            peer: self.peer,
            causal_parents,
            result: Win16HostClassicDdeCallbackResult::WindowProcedure(0),
        })
    }

    fn responder_from_receipt(
        &self,
        result: &Win16HostClassicDdeResult,
    ) -> Result<Win16Ole1InitiateResponder, RuntimeError> {
        let Win16HostClassicDdeResult::ConversationBound(receipt) = result else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 responder has no conversation-binding receipt",
            ));
        };
        Ok(Win16Ole1InitiateResponder {
            peer: receipt.peer,
            conversation: receipt.conversation,
        })
    }
}
