use super::*;

impl Win16Ole1ClientDdeJournal {
    pub(in crate::win16_runtime) fn route_host_terminal(
        &mut self,
        host: Win16ClassicDdeOperationIdentity,
        terminal: Win16HostClassicDdeTerminal,
    ) -> Result<Win16Ole1ClientDdeDisposition, RuntimeError> {
        let Some(index) = self
            .host_operations
            .iter()
            .position(|entry| entry.host == host)
        else {
            return Ok(Win16Ole1ClientDdeDisposition::NotOwned);
        };
        let binding_operation = self.host_operations[index].operation;
        let Some(stored_action) = self.host_operations[index].action.as_ref() else {
            return Ok(Win16Ole1ClientDdeDisposition::NotOwned);
        };
        if self.host_action_owner(binding_operation, stored_action) != Some(host.owner) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "classic DDE terminal owner does not match its OLE1 action",
            ));
        }
        let action_operation = match stored_action {
            Win16Ole1ClientHostAction::CreateEndpoint { .. }
            | Win16Ole1ClientHostAction::InitiateBroadcast => binding_operation,
            Win16Ole1ClientHostAction::RetireEndpoint { .. }
            | Win16Ole1ClientHostAction::TerminateClientConversation { .. }
            | Win16Ole1ClientHostAction::RetireClientConversation { .. } => binding_operation,
            Win16Ole1ClientHostAction::PostTransaction { .. } => binding_operation,
            Win16Ole1ClientHostAction::BindFirstResponder { candidate, .. }
            | Win16Ole1ClientHostAction::BindExtraResponder { candidate, .. }
            | Win16Ole1ClientHostAction::TerminateExtraResponder { candidate, .. }
            | Win16Ole1ClientHostAction::RetireExtraResponder { candidate, .. } => {
                candidate.operation
            }
        };
        if binding_operation != action_operation {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "classic DDE action was rebound to another OLE1 operation",
            ));
        }

        if !super::host_data::terminal_identity_matches(host, &terminal) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "classic DDE terminal source-retirement identity does not match its operation",
            ));
        }
        if let Some(cached) = self.host_operations[index].terminal.as_ref() {
            if !copy::terminal_matches(cached, &terminal) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "classic DDE operation was replayed with a different terminal result",
                ));
            }
        } else {
            self.host_operations[index].terminal = Some(terminal);
        }
        let stored_action = self.host_operations[index].action.as_ref().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 client host action disappeared while caching its terminal",
            )
        })?;
        let action = copy::clone_action(stored_action)?;
        let stored_terminal = self.host_operations[index]
            .terminal
            .as_ref()
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "OLE1 client terminal disappeared while preparing its commit",
                )
            })?;
        let terminal = copy::clone_terminal(stored_terminal)?;
        let result = match terminal {
            Win16HostClassicDdeTerminal::Complete {
                result,
                source_retired,
            } => {
                if source_retired.operation != host {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "classic DDE completion source-retirement identity does not match its operation",
                    ));
                }
                result
            }
            Win16HostClassicDdeTerminal::StartedFailure(failure) => {
                if failure.operation != host || failure.source_retired.operation != host {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "classic DDE failure source-retirement identity does not match its operation",
                    ));
                }
                if let Some(Win16Ole1ClientHostAction::PostTransaction { call, .. }) =
                    self.host_operations[index].action.as_ref()
                {
                    self.cancel_call(*call)
                        .map_err(|message| RuntimeError::new(Kind::InternalInvariant, message))?;
                }
                self.host_operations.remove(index);
                return Err(super::copy::shared_runtime_error(std::sync::Arc::clone(
                    &failure.cause,
                )));
            }
        };

        let routed = match action {
            Win16Ole1ClientHostAction::CreateEndpoint { owner } => {
                let Win16HostClassicDdeResult::Endpoint(endpoint) = result else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 client endpoint creation did not return an endpoint token",
                    ));
                };
                if self
                    .endpoints
                    .iter()
                    .any(|current| current.owner == owner && current.endpoint == endpoint)
                {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "host reused a live OLE1 client endpoint identity",
                    ));
                }
                self.endpoints.try_reserve(1).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve OLE1 client endpoint journal",
                        error,
                    )
                })?;
                self.endpoints.push(Win16Ole1ClientDdeEndpoint {
                    operation: binding_operation,
                    owner,
                    endpoint,
                });
                Ok(Win16Ole1ClientDdeDisposition::EndpointCreated {
                    operation: binding_operation,
                    owner,
                    endpoint,
                })
            }
            Win16Ole1ClientHostAction::RetireEndpoint { owner, endpoint } => {
                let Win16HostClassicDdeResult::Retired(receipt) = result else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 client endpoint retirement did not return a retirement receipt",
                    ));
                };
                if receipt.owner != owner
                    || receipt.endpoint != endpoint
                    || receipt.worker_generation != host.worker_generation
                    || !receipt.retired
                {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 client endpoint retirement receipt is not exact",
                    ));
                }
                // Release has a different public operation from the Create
                // operation recorded for this endpoint. Both callers reserve
                // its unique owner/endpoint before dispatch; retain the Create
                // identity and consume that exact endpoint on the receipt.
                if self
                    .endpoints
                    .iter()
                    .filter(|entry| entry.owner == owner && entry.endpoint == endpoint)
                    .count()
                    != 1
                {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "retired OLE1 endpoint has no unique exact creation identity",
                    ));
                }
                let Some(index) = self
                    .endpoints
                    .iter()
                    .position(|entry| entry.owner == owner && entry.endpoint == endpoint)
                else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "retired OLE1 endpoint is absent from its owning operation journal",
                    ));
                };
                self.endpoints.remove(index);
                Ok(Win16Ole1ClientDdeDisposition::EndpointRetired {
                    operation: binding_operation,
                    receipt,
                })
            }
            Win16Ole1ClientHostAction::TerminateClientConversation {
                owner,
                endpoint,
                peer,
                conversation,
            } => {
                let Win16HostClassicDdeResult::Posted(receipt) = result else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "client DDE TERMINATE did not return its exact post receipt",
                    ));
                };
                if receipt.owner != owner
                    || receipt.endpoint != endpoint
                    || receipt.peer != peer
                    || receipt.conversation != Some(conversation)
                    || receipt.message != crate::WM_DDE_TERMINATE
                {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "client DDE TERMINATE receipt changed its conversation identity",
                    ));
                }
                self.completed_client_termination_post(
                    binding_operation,
                    owner,
                    endpoint,
                    peer,
                    conversation,
                    receipt.queued,
                )
            }
            Win16Ole1ClientHostAction::RetireClientConversation {
                owner,
                endpoint,
                peer,
                conversation,
                terminate_queued,
            } => {
                let expected = Win16HostClassicDdeResult::ConversationRetired {
                    owner,
                    endpoint,
                    conversation,
                    peer,
                };
                if result != expected {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "client DDE conversation retirement lacks its exact host receipt",
                    ));
                }
                if !self.retire_conversation(owner, endpoint, conversation) {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "retired client DDE conversation was absent from its journal",
                    ));
                }
                self.finish_client_termination(
                    binding_operation,
                    owner,
                    endpoint,
                    peer,
                    conversation,
                )?;
                Ok(Win16Ole1ClientDdeDisposition::ConversationRetired {
                    operation: binding_operation,
                    owner,
                    endpoint,
                    peer,
                    conversation,
                    terminate_queued,
                })
            }
            Win16Ole1ClientHostAction::InitiateBroadcast => {
                let Win16HostClassicDdeResult::Sent(receipt) = result else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 INITIATE host call did not return a send receipt",
                    ));
                };
                let Some((attempt_owner, attempt_endpoint)) = self
                    .initiate_attempts
                    .iter()
                    .find(|attempt| attempt.host == Some(host))
                    .map(|attempt| (attempt.owner, attempt.endpoint))
                else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 INITIATE terminal lost its exact attempt state",
                    ));
                };
                if receipt.owner != attempt_owner
                    || receipt.endpoint != attempt_endpoint
                    || receipt.target != Win16HostClassicDdeTarget::BroadcastInitiate
                    || receipt.conversation.is_some()
                    || receipt.message != crate::WM_DDE_INITIATE
                {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 INITIATE send receipt does not match the broadcast request",
                    ));
                }
                let Some(attempt_state) = self
                    .finish_initiate_attempt(host)
                    .map_err(|message| RuntimeError::new(Kind::InternalInvariant, message))?
                else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "OLE1 INITIATE attempt disappeared before receipt commit",
                    ));
                };
                Ok(Win16Ole1ClientDdeDisposition::InitiateCompleted {
                    operation: binding_operation,
                    purpose: attempt_state.purpose,
                    responder: attempt_state.first_responder,
                })
            }
            Win16Ole1ClientHostAction::BindFirstResponder {
                candidate,
                resume_callback,
            } => {
                self.validate_resume_reply(&candidate, &resume_callback)?;
                let conversation = Self::prepare_conversation_receipt(&candidate, &result)?;
                self.reserve_conversation_slot(&conversation)?;
                let Some(attempt_index) = self.initiate_attempts.iter().position(|attempt| {
                    attempt.host == Some(candidate.source_operation)
                        && attempt.first_responder.is_none()
                        && attempt.pending_first_responder.as_ref() == Some(&candidate)
                }) else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "first OLE1 INITIATE responder does not match the pending candidate",
                    ));
                };
                let responder = candidate.responder_from_receipt(&result)?;
                self.conversations.push(conversation);
                let attempt = &mut self.initiate_attempts[attempt_index];
                attempt.first_responder = Some(responder);
                attempt.pending_first_responder = None;
                Ok(Win16Ole1ClientDdeDisposition::ResumeCallback(
                    resume_callback,
                ))
            }
            Win16Ole1ClientHostAction::BindExtraResponder {
                candidate,
                resume_callback,
            } => {
                self.validate_resume_reply(&candidate, &resume_callback)?;
                let Some(attempt_index) = self.initiate_attempts.iter().position(|attempt| {
                    attempt.host == Some(candidate.source_operation)
                        && !attempt
                            .extra_responders
                            .iter()
                            .any(|responder| responder.peer == candidate.peer)
                        && attempt
                            .pending_extra_responders
                            .iter()
                            .any(|pending| pending == &candidate)
                }) else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "extra OLE1 responder does not match a unique pending candidate",
                    ));
                };
                let conversation = Self::prepare_conversation_receipt(&candidate, &result)?;
                self.reserve_conversation_slot(&conversation)?;
                self.initiate_attempts[attempt_index]
                    .extra_responders
                    .try_reserve(1)
                    .map_err(|error| {
                        RuntimeError::with_source(
                            Kind::ResourceExhausted,
                            "reserve OLE1 extra responder journal",
                            error,
                        )
                    })?;
                self.pending_host_actions.try_reserve(1).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve OLE1 responder follow-up journal",
                        error,
                    )
                })?;
                let responder = candidate.responder_from_receipt(&result)?;
                let follow_up_candidate = copy::clone_candidate(&candidate)?;
                let follow_up_reply = copy::clone_callback_reply(&resume_callback)?;
                let follow_up = Win16Ole1ClientHostAction::TerminateExtraResponder {
                    candidate: follow_up_candidate,
                    conversation: responder.conversation,
                    resume_callback: follow_up_reply,
                };
                self.conversations.push(conversation);
                let attempt = &mut self.initiate_attempts[attempt_index];
                // Keep the exact callback identity parked through the
                // TERMINATE and conversation-retirement host operations.
                // The peer becomes a duplicate only after that sequence has
                // committed and its original callback may be resumed.
                attempt.extra_responders.push(responder);
                self.pending_host_actions.push(Win16Ole1PendingHostAction {
                    operation: binding_operation,
                    owner: candidate.source_operation.owner,
                    action: follow_up,
                });
                Ok(Win16Ole1ClientDdeDisposition::HostCall {
                    operation: binding_operation,
                    call: Win16HostClassicDdeCall::Post {
                        owner: candidate.source_operation.owner,
                        endpoint: candidate.endpoint,
                        target: candidate.peer,
                        conversation: responder.conversation,
                        transaction: None,
                        message: Win16ClassicDdeMessage::Terminate,
                    },
                    resume_callback: Some(resume_callback),
                })
            }
            Win16Ole1ClientHostAction::TerminateExtraResponder {
                candidate,
                conversation,
                resume_callback,
            } => {
                let Win16HostClassicDdeResult::Posted(receipt) = result else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "extra OLE1 responder TERMINATE did not return a post receipt",
                    ));
                };
                if receipt.owner != candidate.source_operation.owner
                    || receipt.endpoint != candidate.endpoint
                    || receipt.peer != candidate.peer
                    || receipt.conversation != Some(conversation)
                    || receipt.message != crate::WM_DDE_TERMINATE
                    || !receipt.queued
                {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "extra OLE1 responder TERMINATE receipt is not exact",
                    ));
                }
                let retire_candidate = copy::clone_candidate(&candidate)?;
                let retire_reply = copy::clone_callback_reply(&resume_callback)?;
                self.queue_host_action(
                    binding_operation,
                    Win16Ole1ClientHostAction::RetireExtraResponder {
                        candidate: retire_candidate,
                        conversation,
                        resume_callback: retire_reply,
                    },
                )
                .map_err(|message| RuntimeError::new(Kind::ResourceExhausted, message))?;
                Ok(Win16Ole1ClientDdeDisposition::HostCall {
                    operation: binding_operation,
                    call: Win16HostClassicDdeCall::RetireConversation {
                        owner: candidate.source_operation.owner,
                        endpoint: candidate.endpoint,
                        conversation,
                        peer: candidate.peer,
                    },
                    resume_callback: Some(resume_callback),
                })
            }
            Win16Ole1ClientHostAction::RetireExtraResponder {
                candidate,
                conversation,
                resume_callback,
            } => {
                let expected = Win16HostClassicDdeResult::ConversationRetired {
                    owner: candidate.source_operation.owner,
                    endpoint: candidate.endpoint,
                    conversation,
                    peer: candidate.peer,
                };
                if result != expected {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "extra OLE1 responder conversation retirement was not confirmed",
                    ));
                }
                self.validate_resume_reply(&candidate, &resume_callback)?;
                if !self.conversations.iter().any(|entry| {
                    entry.owner == candidate.source_operation.owner
                        && entry.endpoint == candidate.endpoint
                        && entry.peer == candidate.peer
                        && entry.id == conversation
                }) {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "retired extra OLE1 responder was absent from the client journal",
                    ));
                }
                let Some(attempt) = self.initiate_attempt_mut(candidate.source_operation) else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "retired extra OLE1 responder lost its INITIATE attempt",
                    ));
                };
                let Some(pending_index) = attempt
                    .pending_extra_responders
                    .iter()
                    .position(|pending| pending == &candidate)
                else {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "retired extra OLE1 responder lost its pending callback identity",
                    ));
                };
                attempt.pending_extra_responders.remove(pending_index);
                self.retire_conversation(
                    candidate.source_operation.owner,
                    candidate.endpoint,
                    conversation,
                );
                Ok(Win16Ole1ClientDdeDisposition::ResumeCallback(
                    resume_callback,
                ))
            }
            action @ Win16Ole1ClientHostAction::PostTransaction { .. } => {
                super::host_data::route_data_terminal(self, binding_operation, action, result)
            }
        };
        if routed.is_ok() {
            self.host_operations.remove(index);
        }
        routed
    }
}
