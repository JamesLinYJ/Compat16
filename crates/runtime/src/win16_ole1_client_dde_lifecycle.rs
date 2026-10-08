use super::transactions::{Win16Ole1AtomIdentity, atom_matches_or_waits};
use super::*;

#[path = "win16_ole1_client_dde_lifecycle_reservations.rs"]
mod reservations;

#[path = "win16_ole1_client_dde_lifecycle_initiate_ack.rs"]
mod initiate_ack;

impl Win16Ole1ClientDdeJournal {
    pub(in crate::win16_runtime) fn endpoint_has_pending_traffic(
        &self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
    ) -> bool {
        let action_matches = |action: &Win16Ole1ClientHostAction| match action {
            Win16Ole1ClientHostAction::RetireEndpoint {
                owner: found,
                endpoint: target,
            }
            | Win16Ole1ClientHostAction::TerminateClientConversation {
                owner: found,
                endpoint: target,
                ..
            }
            | Win16Ole1ClientHostAction::RetireClientConversation {
                owner: found,
                endpoint: target,
                ..
            }
            | Win16Ole1ClientHostAction::PostTransaction {
                owner: found,
                endpoint: target,
                ..
            } => *found == owner && *target == endpoint,
            Win16Ole1ClientHostAction::BindFirstResponder { candidate, .. }
            | Win16Ole1ClientHostAction::BindExtraResponder { candidate, .. }
            | Win16Ole1ClientHostAction::TerminateExtraResponder { candidate, .. }
            | Win16Ole1ClientHostAction::RetireExtraResponder { candidate, .. } => {
                candidate.source_operation.owner == owner && candidate.endpoint == endpoint
            }
            Win16Ole1ClientHostAction::CreateEndpoint { .. }
            | Win16Ole1ClientHostAction::InitiateBroadcast => false,
        };
        if self
            .terminations
            .iter()
            .any(|entry| entry.owner == owner && entry.endpoint == endpoint)
        {
            return true;
        }
        if self
            .pending
            .iter()
            .any(|call| call.owner == owner && call.endpoint == endpoint)
            || self
                .committed_events
                .iter()
                .any(|event| event.owner == owner && event.endpoint == endpoint)
            || self
                .pending_host_actions
                .iter()
                .any(|pending| pending.owner == owner && action_matches(&pending.action))
        {
            return true;
        }
        self.host_operations.iter().any(|entry| {
            entry.host.owner == owner
                && (entry.action.as_ref().is_some_and(action_matches)
                    || self.initiate_attempts.iter().any(|attempt| {
                        attempt.operation == entry.operation
                            && attempt.owner == owner
                            && attempt.endpoint == endpoint
                    }))
        })
    }

    /// Start one private OLE client endpoint for this API operation. The
    /// returned token is owner-bound and never exposed as a guest HWND.
    pub(in crate::win16_runtime) fn prepare_endpoint_call(
        &mut self,
        operation: Win16Ole1OperationId,
        owner: OwnerId,
    ) -> Result<Win16Ole1ClientDdeDisposition, &'static str> {
        if self
            .endpoints
            .iter()
            .any(|endpoint| endpoint.operation == operation)
        {
            return Err("OLE1 client operation already owns a DDE endpoint");
        }
        self.queue_host_action(
            operation,
            Win16Ole1ClientHostAction::CreateEndpoint { owner },
        )?;
        Ok(Win16Ole1ClientDdeDisposition::HostCall {
            operation,
            call: Win16HostClassicDdeCall::CreateEndpoint {
                owner,
                parent: None,
            },
            resume_callback: None,
        })
    }

    /// Retire an endpoint after the client operation has cancelled or
    /// completed all owned conversations. The exact host retirement receipt
    /// is returned because pending events/callbacks/transfers are independent
    /// cleanup evidence and must not be silently discarded.
    pub(in crate::win16_runtime) fn prepare_endpoint_retirement(
        &mut self,
        operation: Win16Ole1OperationId,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
    ) -> Result<Win16Ole1ClientDdeDisposition, &'static str> {
        if !self.endpoints.iter().any(|entry| {
            entry.operation == operation && entry.owner == owner && entry.endpoint == endpoint
        }) {
            return Err("OLE1 client operation does not own this DDE endpoint");
        }
        if self
            .conversations
            .iter()
            .any(|conversation| conversation.owner == owner && conversation.endpoint == endpoint)
            || self
                .pending
                .iter()
                .any(|call| call.owner == owner && call.endpoint == endpoint)
            || self
                .committed_events
                .iter()
                .any(|event| event.owner == owner && event.endpoint == endpoint)
        {
            return Err("OLE1 DDE endpoint still has live conversations or committed transactions");
        }
        self.queue_host_action(
            operation,
            Win16Ole1ClientHostAction::RetireEndpoint { owner, endpoint },
        )?;
        Ok(Win16Ole1ClientDdeDisposition::HostCall {
            operation,
            call: Win16HostClassicDdeCall::RetireEndpoint { owner, endpoint },
            resume_callback: None,
        })
    }

    /// Release is a new public OLE operation, while its private DDE endpoint
    /// remains owned by the create operation. Preserve both exact identities:
    /// the host action belongs to `release_operation`, and the endpoint lookup
    /// must match `endpoint_operation`.
    pub(in crate::win16_runtime) fn prepare_client_endpoint_retirement(
        &mut self,
        release_operation: Win16Ole1OperationId,
        endpoint_operation: Win16Ole1OperationId,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
    ) -> Result<Win16Ole1ClientDdeDisposition, &'static str> {
        if owner.0 == 0
            || self
                .endpoints
                .iter()
                .filter(|entry| {
                    entry.operation == endpoint_operation
                        && entry.owner == owner
                        && entry.endpoint == endpoint
                })
                .count()
                != 1
        {
            return Err("OLE1 release does not identify the exact endpoint creation owner");
        }
        if self
            .conversations
            .iter()
            .any(|entry| entry.owner == owner && entry.endpoint == endpoint)
            || self
                .pending
                .iter()
                .any(|entry| entry.owner == owner && entry.endpoint == endpoint)
            || self
                .committed_events
                .iter()
                .any(|entry| entry.owner == owner && entry.endpoint == endpoint)
        {
            return Err(
                "OLE1 release endpoint still has live conversations or committed transactions",
            );
        }
        self.queue_host_action(
            release_operation,
            Win16Ole1ClientHostAction::RetireEndpoint { owner, endpoint },
        )?;
        Ok(Win16Ole1ClientDdeDisposition::HostCall {
            operation: release_operation,
            call: Win16HostClassicDdeCall::RetireEndpoint { owner, endpoint },
            resume_callback: None,
        })
    }

    /// Begin exact client-side WM_DDE_TERMINATE and retire its conversation
    /// only after the host confirms the matching owner/endpoint/peer/token.
    pub(in crate::win16_runtime) fn prepare_client_conversation_retirement(
        &mut self,
        operation: Win16Ole1OperationId,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        peer: Win16HostClassicDdePeer,
        conversation: Win16ClassicDdeConversationId,
    ) -> Result<Win16Ole1ClientDdeDisposition, &'static str> {
        if owner.0 == 0
            || self
                .conversations
                .iter()
                .filter(|entry| {
                    entry.owner == owner
                        && entry.endpoint == endpoint
                        && entry.peer == peer
                        && entry.id == conversation
                })
                .count()
                != 1
        {
            return Err("OLE1 client conversation retirement has no unique live owner binding");
        }
        if self.pending.iter().any(|entry| {
            entry.owner == owner && entry.endpoint == endpoint && entry.conversation == conversation
        }) || self.committed_events.iter().any(|entry| {
            entry.owner == owner && entry.endpoint == endpoint && entry.conversation == conversation
        }) {
            return Err("OLE1 client conversation still owns a pending call or committed event");
        }
        self.reserve_client_termination(operation, owner, endpoint, peer, conversation)?;
        if let Err(error) = self.queue_host_action(
            operation,
            Win16Ole1ClientHostAction::TerminateClientConversation {
                owner,
                endpoint,
                peer,
                conversation,
            },
        ) {
            self.discard_unposted_client_termination(operation, owner, endpoint, conversation);
            return Err(error);
        }
        Ok(Win16Ole1ClientDdeDisposition::HostCall {
            operation,
            call: Win16HostClassicDdeCall::Post {
                owner,
                endpoint,
                target: peer,
                conversation,
                transaction: None,
                message: Win16ClassicDdeMessage::Terminate,
            },
            resume_callback: None,
        })
    }

    pub(in crate::win16_runtime) fn endpoint_for_operation(
        &self,
        operation: Win16Ole1OperationId,
        owner: OwnerId,
    ) -> Option<Win16HostClassicDdeEndpoint> {
        self.endpoints
            .iter()
            .find(|entry| entry.operation == operation && entry.owner == owner)
            .map(|entry| entry.endpoint)
    }

    /// Complete a reserved INITIATE after the atom sidecar has materialized
    /// and retained both exact WORD references. This does not create atoms.
    pub(in crate::win16_runtime) fn prepare_reserved_initiate_call(
        &mut self,
        operation: Win16Ole1OperationId,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        application_atom: u16,
        topic_atom: u16,
        application_name: &[u8],
        topic_name: &[u8],
        purpose: Win16Ole1InitiatePurpose,
    ) -> Result<Win16Ole1ClientDdeDisposition, &'static str> {
        if self.endpoint_for_operation(operation, owner) != Some(endpoint) {
            return Err("OLE1 INITIATE endpoint is not owned by this client operation");
        }
        self.bind_initiate_attempt_atoms(operation, owner, endpoint, application_atom, topic_atom)?;
        let Some(attempt) = self.initiate_attempts.iter().find(|attempt| {
            attempt.operation == operation
                && attempt.owner == owner
                && attempt.endpoint == endpoint
                && attempt.purpose == purpose
                && attempt.application_name == application_name
                && attempt.topic_name == topic_name
                && attempt.application_atom == Some(application_atom)
                && attempt.topic_atom == Some(topic_atom)
                && attempt.host.is_none()
        }) else {
            return Err("OLE1 INITIATE prepared names or purpose differ from its reserved attempt");
        };
        let _ = attempt;
        match initiate::begin_client_initiate(
            owner,
            endpoint,
            application_atom,
            topic_atom,
            application_name,
            topic_name,
        ) {
            Ok(call) => Ok(Win16Ole1ClientDdeDisposition::HostCall {
                operation,
                call,
                resume_callback: None,
            }),
            Err(error) => {
                self.initiate_attempts
                    .retain(|attempt| attempt.operation != operation || attempt.host.is_some());
                Err(error)
            }
        }
    }

    pub(in crate::win16_runtime) fn bind_initiate_host_operation(
        &mut self,
        operation: Win16Ole1OperationId,
        host: Win16ClassicDdeOperationIdentity,
    ) -> Result<(), &'static str> {
        let Some(index) = self
            .initiate_attempts
            .iter()
            .position(|attempt| attempt.operation == operation && attempt.host.is_none())
        else {
            return Err("OLE1 INITIATE host operation has no exact reserved attempt");
        };
        if self.initiate_attempts[index].owner != host.owner {
            return Err("OLE1 INITIATE host operation belongs to another task");
        }
        self.queue_host_action(operation, Win16Ole1ClientHostAction::InitiateBroadcast)?;
        if let Err(error) = self.bind_host_operation(operation, host) {
            self.pending_host_actions
                .retain(|pending| pending.operation != operation);
            return Err(error);
        }
        self.initiate_attempts[index].host = Some(host);
        Ok(())
    }

    /// Capture one exact synchronous INITIATE ACK. The ACK event may not yet
    /// have a conversation id: the runtime must explicitly bind the selected
    /// peer and atom pair through the host before this journal commits one.
    pub(super) fn observe_initiate_ack(
        &mut self,
        event: &Win16HostClassicDdeEvent,
        causal_parents: &[Win16ClassicDdeOperationIdentity],
    ) -> Result<Win16Ole1InitiateAckDecision, &'static str> {
        initiate_ack::observe(self, event, causal_parents)
    }

    pub(super) fn initiate_attempt_mut(
        &mut self,
        host: Win16ClassicDdeOperationIdentity,
    ) -> Option<&mut Win16Ole1InitiateAttempt> {
        self.initiate_attempts
            .iter_mut()
            .find(|attempt| attempt.host == Some(host))
    }

    pub(super) fn rollback_pending_responder(&mut self, candidate: &Win16Ole1InitiateCandidate) {
        if let Some(attempt) = self.initiate_attempt_mut(candidate.source_operation) {
            if attempt.pending_first_responder.as_ref() == Some(candidate) {
                attempt.pending_first_responder = None;
            }
            attempt
                .pending_extra_responders
                .retain(|pending| pending != candidate);
        }
    }

    pub(super) fn prepare_conversation_receipt(
        candidate: &Win16Ole1InitiateCandidate,
        result: &Win16HostClassicDdeResult,
    ) -> Result<Win16Ole1ClientDdeConversation, RuntimeError> {
        let Win16HostClassicDdeResult::ConversationBound(receipt) = result else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 responder binding did not return a conversation receipt",
            ));
        };
        if receipt.owner != candidate.source_operation.owner
            || receipt.endpoint != candidate.endpoint
            || receipt.peer != candidate.peer
            || receipt.source_operation != candidate.source_operation
            || receipt.initiate_event_id != candidate.event_id
            || receipt.application.as_ref() != Some(&candidate.application)
            || receipt.topic.as_ref() != Some(&candidate.topic)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 responder conversation receipt does not match the exact INITIATE ACK",
            ));
        }
        let application = atom_name(&candidate.application).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 application atom is not a string",
            )
        })?;
        let topic = atom_name(&candidate.topic).ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant, "OLE1 topic atom is not a string")
        })?;
        let application_atom = atom_guest_value(&candidate.application).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 application atom has no materialized guest identity",
            )
        })?;
        let topic_atom = atom_guest_value(&candidate.topic).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 topic atom has no materialized guest identity",
            )
        })?;
        let mut application_name = Vec::new();
        application_name
            .try_reserve_exact(application.len())
            .map_err(|_| {
                RuntimeError::new(Kind::ResourceExhausted, "OLE1 application name cannot grow")
            })?;
        application_name.extend_from_slice(application);
        let mut topic_name = Vec::new();
        topic_name.try_reserve_exact(topic.len()).map_err(|_| {
            RuntimeError::new(Kind::ResourceExhausted, "OLE1 topic name cannot grow")
        })?;
        topic_name.extend_from_slice(topic);
        Ok(Win16Ole1ClientDdeConversation {
            owner: receipt.owner,
            endpoint: receipt.endpoint,
            peer: receipt.peer,
            id: receipt.conversation,
            initiate_event_id: candidate.event_id,
            application_atom,
            topic_atom,
            application: application_name,
            topic: topic_name,
        })
    }

    pub(super) fn reserve_conversation_slot(
        &mut self,
        conversation: &Win16Ole1ClientDdeConversation,
    ) -> Result<(), RuntimeError> {
        if conversation.application.is_empty()
            || conversation.topic.is_empty()
            || conversation.application.contains(&0)
            || conversation.topic.contains(&0)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 DDE conversation receipt has invalid atom names",
            ));
        }
        if self.conversations.iter().any(|current| {
            current.owner == conversation.owner
                && current.endpoint == conversation.endpoint
                && current.id == conversation.id
        }) {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 DDE conversation identity is already bound",
            ));
        }
        self.conversations.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve OLE1 DDE conversation journal",
                error,
            )
        })
    }

    pub(super) fn validate_resume_reply(
        &self,
        candidate: &Win16Ole1InitiateCandidate,
        reply: &Win16HostClassicDdeCallbackReply,
    ) -> Result<(), RuntimeError> {
        if reply.owner != candidate.source_operation.owner
            || reply.endpoint != candidate.endpoint
            || reply.operation_id != candidate.source_operation.id
            || reply.worker_generation != candidate.source_operation.worker_generation
            || reply.callback != candidate.callback
            || reply.frame != candidate.frame
            || reply.causal_parents != candidate.causal_parents
            || reply.event_id != candidate.event_id
            || reply.peer != candidate.peer
            || reply.result != Win16HostClassicDdeCallbackResult::WindowProcedure(0)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "OLE1 responder callback reply changed its exact suspended frame",
            ));
        }
        Ok(())
    }

    pub(super) fn finish_initiate_attempt(
        &mut self,
        host: Win16ClassicDdeOperationIdentity,
    ) -> Result<Option<Win16Ole1InitiateAttempt>, &'static str> {
        let Some(index) = self
            .initiate_attempts
            .iter()
            .position(|attempt| attempt.host == Some(host))
        else {
            return Ok(None);
        };
        Ok(Some(self.initiate_attempts.remove(index)))
    }

    pub(in crate::win16_runtime) fn conversation_atoms(
        &self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        conversation: Win16ClassicDdeConversationId,
    ) -> Option<Win16Ole1ClientDdeConversationAtoms> {
        let current = self.conversations.iter().find(|current| {
            current.owner == owner && current.endpoint == endpoint && current.id == conversation
        })?;
        Some(Win16Ole1ClientDdeConversationAtoms {
            owner: current.owner,
            endpoint: current.endpoint,
            conversation: current.id,
            source_event_id: current.initiate_event_id,
            application_atom: current.application_atom,
            topic_atom: current.topic_atom,
        })
    }

    /// Accept a true `WM_DDE_ACK` to the exact class/topic `WM_DDE_INITIATE`.
    /// The DDE application atom is the OLE class name; the registered
    /// `...\\server` value is deliberately not consulted here.
    pub(super) fn match_initiate_ack<'event>(
        event: &'event Win16HostClassicDdeEvent,
        expected_owner: OwnerId,
        expected_endpoint: Win16HostClassicDdeEndpoint,
        application_atom: u16,
        topic_atom: u16,
    ) -> Win16Ole1InitiateAtomMatch<'event> {
        if application_atom == 0
            || topic_atom == 0
            || event.owner != expected_owner
            || event.endpoint != expected_endpoint
        {
            return Win16Ole1InitiateAtomMatch::NotMatch;
        }
        let Win16ClassicDdeMessage::Ack {
            value:
                Win16ClassicDdeAckValue::InitiateAtoms {
                    application: Some(application),
                    topic: Some(topic),
                },
            ..
        } = &event.message
        else {
            return Win16Ole1InitiateAtomMatch::NotMatch;
        };
        let application_match = atom_matches_or_waits(application, application_atom);
        let topic_match = atom_matches_or_waits(topic, topic_atom);
        if application_match == Win16Ole1AtomIdentity::Mismatch
            || topic_match == Win16Ole1AtomIdentity::Mismatch
        {
            return Win16Ole1InitiateAtomMatch::NotMatch;
        }
        if application_match == Win16Ole1AtomIdentity::Pending
            || topic_match == Win16Ole1AtomIdentity::Pending
        {
            return Win16Ole1InitiateAtomMatch::GuestIdentityPending;
        }
        Win16Ole1InitiateAtomMatch::Matched(Win16Ole1ClientDdeInitiateMatch {
            peer: event.peer,
            application,
            topic,
        })
    }

    pub(super) fn retire_conversation(
        &mut self,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        id: Win16ClassicDdeConversationId,
    ) -> bool {
        let Some(index) = self.conversations.iter().position(|current| {
            current.owner == owner && current.endpoint == endpoint && current.id == id
        }) else {
            return false;
        };
        self.conversations.remove(index);
        self.pending.retain(|call| {
            call.owner != owner || call.endpoint != endpoint || call.conversation != id
        });
        true
    }
}

fn copy_name(name: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(name.len())
        .map_err(|_| "OLE1 INITIATE name storage cannot grow")?;
    copy.extend_from_slice(name);
    Ok(copy)
}

fn atom_name(atom: &Win16ClassicDdeAtom) -> Option<&[u8]> {
    match atom {
        Win16ClassicDdeAtom::Name { name_bytes, .. } => Some(name_bytes),
        Win16ClassicDdeAtom::Integer(_) => None,
    }
}

fn atom_guest_value(atom: &Win16ClassicDdeAtom) -> Option<u16> {
    match atom {
        Win16ClassicDdeAtom::Name {
            guest_value: Some(value),
            ..
        } if *value != 0 => Some(*value),
        _ => None,
    }
}
