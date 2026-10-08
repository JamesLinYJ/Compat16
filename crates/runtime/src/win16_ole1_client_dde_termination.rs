//! Exact client WM_DDE_TERMINATE handshake and delivery acknowledgement.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ClientTermination {
    pub(super) operation: Win16Ole1OperationId,
    pub(super) owner: OwnerId,
    pub(super) endpoint: Win16HostClassicDdeEndpoint,
    pub(super) peer: Win16HostClassicDdePeer,
    pub(super) conversation: Win16ClassicDdeConversationId,
    event_id: Option<crate::Win16ClassicDdeEventId>,
    event_acknowledged: bool,
    reply_required: bool,
    post_completed: bool,
    terminate_queued: bool,
    retirement_prepared: bool,
}

impl Win16Ole1ClientDdeJournal {
    pub(super) fn reserve_client_termination(
        &mut self,
        operation: Win16Ole1OperationId,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        peer: Win16HostClassicDdePeer,
        conversation: Win16ClassicDdeConversationId,
    ) -> Result<(), &'static str> {
        if self.terminations.iter().any(|entry| {
            entry.owner == owner && entry.endpoint == endpoint && entry.conversation == conversation
        }) {
            return Err("exact client DDE conversation already has a termination handshake");
        }
        self.terminations
            .try_reserve(1)
            .map_err(|_| "client DDE termination handshake cannot grow")?;
        self.terminations.push(ClientTermination {
            operation,
            owner,
            endpoint,
            peer,
            conversation,
            event_id: None,
            event_acknowledged: false,
            reply_required: false,
            post_completed: false,
            terminate_queued: false,
            retirement_prepared: false,
        });
        Ok(())
    }

    pub(super) fn discard_unposted_client_termination(
        &mut self,
        operation: Win16Ole1OperationId,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        conversation: Win16ClassicDdeConversationId,
    ) {
        self.terminations.retain(|entry| {
            !(entry.operation == operation
                && entry.owner == owner
                && entry.endpoint == endpoint
                && entry.conversation == conversation
                && !entry.post_completed
                && entry.event_id.is_none())
        });
    }

    pub(super) fn commit_client_termination(
        &mut self,
        event: Win16HostClassicDdeEvent,
    ) -> Result<Win16Ole1ClientDdeEventCommit, RuntimeError> {
        let Some(conversation) = event.conversation else {
            return Ok(Win16Ole1ClientDdeEventCommit::NotOwned(event));
        };
        if self
            .conversations
            .iter()
            .filter(|entry| {
                entry.owner == event.owner
                    && entry.endpoint == event.endpoint
                    && entry.peer == event.peer
                    && entry.id == conversation
            })
            .count()
            != 1
        {
            return Ok(Win16Ole1ClientDdeEventCommit::NotOwned(event));
        }
        // Preserve normal ACK/DATA ordering before closing the exact document
        // conversation. A retained event is rerouted after that call commits.
        if self.pending.iter().any(|entry| {
            entry.owner == event.owner
                && entry.endpoint == event.endpoint
                && entry.conversation == conversation
        }) || self.committed_events.iter().any(|entry| {
            entry.owner == event.owner
                && entry.endpoint == event.endpoint
                && entry.conversation == conversation
        }) {
            return Ok(Win16Ole1ClientDdeEventCommit::NotOwned(event));
        }
        let mut endpoints = self
            .endpoints
            .iter()
            .filter(|entry| entry.owner == event.owner && entry.endpoint == event.endpoint);
        let Some(endpoint) = endpoints.next().copied() else {
            return Ok(Win16Ole1ClientDdeEventCommit::NotOwned(event));
        };
        if endpoints.next().is_some() {
            return Ok(Win16Ole1ClientDdeEventCommit::Ambiguous(event));
        }
        let existing = self.terminations.iter().position(|entry| {
            entry.owner == event.owner
                && entry.endpoint == event.endpoint
                && entry.peer == event.peer
                && entry.conversation == conversation
        });
        if existing.is_some_and(|index| {
            self.terminations[index].event_id.is_some()
                && self.terminations[index].event_id != Some(event.event_id)
        }) {
            return Ok(Win16Ole1ClientDdeEventCommit::Ambiguous(event));
        }
        self.committed_events.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve committed client DDE TERMINATE event",
                error,
            )
        })?;
        if existing.is_none() {
            self.terminations.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve peer-initiated client DDE termination",
                    error,
                )
            })?;
        }
        let index = if let Some(index) = existing {
            index
        } else {
            self.terminations.push(ClientTermination {
                operation: endpoint.operation,
                owner: event.owner,
                endpoint: event.endpoint,
                peer: event.peer,
                conversation,
                event_id: None,
                event_acknowledged: false,
                reply_required: true,
                post_completed: false,
                terminate_queued: false,
                retirement_prepared: false,
            });
            self.terminations.len() - 1
        };
        self.terminations[index].event_id = Some(event.event_id);
        let operation = self.terminations[index].operation;
        self.committed_events
            .push(Win16Ole1ClientDdeCommittedEvent {
                event_id: event.event_id,
                owner: event.owner,
                endpoint: event.endpoint,
                peer: event.peer,
                conversation,
                transaction: event.transaction,
                response: Win16Ole1ClientDdeCommittedResponse::Terminate { operation },
            });
        Ok(Win16Ole1ClientDdeEventCommit::Committed(event.event_id))
    }

    pub(super) fn completed_client_termination_post(
        &mut self,
        operation: Win16Ole1OperationId,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        peer: Win16HostClassicDdePeer,
        conversation: Win16ClassicDdeConversationId,
        queued: bool,
    ) -> Result<Win16Ole1ClientDdeDisposition, RuntimeError> {
        let index = self
            .terminations
            .iter()
            .position(|entry| {
                entry.operation == operation
                    && entry.owner == owner
                    && entry.endpoint == endpoint
                    && entry.peer == peer
                    && entry.conversation == conversation
            })
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "client TERMINATE post lost its exact handshake",
                )
            })?;
        if self.terminations[index].post_completed
            && self.terminations[index].terminate_queued != queued
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "client TERMINATE post changed its queue acceptance",
            ));
        }
        self.terminations[index].post_completed = true;
        self.terminations[index].terminate_queued = queued;
        self.advance_client_termination(index)
    }

    pub(super) fn acknowledge_client_termination(
        &mut self,
        owner: OwnerId,
        operation: Win16Ole1OperationId,
        event_id: crate::Win16ClassicDdeEventId,
    ) -> Result<Option<Win16Ole1ClientDdeDisposition>, RuntimeError> {
        let Some(index) = self.terminations.iter().position(|entry| {
            entry.owner == owner && entry.operation == operation && entry.event_id == Some(event_id)
        }) else {
            return Ok(None);
        };
        self.terminations[index].event_acknowledged = true;
        self.advance_client_termination(index).map(Some)
    }

    fn advance_client_termination(
        &mut self,
        index: usize,
    ) -> Result<Win16Ole1ClientDdeDisposition, RuntimeError> {
        let entry = self.terminations[index];
        if entry.retirement_prepared {
            return Ok(Win16Ole1ClientDdeDisposition::Deferred);
        }
        if entry.reply_required && entry.event_acknowledged && !entry.post_completed {
            self.queue_host_action(
                entry.operation,
                Win16Ole1ClientHostAction::TerminateClientConversation {
                    owner: entry.owner,
                    endpoint: entry.endpoint,
                    peer: entry.peer,
                    conversation: entry.conversation,
                },
            )
            .map_err(|message| RuntimeError::new(Kind::ResourceExhausted, message))?;
            return Ok(Win16Ole1ClientDdeDisposition::HostCall {
                operation: entry.operation,
                call: Win16HostClassicDdeCall::Post {
                    owner: entry.owner,
                    endpoint: entry.endpoint,
                    target: entry.peer,
                    conversation: entry.conversation,
                    transaction: None,
                    message: Win16ClassicDdeMessage::Terminate,
                },
                resume_callback: None,
            });
        }
        // An initiated handshake waits for the exact peer response and its
        // EventId delivery ACK. A failed Post has no peer response to await.
        if !entry.post_completed || (entry.terminate_queued && !entry.event_acknowledged) {
            return Ok(Win16Ole1ClientDdeDisposition::Deferred);
        }
        self.queue_host_action(
            entry.operation,
            Win16Ole1ClientHostAction::RetireClientConversation {
                owner: entry.owner,
                endpoint: entry.endpoint,
                peer: entry.peer,
                conversation: entry.conversation,
                terminate_queued: entry.terminate_queued,
            },
        )
        .map_err(|message| RuntimeError::new(Kind::ResourceExhausted, message))?;
        self.terminations[index].retirement_prepared = true;
        Ok(Win16Ole1ClientDdeDisposition::HostCall {
            operation: entry.operation,
            call: Win16HostClassicDdeCall::RetireConversation {
                owner: entry.owner,
                endpoint: entry.endpoint,
                conversation: entry.conversation,
                peer: entry.peer,
            },
            resume_callback: None,
        })
    }

    pub(super) fn finish_client_termination(
        &mut self,
        operation: Win16Ole1OperationId,
        owner: OwnerId,
        endpoint: Win16HostClassicDdeEndpoint,
        peer: Win16HostClassicDdePeer,
        conversation: Win16ClassicDdeConversationId,
    ) -> Result<(), RuntimeError> {
        let index = self
            .terminations
            .iter()
            .position(|entry| {
                entry.operation == operation
                    && entry.owner == owner
                    && entry.endpoint == endpoint
                    && entry.peer == peer
                    && entry.conversation == conversation
                    && entry.retirement_prepared
            })
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "retired client conversation lost its exact termination handshake",
                )
            })?;
        self.terminations.remove(index);
        Ok(())
    }
}

pub(super) fn process_committed_event(
    state: &Win16State,
    event: &Win16HostClassicDdeEvent,
) -> Result<Option<(Win16Ole1OperationId, Win16Ole1ClientDdeDisposition)>, RuntimeError> {
    let journal = &state.ole1_client_documents.client_dde;
    let Some(committed) = journal.committed_event(event.owner, event.endpoint, event.event_id)
    else {
        return Ok(None);
    };
    let Win16Ole1ClientDdeCommittedResponse::Terminate { operation } = &committed.response else {
        return Ok(None);
    };
    let operation = *operation;
    if !journal.terminations.iter().any(|entry| {
        entry.operation == operation
            && entry.owner == event.owner
            && entry.endpoint == event.endpoint
            && entry.peer == event.peer
            && Some(entry.conversation) == event.conversation
            && entry.event_id == Some(event.event_id)
    }) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "committed client TERMINATE lost its exact conversation and EventId",
        ));
    }
    Ok(Some((
        operation,
        Win16Ole1ClientDdeDisposition::EventAcknowledgementReady {
            operation,
            event_id: event.event_id,
        },
    )))
}

pub(super) fn note_conversation_retirement(
    state: &mut Win16State,
    owner: OwnerId,
    disposition: &Win16Ole1ClientDdeDisposition,
) {
    let Win16Ole1ClientDdeDisposition::ConversationRetired {
        owner: found,
        endpoint,
        peer,
        conversation,
        ..
    } = disposition
    else {
        return;
    };
    if *found != owner {
        return;
    }
    for record in &mut state.ole1_client_documents.dde_object_proxies {
        if record.owner != owner || record.endpoint != *endpoint {
            continue;
        }
        if record.document_peer == *peer && record.document_conversation == *conversation {
            record.document_conversation_retired = true;
            record.closed = true;
        }
        if record.system_peer == *peer && record.system_conversation == *conversation {
            record.system_conversation_retired = true;
        }
    }
}
