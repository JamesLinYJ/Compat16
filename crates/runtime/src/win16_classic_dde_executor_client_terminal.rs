//! Classic DDE executor support for client terminal journal receipts.

use super::*;

impl Win16State {
    pub(super) fn commit_client_classic_dde_receipt(
        &mut self,
        identity: Win16ClassicDdeOperationIdentity,
        client_operation: super::super::ole1::Win16Ole1OperationId,
        result: &Win16HostClassicDdeResult,
        disposition: &Win16Ole1ClientDdeDisposition,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if let Win16HostClassicDdeResult::ConversationBound(receipt) = result {
            let atoms = self
                .ole1_client_dde_conversation_atoms(
                    receipt.owner,
                    receipt.endpoint,
                    receipt.conversation,
                )
                .ok_or_else(|| {
                    dde_invariant("client conversation receipt has no exact INITIATE atom journal")
                })?;
            if atoms.owner != receipt.owner
                || atoms.endpoint != receipt.endpoint
                || atoms.conversation != receipt.conversation
                || atoms.source_event_id != receipt.initiate_event_id
            {
                return Err(dde_invariant(
                    "client INITIATE atom handoff changed receipt identity",
                ));
            }
            self.bind_classic_dde_client_conversation_atoms(
                client_operation,
                identity,
                atoms,
                result,
            )?;
        }
        if let Win16HostClassicDdeResult::ConversationRetired {
            owner,
            endpoint,
            conversation,
            peer,
        } = result
        {
            if let Win16Ole1ClientDdeDisposition::ConversationRetired {
                operation,
                owner: disposition_owner,
                endpoint: disposition_endpoint,
                peer: disposition_peer,
                conversation: disposition_conversation,
                terminate_queued: _,
            } = disposition
            {
                if *operation != client_operation
                    || disposition_owner != owner
                    || disposition_endpoint != endpoint
                    || disposition_peer != peer
                    || disposition_conversation != conversation
                {
                    return Err(dde_invariant(
                        "client conversation-retirement disposition changed its exact receipt",
                    ));
                }
            }
            self.retire_classic_dde_conversation_atoms(
                *owner,
                *endpoint,
                identity.worker_generation,
                *conversation,
                *peer,
                host,
            )?;
        }
        if let Win16Ole1ClientDdeDisposition::InitiateCompleted {
            operation,
            ..
        } = disposition
        {
            if *operation != client_operation {
                return Err(dde_invariant(
                    "client INITIATE completion changed its exact operation owner",
                ));
            }
            self.retire_classic_dde_client_initiate_atoms(
                identity.owner,
                match &self
                    .classic_dde
                    .operations
                    .last()
                    .filter(|frame| frame.identity == identity)
                    .ok_or_else(|| {
                        dde_invariant("client INITIATE completion lost its operation frame")
                    })?
                    .call
                {
                    Win16HostClassicDdeCall::Send { endpoint, .. } => *endpoint,
                    _ => {
                        return Err(dde_invariant(
                            "client INITIATE completion is not backed by a Send operation",
                        ));
                    }
                },
                client_operation,
                host,
            )?;
        }
        Ok(())
    }

    pub(super) fn apply_client_terminal_disposition(
        &mut self,
        owner: OwnerId,
        operation: super::super::ole1::Win16Ole1OperationId,
        resume_parent: Option<Win16HostClassicDdeCallbackReply>,
        disposition: Win16Ole1ClientDdeDisposition,
        cpu: &mut Cpu,
        dos: &mut DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let fallback_disposition = disposition.clone();
        let disposition = match self.advance_ole1_client_dde_sequence(
            owner,
            operation,
            disposition,
            cpu,
            dos,
            memory,
            host,
        )? {
            Some(next) => next,
            None => fallback_disposition,
        };
        self.apply_client_terminal_disposition_ready(
            owner,
            operation,
            resume_parent,
            disposition,
            host,
        )
    }

    /// Consume a client disposition whose OLE1 sequence stage has already
    /// advanced. EventId acknowledgement terminals use this entry point so
    /// their exact ACK receipt cannot advance the same sequence twice.
    pub(super) fn apply_client_terminal_disposition_ready(
        &mut self,
        owner: OwnerId,
        operation: super::super::ole1::Win16Ole1OperationId,
        resume_parent: Option<Win16HostClassicDdeCallbackReply>,
        disposition: Win16Ole1ClientDdeDisposition,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        match disposition {
            Win16Ole1ClientDdeDisposition::HostCall {
                operation: next,
                call,
                resume_callback,
            } => {
                if next != operation {
                    return Err(dde_invariant(
                        "OLE1 client host action changed business operation",
                    ));
                }
                let resume = resume_callback.or(resume_parent);
                let bind_initiate = matches!(
                    &call,
                    Win16HostClassicDdeCall::Send {
                        target: crate::Win16HostClassicDdeTarget::BroadcastInitiate,
                        ..
                    }
                );
                self.begin_classic_dde_host_call(
                    call,
                    ClassicDdeOperationOwner::Client {
                        owner,
                        operation,
                        bind_initiate,
                    },
                    resume,
                    host,
                )?;
                Ok(true)
            }
            Win16Ole1ClientDdeDisposition::EventAcknowledgementReady {
                operation: found,
                event_id,
            } => {
                if found != operation {
                    return Err(dde_invariant(
                        "OLE1 EventId ACK changed its client operation",
                    ));
                }
                let mut matching = self.classic_dde.queued_events.iter().filter(|record| {
                    record.event.owner == owner && record.event.event_id == event_id
                });
                let event = matching.next().ok_or_else(|| {
                    dde_invariant("ready EventId ACK has no retained exact queued event")
                })?;
                if matching.next().is_some()
                    || event.event.delivery != Win16ClassicDdeDeliveryKind::Queued
                    || event.event.worker_generation == 0
                {
                    return Err(dde_invariant(
                        "ready EventId ACK maps to an ambiguous or nonqueued event",
                    ));
                }
                let event = event.event.clone();
                let published = self.classic_dde.event_tracker.pending().any(|progress| {
                    progress.owner == owner
                        && progress.endpoint == event.endpoint
                        && progress.worker_generation == event.worker_generation
                        && progress.event_id == event_id
                        && progress.phase == crate::Win16ClassicDdeEventPhase::Published
                });
                if !published {
                    return Err(dde_invariant(
                        "ready EventId ACK has no exact Published delivery lease",
                    ));
                }
                self.begin_classic_dde_host_call(
                    Win16HostClassicDdeCall::AcknowledgeEvent {
                        owner,
                        endpoint: event.endpoint,
                        event_id,
                    },
                    ClassicDdeOperationOwner::ClientEventAcknowledgement { owner, operation },
                    resume_parent,
                    host,
                )?;
                Ok(true)
            }
            Win16Ole1ClientDdeDisposition::ResumeCallback(reply) => {
                let identity = Win16ClassicDdeOperationIdentity {
                    owner: reply.owner,
                    id: reply.operation_id,
                    worker_generation: reply.worker_generation,
                };
                self.resume_classic_dde_host_call(identity, Some(reply), host)?;
                Ok(true)
            }
            Win16Ole1ClientDdeDisposition::ConversationRetired {
                operation: found,
                owner: found_owner,
                endpoint,
                peer: _,
                conversation,
                terminate_queued: _,
            } => {
                if found != operation
                    || found_owner != owner
                    || endpoint.0 == 0
                    || conversation.0 == 0
                {
                    return Err(dde_invariant(
                        "OLE1 client conversation retirement changed its exact owner or terminal",
                    ));
                }
                if let Some(reply) = resume_parent {
                    let identity = Win16ClassicDdeOperationIdentity {
                        owner: reply.owner,
                        id: reply.operation_id,
                        worker_generation: reply.worker_generation,
                    };
                    self.resume_classic_dde_host_call(identity, Some(reply), host)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Win16Ole1ClientDdeDisposition::InitiateCompleted {
                operation: found, ..
            }
            | Win16Ole1ClientDdeDisposition::EndpointCreated {
                operation: found, ..
            }
            | Win16Ole1ClientDdeDisposition::EndpointRetired {
                operation: found, ..
            }
            | Win16Ole1ClientDdeDisposition::ApiCompleted { operation: found }
            | Win16Ole1ClientDdeDisposition::DdeCallPosted {
                operation: found, ..
            }
            | Win16Ole1ClientDdeDisposition::DdeCallRejected {
                operation: found, ..
            } => {
                if found != operation {
                    return Err(dde_invariant(
                        "OLE1 client terminal changed business operation",
                    ));
                }
                if let Some(reply) = resume_parent {
                    let identity = Win16ClassicDdeOperationIdentity {
                        owner: reply.owner,
                        id: reply.operation_id,
                        worker_generation: reply.worker_generation,
                    };
                    self.resume_classic_dde_host_call(identity, Some(reply), host)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Win16Ole1ClientDdeDisposition::Deferred => Ok(true),
            Win16Ole1ClientDdeDisposition::NotOwned
            | Win16Ole1ClientDdeDisposition::CallbackReply(_) => Err(dde_invariant(
                "OLE1 client returned an invalid disposition for a host terminal",
            )),
        }
    }
}
