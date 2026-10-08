use super::*;

fn reserve_error(label: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::ResourceExhausted, label)
}

fn copy_slice<T: Copy>(source: &[T], label: &'static str) -> Result<Vec<T>, RuntimeError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(source.len())
        .map_err(|_| reserve_error(label))?;
    copy.extend_from_slice(source);
    Ok(copy)
}

pub(super) fn clone_atom_checked(
    atom: &Win16ClassicDdeAtom,
) -> Result<Win16ClassicDdeAtom, RuntimeError> {
    match atom {
        Win16ClassicDdeAtom::Integer(value) => Ok(Win16ClassicDdeAtom::Integer(*value)),
        Win16ClassicDdeAtom::Name {
            guest_value,
            name_bytes,
        } => Ok(Win16ClassicDdeAtom::Name {
            guest_value: *guest_value,
            name_bytes: copy_slice(name_bytes, "copy OLE1 DDE atom name")?,
        }),
    }
}

fn clone_optional_atom(
    atom: &Option<Win16ClassicDdeAtom>,
) -> Result<Option<Win16ClassicDdeAtom>, RuntimeError> {
    atom.as_ref().map(clone_atom_checked).transpose()
}

pub(super) fn clone_candidate(
    candidate: &Win16Ole1InitiateCandidate,
) -> Result<Win16Ole1InitiateCandidate, RuntimeError> {
    Ok(Win16Ole1InitiateCandidate {
        operation: candidate.operation,
        source_operation: candidate.source_operation,
        endpoint: candidate.endpoint,
        event_id: candidate.event_id,
        peer: candidate.peer,
        callback: candidate.callback,
        frame: candidate.frame,
        causal_parents: copy_slice(
            &candidate.causal_parents,
            "copy OLE1 DDE callback causal chain",
        )?,
        application: clone_atom_checked(&candidate.application)?,
        topic: clone_atom_checked(&candidate.topic)?,
    })
}

pub(super) fn clone_callback_reply(
    reply: &Win16HostClassicDdeCallbackReply,
) -> Result<Win16HostClassicDdeCallbackReply, RuntimeError> {
    Ok(Win16HostClassicDdeCallbackReply {
        owner: reply.owner,
        endpoint: reply.endpoint,
        operation_id: reply.operation_id,
        worker_generation: reply.worker_generation,
        callback: reply.callback,
        frame: reply.frame,
        event_id: reply.event_id,
        peer: reply.peer,
        causal_parents: copy_slice(
            &reply.causal_parents,
            "copy OLE1 DDE callback reply causal chain",
        )?,
        result: reply.result.clone(),
    })
}

fn clone_message(message: &Win16ClassicDdeMessage) -> Result<Win16ClassicDdeMessage, RuntimeError> {
    Ok(match message {
        Win16ClassicDdeMessage::Initiate { application, topic } => {
            Win16ClassicDdeMessage::Initiate {
                application: clone_optional_atom(application)?,
                topic: clone_optional_atom(topic)?,
            }
        }
        Win16ClassicDdeMessage::Terminate => Win16ClassicDdeMessage::Terminate,
        Win16ClassicDdeMessage::Ack { status, value } => Win16ClassicDdeMessage::Ack {
            status: *status,
            value: match value {
                Win16ClassicDdeAckValue::InitiateAtoms { application, topic } => {
                    Win16ClassicDdeAckValue::InitiateAtoms {
                        application: clone_optional_atom(application)?,
                        topic: clone_optional_atom(topic)?,
                    }
                }
                Win16ClassicDdeAckValue::ItemAtom(atom) => {
                    Win16ClassicDdeAckValue::ItemAtom(clone_optional_atom(atom)?)
                }
                Win16ClassicDdeAckValue::ExecuteTransfer(transfer) => {
                    Win16ClassicDdeAckValue::ExecuteTransfer(*transfer)
                }
                Win16ClassicDdeAckValue::Unmatched => Win16ClassicDdeAckValue::Unmatched,
            },
        },
        Win16ClassicDdeMessage::Advise {
            item,
            format,
            options,
            global,
        } => Win16ClassicDdeMessage::Advise {
            item: clone_optional_atom(item)?,
            format: *format,
            options: *options,
            global: clone_global(global)?,
        },
        Win16ClassicDdeMessage::Unadvise { item, reserved } => Win16ClassicDdeMessage::Unadvise {
            item: clone_optional_atom(item)?,
            reserved: *reserved,
        },
        Win16ClassicDdeMessage::Request { item, format } => Win16ClassicDdeMessage::Request {
            item: clone_optional_atom(item)?,
            format: *format,
        },
        Win16ClassicDdeMessage::Poke {
            item,
            format,
            flags,
            global,
        } => Win16ClassicDdeMessage::Poke {
            item: clone_optional_atom(item)?,
            format: *format,
            flags: *flags,
            global: clone_global(global)?,
        },
        Win16ClassicDdeMessage::Data {
            item,
            format,
            flags,
            global,
        } => Win16ClassicDdeMessage::Data {
            item: clone_optional_atom(item)?,
            format: *format,
            flags: *flags,
            global: clone_global(global)?,
        },
        Win16ClassicDdeMessage::Execute { global } => Win16ClassicDdeMessage::Execute {
            global: clone_global(global)?,
        },
    })
}

fn clone_global(
    global: &Win16ClassicDdeGlobalBlock,
) -> Result<Win16ClassicDdeGlobalBlock, RuntimeError> {
    Ok(Win16ClassicDdeGlobalBlock {
        transfer: global.transfer,
        guest_global: global.guest_global,
        bytes: copy_slice(&global.bytes, "copy OLE1 DDE global payload")?,
    })
}

fn clone_event(event: &Win16HostClassicDdeEvent) -> Result<Win16HostClassicDdeEvent, RuntimeError> {
    Ok(Win16HostClassicDdeEvent {
        owner: event.owner,
        endpoint: event.endpoint,
        worker_generation: event.worker_generation,
        event_id: event.event_id,
        peer: event.peer,
        conversation: event.conversation,
        transaction: event.transaction,
        delivery: event.delivery,
        message: clone_message(&event.message)?,
    })
}

fn clone_retirement_receipt(
    receipt: &Win16HostClassicDdeRetirementReceipt,
) -> Result<Win16HostClassicDdeRetirementReceipt, RuntimeError> {
    Ok(Win16HostClassicDdeRetirementReceipt {
        owner: receipt.owner,
        endpoint: receipt.endpoint,
        worker_generation: receipt.worker_generation,
        retired: receipt.retired,
        pending_events: copy_slice(
            &receipt.pending_events,
            "copy OLE1 DDE retirement event evidence",
        )?,
        retained_callbacks: copy_slice(
            &receipt.retained_callbacks,
            "copy OLE1 DDE retirement callback evidence",
        )?,
        retained_transfers: copy_slice(
            &receipt.retained_transfers,
            "copy OLE1 DDE retirement transfer evidence",
        )?,
    })
}

fn clone_endpoint_quiescence(
    source: &crate::Win16HostClassicDdeEndpointQuiescence,
) -> Result<crate::Win16HostClassicDdeEndpointQuiescence, RuntimeError> {
    Ok(crate::Win16HostClassicDdeEndpointQuiescence {
        endpoint: source.endpoint,
        parent: source.parent,
        pending_events: copy_slice(
            &source.pending_events,
            "copy OLE1 DDE owner-quiescence event identities",
        )?,
        callbacks: copy_slice(
            &source.callbacks,
            "copy OLE1 DDE owner-quiescence callback identities",
        )?,
        transfers: copy_slice(
            &source.transfers,
            "copy OLE1 DDE owner-quiescence transfer identities",
        )?,
        conversations: copy_slice(
            &source.conversations,
            "copy OLE1 DDE owner-quiescence conversations",
        )?,
        transactions: copy_slice(
            &source.transactions,
            "copy OLE1 DDE owner-quiescence transactions",
        )?,
    })
}

fn clone_owner_quiescence(
    source: &crate::Win16HostClassicDdeOwnerQuiescence,
) -> Result<crate::Win16HostClassicDdeOwnerQuiescence, RuntimeError> {
    let mut endpoints = Vec::new();
    endpoints
        .try_reserve_exact(source.endpoints.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve OLE1 DDE owner-quiescence snapshot copy",
                error,
            )
        })?;
    for endpoint in &source.endpoints {
        endpoints.push(clone_endpoint_quiescence(endpoint)?);
    }
    Ok(crate::Win16HostClassicDdeOwnerQuiescence {
        owner: source.owner,
        worker_generation: source.worker_generation,
        id: source.id,
        endpoints,
        active_operations: copy_slice(
            &source.active_operations,
            "copy OLE1 DDE owner-quiescence active operations",
        )?,
    })
}

#[derive(Debug)]
struct SharedRuntimeCause(std::sync::Arc<RuntimeError>);

impl std::fmt::Display for SharedRuntimeCause {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.0.as_ref(), formatter)
    }
}

impl std::error::Error for SharedRuntimeCause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

pub(super) fn shared_runtime_error(cause: std::sync::Arc<RuntimeError>) -> RuntimeError {
    RuntimeError::with_source(
        cause.kind(),
        "classic DDE operation failed; shared diagnostic cause retained",
        SharedRuntimeCause(cause),
    )
}

fn clone_result(
    result: &Win16HostClassicDdeResult,
) -> Result<Win16HostClassicDdeResult, RuntimeError> {
    Ok(match result {
        Win16HostClassicDdeResult::OwnerQuiescing(quiescence) => {
            Win16HostClassicDdeResult::OwnerQuiescing(clone_owner_quiescence(quiescence)?)
        }
        Win16HostClassicDdeResult::OwnerQuiesced(proof) => {
            Win16HostClassicDdeResult::OwnerQuiesced(*proof)
        }
        Win16HostClassicDdeResult::Endpoint(endpoint) => {
            Win16HostClassicDdeResult::Endpoint(*endpoint)
        }
        Win16HostClassicDdeResult::Retired(receipt) => {
            Win16HostClassicDdeResult::Retired(clone_retirement_receipt(receipt)?)
        }
        Win16HostClassicDdeResult::Posted(receipt) => {
            Win16HostClassicDdeResult::Posted(receipt.clone())
        }
        Win16HostClassicDdeResult::Sent(receipt) => {
            Win16HostClassicDdeResult::Sent(receipt.clone())
        }
        Win16HostClassicDdeResult::Event(event) => {
            Win16HostClassicDdeResult::Event(event.as_ref().map(clone_event).transpose()?)
        }
        Win16HostClassicDdeResult::EventAcknowledged(event_id) => {
            Win16HostClassicDdeResult::EventAcknowledged(*event_id)
        }
        Win16HostClassicDdeResult::InitiateReplied(receipt) => {
            Win16HostClassicDdeResult::InitiateReplied(
                crate::Win16HostClassicDdeInitiateReplyReceipt {
                    owner: receipt.owner,
                    endpoint: receipt.endpoint,
                    event_id: receipt.event_id,
                    peer: receipt.peer,
                    accepted: receipt.accepted,
                    application_atom: clone_optional_atom(&receipt.application_atom)?,
                    topic_atom: clone_optional_atom(&receipt.topic_atom)?,
                    native_result: receipt.native_result,
                    conversation: receipt.conversation,
                },
            )
        }
        Win16HostClassicDdeResult::ConversationBound(receipt) => {
            Win16HostClassicDdeResult::ConversationBound(Win16HostClassicDdeConversationReceipt {
                owner: receipt.owner,
                endpoint: receipt.endpoint,
                conversation: receipt.conversation,
                peer: receipt.peer,
                application: clone_optional_atom(&receipt.application)?,
                topic: clone_optional_atom(&receipt.topic)?,
                source_operation: receipt.source_operation,
                initiate_event_id: receipt.initiate_event_id,
            })
        }
        Win16HostClassicDdeResult::ConversationRetired {
            owner,
            endpoint,
            conversation,
            peer,
        } => Win16HostClassicDdeResult::ConversationRetired {
            owner: *owner,
            endpoint: *endpoint,
            conversation: *conversation,
            peer: *peer,
        },
        Win16HostClassicDdeResult::ForwardInitiateReturned {
            owner,
            parent,
            child,
            peer,
            native_result,
        } => Win16HostClassicDdeResult::ForwardInitiateReturned {
            owner: *owner,
            parent: *parent,
            child: *child,
            peer: *peer,
            native_result: *native_result,
        },
        Win16HostClassicDdeResult::CallbackResumed(frame) => {
            Win16HostClassicDdeResult::CallbackResumed(*frame)
        }
    })
}

pub(super) fn clone_terminal(
    terminal: &Win16HostClassicDdeTerminal,
) -> Result<Win16HostClassicDdeTerminal, RuntimeError> {
    Ok(match terminal {
        Win16HostClassicDdeTerminal::Complete {
            result,
            source_retired,
        } => Win16HostClassicDdeTerminal::Complete {
            result: clone_result(result)?,
            source_retired: std::sync::Arc::clone(source_retired),
        },
        Win16HostClassicDdeTerminal::StartedFailure(failure) => {
            Win16HostClassicDdeTerminal::StartedFailure(std::sync::Arc::clone(failure))
        }
    })
}

pub(super) fn clone_action(
    action: &Win16Ole1ClientHostAction,
) -> Result<Win16Ole1ClientHostAction, RuntimeError> {
    Ok(match action {
        Win16Ole1ClientHostAction::CreateEndpoint { owner } => {
            Win16Ole1ClientHostAction::CreateEndpoint { owner: *owner }
        }
        Win16Ole1ClientHostAction::RetireEndpoint { owner, endpoint } => {
            Win16Ole1ClientHostAction::RetireEndpoint {
                owner: *owner,
                endpoint: *endpoint,
            }
        }
        Win16Ole1ClientHostAction::TerminateClientConversation {
            owner,
            endpoint,
            peer,
            conversation,
        } => Win16Ole1ClientHostAction::TerminateClientConversation {
            owner: *owner,
            endpoint: *endpoint,
            peer: *peer,
            conversation: *conversation,
        },
        Win16Ole1ClientHostAction::RetireClientConversation {
            owner,
            endpoint,
            peer,
            conversation,
            terminate_queued,
        } => Win16Ole1ClientHostAction::RetireClientConversation {
            owner: *owner,
            endpoint: *endpoint,
            peer: *peer,
            conversation: *conversation,
            terminate_queued: *terminate_queued,
        },
        Win16Ole1ClientHostAction::InitiateBroadcast => {
            Win16Ole1ClientHostAction::InitiateBroadcast
        }
        Win16Ole1ClientHostAction::BindFirstResponder {
            candidate,
            resume_callback,
        } => Win16Ole1ClientHostAction::BindFirstResponder {
            candidate: clone_candidate(candidate)?,
            resume_callback: clone_callback_reply(resume_callback)?,
        },
        Win16Ole1ClientHostAction::BindExtraResponder {
            candidate,
            resume_callback,
        } => Win16Ole1ClientHostAction::BindExtraResponder {
            candidate: clone_candidate(candidate)?,
            resume_callback: clone_callback_reply(resume_callback)?,
        },
        Win16Ole1ClientHostAction::TerminateExtraResponder {
            candidate,
            conversation,
            resume_callback,
        } => Win16Ole1ClientHostAction::TerminateExtraResponder {
            candidate: clone_candidate(candidate)?,
            conversation: *conversation,
            resume_callback: clone_callback_reply(resume_callback)?,
        },
        Win16Ole1ClientHostAction::RetireExtraResponder {
            candidate,
            conversation,
            resume_callback,
        } => Win16Ole1ClientHostAction::RetireExtraResponder {
            candidate: clone_candidate(candidate)?,
            conversation: *conversation,
            resume_callback: clone_callback_reply(resume_callback)?,
        },
        Win16Ole1ClientHostAction::PostTransaction {
            owner,
            endpoint,
            peer,
            conversation,
            call,
            sent_message,
        } => Win16Ole1ClientHostAction::PostTransaction {
            owner: *owner,
            endpoint: *endpoint,
            peer: *peer,
            conversation: *conversation,
            call: *call,
            sent_message: *sent_message,
        },
    })
}

pub(super) fn terminal_matches(
    cached: &Win16HostClassicDdeTerminal,
    replay: &Win16HostClassicDdeTerminal,
) -> bool {
    match (cached, replay) {
        (
            Win16HostClassicDdeTerminal::Complete {
                result: cached_result,
                source_retired: cached_proof,
            },
            Win16HostClassicDdeTerminal::Complete {
                result: replay_result,
                source_retired: replay_proof,
            },
        ) => {
            cached_result == replay_result
                && cached_proof.operation == replay_proof.operation
                && cached_proof.callbacks == replay_proof.callbacks
        }
        (
            Win16HostClassicDdeTerminal::StartedFailure(cached),
            Win16HostClassicDdeTerminal::StartedFailure(replay),
        ) => {
            cached.operation == replay.operation
                && cached.source_retired.operation == replay.source_retired.operation
                && cached.source_retired.callbacks == replay.source_retired.callbacks
                && std::sync::Arc::ptr_eq(&cached.cause, &replay.cause)
        }
        _ => false,
    }
}
