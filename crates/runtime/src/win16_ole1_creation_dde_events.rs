use super::*;

pub(in crate::win16_runtime) fn advance_sequence(
    state: &mut Win16State,
    owner: OwnerId,
    operation: Win16Ole1OperationId,
    disposition: Win16Ole1ClientDdeDisposition,
    cpu: &mut Cpu,
    dos: &mut DosKernel,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<Option<Win16Ole1ClientDdeDisposition>, RuntimeError> {
    let Some(index) = state
        .ole1_client_documents
        .pending_dde_creations
        .iter()
        .position(|seq| seq.owner == owner && seq.operation == operation)
    else {
        return Ok(None);
    };
    match disposition {
        Win16Ole1ClientDdeDisposition::EndpointCreated {
            operation: found,
            owner: found_owner,
            endpoint,
        } => {
            if found != operation
                || found_owner != owner
                || state.ole1_client_documents.pending_dde_creations[index].stage
                    != Stage::AwaitEndpoint
            {
                return Err(dde_error(
                    Kind::InternalInvariant,
                    "OLE1 DDE endpoint result changed its create owner or stage",
                ));
            }
            state.ole1_client_documents.pending_dde_creations[index].endpoint = Some(endpoint);
            let application = copy_bytes(
                &state.ole1_client_documents.pending_dde_creations[index].class_name,
                "copy OLE1 DDE system application",
            )?;
            start_initiate(
                state,
                index,
                Win16Ole1InitiatePurpose::SystemOleTopic,
                &application,
                b"OLEsystem",
                host,
            )
        }
        Win16Ole1ClientDdeDisposition::InitiateCompleted {
            operation: found,
            purpose,
            responder,
        } => {
            if found != operation {
                return Err(dde_error(
                    Kind::InternalInvariant,
                    "OLE1 DDE INITIATE result changed operation",
                ));
            }
            if state.ole1_client_documents.pending_dde_creations[index].stage
                == Stage::PublishedReturn
            {
                if purpose != Win16Ole1InitiatePurpose::DocumentTopic
                    || state.ole1_client_documents.pending_dde_creations[index]
                        .document_conversation
                        != responder
                {
                    return Err(dde_error(
                        Kind::InternalInvariant,
                        "retried OLE1 DDE create terminal changed its published conversation",
                    ));
                }
                return finish_successful_creation(state, index, cpu);
            }
            if state.ole1_client_documents.pending_dde_creations[index].stage
                != Stage::AwaitInitiate
                || state.ole1_client_documents.pending_dde_creations[index].initiate_purpose
                    != Some(purpose)
            {
                return Err(dde_error(
                    Kind::InternalInvariant,
                    "OLE1 DDE INITIATE result changed its operation, purpose, or stage",
                ));
            }
            state.ole1_client_documents.pending_dde_creations[index].initiate_purpose = None;
            match (purpose, responder) {
                (Win16Ole1InitiatePurpose::SystemOleTopic, None) => {
                    let application = copy_bytes(
                        &state.ole1_client_documents.pending_dde_creations[index].class_name,
                        "copy OLE1 DDE fallback application",
                    )?;
                    start_initiate(
                        state,
                        index,
                        Win16Ole1InitiatePurpose::SystemFallbackTopic,
                        &application,
                        b"System",
                        host,
                    )
                }
                (Win16Ole1InitiatePurpose::SystemFallbackTopic, None) => begin_failure_cleanup(
                    state,
                    index,
                    OLE1_ERROR_LAUNCH,
                    "registered OLE1 server did not accept OLEsystem or System INITIATE",
                    cpu,
                    dos,
                    memory,
                    host,
                ),
                (
                    Win16Ole1InitiatePurpose::SystemOleTopic
                    | Win16Ole1InitiatePurpose::SystemFallbackTopic,
                    Some(responder),
                ) => {
                    state.ole1_client_documents.pending_dde_creations[index].system =
                        Some(responder);
                    start_new_document(state, index)
                }
                (Win16Ole1InitiatePurpose::DocumentTopic, None) => begin_failure_cleanup(
                    state,
                    index,
                    OLE1_ERROR_OPEN,
                    "OLE1 server accepted StdNewDocument but did not accept the exact embedded topic",
                    cpu,
                    dos,
                    memory,
                    host,
                ),
                (Win16Ole1InitiatePurpose::DocumentTopic, Some(responder)) => {
                    state.ole1_client_documents.pending_dde_creations[index]
                        .document_conversation = Some(responder);
                    match publish_object(state, index, memory) {
                        Ok(object_far) => {
                            state.ole1_client_documents.pending_dde_creations[index]
                                .published_object_far = Some(object_far);
                            state.ole1_client_documents.pending_dde_creations[index].stage =
                                Stage::PublishedReturn;
                            finish_successful_creation(state, index, cpu)
                        }
                        Err(PublishFailure::Status(status)) => begin_failure_cleanup(
                            state,
                            index,
                            status,
                            "OLE1 DDE proxy could not be published after exact server creation",
                            cpu,
                            dos,
                            memory,
                            host,
                        ),
                        Err(PublishFailure::Runtime(error)) => {
                            state.ole1_client_documents.pending_dde_creations[index].fatal =
                                Some(error);
                            begin_failure_cleanup(
                                state,
                                index,
                                OLE1_ERROR_MEMORY,
                                "OLE1 DDE proxy publication failed and local cleanup is required",
                                cpu,
                                dos,
                                memory,
                                host,
                            )
                        }
                    }
                }
            }
        }
        Win16Ole1ClientDdeDisposition::DdeCallPosted {
            operation: found,
            call,
        } => {
            if found != operation
                || !state
                    .ole1_client_documents
                    .client_dde
                    .pending_call_matches(operation, owner, call)
            {
                return Err(dde_error(
                    Kind::InternalInvariant,
                    "OLE1 execute POST changed create operation or call",
                ));
            }
            let sequence = &mut state.ole1_client_documents.pending_dde_creations[index];
            match sequence.stage {
                Stage::AwaitExecutePost if sequence.execute_call == Some(call) => {
                    sequence.stage = Stage::AwaitExecuteResponse;
                }
                Stage::AwaitClosePost if sequence.close_call == Some(call) => {
                    sequence.stage = Stage::AwaitCloseResponse;
                }
                _ => {
                    return Err(dde_error(
                        Kind::InternalInvariant,
                        "OLE1 execute POST completed outside its reserved stage",
                    ));
                }
            }
            Ok(Some(Win16Ole1ClientDdeDisposition::DdeCallPosted {
                operation: found,
                call,
            }))
        }
        Win16Ole1ClientDdeDisposition::DdeCallRejected {
            operation: found,
            call,
        } => {
            if found != operation
                || !matches!(
                    state.ole1_client_documents.pending_dde_creations[index].stage,
                    Stage::AwaitExecutePost | Stage::AwaitClosePost
                )
            {
                return Err(dde_error(
                    Kind::InternalInvariant,
                    "rejected OLE1 execute POST changed operation or stage",
                ));
            }
            let sequence = &state.ole1_client_documents.pending_dde_creations[index];
            if (sequence.stage == Stage::AwaitExecutePost && sequence.execute_call != Some(call))
                || (sequence.stage == Stage::AwaitClosePost && sequence.close_call != Some(call))
            {
                return Err(dde_error(
                    Kind::InternalInvariant,
                    "rejected OLE1 execute POST changed its reserved DDE call",
                ));
            }
            if state.ole1_client_documents.pending_dde_creations[index].stage
                == Stage::AwaitClosePost
            {
                host.report_diagnostic(&Diagnostic::warning(Kind::HostFailure,
                    "OLE1 StdCloseDocument was not accepted by the native DDE queue; retiring exact client conversations"));
                begin_conversation_cleanup(state, index, cpu, dos, memory, host).map(Some)
            } else if state.ole1_client_documents.pending_dde_creations[index].stage
                == Stage::AwaitExecutePost
            {
                begin_failure_cleanup(
                    state,
                    index,
                    OLE1_ERROR_COMMAND,
                    "native DDE queue rejected StdNewDocument",
                    cpu,
                    dos,
                    memory,
                    host,
                )
            } else {
                Err(dde_error(
                    Kind::InternalInvariant,
                    "rejected OLE1 execute POST completed outside its reserved stage",
                ))
            }
        }
        Win16Ole1ClientDdeDisposition::EventAcknowledgementReady {
            operation: found,
            event_id,
        } => {
            if found != operation
                || !matches!(state.ole1_client_documents.pending_dde_creations[index].stage,
                Stage::AwaitExecuteDeliveryAck(expected) | Stage::AwaitCloseDeliveryAck(expected) if expected == event_id)
            {
                return Err(dde_error(
                    Kind::InternalInvariant,
                    "OLE1 DDE create EventId ACK changed its committed event or stage",
                ));
            }
            Ok(Some(
                Win16Ole1ClientDdeDisposition::EventAcknowledgementReady {
                    operation: found,
                    event_id,
                },
            ))
        }
        Win16Ole1ClientDdeDisposition::ConversationRetired {
            operation: found,
            owner: found_owner,
            endpoint,
            peer,
            conversation,
            terminate_queued,
        } => {
            if found != operation || found_owner != owner {
                return Err(dde_error(
                    Kind::InternalInvariant,
                    "OLE1 create conversation retirement changed its operation owner",
                ));
            }
            let sequence = &mut state.ole1_client_documents.pending_dde_creations[index];
            let exact = match sequence.stage {
                Stage::RetireDocumentConversation => sequence.document_conversation,
                Stage::RetireSystemConversation => sequence.system,
                _ => {
                    return Err(dde_error(
                        Kind::InternalInvariant,
                        "OLE1 create conversation retired outside cleanup stage",
                    ));
                }
            };
            let endpoint_matches = sequence.endpoint == Some(endpoint);
            if !endpoint_matches
                || exact.is_none_or(|expected| {
                    expected.peer != peer || expected.conversation != conversation
                })
            {
                return Err(dde_error(
                    Kind::InternalInvariant,
                    "OLE1 create conversation retirement changed exact peer or endpoint",
                ));
            }
            if !terminate_queued {
                host.report_diagnostic(&Diagnostic::warning(Kind::HostFailure,
                    "exact OLE1 DDE conversation retirement completed although WM_DDE_TERMINATE was not queued"));
            }
            if sequence.stage == Stage::RetireDocumentConversation {
                sequence.document_conversation = None;
            } else {
                sequence.system = None;
            }
            if sequence.stage == Stage::RetireDocumentConversation && sequence.system.is_some() {
                start_conversation_retirement(state, index, false).map(Some)
            } else if sequence.system.is_some() {
                start_conversation_retirement(state, index, false).map(Some)
            } else {
                start_endpoint_retirement(state, index).map(Some)
            }
        }
        Win16Ole1ClientDdeDisposition::EndpointRetired {
            operation: found,
            receipt,
        } => {
            if found != operation
                || state.ole1_client_documents.pending_dde_creations[index].stage
                    != Stage::RetireEndpoint
                || receipt.owner != owner
                || Some(receipt.endpoint)
                    != state.ole1_client_documents.pending_dde_creations[index].endpoint
                || !receipt.retired
            {
                return Err(dde_error(
                    Kind::InternalInvariant,
                    "OLE1 DDE endpoint retirement changed its exact cleanup receipt",
                ));
            }
            finish_failed_creation(state, index, cpu, host)
        }
        _ => Ok(None),
    }
}

pub(in crate::win16_runtime) fn process_committed_event(
    state: &mut Win16State,
    event: Win16HostClassicDdeEvent,
    _cpu: &mut Cpu,
    _dos: &mut DosKernel,
    _memory: &mut Memory,
    _host: &mut impl RuntimeHost,
) -> Result<Option<(Win16Ole1OperationId, Win16Ole1ClientDdeDisposition)>, RuntimeError> {
    if event.delivery != Win16ClassicDdeDeliveryKind::Queued {
        return Ok(None);
    }
    let Some(committed) = state.ole1_client_documents.client_dde.committed_event(
        event.owner,
        event.endpoint,
        event.event_id,
    ) else {
        return Ok(None);
    };
    let Win16Ole1ClientDdeCommittedResponse::Ack {
        operation: Some(operation),
        call,
        acknowledged,
        busy,
        application_return_code,
        ..
    } = &committed.response
    else {
        return Ok(None);
    };
    let operation = *operation;
    let Some(index) = state
        .ole1_client_documents
        .pending_dde_creations
        .iter()
        .position(|seq| {
            seq.owner == event.owner
                && seq.operation == operation
                && matches!(
                    seq.stage,
                    Stage::AwaitExecuteResponse | Stage::AwaitCloseResponse
                )
        })
    else {
        return Ok(None);
    };
    let sequence = &mut state.ole1_client_documents.pending_dde_creations[index];
    let (expected_call, expected_responder, is_close) = match sequence.stage {
        Stage::AwaitExecuteResponse => (sequence.execute_call, sequence.system, false),
        Stage::AwaitCloseResponse => (sequence.close_call, sequence.close_target, true),
        _ => {
            return Err(dde_error(
                Kind::InternalInvariant,
                "OLE1 DDE response stage changed while being committed",
            ));
        }
    };
    let Some(responder) = expected_responder else {
        return Err(dde_error(
            Kind::InternalInvariant,
            "OLE1 DDE execute response lost its exact conversation",
        ));
    };
    if Some(*call) != expected_call
        || sequence.endpoint != Some(event.endpoint)
        || event.peer != responder.peer
        || event.conversation != Some(responder.conversation)
        || committed.owner != sequence.owner
        || committed.endpoint != event.endpoint
        || committed.peer != event.peer
        || committed.conversation != responder.conversation
    {
        return Err(dde_error(
            Kind::InternalInvariant,
            "OLE1 DDE execute ACK does not match its exact posted transaction",
        ));
    }
    let accepted = *acknowledged && !*busy && *application_return_code == 0;
    if is_close {
        sequence.stage = Stage::AwaitCloseDeliveryAck(event.event_id);
        sequence.close_accepted = accepted;
    } else {
        sequence.stage = Stage::AwaitExecuteDeliveryAck(event.event_id);
        sequence.execute_accepted = accepted;
    }
    Ok(Some((
        operation,
        Win16Ole1ClientDdeDisposition::EventAcknowledgementReady {
            operation,
            event_id: event.event_id,
        },
    )))
}

pub(in crate::win16_runtime) fn advance_event_ack(
    state: &mut Win16State,
    owner: OwnerId,
    operation: Win16Ole1OperationId,
    event_id: Win16ClassicDdeEventId,
    cpu: &mut Cpu,
    dos: &mut DosKernel,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<Option<Win16Ole1ClientDdeDisposition>, RuntimeError> {
    let Some(index) = state
        .ole1_client_documents
        .pending_dde_creations
        .iter()
        .position(|seq| seq.owner == owner && seq.operation == operation)
    else {
        return Ok(None);
    };
    match state.ole1_client_documents.pending_dde_creations[index].stage {
        Stage::AwaitExecuteDeliveryAck(expected) if expected == event_id => {
            if state.ole1_client_documents.pending_dde_creations[index].execute_accepted {
                start_document_initiate(state, index, host).map(Some)
            } else {
                begin_failure_cleanup(
                    state,
                    index,
                    OLE1_ERROR_OPEN,
                    "OLE1 server rejected StdNewDocument",
                    cpu,
                    dos,
                    memory,
                    host,
                )
            }
        }
        Stage::AwaitCloseDeliveryAck(expected) if expected == event_id => {
            if !state.ole1_client_documents.pending_dde_creations[index].close_accepted {
                host.report_diagnostic(&Diagnostic::warning(Kind::HostFailure,
                    "OLE1 StdCloseDocument was not acknowledged; retiring the exact DDE conversation anyway"));
            }
            begin_conversation_cleanup(state, index, cpu, dos, memory, host).map(Some)
        }
        Stage::AwaitExecuteDeliveryAck(_) | Stage::AwaitCloseDeliveryAck(_) => Err(dde_error(
            Kind::InternalInvariant,
            "OLE1 create delivery ACK changed EventId",
        )),
        _ => Ok(None),
    }
}
