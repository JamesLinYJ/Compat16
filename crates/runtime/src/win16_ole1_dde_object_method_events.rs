use super::*;

pub(in crate::win16_runtime) fn advance_sequence(
    state: &mut Win16State,
    owner: OwnerId,
    operation: Win16Ole1OperationId,
    disposition: Win16Ole1ClientDdeDisposition,
    cpu: &mut Cpu,
    _dos: &mut DosKernel,
    _memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<Option<Win16Ole1ClientDdeDisposition>, RuntimeError> {
    let Some(index) = state
        .ole1_client_documents
        .pending_dde_methods
        .iter()
        .position(|seq| seq.owner == owner && seq.operation == operation)
    else {
        return Ok(None);
    };
    match disposition {
        Win16Ole1ClientDdeDisposition::DdeCallPosted {
            operation: found,
            call,
        } => {
            if found != operation
                || !state
                    .ole1_client_documents
                    .client_dde
                    .pending_call_matches(operation, owner, call)
                || state.ole1_client_documents.pending_dde_methods[index].call != Some(call)
            {
                return Err(dde_error(
                    Kind::InternalInvariant,
                    "DDE method POST terminal changed operation or call",
                ));
            }
            let sequence = &mut state.ole1_client_documents.pending_dde_methods[index];
            if sequence.stage != Stage::AwaitExecutePost {
                return Err(dde_error(
                    Kind::InternalInvariant,
                    "DDE method POST completed outside its reserved stage",
                ));
            }
            sequence.stage = Stage::AwaitResponse;
            Ok(Some(disposition))
        }
        Win16Ole1ClientDdeDisposition::DdeCallRejected {
            operation: found,
            call,
        } => {
            if found != operation
                || state.ole1_client_documents.pending_dde_methods[index].stage
                    != Stage::AwaitExecutePost
                || state.ole1_client_documents.pending_dde_methods[index].call != Some(call)
            {
                return Err(dde_error(
                    Kind::InternalInvariant,
                    "rejected DDE method POST changed operation or reserved stage",
                ));
            }
            host_names::retire_item_atom(state, index, host)?;
            let sequence = &state.ole1_client_documents.pending_dde_methods[index];
            let (return_to, return_kind) = (sequence.return_to, sequence.return_kind);
            host.report_diagnostic(&Diagnostic::warning(
                Kind::HostFailure,
                "native DDE queue rejected an OLE1 object-method command; returning OLE_ERROR_COMMAND",
            ));
            state.complete_return(
                &mut cpu.regs,
                return_to.0,
                return_to.1,
                return_to.2,
                u32::from(OLE1_ERROR_COMMAND),
                return_kind,
            )?;
            state
                .ole1_client_documents
                .pending_dde_methods
                .remove(index);
            Ok(Some(Win16Ole1ClientDdeDisposition::ApiCompleted {
                operation,
            }))
        }
        Win16Ole1ClientDdeDisposition::EventAcknowledgementReady {
            operation: found,
            event_id,
        } => {
            if found != operation
                || !matches!(
                    state.ole1_client_documents.pending_dde_methods[index].stage,
                    Stage::AwaitDeliveryAck { event_id: staged, .. } if staged == event_id
                )
            {
                return Err(dde_error(
                    Kind::InternalInvariant,
                    "OLE1 method EventId ACK does not match its committed response",
                ));
            }
            Ok(Some(disposition))
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
                    "DDE Release conversation receipt changed exact operation owner",
                ));
            }
            let sequence = &state.ole1_client_documents.pending_dde_methods[index];
            let retired_stage = sequence.stage;
            if sequence.slot != 1 || sequence.endpoint != Some(endpoint) {
                return Err(dde_error(
                    Kind::InternalInvariant,
                    "DDE Release conversation receipt changed endpoint or method",
                ));
            }
            let (expected, next_stage) = match sequence.stage {
                Stage::RetireDocumentConversation => {
                    (sequence.document_responder, Stage::RetireSystemConversation)
                }
                Stage::RetireSystemConversation => {
                    (sequence.system_responder, Stage::RetireEndpoint)
                }
                _ => {
                    return Err(dde_error(
                        Kind::InternalInvariant,
                        "DDE Release conversation retired outside its exact cleanup stage",
                    ));
                }
            };
            if expected.is_none_or(|expected| {
                expected.peer != peer || expected.conversation != conversation
            }) {
                return Err(dde_error(
                    Kind::InternalInvariant,
                    "DDE Release conversation receipt changed exact peer or token",
                ));
            }
            if !terminate_queued {
                host.report_diagnostic(&Diagnostic::warning(Kind::HostFailure,
                    "DDE OLE1 Release retired the exact conversation although WM_DDE_TERMINATE was not queued"));
                state.ole1_client_documents.pending_dde_methods[index].retirement_status =
                    OLE1_ERROR_TERMINATE;
            }
            match retired_stage {
                Stage::RetireDocumentConversation => {
                    state.ole1_client_documents.pending_dde_methods[index].document_responder =
                        None;
                }
                Stage::RetireSystemConversation => {
                    state.ole1_client_documents.pending_dde_methods[index].system_responder = None;
                }
                _ => {
                    return Err(dde_error(
                        Kind::InternalInvariant,
                        "DDE Release stage changed during conversation retirement",
                    ));
                }
            }
            state.ole1_client_documents.pending_dde_methods[index].stage = next_stage;
            start_dde_release_cleanup(state, index)
        }
        Win16Ole1ClientDdeDisposition::EndpointRetired {
            operation: found,
            receipt,
        } => {
            if found != operation || receipt.owner != owner || !receipt.retired {
                return Err(dde_error(
                    Kind::InternalInvariant,
                    "DDE Release endpoint retirement lacks its exact successful receipt",
                ));
            }
            let (slot, endpoint, stage, object_id) = {
                let sequence = &state.ole1_client_documents.pending_dde_methods[index];
                (
                    sequence.slot,
                    sequence.endpoint,
                    sequence.stage,
                    sequence.object_id,
                )
            };
            if slot != 1
                || Some(receipt.endpoint) != endpoint
                || !matches!(stage, Stage::RetireEndpoint | Stage::ReleaseLocalRetired)
            {
                return Err(dde_error(
                    Kind::InternalInvariant,
                    "DDE Release endpoint receipt changed the reserved endpoint or stage",
                ));
            }
            if stage == Stage::RetireEndpoint {
                state.retire_ole1_dde_object_proxy(owner, object_id)?;
                state.ole1_client_documents.pending_dde_methods[index].stage =
                    Stage::ReleaseLocalRetired;
            }
            finish_dde_object_release(state, index, cpu)
        }
        _ => Ok(None),
    }
}

fn start_dde_release_cleanup(
    state: &mut Win16State,
    index: usize,
) -> Result<Option<Win16Ole1ClientDdeDisposition>, RuntimeError> {
    let (stage, owner, operation, endpoint, endpoint_operation, system_responder) = {
        let sequence = &state.ole1_client_documents.pending_dde_methods[index];
        (
            sequence.stage,
            sequence.owner,
            sequence.operation,
            sequence.endpoint,
            sequence.endpoint_operation,
            sequence.system_responder,
        )
    };
    if stage == Stage::RetireSystemConversation && system_responder.is_some() {
        let endpoint = endpoint.ok_or_else(|| {
            dde_error(
                Kind::InternalInvariant,
                "DDE Release lost endpoint before system conversation retirement",
            )
        })?;
        let responder = system_responder.ok_or_else(|| {
            dde_error(
                Kind::InternalInvariant,
                "DDE Release system conversation disappeared",
            )
        })?;
        let disposition = state
            .ole1_client_documents
            .client_dde
            .prepare_client_conversation_retirement(
                operation,
                owner,
                endpoint,
                responder.peer,
                responder.conversation,
            )
            .map_err(|message| dde_error(Kind::InvalidInput, message))?;
        return Ok(Some(disposition));
    }
    let endpoint = endpoint.ok_or_else(|| {
        dde_error(
            Kind::InternalInvariant,
            "DDE Release lost endpoint before endpoint retirement",
        )
    })?;
    let endpoint_operation = endpoint_operation.ok_or_else(|| {
        dde_error(
            Kind::InternalInvariant,
            "DDE Release lost the endpoint creation operation",
        )
    })?;
    let disposition = state
        .ole1_client_documents
        .client_dde
        .prepare_client_endpoint_retirement(operation, endpoint_operation, owner, endpoint)
        .map_err(|message| dde_error(Kind::InvalidInput, message))?;
    state.ole1_client_documents.pending_dde_methods[index].stage = Stage::RetireEndpoint;
    Ok(Some(disposition))
}

fn finish_dde_object_release(
    state: &mut Win16State,
    index: usize,
    cpu: &mut Cpu,
) -> Result<Option<Win16Ole1ClientDdeDisposition>, RuntimeError> {
    let sequence = &state.ole1_client_documents.pending_dde_methods[index];
    if sequence.stage != Stage::ReleaseLocalRetired {
        return Err(dde_error(
            Kind::InternalInvariant,
            "DDE Release guest return began before local object retirement",
        ));
    }
    let (operation, return_to, return_kind, status) = (
        sequence.operation,
        sequence.return_to,
        sequence.return_kind,
        sequence.retirement_status,
    );
    state.complete_return(
        &mut cpu.regs,
        return_to.0,
        return_to.1,
        return_to.2,
        u32::from(status),
        return_kind,
    )?;
    state.ole1_client_documents.finish_operation(operation);
    state
        .ole1_client_documents
        .pending_dde_methods
        .remove(index);
    Ok(Some(Win16Ole1ClientDdeDisposition::ApiCompleted {
        operation,
    }))
}

pub(in crate::win16_runtime) fn process_committed_event(
    state: &mut Win16State,
    event: Win16HostClassicDdeEvent,
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
    let Some(sequence) = state
        .ole1_client_documents
        .pending_dde_methods
        .iter_mut()
        .find(|seq| {
            seq.owner == event.owner
                && seq.operation == operation
                && seq.stage == Stage::AwaitResponse
        })
    else {
        return Ok(None);
    };
    if sequence.call != Some(*call) {
        return Err(dde_error(
            Kind::InternalInvariant,
            "DDE method ACK changed the exact reserved transaction",
        ));
    }
    if state
        .ole1_client_documents
        .dde_object_proxies
        .iter()
        .all(|object| object.id != sequence.object_id || object.endpoint != event.endpoint)
    {
        return Err(dde_error(
            Kind::InternalInvariant,
            "DDE method response endpoint does not match its object",
        ));
    }
    let status = if *acknowledged && !*busy && *application_return_code == 0 {
        OLE1_OK
    } else {
        OLE1_ERROR_COMMAND
    };
    sequence.stage = Stage::AwaitDeliveryAck {
        event_id: event.event_id,
        status,
    };
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
    event_id: crate::Win16ClassicDdeEventId,
    cpu: &mut Cpu,
    host: &mut impl RuntimeHost,
) -> Result<Option<Win16Ole1ClientDdeDisposition>, RuntimeError> {
    let Some(index) = state
        .ole1_client_documents
        .pending_dde_methods
        .iter()
        .position(|seq| seq.owner == owner && seq.operation == operation)
    else {
        return Ok(None);
    };
    let sequence = &state.ole1_client_documents.pending_dde_methods[index];
    let Stage::AwaitDeliveryAck {
        event_id: expected,
        status,
    } = sequence.stage
    else {
        return Ok(None);
    };
    if expected != event_id {
        return Err(dde_error(
            Kind::InternalInvariant,
            "DDE method delivery ACK changed EventId",
        ));
    }
    if status == OLE1_OK {
        if let Some(record) = state
            .ole1_client_documents
            .dde_object_proxies
            .iter_mut()
            .find(|record| record.id == sequence.object_id)
        {
            if sequence.slot == 20 {
                record.closed = true;
            }
            if let (Some(application), Some(document)) = (
                sequence.next_application.as_ref(),
                sequence.next_document.as_ref(),
            ) {
                record.client_application = application.clone();
                record.document_name = document.clone();
            }
        } else {
            return Err(dde_error(
                Kind::InternalInvariant,
                "DDE method completion lost its live object proxy",
            ));
        }
    }
    host_names::retire_item_atom(state, index, host)?;
    let sequence = &state.ole1_client_documents.pending_dde_methods[index];
    let (return_to, return_kind) = (sequence.return_to, sequence.return_kind);
    state.complete_return(
        &mut cpu.regs,
        return_to.0,
        return_to.1,
        return_to.2,
        u32::from(status),
        return_kind,
    )?;
    state
        .ole1_client_documents
        .pending_dde_methods
        .remove(index);
    Ok(Some(Win16Ole1ClientDdeDisposition::ApiCompleted {
        operation,
    }))
}
