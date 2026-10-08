use super::*;

pub(super) fn start_initiate(
    state: &mut Win16State,
    index: usize,
    purpose: Win16Ole1InitiatePurpose,
    application: &[u8],
    topic: &[u8],
    host: &mut impl RuntimeHost,
) -> Result<Option<Win16Ole1ClientDdeDisposition>, RuntimeError> {
    let sequence = &state.ole1_client_documents.pending_dde_creations[index];
    let endpoint = sequence.endpoint.ok_or_else(|| {
        dde_error(
            Kind::InternalInvariant,
            "OLE1 INITIATE lost its exact DDE endpoint",
        )
    })?;
    if application.is_empty() || topic.is_empty() || application.contains(&0) || topic.contains(&0)
    {
        return Err(dde_error(
            Kind::InvalidInput,
            "OLE1 DDE INITIATE application/topic is empty or contains a NUL",
        ));
    }
    let operation = sequence.operation;
    let owner = sequence.owner;
    state
        .ole1_client_documents
        .client_dde
        .reserve_unmaterialized_initiate_attempt(
            operation,
            owner,
            endpoint,
            application,
            topic,
            purpose,
        )
        .map_err(|message| dde_error(Kind::InvalidInput, message))?;
    let (application_atom, topic_atom) = match state.create_classic_dde_client_initiate_atoms(
        owner,
        endpoint,
        operation,
        application,
        topic,
        host,
    ) {
        Ok(atoms) => atoms,
        Err(primary) => {
            return match state
                .retire_classic_dde_client_initiate_atoms(owner, endpoint, operation, host)
            {
                Ok(()) => {
                    if let Err(cleanup) = state
                        .ole1_client_documents
                        .client_dde
                        .discard_unhosted_initiate_attempt(operation, owner, endpoint)
                    {
                        return Err(primary.with_cleanup(
                            "discard OLE1 INITIATE reservation after atom rollback",
                            dde_error(Kind::InternalInvariant, cleanup),
                        ));
                    }
                    Err(primary)
                }
                Err(cleanup) => {
                    Err(primary.with_cleanup("retry exact OLE1 INITIATE atom rollback", cleanup))
                }
            };
        }
    };
    let disposition = match state
        .ole1_client_documents
        .client_dde
        .prepare_reserved_initiate_call(
            operation,
            owner,
            endpoint,
            application_atom,
            topic_atom,
            application,
            topic,
            purpose,
        ) {
        Ok(disposition) => disposition,
        Err(primary) => {
            let primary = dde_error(Kind::InvalidInput, primary);
            return match state
                .retire_classic_dde_client_initiate_atoms(owner, endpoint, operation, host)
            {
                Ok(()) => {
                    if let Err(cleanup) = state
                        .ole1_client_documents
                        .client_dde
                        .discard_unhosted_initiate_attempt(operation, owner, endpoint)
                    {
                        return Err(primary.with_cleanup(
                            "discard failed OLE1 INITIATE attempt",
                            dde_error(Kind::InternalInvariant, cleanup),
                        ));
                    }
                    Err(primary)
                }
                Err(cleanup) => Err(primary.with_cleanup(
                    "retire OLE1 INITIATE atom leases after preparation failed",
                    cleanup,
                )),
            };
        }
    };
    state.ole1_client_documents.pending_dde_creations[index].initiate_purpose = Some(purpose);
    state.ole1_client_documents.pending_dde_creations[index].stage = Stage::AwaitInitiate;
    Ok(Some(disposition))
}

pub(super) fn start_new_document(
    state: &mut Win16State,
    index: usize,
) -> Result<Option<Win16Ole1ClientDdeDisposition>, RuntimeError> {
    let sequence = &state.ole1_client_documents.pending_dde_creations[index];
    let system = sequence.system.ok_or_else(|| {
        dde_error(
            Kind::InternalInvariant,
            "OLE1 StdNewDocument has no system conversation",
        )
    })?;
    let endpoint = sequence.endpoint.ok_or_else(|| {
        dde_error(
            Kind::InternalInvariant,
            "OLE1 StdNewDocument lost its endpoint",
        )
    })?;
    let message = super::super::client_dde::new_document_execute(
        &sequence.class_name,
        &sequence.document_topic,
    )
    .map_err(|error| {
        dde_error(
            Kind::InvalidInput,
            format!("encode OLE1 StdNewDocument: {error:?}"),
        )
    })?;
    let operation = sequence.operation;
    let owner = sequence.owner;
    let disposition = state
        .ole1_client_documents
        .client_dde
        .prepare_post_transaction(
            operation,
            owner,
            endpoint,
            system.peer,
            system.conversation,
            WM_DDE_EXECUTE,
            Win16Ole1ExpectedReply::ExecuteAck,
            message,
        )
        .map_err(|message| dde_error(Kind::InvalidInput, message))?;
    let call = state
        .ole1_client_documents
        .client_dde
        .pending_call_for_operation(operation, owner)
        .map_err(|message| dde_error(Kind::InternalInvariant, message))?;
    state.ole1_client_documents.pending_dde_creations[index].stage = Stage::AwaitExecutePost;
    state.ole1_client_documents.pending_dde_creations[index].execute_call = Some(call);
    Ok(Some(disposition))
}

pub(super) fn start_document_initiate(
    state: &mut Win16State,
    index: usize,
    host: &mut impl RuntimeHost,
) -> Result<Win16Ole1ClientDdeDisposition, RuntimeError> {
    let (class_name, topic) = {
        let sequence = &state.ole1_client_documents.pending_dde_creations[index];
        (
            copy_bytes(&sequence.class_name, "copy OLE1 class name")?,
            copy_bytes(&sequence.document_topic, "copy OLE1 embedded topic")?,
        )
    };
    start_initiate(
        state,
        index,
        Win16Ole1InitiatePurpose::DocumentTopic,
        &class_name,
        &topic,
        host,
    )?
    .ok_or_else(|| {
        dde_error(
            Kind::InternalInvariant,
            "OLE1 document INITIATE preparation returned no host action",
        )
    })
}

pub(super) fn publish_object(
    state: &mut Win16State,
    index: usize,
    memory: &mut Memory,
) -> Result<u32, PublishFailure> {
    let sequence = &state.ole1_client_documents.pending_dde_creations[index];
    let (Some(endpoint), Some(system_responder), Some(document_responder)) = (
        sequence.endpoint,
        sequence.system,
        sequence.document_conversation,
    ) else {
        return Err(PublishFailure::Runtime(dde_error(
            Kind::InternalInvariant,
            "OLE1 object publish lacks its endpoint or exact conversations",
        )));
    };
    let spec = Win16Ole1DdeObjectProxySpec {
        document: sequence.document,
        client_far: sequence.client_far,
        client_proxy_id: sequence.client_proxy_id,
        operation_id: sequence.operation,
        owner: sequence.owner,
        endpoint,
        system_responder,
        document_responder,
        server_application: copy_bytes(
            &sequence.server_application,
            "copy OLE1 server application",
        )?,
        client_application: copy_bytes(
            &sequence.client_application,
            "copy OLE1 client application",
        )?,
        document_name: copy_bytes(&sequence.document_name, "copy OLE1 document name")?,
        class_name: copy_bytes(&sequence.class_name, "copy OLE1 class name")?,
        object_name: copy_bytes(&sequence.object_name, "copy OLE1 object name")?,
        document_topic: copy_bytes(&sequence.document_topic, "copy OLE1 embedded topic")?,
    };
    let output = sequence.output;
    state
        .publish_ole1_dde_object_proxy(spec, output, memory)
        .map_err(|error| match error {
            super::super::object_proxy::Win16Ole1ObjectProxyError::Status(status) => {
                PublishFailure::Status(status)
            }
            super::super::object_proxy::Win16Ole1ObjectProxyError::Runtime(error) => {
                PublishFailure::Runtime(error)
            }
        })
}

pub(super) enum PublishFailure {
    Status(Win16Ole1Status),
    Runtime(RuntimeError),
}

pub(super) fn begin_failure_cleanup(
    state: &mut Win16State,
    index: usize,
    status: Win16Ole1Status,
    detail: &'static str,
    cpu: &mut Cpu,
    dos: &mut DosKernel,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<Option<Win16Ole1ClientDdeDisposition>, RuntimeError> {
    let sequence = &mut state.ole1_client_documents.pending_dde_creations[index];
    if sequence.failure_status.is_none() {
        sequence.failure_status = Some(status);
        sequence.failure_detail = Some(detail);
    }
    if sequence.execute_accepted
        && sequence.close_target.is_none()
        && !matches!(
            sequence.stage,
            Stage::AwaitClosePost | Stage::AwaitCloseResponse | Stage::AwaitCloseDeliveryAck(_)
        )
    {
        match start_close(state, index) {
            Ok(disposition) => return Ok(Some(disposition)),
            Err(error) => {
                if state.ole1_client_documents.pending_dde_creations[index]
                    .fatal
                    .is_none()
                {
                    state.ole1_client_documents.pending_dde_creations[index].fatal = Some(error);
                }
            }
        }
    }
    begin_conversation_cleanup(state, index, cpu, dos, memory, host).map(Some)
}

fn start_close(
    state: &mut Win16State,
    index: usize,
) -> Result<Win16Ole1ClientDdeDisposition, RuntimeError> {
    let sequence = &state.ole1_client_documents.pending_dde_creations[index];
    let target = sequence
        .document_conversation
        .or(sequence.system)
        .ok_or_else(|| {
            dde_error(
                Kind::InternalInvariant,
                "accepted OLE1 StdNewDocument lost every conversation",
            )
        })?;
    let endpoint = sequence.endpoint.ok_or_else(|| {
        dde_error(
            Kind::InternalInvariant,
            "OLE1 StdCloseDocument lost its endpoint",
        )
    })?;
    let bytes = super::super::stdexecute::encode_win16_ole1_std_execute(
        super::super::stdexecute::Win16Ole1StdExecuteCommand::CloseDocument,
    )
    .map_err(|error| {
        dde_error(
            Kind::InvalidInput,
            format!("encode OLE1 StdCloseDocument: {error:?}"),
        )
    })?;
    let message = Win16ClassicDdeMessage::Execute {
        global: crate::Win16ClassicDdeGlobalBlock {
            transfer: None,
            guest_global: None,
            bytes,
        },
    };
    let operation = sequence.operation;
    let owner = sequence.owner;
    let disposition = state
        .ole1_client_documents
        .client_dde
        .prepare_post_transaction(
            operation,
            owner,
            endpoint,
            target.peer,
            target.conversation,
            WM_DDE_EXECUTE,
            Win16Ole1ExpectedReply::ExecuteAck,
            message,
        )
        .map_err(|message| dde_error(Kind::InvalidInput, message))?;
    let call = state
        .ole1_client_documents
        .client_dde
        .pending_call_for_operation(operation, owner)
        .map_err(|message| dde_error(Kind::InternalInvariant, message))?;
    state.ole1_client_documents.pending_dde_creations[index].close_target = Some(target);
    state.ole1_client_documents.pending_dde_creations[index].close_call = Some(call);
    state.ole1_client_documents.pending_dde_creations[index].stage = Stage::AwaitClosePost;
    Ok(disposition)
}

pub(super) fn begin_conversation_cleanup(
    state: &mut Win16State,
    index: usize,
    _cpu: &mut Cpu,
    _dos: &mut DosKernel,
    _memory: &mut Memory,
    _host: &mut impl RuntimeHost,
) -> Result<Win16Ole1ClientDdeDisposition, RuntimeError> {
    if state.ole1_client_documents.pending_dde_creations[index]
        .document_conversation
        .is_some()
    {
        start_conversation_retirement(state, index, true)
    } else if state.ole1_client_documents.pending_dde_creations[index]
        .system
        .is_some()
    {
        start_conversation_retirement(state, index, false)
    } else {
        start_endpoint_retirement(state, index)
    }
}

pub(super) fn start_conversation_retirement(
    state: &mut Win16State,
    index: usize,
    document: bool,
) -> Result<Win16Ole1ClientDdeDisposition, RuntimeError> {
    let sequence = &state.ole1_client_documents.pending_dde_creations[index];
    let responder = if document {
        sequence.document_conversation
    } else {
        sequence.system
    }
    .ok_or_else(|| {
        dde_error(
            Kind::InternalInvariant,
            "OLE1 cleanup lost its conversation",
        )
    })?;
    let endpoint = sequence
        .endpoint
        .ok_or_else(|| dde_error(Kind::InternalInvariant, "OLE1 cleanup lost its endpoint"))?;
    let operation = sequence.operation;
    let owner = sequence.owner;
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
    state.ole1_client_documents.pending_dde_creations[index].stage = if document {
        Stage::RetireDocumentConversation
    } else {
        Stage::RetireSystemConversation
    };
    Ok(disposition)
}

pub(super) fn start_endpoint_retirement(
    state: &mut Win16State,
    index: usize,
) -> Result<Win16Ole1ClientDdeDisposition, RuntimeError> {
    let sequence = &state.ole1_client_documents.pending_dde_creations[index];
    let endpoint = sequence.endpoint.ok_or_else(|| {
        dde_error(
            Kind::InternalInvariant,
            "OLE1 endpoint cleanup lost its exact endpoint",
        )
    })?;
    let disposition = state
        .ole1_client_documents
        .client_dde
        .prepare_endpoint_retirement(sequence.operation, sequence.owner, endpoint)
        .map_err(|message| dde_error(Kind::InvalidInput, message))?;
    state.ole1_client_documents.pending_dde_creations[index].stage = Stage::RetireEndpoint;
    Ok(disposition)
}

impl From<RuntimeError> for PublishFailure {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}
