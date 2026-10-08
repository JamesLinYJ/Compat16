use super::*;

impl super::super::Win16State {
    /// Prepare the checked server callback selected by one exact live DDE
    /// conversation. Standard document commands reserve their child endpoint,
    /// document token, and callback scratch before entry; application data is
    /// sent only to the registered Execute slot.
    pub(in crate::win16_runtime) fn prepare_server_execute_callback(
        &mut self,
        event: &Win16HostClassicDdeEvent,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Result<Option<Ole1ServerGuestCallbackPlan>, u16>, RuntimeError> {
        let Win16ClassicDdeMessage::Execute { global } = &event.message else {
            return Ok(Err(OLE_ERROR_PROTOCOL));
        };
        let Some(guest_global) = global.guest_global else {
            return Ok(Err(OLE_ERROR_HANDLE));
        };
        if guest_global.owner != event.owner
            || guest_global.handle == 0
            || guest_global.generation == 0
        {
            return Ok(Err(OLE_ERROR_HANDLE));
        }
        let Some(transfer) = global.transfer else {
            return Ok(Err(OLE_ERROR_PROTOCOL));
        };
        let Some(conversation) = event.conversation else {
            return Ok(Err(OLE_ERROR_TERMINATE));
        };
        let Some(context) = self.ole1_server_state.conversation_target(
            event.owner,
            event.endpoint,
            conversation,
            event.peer,
        ) else {
            return Ok(Err(OLE_ERROR_TERMINATE));
        };
        let Some((server_handle, server)) =
            self.ole1_server_state
                .owner_servers(event.owner)
                .find(|(handle, record)| {
                    *handle == context.server && record.generation == context.server_generation
                })
        else {
            return Ok(Err(OLE_ERROR_HANDLE));
        };
        if server.blocked {
            return Ok(Err(OLE_ERROR_SERVER_BLOCKED));
        }
        let server_generation = server.generation;
        let server_far = server.server_far;
        let server_endpoint = server.endpoint;
        let server_worker_generation = server.endpoint_worker_generation;
        let mut server_class_name = Vec::new();
        server_class_name
            .try_reserve_exact(server.class_name.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    crate::DiagnosticKind::ResourceExhausted,
                    "copy OLE1 server class name for callback preparation",
                    error,
                )
            })?;
        server_class_name.extend_from_slice(&server.class_name);

        let command = match parse_server_execute(&global.bytes) {
            Ok(command) => command,
            Err(status) => return Ok(Err(status)),
        };
        let allow_document_self_retirement =
            matches!(&command, ServerExecuteCommand::CloseDocument { .. });
        let target;
        let procedure;
        let return_kind;
        let arguments;
        let mut prepared_document = None;

        match (context.document, command) {
            (None, ServerExecuteCommand::ApplicationSpecific) => {
                if !server_has_protocol(host, &server_class_name, b"StdExecute")? {
                    return Ok(Err(OLE_ERROR_PROTOCOL));
                }
                target = Ole1ServerCallbackTarget::Server {
                    handle: server_handle,
                    generation: server_generation,
                };
                let callback = ServerCallbackArguments::Execute {
                    server_far,
                    command_hglobal: guest_global.handle,
                };
                let callback_method = callback.method();
                procedure = match self.ole1_server_method_address(
                    server_far,
                    callback_method.vtable_slot(),
                    memory,
                ) {
                    Ok(address) => address,
                    Err(error) => {
                        return match super::super::win16_ole1_server_wire::status_or_runtime(error)
                        {
                            Ok(status) => Ok(Err(status)),
                            Err(error) => Err(error),
                        };
                    }
                };
                return_kind = callback.callback_return();
                arguments = callback.encode();
            }
            (Some(document_handle), ServerExecuteCommand::ApplicationSpecific) => {
                let Some(document) = self
                    .ole1_server_state
                    .document(event.owner, document_handle)
                    .filter(|record| Some(record.generation) == context.document_generation)
                else {
                    return Ok(Err(OLE_ERROR_HANDLE));
                };
                let Some(document_far) = document.server_document_far else {
                    return Ok(Err(OLE_ERROR_OBJECT));
                };
                if !server_has_protocol(host, &server_class_name, b"StdExecute")? {
                    return Ok(Err(OLE_ERROR_PROTOCOL));
                }
                target = Ole1ServerCallbackTarget::Document {
                    handle: document_handle,
                    generation: document.generation,
                };
                let callback = ServerDocumentCallbackArguments::Execute {
                    server_document_far: document_far,
                    command_hglobal: guest_global.handle,
                };
                let callback_method = callback.method();
                procedure = match self.ole1_server_document_method_address(
                    document_far,
                    callback_method.vtable_slot(),
                    memory,
                ) {
                    Ok(address) => address,
                    Err(error) => {
                        return match super::super::win16_ole1_server_wire::status_or_runtime(error)
                        {
                            Ok(status) => Ok(Err(status)),
                            Err(error) => Err(error),
                        };
                    }
                };
                return_kind = callback.callback_return();
                arguments = callback.encode();
            }
            (None, ServerExecuteCommand::Exit) => {
                target = Ole1ServerCallbackTarget::Server {
                    handle: server_handle,
                    generation: server_generation,
                };
                let callback = ServerCallbackArguments::Exit { server_far };
                let callback_method = callback.method();
                procedure = match self.ole1_server_method_address(
                    server_far,
                    callback_method.vtable_slot(),
                    memory,
                ) {
                    Ok(address) => address,
                    Err(error) => {
                        return match super::super::win16_ole1_server_wire::status_or_runtime(error)
                        {
                            Ok(status) => Ok(Err(status)),
                            Err(error) => Err(error),
                        };
                    }
                };
                return_kind = callback.callback_return();
                arguments = callback.encode();
            }
            (None, ServerExecuteCommand::CloseDocument { document: name }) => {
                let Some((document_handle, document)) =
                    self.ole1_server_state
                        .document_by_name(event.owner, server_handle, &name)
                else {
                    return Ok(Err(OLE_ERROR_NAME));
                };
                let Some(document_far) = document.server_document_far else {
                    return Ok(Err(OLE_ERROR_OBJECT));
                };
                let document_generation = document.generation;
                target = Ole1ServerCallbackTarget::Document {
                    handle: document_handle,
                    generation: document_generation,
                };
                let callback = ServerDocumentCallbackArguments::Close {
                    server_document_far: document_far,
                };
                let callback_method = callback.method();
                procedure = match self.ole1_server_document_method_address(
                    document_far,
                    callback_method.vtable_slot(),
                    memory,
                ) {
                    Ok(address) => address,
                    Err(error) => {
                        return match super::super::win16_ole1_server_wire::status_or_runtime(error)
                        {
                            Ok(status) => Ok(Err(status)),
                            Err(error) => Err(error),
                        };
                    }
                };
                return_kind = callback.callback_return();
                arguments = callback.encode();
            }
            (None, ServerExecuteCommand::OpenDocument { document }) => {
                let mut matching_document = false;
                let mut published_document = false;
                for (_, existing) in self.ole1_server_state.owner_documents(event.owner) {
                    if existing.server != server_handle
                        || !existing.name.eq_ignore_ascii_case(&document)
                    {
                        continue;
                    }
                    matching_document = true;
                    if existing.state
                        == super::super::win16_ole1_server_state::Ole1DocumentState::Active
                        && existing.guest_handle_published
                        && existing.server_document_far.is_some()
                        && existing.prepared_callback_scratch.is_none()
                    {
                        published_document = true;
                        break;
                    }
                }
                if published_document {
                    return Ok(Ok(None));
                }
                if matching_document {
                    return Ok(Err(OLE_BUSY));
                }
                let prepared = match self.prepare_server_document_callback(
                    event,
                    server_handle,
                    server_generation,
                    server_far,
                    server_endpoint,
                    server_worker_generation,
                    ServerCallbackMethod::Open,
                    None,
                    &document,
                    None,
                    memory,
                    host,
                )? {
                    Ok(prepared) => prepared,
                    Err(status) => return Ok(Err(status)),
                };
                let (
                    prepared_target,
                    prepared_procedure,
                    prepared_return,
                    prepared_arguments,
                    proof,
                ) = prepared;
                target = prepared_target;
                procedure = prepared_procedure;
                return_kind = prepared_return;
                arguments = prepared_arguments;
                prepared_document = Some(proof);
            }
            (
                None,
                ServerExecuteCommand::NewDocument {
                    class_name,
                    document,
                },
            ) => {
                let prepared = match self.prepare_server_document_callback(
                    event,
                    server_handle,
                    server_generation,
                    server_far,
                    server_endpoint,
                    server_worker_generation,
                    ServerCallbackMethod::Create,
                    Some(&class_name),
                    &document,
                    None,
                    memory,
                    host,
                )? {
                    Ok(prepared) => prepared,
                    Err(status) => return Ok(Err(status)),
                };
                let (
                    prepared_target,
                    prepared_procedure,
                    prepared_return,
                    prepared_arguments,
                    proof,
                ) = prepared;
                target = prepared_target;
                procedure = prepared_procedure;
                return_kind = prepared_return;
                arguments = prepared_arguments;
                prepared_document = Some(proof);
            }
            (
                None,
                ServerExecuteCommand::NewFromTemplate {
                    class_name,
                    document,
                    template,
                },
            ) => {
                let prepared = match self.prepare_server_document_callback(
                    event,
                    server_handle,
                    server_generation,
                    server_far,
                    server_endpoint,
                    server_worker_generation,
                    ServerCallbackMethod::CreateFromTemplate,
                    Some(&class_name),
                    &document,
                    Some(&template),
                    memory,
                    host,
                )? {
                    Ok(prepared) => prepared,
                    Err(status) => return Ok(Err(status)),
                };
                let (
                    prepared_target,
                    prepared_procedure,
                    prepared_return,
                    prepared_arguments,
                    proof,
                ) = prepared;
                target = prepared_target;
                procedure = prepared_procedure;
                return_kind = prepared_return;
                arguments = prepared_arguments;
                prepared_document = Some(proof);
            }
            (None, ServerExecuteCommand::EditDocument { document }) => {
                let prepared = match self.prepare_server_document_callback(
                    event,
                    server_handle,
                    server_generation,
                    server_far,
                    server_endpoint,
                    server_worker_generation,
                    ServerCallbackMethod::Edit,
                    Some(&server_class_name),
                    &document,
                    None,
                    memory,
                    host,
                )? {
                    Ok(prepared) => prepared,
                    Err(status) => return Ok(Err(status)),
                };
                let (
                    prepared_target,
                    prepared_procedure,
                    prepared_return,
                    prepared_arguments,
                    proof,
                ) = prepared;
                target = prepared_target;
                procedure = prepared_procedure;
                return_kind = prepared_return;
                arguments = prepared_arguments;
                prepared_document = Some(proof);
            }
            // Item rendering/show commands require a live item binding and
            // dispatch to that object's checked OLEOBJECT vtable. They are
            // not generic Execute data.
            (_, ServerExecuteCommand::ShowItem { .. }) => {
                return Ok(Err(OLE_ERROR_COMMAND));
            }
            _ => return Ok(Err(OLE_ERROR_COMMAND)),
        }

        let completion = Ole1ServerCallbackCompletion::DdeExecute {
            event: event.clone(),
            target,
            transfer,
            global_handle: guest_global.handle,
            global_generation: guest_global.generation,
            allow_document_self_retirement,
            prepared_document,
        };
        Ok(Ok(Some(Ole1ServerGuestCallbackPlan {
            owner: event.owner,
            target,
            procedure,
            arguments,
            return_kind,
            completion,
        })))
    }
}
