pub(super) fn route_server_initiate(
    state: &Ole1ServerState,
    event: &Win16HostClassicDdeEvent,
    application: Option<u16>,
    topic: Option<u16>,
    system_topic: Option<u16>,
    ole_topic: Option<u16>,
) -> Result<Ole1ServerDdeDisposition, u16> {
    let server_endpoint = state
        .server_for_endpoint(event.owner, event.endpoint)
        .is_some();
    let document_endpoint = state
        .document_for_endpoint(event.owner, event.endpoint)
        .is_some();
    if !server_endpoint && !document_endpoint {
        return Ok(Ole1ServerDdeDisposition::NotOwned);
    }
    let Win16ClassicDdeDeliveryKind::Synchronous {
        operation_id,
        callback,
        frame,
    } = event.delivery
    else {
        return Ok(Ole1ServerDdeDisposition::OwnedMessage(event.clone()));
    };
    let crate::Win16ClassicDdeMessage::Initiate {
        application: application_atom,
        topic: topic_atom,
    } = &event.message
    else {
        return Ok(Ole1ServerDdeDisposition::OwnedMessage(event.clone()));
    };
    let Some(application) = application else {
        return Ok(reply_route(
            event,
            operation_id,
            callback,
            frame,
            false,
            None,
        ));
    };
    let Some(topic) = topic else {
        return Ok(reply_route(
            event,
            operation_id,
            callback,
            frame,
            false,
            None,
        ));
    };

    if let Some((server_handle, server)) = state.server_for_endpoint(event.owner, event.endpoint) {
        if server.state != Ole1RegistrationState::Active {
            return Ok(reply_route(
                event,
                operation_id,
                callback,
                frame,
                false,
                None,
            ));
        }
        // XP's server window responds to the registered class atom, or to the
        // executable atom only for OLE_SERVER_SINGLE. No case-folded string
        // approximation is used here.
        if application != server.class_atom
            && !(server.use_mode == Ole1ServerUse::Single && application == server.executable_atom)
        {
            return Ok(reply_route(
                event,
                operation_id,
                callback,
                frame,
                false,
                None,
            ));
        }
        if server.blocked && !server.processing_deferred_message {
            return Ok(Ole1ServerDdeDisposition::Deferred);
        }
        if Some(topic) == system_topic || Some(topic) == ole_topic {
            // XP refuses the root server conversation for a multi-document
            // server after a document/client is already present. The caller
            // can still route exact registered document topics below.
            let can_accept = server.use_mode == Ole1ServerUse::Single
                || (server.documents.is_empty() && server.conversations.is_empty());
            let target = can_accept.then_some(ServerInitTarget {
                server: server_handle,
                server_generation: server.generation,
                document: None,
                document_generation: None,
                endpoint: server.endpoint,
                peer: event.peer,
            });
            return Ok(reply_route(
                event,
                operation_id,
                callback,
                frame,
                can_accept,
                target,
            ));
        }

        // SrvrWndProc forwards a non-System/OLE topic to registered document
        // child windows. Select only the exact Win16 document atom.
        let matching_doc = state.owner_documents(event.owner).find(|(_, document)| {
            document.server == server_handle
                && document.state == Ole1DocumentState::Active
                && document.document_atom == topic
        });
        if let Some((_, document)) = matching_doc {
            return Ok(Ole1ServerDdeDisposition::HostCall {
                call: Win16HostClassicDdeCall::ForwardInitiateToChild {
                    owner: event.owner,
                    parent: event.endpoint,
                    worker_generation: event.worker_generation,
                    operation_id,
                    callback,
                    frame,
                    event_id: event.event_id,
                    child: document.endpoint,
                    peer: event.peer,
                    application_atom: application_atom.clone(),
                    topic_atom: topic_atom.clone(),
                },
                target: None,
                continuation: None,
            });
        }
        return Ok(reply_route(
            event,
            operation_id,
            callback,
            frame,
            false,
            None,
        ));
    }

    if let Some((document_handle, document)) =
        state.document_for_endpoint(event.owner, event.endpoint)
    {
        let Some((server_handle, server, _)) =
            state.server_for_document(event.owner, document_handle)
        else {
            return Ok(Ole1ServerDdeDisposition::NotOwned);
        };
        if document.state != Ole1DocumentState::Active
            || server.state != Ole1RegistrationState::Active
            || document.document_atom != topic
            || (application != server.class_atom
                && !(server.use_mode == Ole1ServerUse::Single
                    && application == server.executable_atom))
        {
            return Ok(reply_route(
                event,
                operation_id,
                callback,
                frame,
                false,
                None,
            ));
        }
        if server.blocked && !server.processing_deferred_message {
            return Ok(Ole1ServerDdeDisposition::Deferred);
        }
        // Binding is published only after the exact Host InitiateReplied
        // receipt returns a nonzero conversation.
        let target = ServerInitTarget {
            server: server_handle,
            server_generation: server.generation,
            document: Some(document_handle),
            document_generation: Some(document.generation),
            endpoint: document.endpoint,
            peer: event.peer,
        };
        return Ok(reply_route(
            event,
            operation_id,
            callback,
            frame,
            true,
            Some(target),
        ));
    }

    Ok(Ole1ServerDdeDisposition::NotOwned)
}

fn atom_value(
    atom: &Option<Win16ClassicDdeAtom>,
    host: &mut impl RuntimeHost,
) -> Result<Option<u16>, RuntimeError> {
    match atom {
        Some(Win16ClassicDdeAtom::Integer(value)) => Ok(Some(*value)),
        Some(Win16ClassicDdeAtom::Name {
            guest_value: Some(value),
            ..
        }) => Ok(Some(*value)),
        Some(Win16ClassicDdeAtom::Name {
            guest_value: None,
            name_bytes,
        }) => {
            let atom = host.win16_global_find_atom(Win16HostAtomName::String(name_bytes))?;
            Ok((atom != 0).then_some(atom))
        }
        None => Ok(None),
    }
}

fn reply_route(
    event: &Win16HostClassicDdeEvent,
    operation_id: Win16ClassicDdeOperationId,
    callback: crate::Win16HostCallback,
    frame: crate::Win16HostClassicDdeCallbackFrame,
    accepted: bool,
    target: Option<ServerInitTarget>,
) -> Ole1ServerDdeDisposition {
    let crate::Win16ClassicDdeMessage::Initiate { application, topic } = &event.message else {
        unreachable!("reply_route is constructed only for a typed INITIATE event")
    };
    Ole1ServerDdeDisposition::HostCall {
        call: Win16HostClassicDdeCall::ReplyInitiate {
            owner: event.owner,
            endpoint: event.endpoint,
            worker_generation: event.worker_generation,
            operation_id,
            callback,
            frame,
            event_id: event.event_id,
            peer: event.peer,
            accepted,
            application_atom: application.clone(),
            topic_atom: topic.clone(),
        },
        target,
        continuation: None,
    }
}

/// Convert the exact host conversation returned by ReplyInitiate into runtime
/// server/document membership. This is called only after the host's synchronous
/// ACK send has completed successfully.
pub(super) fn bind_server_initiate_receipt(
    state: &mut Ole1ServerState,
    owner: guest_core::OwnerId,
    target: ServerInitTarget,
    conversation: Win16ClassicDdeConversationId,
) -> Result<(), u16> {
    if conversation.0 == 0 {
        return Err(super::win16_ole1_server_state::OLE_ERROR_PROTOCOL);
    }
    let Some(server_record) = state.server(owner, target.server) else {
        return Err(super::win16_ole1_server_state::OLE_ERROR_HANDLE);
    };
    if server_record.generation != target.server_generation {
        return Err(super::win16_ole1_server_state::OLE_ERROR_HANDLE);
    }
    if let Some(document) = target.document {
        let Some((actual_document, document_record)) =
            state.document_for_endpoint(owner, target.endpoint)
        else {
            return Err(super::win16_ole1_server_state::OLE_ERROR_HANDLE);
        };
        if actual_document != document
            || Some(document_record.generation) != target.document_generation
            || document_record.server != target.server
        {
            return Err(super::win16_ole1_server_state::OLE_ERROR_HANDLE);
        }
    } else if server_record.endpoint != target.endpoint {
        return Err(super::win16_ole1_server_state::OLE_ERROR_HANDLE);
    }
    let binding = Ole1ConversationBinding {
        id: conversation,
        generation: target.server_generation,
        peer: target.peer,
    };
    state.bind_server_document_conversation(owner, target.server, target.document, binding)
}
