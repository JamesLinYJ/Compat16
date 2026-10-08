//! OLE1 client DDE initiation and Standard Execute wire builders.
//!
//! These helpers only construct protocol messages and exact callback replies;
//! neither a host Send/Post result nor an EXECUTE ACK fabricates an OLEOBJECT.

use super::super::stdexecute;
use super::*;

/// Bind one exact INITIATE ACK responder before allowing the broadcast's
/// suspended WndProc callback to continue. The returned callback reply is only
/// a resume token; it does not complete the OLE1 API or retire the source
/// operation.
pub(in crate::win16_runtime) fn bind_initiate_responder(
    operation: Win16Ole1OperationId,
    step: &Win16HostClassicDdeCallbackStep,
    candidate: Win16Ole1InitiateCandidate,
) -> Result<Win16Ole1ClientDdeDisposition, RuntimeError> {
    let Win16ClassicDdeDeliveryKind::Synchronous {
        operation_id,
        callback,
        frame,
    } = step.event.delivery
    else {
        return Err(RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "INITIATE responder is not in a synchronous callback frame",
        ));
    };
    if candidate.operation != operation
        || candidate.source_operation.owner != step.owner
        || candidate.source_operation.id != operation_id
        || candidate.source_operation.worker_generation != step.worker_generation
        || candidate.endpoint != step.endpoint
        || candidate.event_id != step.event.event_id
        || candidate.peer != step.event.peer
        || candidate.callback != callback
        || candidate.frame != frame
        || candidate.causal_parents != step.causal_parents
    {
        return Err(RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "INITIATE responder candidate changed its exact callback source",
        ));
    }
    if !matches!(
        &step.event.message,
        Win16ClassicDdeMessage::Ack {
            value: Win16ClassicDdeAckValue::InitiateAtoms { .. },
            ..
        }
    ) {
        return Err(RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "INITIATE responder binding was requested for a non-INITIATE ACK",
        ));
    }
    let reply = candidate
        .callback_reply()
        .map_err(|message| RuntimeError::new(crate::DiagnosticKind::ResourceExhausted, message))?;
    let application = clone_atom(&candidate.application)
        .map_err(|message| RuntimeError::new(crate::DiagnosticKind::ResourceExhausted, message))?;
    let topic = clone_atom(&candidate.topic)
        .map_err(|message| RuntimeError::new(crate::DiagnosticKind::ResourceExhausted, message))?;
    Ok(Win16Ole1ClientDdeDisposition::HostCall {
        operation,
        call: Win16HostClassicDdeCall::BindConversation {
            owner: candidate.source_operation.owner,
            endpoint: candidate.endpoint,
            peer: candidate.peer,
            source_operation: candidate.source_operation,
            initiate_event_id: candidate.event_id,
            application: Some(application),
            topic: Some(topic),
        },
        resume_callback: Some(reply),
    })
}

/// Build one exact class/topic pair used for an OLE1 server INITIATE. The
/// system conversation uses `OLEsystem` first and retries `System` only when
/// the first broadcast produced no matching responder. A document
/// conversation uses the separately constructed embedded topic below. The
/// The caller supplies both WORDs returned by the task's real GlobalAddAtom
/// service and retains those exact atom references through the conversation
/// lifetime. The host uses only the owned spelling bytes for native atoms;
/// the guest WORD is identity metadata, never a native ATOM value.
pub(in crate::win16_runtime) fn client_initiate_message(
    application_atom: u16,
    topic_atom: u16,
    application_name: &[u8],
    topic_name: &[u8],
) -> Result<Win16ClassicDdeMessage, &'static str> {
    if application_atom == 0
        || topic_atom == 0
        || application_name.is_empty()
        || topic_name.is_empty()
        || application_name.contains(&0)
        || topic_name.contains(&0)
    {
        return Err("OLE1 DDE INITIATE requires bounded NUL-free application and topic names");
    }
    let mut application = Vec::new();
    application
        .try_reserve_exact(application_name.len())
        .map_err(|_| "OLE1 DDE application atom name cannot grow")?;
    application.extend_from_slice(application_name);
    let mut topic = Vec::new();
    topic
        .try_reserve_exact(topic_name.len())
        .map_err(|_| "OLE1 DDE topic atom name cannot grow")?;
    topic.extend_from_slice(topic_name);
    Ok(Win16ClassicDdeMessage::Initiate {
        application: Some(Win16ClassicDdeAtom::Name {
            guest_value: Some(application_atom),
            name_bytes: application,
        }),
        topic: Some(Win16ClassicDdeAtom::Name {
            guest_value: Some(topic_atom),
            name_bytes: topic,
        }),
    })
}

/// Exact bounded `SetEmbeddedTopic` spelling from NTVDM `ole/client/le.c`:
/// `<client document class>%<document basename>%<object name>#NNN`.
/// The process-wide serial starts at 001, advances before use, and wraps after
/// 999 to 000 like the source implementation. `document_name` strips only
/// backslash and drive-colon path components, matching that implementation.
pub(in crate::win16_runtime) fn embedded_document_topic(
    client_document_class: &[u8],
    document_name: &[u8],
    object_name: &[u8],
    serial: u16,
) -> Result<Vec<u8>, &'static str> {
    const MAX_ATOM_NAME_BYTES: usize = 255;
    if client_document_class.is_empty()
        || document_name.is_empty()
        || client_document_class.contains(&0)
        || document_name.contains(&0)
        || object_name.contains(&0)
        || serial > 999
    {
        return Err("invalid Win16 OLE embedded document topic component");
    }
    let basename = document_name
        .iter()
        .rposition(|byte| matches!(*byte, b'\\' | b':'))
        .map_or(document_name, |index| &document_name[index + 1..]);
    if basename.is_empty() {
        return Err("Win16 OLE client document has an empty basename");
    }
    let total = client_document_class
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(basename.len()))
        .and_then(|length| length.checked_add(1))
        .and_then(|length| length.checked_add(object_name.len()))
        .and_then(|length| length.checked_add(4))
        .ok_or("Win16 OLE embedded document topic length overflowed")?;
    if total > MAX_ATOM_NAME_BYTES {
        return Err("Win16 OLE embedded document topic exceeds atom-name capacity");
    }
    let mut topic = Vec::new();
    topic
        .try_reserve_exact(total)
        .map_err(|_| "Win16 OLE embedded document topic cannot grow")?;
    topic.extend_from_slice(client_document_class);
    topic.push(b'%');
    topic.extend_from_slice(basename);
    topic.push(b'%');
    topic.extend_from_slice(object_name);
    topic.push(b'#');
    topic.push(b'0' + u8::try_from(serial / 100).unwrap_or(0));
    topic.push(b'0' + u8::try_from((serial / 10) % 10).unwrap_or(0));
    topic.push(b'0' + u8::try_from(serial % 10).unwrap_or(0));
    Ok(topic)
}

/// State for the process-wide embedded-topic suffix used by NTVDM's OLE1
/// client. The first allocated suffix is `#001`; after `#999`, it wraps to
/// `#000`. This counter is isolated from DDE transaction/generation IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) struct Win16Ole1EmbeddedTopicSerial(u16);

impl Default for Win16Ole1EmbeddedTopicSerial {
    fn default() -> Self {
        Self(0)
    }
}

impl Win16Ole1EmbeddedTopicSerial {
    pub(in crate::win16_runtime) fn take_next(&mut self) -> u16 {
        self.0 = if self.0 == 999 { 0 } else { self.0 + 1 };
        self.0
    }
}

/// Begin the synchronous application/topic discovery broadcast. The returned
/// native send receipt is not a peer conversation; each accepted ACK event
/// must be matched independently and supplies its exact peer/conversation.
pub(in crate::win16_runtime) fn begin_client_initiate(
    owner: OwnerId,
    endpoint: Win16HostClassicDdeEndpoint,
    application_atom: u16,
    topic_atom: u16,
    application_name: &[u8],
    topic_name: &[u8],
) -> Result<Win16HostClassicDdeCall, &'static str> {
    Ok(Win16HostClassicDdeCall::Send {
        owner,
        endpoint,
        target: Win16HostClassicDdeTarget::BroadcastInitiate,
        conversation: None,
        transaction: None,
        message: client_initiate_message(
            application_atom,
            topic_atom,
            application_name,
            topic_name,
        )?,
    })
}

/// Build an OLE1 `StdNewDocument` command block. A successful build is only
/// command data; the caller must still complete exact DDE initiate, execute
/// ACK, document connection, and native-data exchange before returning an
/// object to the Win16 caller.
pub(in crate::win16_runtime) fn new_document_execute(
    class_name: &[u8],
    embedded_topic: &[u8],
) -> Result<Win16ClassicDdeMessage, stdexecute::Win16Ole1StdExecuteError> {
    let bytes = stdexecute::encode_win16_ole1_std_execute(
        stdexecute::Win16Ole1StdExecuteCommand::NewDocument {
            class_name,
            document_name: embedded_topic,
        },
    )?;
    Ok(Win16ClassicDdeMessage::Execute {
        global: crate::Win16ClassicDdeGlobalBlock {
            transfer: None,
            guest_global: None,
            bytes,
        },
    })
}
