use super::*;

pub(super) fn execute_call(
    state: &Rc<RefCell<WorkerState>>,
    identity: Win16ClassicDdeOperationIdentity,
    call: &Win16HostClassicDdeCall,
) -> Result<Win16HostClassicDdeResult, RuntimeError> {
    match call {
        Win16HostClassicDdeCall::QuiesceOwner { owner, id } => {
            quiesce_owner(state, identity, *owner, *id)
        }
        Win16HostClassicDdeCall::CreateEndpoint { owner, parent } => {
            create_endpoint(state, identity, *owner, *parent)
                .map(Win16HostClassicDdeResult::Endpoint)
        }
        Win16HostClassicDdeCall::RetireEndpoint { owner, endpoint } => {
            retire_endpoint(state, *owner, *endpoint).map(Win16HostClassicDdeResult::Retired)
        }
        Win16HostClassicDdeCall::BindConversation {
            owner,
            endpoint,
            peer,
            source_operation,
            initiate_event_id,
            application,
            topic,
        } => bind_conversation(
            state,
            *owner,
            *endpoint,
            *peer,
            *source_operation,
            *initiate_event_id,
            application.as_ref(),
            topic.as_ref(),
        )
        .map(Win16HostClassicDdeResult::ConversationBound),
        Win16HostClassicDdeCall::RetireConversation {
            owner,
            endpoint,
            conversation,
            peer,
        } => retire_conversation(state, *owner, *endpoint, *conversation, *peer).map(|()| {
            Win16HostClassicDdeResult::ConversationRetired {
                owner: *owner,
                endpoint: *endpoint,
                conversation: *conversation,
                peer: *peer,
            }
        }),
        Win16HostClassicDdeCall::Send {
            owner,
            endpoint,
            target,
            conversation,
            transaction,
            message,
        } => send_message(
            state,
            identity,
            *owner,
            *endpoint,
            *target,
            *conversation,
            *transaction,
            message,
        )
        .map(Win16HostClassicDdeResult::Sent),
        Win16HostClassicDdeCall::Post {
            owner,
            endpoint,
            target,
            conversation,
            transaction,
            message,
        } => post_message(
            state,
            identity,
            *owner,
            *endpoint,
            *target,
            *conversation,
            *transaction,
            message,
        )
        .map(Win16HostClassicDdeResult::Posted),
        Win16HostClassicDdeCall::Poll { owner, endpoint } => {
            poll_endpoint(state, *owner, Some(*endpoint)).map(Win16HostClassicDdeResult::Event)
        }
        Win16HostClassicDdeCall::PollOwner { owner } => {
            poll_endpoint(state, *owner, None).map(Win16HostClassicDdeResult::Event)
        }
        Win16HostClassicDdeCall::AcknowledgeEvent {
            owner,
            endpoint,
            event_id,
        } => acknowledge_event(state, *owner, *endpoint, *event_id)
            .map(Win16HostClassicDdeResult::EventAcknowledged),
        Win16HostClassicDdeCall::ReplyInitiate {
            owner,
            endpoint,
            worker_generation,
            operation_id,
            callback,
            frame,
            event_id,
            peer,
            accepted,
            application_atom,
            topic_atom,
        } => reply_initiate(
            state,
            identity,
            *owner,
            *endpoint,
            *worker_generation,
            *operation_id,
            *callback,
            *frame,
            *event_id,
            *peer,
            *accepted,
            application_atom.as_ref(),
            topic_atom.as_ref(),
        )
        .map(Win16HostClassicDdeResult::InitiateReplied),
        Win16HostClassicDdeCall::ForwardInitiateToChild {
            owner,
            parent,
            worker_generation,
            operation_id,
            callback,
            frame,
            event_id,
            child,
            peer,
            application_atom,
            topic_atom,
        } => forward_initiate_to_child(
            state,
            identity,
            *owner,
            *parent,
            *worker_generation,
            *operation_id,
            *callback,
            *frame,
            *event_id,
            *child,
            *peer,
            application_atom.as_ref(),
            topic_atom.as_ref(),
        ),
    }
}

pub(super) struct PreparedClassicDdePacket {
    message: u16,
    l_param: LPARAM,
    packed: Option<wire::PackedDdeLParam>,
    global: Option<wire::NativeGlobalBlockLease>,
    atom_leases: Vec<wire::NativeGlobalAtomLease>,
    item: Option<Win16ClassicDdeAtom>,
    keep_sender_global: bool,
    expects_protocol_reply: bool,
    release_after_positive_ack: bool,
    execute_ack_transfer: Option<Win16ClassicDdeTransferId>,
}

pub(super) fn send_message(
    state: &Rc<RefCell<WorkerState>>,
    identity: Win16ClassicDdeOperationIdentity,
    owner: guest_core::OwnerId,
    endpoint: Win16HostClassicDdeEndpoint,
    target: runtime::Win16HostClassicDdeTarget,
    conversation: Option<Win16ClassicDdeConversationId>,
    transaction: Option<runtime::Win16ClassicDdeTransactionId>,
    message: &Win16ClassicDdeMessage,
) -> Result<runtime::Win16HostClassicDdeSendReceipt, RuntimeError> {
    if identity.owner != owner {
        return Err(invariant("classic DDE Send operation crossed task owner"));
    }
    let source = endpoint_hwnd(state, endpoint, owner, identity.worker_generation)?;
    let codec = state.borrow().text_codec;
    let target_hwnd = match target {
        runtime::Win16HostClassicDdeTarget::BroadcastInitiate => {
            if conversation.is_some() || !matches!(message, Win16ClassicDdeMessage::Initiate { .. })
            {
                return Err(RuntimeError::new(
                    Kind::InvalidInput,
                    "only an unbound WM_DDE_INITIATE may target HWND_BROADCAST",
                ));
            }
            HWND_BROADCAST
        }
        runtime::Win16HostClassicDdeTarget::Peer(peer) => {
            if matches!(message, Win16ClassicDdeMessage::Initiate { .. }) {
                if conversation.is_some() {
                    return Err(RuntimeError::new(
                        Kind::InvalidInput,
                        "WM_DDE_INITIATE cannot reuse an existing conversation",
                    ));
                }
            } else {
                let conversation = conversation.ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InvalidInput,
                        "peer-directed classic DDE Send requires an exact conversation",
                    )
                })?;
                validate_conversation_peer(state, owner, endpoint, conversation, peer)?;
            }
            native_peer_hwnd(state, peer, owner, identity.worker_generation)?
        }
    };
    let mut packet = prepare_outbound_packet(state, message, codec)?;
    if packet.message == runtime::WM_DDE_ACK {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "WM_DDE_ACK requires PostMessage except for the exact INITIATE reply",
        ));
    }
    if packet.message != runtime::WM_DDE_INITIATE {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "classic DDE uses SendMessage only for WM_DDE_INITIATE; other messages require PostMessage",
        ));
    }
    if let Some(transfer) = packet.execute_ack_transfer {
        let peer = match target {
            runtime::Win16HostClassicDdeTarget::Peer(peer) => peer,
            runtime::Win16HostClassicDdeTarget::BroadcastInitiate => {
                return Err(RuntimeError::new(
                    Kind::InvalidInput,
                    "EXECUTE ACK cannot target HWND_BROADCAST",
                ));
            }
        };
        validate_execute_ack_target(state, endpoint, transfer, peer, conversation)?;
    }
    let (tx_id, transfer_id) = prepare_outbound_ids(
        state,
        endpoint,
        conversation,
        match target {
            runtime::Win16HostClassicDdeTarget::Peer(peer) => Some(peer),
            runtime::Win16HostClassicDdeTarget::BroadcastInitiate => None,
        },
        transaction,
        &packet,
    )?;
    install_outbound_leases(
        state,
        owner,
        endpoint,
        conversation,
        match target {
            runtime::Win16HostClassicDdeTarget::Peer(peer) => Some(peer),
            runtime::Win16HostClassicDdeTarget::BroadcastInitiate => None,
        },
        &mut packet,
        tx_id,
        transfer_id,
    )?;
    let l_param = packet
        .packed
        .as_ref()
        .map_or(packet.l_param, |packed| packed.value());
    // SAFETY: This path accepts only the synchronous WM_DDE_INITIATE path;
    // replies to INITIATE use the dedicated exact ReplyInitiate operation.
    let native_result = unsafe {
        SendMessageW(
            target_hwnd,
            u32::from(packet.message),
            source as usize,
            l_param,
        )
    };
    if packet.message != runtime::WM_DDE_INITIATE {
        // The peer only owns these atom references after the native call has
        // returned. INITIATE is the exception: its sender deletes both refs
        // after this synchronous call rather than transferring them.
        for lease in &mut packet.atom_leases {
            lease.transfer_to_receiver();
        }
    }
    if transfer_id.is_none() {
        if let Some(global) = packet.global.as_mut() {
            // A release=true message without an ACK decision transfers only
            // after SendMessage has accepted and dispatched the exact packet.
            global.transfer_to_receiver();
        }
    }
    if let Some(packed) = packet.packed.as_mut() {
        packed.transfer_to_receiver();
    }
    commit_execute_ack_transfer(state, endpoint, packet.execute_ack_transfer)?;
    Ok(runtime::Win16HostClassicDdeSendReceipt {
        owner,
        endpoint,
        target,
        conversation,
        message: packet.message,
        native_result,
        transfer: transfer_id,
        transaction: tx_id,
    })
}

pub(super) fn post_message(
    state: &Rc<RefCell<WorkerState>>,
    identity: Win16ClassicDdeOperationIdentity,
    owner: guest_core::OwnerId,
    endpoint: Win16HostClassicDdeEndpoint,
    target: Win16HostClassicDdePeer,
    conversation: Win16ClassicDdeConversationId,
    transaction: Option<runtime::Win16ClassicDdeTransactionId>,
    message: &Win16ClassicDdeMessage,
) -> Result<runtime::Win16HostClassicDdePostReceipt, RuntimeError> {
    if identity.owner != owner {
        return Err(invariant("classic DDE Post operation crossed task owner"));
    }
    let source = endpoint_hwnd(state, endpoint, owner, identity.worker_generation)?;
    validate_conversation_peer(state, owner, endpoint, conversation, target)?;
    let target_hwnd = native_peer_hwnd(state, target, owner, identity.worker_generation)?;
    let codec = state.borrow().text_codec;
    let mut packet = prepare_outbound_packet(state, message, codec)?;
    if packet.message == runtime::WM_DDE_INITIATE {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "WM_DDE_INITIATE requires synchronous SendMessage delivery",
        ));
    }
    if let Some(transfer) = packet.execute_ack_transfer {
        validate_execute_ack_target(state, endpoint, transfer, target, Some(conversation))?;
    }
    let (tx_id, transfer_id) = prepare_outbound_ids(
        state,
        endpoint,
        Some(conversation),
        Some(target),
        transaction,
        &packet,
    )?;
    let local_ack = prepare_local_ack_response(
        state,
        owner,
        identity.worker_generation,
        endpoint,
        target,
        conversation,
        tx_id,
        message,
    )?;
    let l_param = packet
        .packed
        .as_ref()
        .map_or(packet.l_param, |packed| packed.value());
    // SAFETY: The private endpoint and exact conversation peer resolve to live
    // native windows; packet arguments are created and owned on this worker.
    if unsafe {
        PostMessageW(
            target_hwnd,
            u32::from(packet.message),
            source as usize,
            l_param,
        )
    } == 0
    {
        return Err(last_error("PostMessageW classic DDE packet"));
    }
    if let Some(packed) = packet.packed.as_mut() {
        packed.transfer_to_receiver();
    }
    for lease in &mut packet.atom_leases {
        lease.transfer_to_receiver();
    }
    // PostMessage does not dispatch on this worker until this command returns.
    // Install the exact transfer/transaction records before the worker resumes
    // its native pump and can receive the peer's protocol ACK.
    install_outbound_leases(
        state,
        owner,
        endpoint,
        Some(conversation),
        Some(target),
        &mut packet,
        tx_id,
        transfer_id,
    )?;
    if transfer_id.is_none() {
        if let Some(global) = packet.global.as_mut() {
            global.transfer_to_receiver();
        }
    }
    if let Some(local_ack) = local_ack {
        commit_local_ack_response(
            state,
            owner,
            identity.worker_generation,
            endpoint,
            local_ack,
        )?;
    }
    commit_execute_ack_transfer(state, endpoint, packet.execute_ack_transfer)?;
    Ok(runtime::Win16HostClassicDdePostReceipt {
        owner,
        endpoint,
        peer: target,
        conversation: Some(conversation),
        message: packet.message,
        queued: true,
        transfer: transfer_id,
        transaction: tx_id,
    })
}

#[derive(Clone, Copy)]
pub(super) struct LocalAckResponse {
    transaction: runtime::Win16ClassicDdeTransactionId,
    event_id: Win16ClassicDdeEventId,
    acknowledged: bool,
}

pub(super) fn prepare_local_ack_response(
    state: &Rc<RefCell<WorkerState>>,
    owner: guest_core::OwnerId,
    worker_generation: u64,
    endpoint: Win16HostClassicDdeEndpoint,
    peer: Win16HostClassicDdePeer,
    conversation: Win16ClassicDdeConversationId,
    transaction: Option<runtime::Win16ClassicDdeTransactionId>,
    message: &Win16ClassicDdeMessage,
) -> Result<Option<LocalAckResponse>, RuntimeError> {
    let Win16ClassicDdeMessage::Ack { status, value } = message else {
        return Ok(None);
    };
    let Some(transaction) = transaction else {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "WM_DDE_ACK Post requires its exact source transaction",
        ));
    };
    let worker = state.borrow();
    let record = worker.classic_dde_endpoints.get(&endpoint).ok_or_else(|| {
        RuntimeError::new(
            Kind::InvalidInput,
            "classic DDE ACK source endpoint is not live",
        )
    })?;
    if record.owner != owner || record.worker_generation != worker_generation {
        return Err(invariant(
            "classic DDE ACK source crossed endpoint owner/generation",
        ));
    }
    let transaction_record = record.transactions.get(&transaction).ok_or_else(|| {
        RuntimeError::new(
            Kind::InvalidInput,
            "classic DDE ACK source transaction is not live",
        )
    })?;
    if transaction_record.peer != peer || transaction_record.conversation != conversation {
        return Err(invariant(
            "classic DDE ACK source transaction changed peer/conversation",
        ));
    }
    if !transaction_record.requires_local_ack {
        return Ok(None);
    }
    if transaction_record.local_acknowledged.is_some() {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "classic DDE source event already has a terminal protocol ACK",
        ));
    }
    let event_id = transaction_record
        .source_event_id
        .ok_or_else(|| invariant("classic DDE local ACK transaction lost its source EventId"))?;
    let event = record
        .events
        .iter()
        .find(|entry| entry.event.event_id == event_id)
        .map(|entry| &entry.event)
        .or_else(|| {
            record
                .synchronous_frames
                .values()
                .find(|frame| frame.event.event_id == event_id)
                .map(|frame| &frame.event)
        })
        .ok_or_else(|| {
            invariant("classic DDE local ACK source event lost its exact native frame")
        })?;
    if event.owner != owner
        || event.worker_generation != worker_generation
        || event.endpoint != endpoint
        || event.peer != peer
        || event.conversation != Some(conversation)
        || event.transaction != Some(transaction)
    {
        return Err(invariant(
            "classic DDE local ACK source EventId changed its exact tuple",
        ));
    }
    let matches_source = match (&event.message, value) {
        (
            Win16ClassicDdeMessage::Advise { item, .. }
            | Win16ClassicDdeMessage::Unadvise { item, .. }
            | Win16ClassicDdeMessage::Poke { item, .. },
            runtime::Win16ClassicDdeAckValue::ItemAtom(ack_item),
        ) => atoms_equal(item.as_ref(), ack_item.as_ref()),
        (
            Win16ClassicDdeMessage::Data { item, flags, .. },
            runtime::Win16ClassicDdeAckValue::ItemAtom(ack_item),
        ) => flags.acknowledge_requested && atoms_equal(item.as_ref(), ack_item.as_ref()),
        (
            Win16ClassicDdeMessage::Execute { global },
            runtime::Win16ClassicDdeAckValue::ExecuteTransfer(Some(transfer)),
        ) => global.transfer == Some(*transfer) && transaction_record.transfer == Some(*transfer),
        _ => false,
    };
    if !matches_source {
        return Err(invariant(
            "classic DDE protocol ACK does not match its exact source message",
        ));
    }
    Ok(Some(LocalAckResponse {
        transaction,
        event_id,
        acknowledged: status.acknowledged,
    }))
}

pub(super) fn commit_local_ack_response(
    state: &Rc<RefCell<WorkerState>>,
    owner: guest_core::OwnerId,
    worker_generation: u64,
    endpoint: Win16HostClassicDdeEndpoint,
    response: LocalAckResponse,
) -> Result<(), RuntimeError> {
    let mut worker = state.borrow_mut();
    let record = worker
        .classic_dde_endpoints
        .get_mut(&endpoint)
        .ok_or_else(|| {
            invariant("classic DDE ACK source endpoint disappeared after PostMessage")
        })?;
    if record.owner != owner || record.worker_generation != worker_generation {
        return Err(invariant(
            "classic DDE ACK source changed owner after PostMessage",
        ));
    }
    let transaction = record
        .transactions
        .get(&response.transaction)
        .ok_or_else(|| {
            invariant("classic DDE ACK source transaction disappeared after PostMessage")
        })?;
    if transaction.source_event_id != Some(response.event_id)
        || !transaction.requires_local_ack
        || transaction.local_acknowledged.is_some()
    {
        return Err(invariant(
            "classic DDE ACK source changed before PostMessage commit",
        ));
    }
    let queued = record
        .events
        .iter()
        .position(|entry| entry.event.event_id == response.event_id);
    let synchronous = record
        .synchronous_frames
        .iter()
        .find_map(|(key, frame)| (frame.event.event_id == response.event_id).then_some(*key));
    if queued.is_some() == synchronous.is_some() {
        return Err(invariant(
            "classic DDE ACK source EventId is absent or duplicated after PostMessage",
        ));
    }
    // PostMessage already committed the protocol decision. Record it before
    // attempting receiver-owned HGLOBAL cleanup, so a GlobalFree failure can
    // be retried by exact EventId retirement without posting a duplicate ACK.
    record
        .transactions
        .get_mut(&response.transaction)
        .ok_or_else(|| invariant("classic DDE ACK source transaction disappeared during commit"))?
        .local_acknowledged = Some(response.acknowledged);
    // Posting the wire ACK is the protocol commit. Keep its exact local ACK
    // state and return the Post receipt even if a receiver-owned HGLOBAL must
    // be freed later; EventId/source retirement owns that retryable cleanup.
    // A cleanup error here must never turn an already posted ACK into a
    // StartedFailure that invites the sender to post a duplicate.
    let _ = (queued, synchronous);
    Ok(())
}

pub(super) fn settle_incoming_global_release(
    handles: &mut Vec<windows_sys::Win32::Foundation::HGLOBAL>,
    acknowledged: bool,
) -> Result<(), RuntimeError> {
    if acknowledged {
        free_owned_incoming_globals(handles)
    } else {
        // A negative ACK leaves ownership with the sender.
        handles.clear();
        Ok(())
    }
}

pub(super) fn free_owned_incoming_globals(
    handles: &mut Vec<windows_sys::Win32::Foundation::HGLOBAL>,
) -> Result<(), RuntimeError> {
    let mut remaining = Vec::new();
    remaining
        .try_reserve_exact(handles.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain classic DDE HGLOBALs whose receiver-owned release failed",
                error,
            )
        })?;
    let mut first_error = None;
    for handle in handles.drain(..) {
        // SAFETY: Each handle is retained by this exact event/frame and the
        // receiver owns it because fRelease transferred ownership.
        let still_owned = unsafe { GlobalFree(handle) };
        if !still_owned.is_null() {
            if first_error.is_none() {
                first_error = Some(last_error("GlobalFree received classic DDE block"));
            }
            remaining.push(handle);
        }
    }
    *handles = remaining;
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

pub(super) fn prepare_outbound_packet(
    state: &Rc<RefCell<WorkerState>>,
    message: &Win16ClassicDdeMessage,
    codec: crate::windows::guest_text::GuestTextCodec,
) -> Result<PreparedClassicDdePacket, RuntimeError> {
    let mut atom_leases = Vec::new();
    atom_leases.try_reserve(2).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve outgoing classic DDE atom references",
            error,
        )
    })?;
    let mut global = None;
    let mut packed = None;
    let mut l_param = 0;
    let mut item = None;
    let mut keep_sender_global = false;
    let mut expects_protocol_reply = false;
    let mut release_after_positive_ack = false;
    let mut execute_ack_transfer = None;
    let message_id = message_id(message);
    match message {
        Win16ClassicDdeMessage::Initiate { application, topic } => {
            let (application_id, application_lease) =
                wire::create_native_atom(application.as_ref(), codec)?;
            let (topic_id, topic_lease) = wire::create_native_atom(topic.as_ref(), codec)?;
            if let Some(lease) = application_lease {
                atom_leases.push(lease);
            }
            if let Some(lease) = topic_lease {
                atom_leases.push(lease);
            }
            l_param = wire::raw_atom_pair(application_id, topic_id);
        }
        Win16ClassicDdeMessage::Terminate => {}
        Win16ClassicDdeMessage::Ack { status, value } => {
            if status.application_return_code != (status.raw & 0x00ff) as u8
                || status.reserved != ((status.raw >> 8) & 0x3f) as u8
                || status.busy != (status.raw & 0x4000 != 0)
                || status.acknowledged != (status.raw & 0x8000 != 0)
            {
                return Err(RuntimeError::new(
                    Kind::InvalidInput,
                    "DDEACK decoded fields disagree with its exact wire status word",
                ));
            }
            let high = match value {
                runtime::Win16ClassicDdeAckValue::InitiateAtoms { .. } => {
                    return Err(RuntimeError::new(
                        Kind::InvalidInput,
                        "INITIATE acknowledgement must use the exact ReplyInitiate operation",
                    ));
                }
                runtime::Win16ClassicDdeAckValue::ItemAtom(atom) => {
                    item = atom.clone();
                    let (native, lease) = wire::create_native_atom(atom.as_ref(), codec)?;
                    if let Some(lease) = lease {
                        atom_leases.push(lease);
                    }
                    usize::from(native)
                }
                runtime::Win16ClassicDdeAckValue::ExecuteTransfer(transfer) => {
                    let Some(transfer) = *transfer else {
                        return Err(RuntimeError::new(
                            Kind::InvalidInput,
                            "EXECUTE ACK requires its exact retained command transfer",
                        ));
                    };
                    let native = transfer_handle(state, transfer)?;
                    execute_ack_transfer = Some(transfer);
                    native as usize
                }
                runtime::Win16ClassicDdeAckValue::Unmatched => {
                    return Err(RuntimeError::new(
                        Kind::InvalidInput,
                        "cannot encode an unmatched classic DDE acknowledgement",
                    ));
                }
            };
            packed = Some(wire::PackedDdeLParam::new(
                message_id,
                usize::from(status.raw),
                high,
            )?);
        }
        Win16ClassicDdeMessage::Advise {
            item: guest_item,
            format,
            options,
            global: block,
        } => {
            validate_wire_header(&block.bytes, options.raw_flags, *format, "DDEADVISE")?;
            let (native_item, lease) = wire::create_native_atom(guest_item.as_ref(), codec)?;
            if let Some(lease) = lease {
                atom_leases.push(lease);
            }
            item = guest_item.clone();
            global = Some(wire::NativeGlobalBlockLease::copy_from(&block.bytes)?);
            release_after_positive_ack = true;
            packed = Some(wire::PackedDdeLParam::new(
                message_id,
                global.as_ref().expect("created DDEADVISE block").handle() as usize,
                usize::from(native_item),
            )?);
            expects_protocol_reply = true;
        }
        Win16ClassicDdeMessage::Unadvise {
            item: guest_item,
            reserved,
        } => {
            let (native_item, lease) = wire::create_native_atom(guest_item.as_ref(), codec)?;
            if let Some(lease) = lease {
                atom_leases.push(lease);
            }
            item = guest_item.clone();
            packed = Some(wire::PackedDdeLParam::new(
                message_id,
                usize::from(*reserved),
                usize::from(native_item),
            )?);
            expects_protocol_reply = true;
        }
        Win16ClassicDdeMessage::Request {
            item: guest_item,
            format,
        } => {
            let (native_item, lease) = wire::create_native_atom(guest_item.as_ref(), codec)?;
            if let Some(lease) = lease {
                atom_leases.push(lease);
            }
            item = guest_item.clone();
            packed = Some(wire::PackedDdeLParam::new(
                message_id,
                usize::from(*format),
                usize::from(native_item),
            )?);
            expects_protocol_reply = true;
        }
        Win16ClassicDdeMessage::Poke {
            item: guest_item,
            format,
            flags,
            global: block,
        } => {
            validate_wire_header(&block.bytes, flags.raw_flags, *format, "DDEPOKE")?;
            let (native_item, lease) = wire::create_native_atom(guest_item.as_ref(), codec)?;
            if let Some(lease) = lease {
                atom_leases.push(lease);
            }
            item = guest_item.clone();
            global = Some(wire::NativeGlobalBlockLease::copy_from(&block.bytes)?);
            keep_sender_global = !flags.release_after_receive;
            release_after_positive_ack = flags.release_after_receive;
            expects_protocol_reply = true;
            packed = Some(wire::PackedDdeLParam::new(
                message_id,
                global.as_ref().expect("created DDEPOKE block").handle() as usize,
                usize::from(native_item),
            )?);
        }
        Win16ClassicDdeMessage::Data {
            item: guest_item,
            format,
            flags,
            global: block,
        } => {
            validate_wire_header(&block.bytes, flags.raw_flags, *format, "DDEDATA")?;
            if !flags.release_after_receive && !flags.acknowledge_requested {
                return Err(RuntimeError::new(
                    Kind::InvalidInput,
                    "DDEDATA cannot clear both fRelease and fAckReq",
                ));
            }
            let (native_item, lease) = wire::create_native_atom(guest_item.as_ref(), codec)?;
            if let Some(lease) = lease {
                atom_leases.push(lease);
            }
            item = guest_item.clone();
            global = Some(wire::NativeGlobalBlockLease::copy_from(&block.bytes)?);
            keep_sender_global = !flags.release_after_receive;
            release_after_positive_ack = flags.release_after_receive;
            expects_protocol_reply = flags.acknowledge_requested;
            packed = Some(wire::PackedDdeLParam::new(
                message_id,
                global.as_ref().expect("created DDEDATA block").handle() as usize,
                usize::from(native_item),
            )?);
        }
        Win16ClassicDdeMessage::Execute { global: block } => {
            if block.bytes.is_empty() {
                return Err(RuntimeError::new(
                    Kind::InvalidInput,
                    "WM_DDE_EXECUTE command block is empty",
                ));
            }
            global = Some(wire::NativeGlobalBlockLease::copy_from(&block.bytes)?);
            keep_sender_global = true;
            expects_protocol_reply = true;
            packed = Some(wire::PackedDdeLParam::new(
                message_id,
                0,
                global
                    .as_ref()
                    .expect("created WM_DDE_EXECUTE block")
                    .handle() as usize,
            )?);
        }
    }
    if wire::uses_packed_lparam(message_id) && packed.is_none() {
        return Err(invariant(
            "classic DDE message encoder omitted PackDDElParam",
        ));
    }
    Ok(PreparedClassicDdePacket {
        message: message_id,
        l_param,
        packed,
        global,
        atom_leases,
        item,
        keep_sender_global,
        expects_protocol_reply,
        release_after_positive_ack,
        execute_ack_transfer,
    })
}

pub(super) fn prepare_outbound_ids(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16HostClassicDdeEndpoint,
    conversation: Option<Win16ClassicDdeConversationId>,
    peer: Option<Win16HostClassicDdePeer>,
    requested_transaction: Option<runtime::Win16ClassicDdeTransactionId>,
    packet: &PreparedClassicDdePacket,
) -> Result<
    (
        Option<runtime::Win16ClassicDdeTransactionId>,
        Option<Win16ClassicDdeTransferId>,
    ),
    RuntimeError,
> {
    // For release=true transfers, the sender still owns the block until a
    // positive ACK arrives; a negative ACK leaves cleanup with the sender.
    // Retain the exact handle while an ACK decision is pending in either case.
    let transfer_needed =
        packet.global.is_some() && (packet.keep_sender_global || packet.expects_protocol_reply);
    if (packet.expects_protocol_reply || transfer_needed)
        && (conversation.is_none() || peer.is_none())
    {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "classic DDE transfer or reply-tracked message requires an exact peer conversation",
        ));
    }
    let transfer = transfer_needed
        .then(|| allocate_identity(state).map(Win16ClassicDdeTransferId))
        .transpose()?;
    let transaction = if let Some(transaction) = requested_transaction {
        if conversation.is_none() || peer.is_none() {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "classic DDE transaction cannot be attached to an unbound message",
            ));
        }
        let worker = state.borrow();
        let record = worker.classic_dde_endpoints.get(&endpoint).ok_or_else(|| {
            RuntimeError::new(Kind::InvalidInput, "classic DDE endpoint is not live")
        })?;
        let existing = record.transactions.get(&transaction).ok_or_else(|| {
            RuntimeError::new(Kind::InvalidInput, "classic DDE transaction is not live")
        })?;
        if Some(existing.peer) != peer || Some(existing.conversation) != conversation {
            return Err(invariant(
                "classic DDE transaction does not match the exact peer conversation",
            ));
        }
        Some(transaction)
    } else if packet.expects_protocol_reply {
        Some(runtime::Win16ClassicDdeTransactionId(allocate_identity(
            state,
        )?))
    } else {
        None
    };
    Ok((transaction, transfer))
}

pub(super) fn install_outbound_leases(
    state: &Rc<RefCell<WorkerState>>,
    owner: guest_core::OwnerId,
    endpoint: Win16HostClassicDdeEndpoint,
    conversation: Option<Win16ClassicDdeConversationId>,
    peer: Option<Win16HostClassicDdePeer>,
    packet: &mut PreparedClassicDdePacket,
    transaction: Option<runtime::Win16ClassicDdeTransactionId>,
    transfer: Option<Win16ClassicDdeTransferId>,
) -> Result<(), RuntimeError> {
    let mut worker = state.borrow_mut();
    let worker_generation = worker.worker_retirement_id;
    let record = worker
        .classic_dde_endpoints
        .get_mut(&endpoint)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InvalidInput,
                "classic DDE endpoint retired before packet dispatch",
            )
        })?;
    if record.owner != owner || record.worker_generation != worker_generation {
        return Err(invariant(
            "classic DDE endpoint changed owner/generation before packet dispatch",
        ));
    }
    if let (Some(transfer), Some(global), Some(peer), Some(conversation)) =
        (transfer, packet.global.as_mut(), peer, conversation)
    {
        let handle = global.transfer_to_ledger();
        record.transfers.insert(
            transfer,
            NativeClassicDdeTransfer {
                handle,
                peer,
                conversation: Some(conversation),
                owns_handle: true,
                release_after_receive: packet.release_after_positive_ack,
                protocol_ack_posted: false,
                message: packet.message,
                atom_leases: Vec::new(),
            },
        );
    }
    if let (Some(transaction), Some(peer), Some(conversation)) = (transaction, peer, conversation) {
        if !record.transactions.contains_key(&transaction) {
            record.transactions.insert(
                transaction,
                NativeClassicDdeTransaction {
                    peer,
                    conversation,
                    message: packet.message,
                    transfer,
                    item: packet.item.clone(),
                    awaiting_peer_ack: true,
                    source_event_id: None,
                    requires_local_ack: false,
                    local_acknowledged: None,
                    _atom_leases: Vec::new(),
                },
            );
        }
    }
    Ok(())
}

pub(super) fn validate_wire_header(
    bytes: &[u8],
    raw_flags: u16,
    format: u16,
    kind: &'static str,
) -> Result<(), RuntimeError> {
    if bytes.len() < 4 {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            format!("{kind} block is shorter than its four-byte DDE header"),
        ));
    }
    let actual_flags = u16::from_le_bytes([bytes[0], bytes[1]]);
    let actual_format = u16::from_le_bytes([bytes[2], bytes[3]]);
    if actual_flags != raw_flags || actual_format != format {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            format!("{kind} DTO header disagrees with its raw global-block bytes"),
        ));
    }
    Ok(())
}

pub(super) fn validate_conversation_peer(
    state: &Rc<RefCell<WorkerState>>,
    owner: guest_core::OwnerId,
    endpoint: Win16HostClassicDdeEndpoint,
    conversation: Win16ClassicDdeConversationId,
    peer: Win16HostClassicDdePeer,
) -> Result<(), RuntimeError> {
    let worker = state.borrow();
    let record = worker
        .classic_dde_endpoints
        .get(&endpoint)
        .ok_or_else(|| RuntimeError::new(Kind::InvalidInput, "classic DDE endpoint is not live"))?;
    let live = record.conversations.get(&conversation).ok_or_else(|| {
        RuntimeError::new(Kind::InvalidInput, "classic DDE conversation is not live")
    })?;
    if record.owner != owner || live.peer != peer {
        return Err(invariant(
            "classic DDE conversation target differs from its owner/peer binding",
        ));
    }
    Ok(())
}

pub(super) fn native_peer_hwnd(
    state: &Rc<RefCell<WorkerState>>,
    peer: Win16HostClassicDdePeer,
    owner: guest_core::OwnerId,
    worker_generation: u64,
) -> Result<HWND, RuntimeError> {
    match peer {
        Win16HostClassicDdePeer::Endpoint(endpoint) => {
            endpoint_hwnd(state, endpoint, owner, worker_generation)
        }
        Win16HostClassicDdePeer::GuestWindow(window) => {
            let worker = state.borrow();
            let hwnd = worker.windows.get(&window).copied().ok_or_else(|| {
                RuntimeError::new(
                    Kind::InvalidInput,
                    "classic DDE guest-window peer is not live",
                )
            })?;
            let identity = worker
                .windows_by_native
                .get(&(hwnd as usize))
                .ok_or_else(|| invariant("classic DDE guest-window native identity disappeared"))?;
            if identity.window != window || hwnd.is_null() || {
                crate::windows::win32_safe::is_window(hwnd)
            } == 0
            {
                return Err(invariant(
                    "classic DDE guest-window peer changed incarnation",
                ));
            }
            Ok(hwnd)
        }
        Win16HostClassicDdePeer::NativeWindow(token) => {
            let worker = state.borrow();
            let peer = worker.classic_dde_native_peers.get(&token).ok_or_else(|| {
                RuntimeError::new(
                    Kind::InvalidInput,
                    "classic DDE native peer token is not live",
                )
            })?;
            if peer.hwnd.is_null() || { crate::windows::win32_safe::is_window(peer.hwnd) } == 0 {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    "classic DDE native peer window has disappeared",
                ));
            }
            let mut process_id = 0;
            // SAFETY: GetWindowThreadProcessId optionally writes a caller-owned process id.
            let thread_id = unsafe { GetWindowThreadProcessId(peer.hwnd, &mut process_id) };
            if thread_id != peer.thread_id || process_id != peer.process_id {
                return Err(invariant(
                    "classic DDE native peer PID/TID observation changed",
                ));
            }
            let _ = (owner, worker_generation);
            Ok(peer.hwnd)
        }
    }
}

pub(super) fn transfer_handle(
    state: &Rc<RefCell<WorkerState>>,
    transfer: Win16ClassicDdeTransferId,
) -> Result<HGLOBAL, RuntimeError> {
    let worker = state.borrow();
    worker
        .classic_dde_endpoints
        .values()
        .find_map(|endpoint| endpoint.transfers.get(&transfer).map(|entry| entry.handle))
        .filter(|handle| !handle.is_null())
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InvalidInput,
                "classic DDE transfer has no live native HGLOBAL",
            )
        })
}

pub(super) fn validate_execute_ack_target(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16HostClassicDdeEndpoint,
    transfer: Win16ClassicDdeTransferId,
    peer: Win16HostClassicDdePeer,
    conversation: Option<Win16ClassicDdeConversationId>,
) -> Result<(), RuntimeError> {
    let worker = state.borrow();
    let entry = worker
        .classic_dde_endpoints
        .get(&endpoint)
        .and_then(|record| record.transfers.get(&transfer))
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InvalidInput,
                "EXECUTE ACK transfer is not owned by this endpoint",
            )
        })?;
    if entry.message != runtime::WM_DDE_EXECUTE
        || entry.owns_handle
        || entry.peer != peer
        || entry.conversation != conversation
        || entry.handle.is_null()
        || entry.protocol_ack_posted
    {
        return Err(invariant(
            "EXECUTE ACK transfer changed endpoint/peer/conversation ownership",
        ));
    }
    Ok(())
}

pub(super) fn commit_execute_ack_transfer(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16HostClassicDdeEndpoint,
    transfer: Option<Win16ClassicDdeTransferId>,
) -> Result<(), RuntimeError> {
    let Some(transfer) = transfer else {
        return Ok(());
    };
    let mut worker = state.borrow_mut();
    let record = worker
        .classic_dde_endpoints
        .get_mut(&endpoint)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InvalidInput,
                "classic DDE execute endpoint is not live",
            )
        })?;
    let lease = record.transfers.get(&transfer).ok_or_else(|| {
        RuntimeError::new(
            Kind::InvalidInput,
            "classic DDE execute transfer retired early",
        )
    })?;
    if lease.message != runtime::WM_DDE_EXECUTE || lease.owns_handle || lease.protocol_ack_posted {
        return Err(invariant(
            "WM_DDE_EXECUTE ACK does not name an uncommitted exact borrowed command block",
        ));
    }
    record
        .transfers
        .get_mut(&transfer)
        .ok_or_else(|| invariant("WM_DDE_EXECUTE ACK transfer disappeared before protocol commit"))?
        .protocol_ack_posted = true;
    Ok(())
}
