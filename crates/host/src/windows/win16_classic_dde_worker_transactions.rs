use super::*;

pub(super) fn find_execute_ack_transaction(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16HostClassicDdeEndpoint,
    peer: Win16HostClassicDdePeer,
    conversation: Option<Win16ClassicDdeConversationId>,
    high: usize,
) -> Option<(Win16ClassicDdeTransactionId, Win16ClassicDdeTransferId)> {
    let conversation = conversation?;
    let worker = state.borrow();
    let endpoint = worker.classic_dde_endpoints.get(&endpoint)?;
    let mut matches = endpoint.transactions.iter().filter_map(|(id, tx)| {
        if !tx.awaiting_peer_ack || tx.peer != peer || tx.conversation != conversation
            || tx.message != runtime::WM_DDE_EXECUTE
        {
            return None;
        }
        let transfer = tx.transfer?;
        let native = endpoint.transfers.get(&transfer)?;
        ((native.handle as usize) == high).then_some((*id, transfer))
    });
    let first = matches.next()?;
    if matches.next().is_some() { None } else { Some(first) }
}

pub(super) fn find_item_transaction(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16HostClassicDdeEndpoint,
    peer: Win16HostClassicDdePeer,
    conversation: Option<Win16ClassicDdeConversationId>,
    item: Option<&Win16ClassicDdeAtom>,
) -> Option<Win16ClassicDdeTransferId> {
    let conversation = conversation?;
    let worker = state.borrow();
    let endpoint = worker.classic_dde_endpoints.get(&endpoint)?;
    let mut matches = endpoint.transactions.values().filter(|tx| tx.awaiting_peer_ack
        && tx.peer == peer
        && tx.conversation == conversation && tx.message == runtime::WM_DDE_REQUEST
        && atoms_equal(tx.item.as_ref(), item));
    let first = matches.next()?;
    if matches.next().is_some() { None } else { first.transfer }
}

pub(super) fn transaction_for_incoming(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16HostClassicDdeEndpoint,
    peer: Win16HostClassicDdePeer,
    conversation: Option<Win16ClassicDdeConversationId>,
    message_id: u16,
    message: &Win16ClassicDdeMessage,
) -> Option<Win16ClassicDdeTransactionId> {
    if matches!(message, Win16ClassicDdeMessage::Data {
        flags: runtime::Win16ClassicDdeDataFlags {
            raw_flags: 0, release_after_receive: false,
            acknowledge_requested: false, ..
        },
        global: runtime::Win16ClassicDdeGlobalBlock {
            transfer: None, bytes, ..
        },
        ..
    } if bytes.is_empty()) {
        return None;
    }
    let conversation = conversation?;
    let worker = state.borrow();
    let endpoint = worker.classic_dde_endpoints.get(&endpoint)?;
    let item = match message {
        Win16ClassicDdeMessage::Ack { value: Win16ClassicDdeAckValue::ItemAtom(item), .. }
        | Win16ClassicDdeMessage::Data { item, .. } => item.as_ref(),
        _ => None,
    };
    let mut matches = endpoint.transactions.iter().filter(|(_, tx)| {
        tx.awaiting_peer_ack && tx.peer == peer && tx.conversation == conversation
            && match (tx.message, message_id) {
            (runtime::WM_DDE_EXECUTE, runtime::WM_DDE_ACK) => {
                matches!(message, Win16ClassicDdeMessage::Ack {
                    value: Win16ClassicDdeAckValue::ExecuteTransfer(Some(id)), .. }
                    if tx.transfer == Some(*id))
            }
            (runtime::WM_DDE_REQUEST, runtime::WM_DDE_DATA | runtime::WM_DDE_ACK) =>
                atoms_equal(tx.item.as_ref(), item),
            (runtime::WM_DDE_ADVISE | runtime::WM_DDE_UNADVISE | runtime::WM_DDE_POKE
                | runtime::WM_DDE_DATA,
                runtime::WM_DDE_ACK) => atoms_equal(tx.item.as_ref(), item),
            _ => false,
        }
    });
    let first = *matches.next()?.0;
    if matches.next().is_some() { None } else { Some(first) }
}

pub(super) fn bind_incoming_event_transaction(
    state: &Rc<RefCell<WorkerState>>,
    owner: guest_core::OwnerId,
    worker_generation: u64,
    endpoint: Win16HostClassicDdeEndpoint,
    peer: Win16HostClassicDdePeer,
    conversation: Option<Win16ClassicDdeConversationId>,
    message_id: u16,
    message: &Win16ClassicDdeMessage,
    event_id: Win16ClassicDdeEventId,
    matching: Option<Win16ClassicDdeTransactionId>,
) -> Result<Option<Win16ClassicDdeTransactionId>, RuntimeError> {
    let requires_local_ack = message_requires_local_ack(message);
    if let Some(transaction) = matching {
        let mut worker = state.borrow_mut();
        let record = worker.classic_dde_endpoints.get_mut(&endpoint).ok_or_else(||
            RuntimeError::new(Kind::InvalidInput, "classic DDE response endpoint is not live"))?;
        if record.owner != owner || record.worker_generation != worker_generation {
            return Err(invariant("classic DDE response endpoint changed owner/generation"));
        }
        let transaction_record = record.transactions.get_mut(&transaction).ok_or_else(||
            invariant("classic DDE response lost its exact pending transaction"))?;
        if transaction_record.peer != peer
            || Some(transaction_record.conversation) != conversation
            || !transaction_record.awaiting_peer_ack
            || transaction_record.source_event_id.is_some()
        {
            return Err(invariant("classic DDE response transaction changed before event binding"));
        }
        transaction_record.awaiting_peer_ack = false;
        transaction_record.source_event_id = Some(event_id);
        transaction_record.requires_local_ack = requires_local_ack;
        transaction_record.local_acknowledged = None;
        return Ok(Some(transaction));
    }
    if !requires_local_ack {
        return Ok(None);
    }
    let conversation = conversation.ok_or_else(|| RuntimeError::new(Kind::InvalidInput,
        "acknowledged classic DDE event has no exact conversation"))?;
    let item = match message {
        Win16ClassicDdeMessage::Advise { item, .. }
        | Win16ClassicDdeMessage::Unadvise { item, .. }
        | Win16ClassicDdeMessage::Poke { item, .. }
        | Win16ClassicDdeMessage::Data { item, .. } => item.clone(),
        _ => None,
    };
    let transfer = match message {
        Win16ClassicDdeMessage::Execute { global } => global.transfer,
        _ => None,
    };
    let transaction = Win16ClassicDdeTransactionId(allocate_identity(state)?);
    let mut worker = state.borrow_mut();
    let record = worker.classic_dde_endpoints.get_mut(&endpoint).ok_or_else(||
        RuntimeError::new(Kind::InvalidInput, "classic DDE event endpoint retired before ACK binding"))?;
    if record.owner != owner || record.worker_generation != worker_generation {
        return Err(invariant("classic DDE inbound ACK transaction owner/generation changed"));
    }
    if let Some(transfer) = transfer {
        let native = record.transfers.get(&transfer).ok_or_else(||
            invariant("classic DDE EXECUTE source lost its exact HGLOBAL transfer"))?;
        if native.peer != peer || native.conversation != Some(conversation)
            || native.message != runtime::WM_DDE_EXECUTE || native.owns_handle
        {
            return Err(invariant("classic DDE EXECUTE HGLOBAL transfer changed its exact tuple"));
        }
    }
    if record.transactions.insert(transaction, NativeClassicDdeTransaction {
        peer, conversation, message: message_id, transfer, item,
        awaiting_peer_ack: false, source_event_id: Some(event_id),
        requires_local_ack: true, local_acknowledged: None, _atom_leases: Vec::new(),
    }).is_some() {
        return Err(invariant("classic DDE inbound ACK transaction identity was reused"));
    }
    Ok(Some(transaction))
}


pub(super) fn discard_unpublished_borrowed_execute(
    state: &Rc<RefCell<WorkerState>>,
    event: &Win16HostClassicDdeEvent,
) -> Result<(), RuntimeError> {
    let Win16ClassicDdeMessage::Execute { global } = &event.message else {
        return Ok(());
    };
    let Some(transfer) = global.transfer else { return Ok(()); };
    let mut worker = state.try_borrow_mut().map_err(|_| RuntimeError::new(
        Kind::InternalInvariant,
        "cannot retire unbound classic DDE EXECUTE during worker-state borrow",
    ))?;
    let endpoint = worker.classic_dde_endpoints.get_mut(&event.endpoint).ok_or_else(||
        RuntimeError::new(Kind::InvalidInput,
            "classic DDE EXECUTE endpoint retired before bind cleanup"))?;
    if endpoint.owner != event.owner || endpoint.worker_generation != event.worker_generation {
        return Err(invariant("unbound classic DDE EXECUTE changed endpoint owner/generation"));
    }
    let native = endpoint.transfers.get(&transfer).ok_or_else(||
        invariant("unbound classic DDE EXECUTE lost its exact borrowed transfer"))?;
    if native.peer != event.peer || native.conversation != event.conversation
        || native.message != runtime::WM_DDE_EXECUTE || native.owns_handle
        || native.protocol_ack_posted
    {
        return Err(invariant("unbound classic DDE EXECUTE is not the exact borrowed transfer"));
    }
    if let Some(transaction_id) = event.transaction {
        let transaction = endpoint.transactions.get(&transaction_id).ok_or_else(||
            invariant("unpublished classic DDE EXECUTE lost its exact bound transaction"))?;
        if transaction.peer != event.peer
            || Some(transaction.conversation) != event.conversation
            || transaction.message != runtime::WM_DDE_EXECUTE
            || transaction.transfer != Some(transfer)
            || transaction.source_event_id != Some(event.event_id)
            || transaction.requires_local_ack != true
            || transaction.local_acknowledged.is_some()
        {
            return Err(invariant("unpublished classic DDE EXECUTE transaction changed its exact tuple"));
        }
    }
    if let Some(transaction_id) = event.transaction {
        endpoint.transactions.remove(&transaction_id);
    }
    endpoint.transfers.remove(&transfer);
    Ok(())
}

pub(super) fn has_retained_synchronous_source(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16HostClassicDdeEndpoint,
    identity: Win16ClassicDdeOperationIdentity,
    frame: Win16HostClassicDdeCallbackFrame,
    event_id: Win16ClassicDdeEventId,
) -> bool {
    let worker = state.borrow();
    worker.classic_dde_endpoints.get(&endpoint).is_some_and(|record|
        record.owner == identity.owner
            && record.worker_generation == identity.worker_generation
            && record.synchronous_frames.get(&(identity.id, frame)).is_some_and(|native|
                native.event.event_id == event_id
                    && native.event.owner == identity.owner
                    && native.event.endpoint == endpoint
                    && native.event.worker_generation == identity.worker_generation))
}

pub(super) fn message_requires_local_ack(message: &Win16ClassicDdeMessage) -> bool {
    match message {
        Win16ClassicDdeMessage::Advise { .. }
        | Win16ClassicDdeMessage::Unadvise { .. }
        | Win16ClassicDdeMessage::Poke { .. }
        | Win16ClassicDdeMessage::Execute { .. } => true,
        Win16ClassicDdeMessage::Data { flags, .. } => flags.acknowledge_requested,
        _ => false,
    }
}

pub(super) fn atoms_equal(left: Option<&Win16ClassicDdeAtom>, right: Option<&Win16ClassicDdeAtom>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(Win16ClassicDdeAtom::Integer(a)), Some(Win16ClassicDdeAtom::Integer(b))) => a == b,
        (Some(Win16ClassicDdeAtom::Name { name_bytes: a, .. }),
            Some(Win16ClassicDdeAtom::Name { name_bytes: b, .. })) => a == b,
        _ => false,
    }
}
