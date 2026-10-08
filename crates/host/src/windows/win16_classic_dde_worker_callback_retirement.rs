use super::*;

pub(super) fn retire_callback_event_after_reply(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16HostClassicDdeEndpoint,
    event: &Win16HostClassicDdeEvent,
    frame_key: (Win16ClassicDdeOperationId, Win16HostClassicDdeCallbackFrame),
    translated: bool,
) -> Result<(), RuntimeError> {
    retire_callback_packed_lparam(state, endpoint, event, frame_key)?;
    if translated || (event.transaction.is_some() && !message_requires_local_ack(&event.message)) {
        retire_event_transaction(state, endpoint, event, frame_key)
    } else if matches!(event.message, Win16ClassicDdeMessage::Execute { .. }) {
        retire_defaulted_borrowed_execute(state, endpoint, event, frame_key)
    } else {
        Ok(())
    }
}

/// Release this frame's exact packed allocation before ledger retirement.
/// Clear its phase only on success so a later failure retains ownership and
/// retrying cleanup cannot free the same LPARAM twice.
fn retire_callback_packed_lparam(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16HostClassicDdeEndpoint,
    event: &Win16HostClassicDdeEvent,
    frame_key: (Win16ClassicDdeOperationId, Win16HostClassicDdeCallbackFrame),
) -> Result<(), RuntimeError> {
    let mut worker = state.borrow_mut();
    let record = worker.classic_dde_endpoints.get_mut(&endpoint).ok_or_else(||
        invariant("classic DDE packed callback cleanup lost its endpoint"))?;
    let frame = record.synchronous_frames.get_mut(&frame_key).ok_or_else(||
        invariant("classic DDE packed callback cleanup lost its native frame"))?;
    if frame.event != *event {
        return Err(invariant("classic DDE packed callback cleanup changed its exact event"));
    }
    if let Some((message, l_param)) = frame.packed_l_param {
        // SAFETY: This exact frame still owns its received packed LPARAM;
        // default processing clears this field when ownership is transferred.
        if unsafe { windows_sys::Win32::System::DataExchange::FreeDDElParam(
            u32::from(message), l_param,
        ) } == 0 {
            return Err(RuntimeError::new(Kind::HostFailure,
                "FreeDDElParam could not retire the classic DDE callback frame parameter"));
        }
        frame.packed_l_param = None;
    }
    Ok(())
}

/// Move an accepted reply into the proof ledger only after its native frame
/// cleanup succeeds. HostOperation proofs are sent after the enclosing native
/// call returns; ParkedUserWait calls this from the post-unwind marker.
pub(super) fn retire_callback_frame_after_cleanup(
    state: &Rc<RefCell<WorkerState>>,
    step: &Win16HostClassicDdeCallbackStep,
) -> Result<(), RuntimeError> {
    let mut worker = state.borrow_mut();
    let active = worker.active_classic_dde_operations.last().ok_or_else(||
        invariant("classic DDE callback lost its exact operation during frame cleanup"))?;
    if active.identity.owner != step.owner || active.identity.id != step.operation_id
        || active.identity.worker_generation != step.worker_generation
        || active.awaiting.is_some() || active.replied.is_none()
        || active.callback_receipts.len() != active.callback_retirements.len() + 1
    {
        return Err(invariant("classic DDE callback changed before its actual frame retirement"));
    }
    let receipt = active.callback_receipts.last().ok_or_else(||
        invariant("classic DDE callback frame has no accepted reply receipt"))?;
    if receipt.callback != step.callback || receipt.frame != step.frame
        || receipt.event_id != step.event.event_id || receipt.endpoint != step.endpoint
        || receipt.peer != step.event.peer || Some(&receipt.result) != active.replied.as_ref()
    {
        return Err(invariant("classic DDE callback retirement differs from its accepted reply"));
    }
    let receipt = receipt.clone();
    let record = worker.classic_dde_endpoints.get_mut(&step.endpoint).ok_or_else(||
        invariant("classic DDE callback lost its endpoint before frame retirement"))?;
    let frame_key = (step.operation_id, step.frame);
    let frame = record.synchronous_frames.get_mut(&frame_key).ok_or_else(||
        invariant("classic DDE callback lost its native frame before actual retirement"))?;
    if frame.event != step.event || frame.callback_step.as_ref() != step
        || frame.packed_l_param.is_some() || !frame.globals_to_free.is_empty()
        || !frame.globals_after_positive_ack.is_empty()
    {
        return Err(invariant("classic DDE callback retained an unretired frame resource"));
    }
    // Defaulted messages transfer their atom references to DefWindowProc;
    // release is a no-op for those leases. Other paths retain failed releases.
    for lease in &mut frame.atom_leases { lease.release()?; }
    record.synchronous_frames.remove(&frame_key);
    let active = worker.active_classic_dde_operations.last_mut()
        .expect("exact active operation was checked before removing the frame");
    // Capacity was reserved while accepting this reply, before any native
    // callback was released. No fallible allocation follows frame removal.
    active.callback_retirements.push(receipt);
    active.replied = None;
    Ok(())
}

/// Retire the local ledger for an exact borrowed EXECUTE only after its
/// published synchronous callback has reached the native default procedure
/// and the matching source-retirement marker has returned. This is not a DDE
/// ACK: the peer still owns the original HGLOBAL, so the endpoint drops only
/// its borrowed identity and never calls GlobalFree on that sender block.
pub(super) fn retire_defaulted_borrowed_execute(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16HostClassicDdeEndpoint,
    event: &Win16HostClassicDdeEvent,
    frame_key: (Win16ClassicDdeOperationId, Win16HostClassicDdeCallbackFrame),
) -> Result<(), RuntimeError> {
    let Win16ClassicDdeMessage::Execute { global } = &event.message else {
        return Err(invariant("defaulted borrowed EXECUTE retirement received another message"));
    };
    let transfer_id = global.transfer.ok_or_else(||
        invariant("defaulted published EXECUTE has no exact borrowed transfer ID"))?;
    let transaction_id = event.transaction.ok_or_else(||
        invariant("defaulted published EXECUTE has no exact EventId transaction"))?;
    let mut worker = state.borrow_mut();
    let record = worker.classic_dde_endpoints.get_mut(&endpoint).ok_or_else(||
        RuntimeError::new(Kind::InvalidInput, "defaulted EXECUTE endpoint is not live"))?;
    if record.owner != event.owner || record.worker_generation != event.worker_generation
        || event.endpoint != endpoint
    {
        return Err(invariant("defaulted EXECUTE changed its exact endpoint owner/generation"));
    }
    let frame = record.synchronous_frames.get(&frame_key).ok_or_else(||
        invariant("defaulted EXECUTE lost its exact synchronous source frame"))?;
    if frame.event.owner != event.owner || frame.event.endpoint != endpoint
        || frame.event.worker_generation != event.worker_generation
        || frame.event.event_id != event.event_id
        || frame.event.peer != event.peer
        || frame.event.conversation != event.conversation
        || frame.event.transaction != Some(transaction_id)
        || frame.packed_l_param.is_some()
        || !frame.globals_to_free.is_empty()
        || !frame.globals_after_positive_ack.is_empty()
        || !frame.atom_leases.is_empty()
    {
        return Err(invariant("defaulted EXECUTE frame changed or retained an untransferred resource"));
    }
    let transaction = record.transactions.get(&transaction_id).ok_or_else(||
        invariant("defaulted EXECUTE lost its exact transaction"))?;
    if transaction.peer != event.peer
        || Some(transaction.conversation) != event.conversation
        || transaction.message != runtime::WM_DDE_EXECUTE
        || transaction.transfer != Some(transfer_id)
        || transaction.source_event_id != Some(event.event_id)
        || transaction.awaiting_peer_ack
        || !transaction.requires_local_ack
        || transaction.local_acknowledged.is_some()
        || !transaction._atom_leases.is_empty()
    {
        return Err(invariant("defaulted EXECUTE transaction changed its exact terminal tuple"));
    }
    let transfer = record.transfers.get(&transfer_id).ok_or_else(||
        invariant("defaulted EXECUTE lost its exact borrowed HGLOBAL record"))?;
    if transfer.peer != event.peer
        || transfer.conversation != event.conversation
        || transfer.message != runtime::WM_DDE_EXECUTE
        || transfer.owns_handle
        || transfer.release_after_receive
        || transfer.protocol_ack_posted
        || transfer.handle.is_null()
        || !transfer.atom_leases.is_empty()
    {
        return Err(invariant("defaulted EXECUTE transfer is not the exact borrowed sender block"));
    }
    record.transactions.remove(&transaction_id).ok_or_else(||
        invariant("defaulted EXECUTE transaction disappeared during retirement"))?;
    record.transfers.remove(&transfer_id);
    Ok(())
}

pub(super) struct EventTransactionTerminal {
    pub(super) transaction: Option<Win16ClassicDdeTransactionId>,
    pub(super) transfer: Option<Win16ClassicDdeTransferId>,
    pub(super) transfer_accepted: bool,
    pub(super) local_acknowledged: Option<bool>,
}

pub(super) fn inspect_event_transaction_terminal(
    record: &super::super::state::NativeClassicDdeEndpoint,
    event: &Win16HostClassicDdeEvent,
) -> Result<EventTransactionTerminal, RuntimeError> {
    let transaction = event.transaction;
    let event_requires_ack = message_requires_local_ack(&event.message);
    let Some(transaction_id) = transaction else {
        if event_requires_ack {
            return Err(invariant("classic DDE source event requiring protocol ACK has no transaction"));
        }
        return Ok(EventTransactionTerminal {
            transaction: None,
            transfer: None,
            transfer_accepted: false,
            local_acknowledged: None,
        });
    };
    let entry = record.transactions.get(&transaction_id).ok_or_else(||
        RuntimeError::new(Kind::InvalidInput, "classic DDE event transaction is not live"))?;
    if entry.source_event_id != Some(event.event_id) {
        return Err(invariant("classic DDE transaction source EventId changed before retirement"));
    }
    if entry.requires_local_ack != event_requires_ack {
        return Err(invariant("classic DDE event ACK requirement changed before retirement"));
    }
    if entry.requires_local_ack && entry.local_acknowledged.is_none() {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "classic DDE EventId cannot retire before its exact positive or negative protocol ACK"));
    }
    let transfer = entry.transfer;
    if let Some(transfer_id) = transfer {
        let native = record.transfers.get(&transfer_id).ok_or_else(||
            invariant("classic DDE transaction lost its exact HGLOBAL transfer"))?;
        if native.peer != entry.peer
            || native.conversation != Some(entry.conversation)
            || native.message != entry.message
        {
            return Err(invariant("classic DDE transaction transfer changed its exact peer/conversation/message"));
        }
        if event.peer != entry.peer || event.conversation != Some(entry.conversation) {
            return Err(invariant("classic DDE transfer terminal changed its exact event peer/conversation"));
        }
        match (&event.message, entry.message) {
            (Win16ClassicDdeMessage::Execute { global }, runtime::WM_DDE_EXECUTE)
                if global.transfer == Some(transfer_id)
                    && !native.owns_handle
                    && native.protocol_ack_posted => {}
            (Win16ClassicDdeMessage::Ack {
                value: Win16ClassicDdeAckValue::ExecuteTransfer(Some(ack_transfer)), ..
            }, runtime::WM_DDE_EXECUTE) if *ack_transfer == transfer_id => {}
            (Win16ClassicDdeMessage::Execute { .. }, runtime::WM_DDE_EXECUTE)
            | (Win16ClassicDdeMessage::Ack {
                value: Win16ClassicDdeAckValue::ExecuteTransfer(_), ..
            }, runtime::WM_DDE_EXECUTE) => {
                return Err(invariant("classic DDE EXECUTE terminal changed its exact transfer ID"));
            }
            _ => {}
        }
    }
    let peer_ack_positive = matches!(&event.message,
        Win16ClassicDdeMessage::Ack { status, .. } if status.acknowledged);
    let transfer_accepted = peer_ack_positive && transfer.is_some_and(|id|
        record.transfers.get(&id).is_some_and(|transfer| transfer.release_after_receive));
    Ok(EventTransactionTerminal {
        transaction: Some(transaction_id),
        transfer,
        transfer_accepted,
        local_acknowledged: entry.local_acknowledged,
    })
}


pub(super) fn settle_global_transfer(
    record: &mut super::super::state::NativeClassicDdeEndpoint,
    transfer_id: Win16ClassicDdeTransferId,
    accepted: bool,
) -> Result<(), RuntimeError> {
    let transfer = record.transfers.get_mut(&transfer_id).ok_or_else(||
        invariant("classic DDE terminal lost its exact HGLOBAL transfer record"))?;
    if accepted {
        // The ACK has already transferred this release=true block to the
        // peer. Record that protocol ownership transition before atom cleanup
        // can fail, so teardown cannot free the peer-owned HGLOBAL.
        transfer.owns_handle = false;
    }
    for lease in &mut transfer.atom_leases { lease.release()?; }
    if !accepted && transfer.owns_handle && !transfer.handle.is_null() {
        // Otherwise this endpoint still owns the block, either as sender of
        // a retained transfer or receiver of WM_DDE_EXECUTE. Keep the exact
        // ledger record if freeing fails so quiescence cannot claim retirement.
        let still_owned = unsafe { GlobalFree(transfer.handle) };
        if !still_owned.is_null() {
            return Err(last_error("GlobalFree retained classic DDE sender block"));
        }
        transfer.owns_handle = false;
    }
    Ok(())
}

pub(super) fn retire_event_transaction(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16HostClassicDdeEndpoint,
    event: &Win16HostClassicDdeEvent,
    frame_key: (Win16ClassicDdeOperationId, Win16HostClassicDdeCallbackFrame),
) -> Result<(), RuntimeError> {
    let mut worker = state.borrow_mut();
    let record = worker.classic_dde_endpoints.get_mut(&endpoint).ok_or_else(||
        RuntimeError::new(Kind::InvalidInput, "classic DDE transaction endpoint is not live"))?;
    let native = record.synchronous_frames.get(&frame_key).ok_or_else(||
        invariant("classic DDE source transaction lost its exact synchronous frame"))?;
    if native.event.event_id != event.event_id || native.event.transaction != event.transaction {
        return Err(invariant("classic DDE source frame changed its exact event transaction"));
    }
    let terminal = inspect_event_transaction_terminal(record, event)?;
    if let Some(accepted) = terminal.local_acknowledged {
        let native = record.synchronous_frames.get_mut(&frame_key)
            .expect("exact frame was checked");
        settle_incoming_global_release(&mut native.globals_after_positive_ack, accepted)?;
    }
    free_owned_incoming_globals(&mut record.synchronous_frames.get_mut(&frame_key)
        .expect("exact frame was checked").globals_to_free)?;
    for lease in &mut record.synchronous_frames.get_mut(&frame_key)
        .expect("exact frame was checked").atom_leases
    {
        lease.release()?;
    }
    if let Some(transfer_id) = terminal.transfer {
        settle_global_transfer(record, transfer_id, terminal.transfer_accepted)?;
    }
    if let Some(transaction) = terminal.transaction {
        record.transactions.remove(&transaction).ok_or_else(||
            invariant("classic DDE event transaction disappeared during retirement"))?;
    }
    if let Some(transfer) = terminal.transfer {
        record.transfers.remove(&transfer);
    }
    Ok(())
}

pub(super) fn fail_worker(state: &Rc<RefCell<WorkerState>>, error: RuntimeError) {
    let mut worker = state.borrow_mut();
    worker.callbacks_enabled = false;
    worker.aborted = true;
    worker.terminal_failures.push(Arc::new(error));
    // Wake both parked USER waiters and command continuations; the owner will
    // observe the terminal failure instead of waiting on a lost DDE source.
    unsafe { SetEvent(worker.wake_event.as_raw_handle() as _) };
}
