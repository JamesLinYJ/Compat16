use super::*;

pub(super) fn receive_message(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    message_id: u16,
    w_param: WPARAM,
    l_param: LPARAM,
) -> Result<Option<LRESULT>, RuntimeError> {
    let endpoint = state
        .borrow()
        .classic_dde_endpoints_by_native
        .get(&(hwnd as usize))
        .copied()
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InvalidInput,
                "classic DDE WndProc HWND has no endpoint identity",
            )
        })?;
    let (owner, worker_generation) = {
        let worker = state.borrow();
        let record = worker
            .classic_dde_endpoints
            .get(&endpoint)
            .ok_or_else(|| invariant("classic DDE WndProc endpoint record disappeared"))?;
        if record.hwnd != hwnd || record.window_destroyed {
            return Err(invariant(
                "classic DDE WndProc endpoint HWND was retired or replaced",
            ));
        }
        (record.owner, record.worker_generation)
    };
    let peer = native_peer_for_hwnd(state, w_param as HWND)?;
    // SAFETY: InSendMessage reports whether the calling thread is handling a sent message.
    let synchronous = unsafe { InSendMessage() } != 0;
    let (callback, frame) = if synchronous {
        (
            Win16HostCallback(allocate_identity(state)?),
            Win16HostClassicDdeCallbackFrame(allocate_identity(state)?),
        )
    } else {
        (Win16HostCallback(0), Win16HostClassicDdeCallbackFrame(0))
    };
    let conversation = conversation_for_peer(state, endpoint, peer);
    let event_id = Win16ClassicDdeEventId(allocate_identity(state)?);
    let (message, atom_leases, globals_to_free, globals_after_positive_ack, packed_l_param) =
        decode_incoming_message(state, endpoint, peer, message_id, l_param, synchronous)?;
    let event = Win16HostClassicDdeEvent {
        owner,
        endpoint,
        worker_generation,
        event_id,
        peer,
        conversation,
        transaction: None,
        delivery: if synchronous {
            // This placeholder never escapes the native WndProc. PollOwner
            // replaces it with its exact operation identity before publishing.
            runtime::Win16ClassicDdeDeliveryKind::Synchronous {
                operation_id: Win16ClassicDdeOperationId(0),
                callback,
                frame,
            }
        } else {
            runtime::Win16ClassicDdeDeliveryKind::Queued
        },
        message,
    };
    let mut ingress = PendingSynchronousClassicDdeIngress {
        endpoint,
        event,
        atom_leases,
        globals_to_free,
        globals_after_positive_ack,
        assigned_operation: None,
        callback,
        frame,
        raw_w_param: w_param,
        raw_l_param: l_param,
        packed_l_param,
    };

    let direct_operation = if synchronous {
        let worker = state.borrow();
        worker
            .active_classic_dde_operations
            .last()
            .and_then(|active| {
                (active.identity.owner == owner
                    && active.identity.worker_generation == worker_generation
                    && active.awaiting.is_none()
                    && active.replied.is_none())
                .then_some(active.identity)
            })
    } else {
        None
    };
    let has_parked_wait = if synchronous && direct_operation.is_none() {
        let worker = state.borrow();
        worker.active_user_waits.last().is_some_and(|(id, _)| {
            worker
                .active_operations
                .iter()
                .any(|active| active.id == *id)
        })
    } else {
        false
    };

    if synchronous && direct_operation.is_none() && !has_parked_wait {
        // No live runtime owner can publish this native callback. Let the
        // exact original message reach DefWindowProc without first binding an
        // EventId transaction that would then have no runtime terminal.
        // SAFETY: DefWindowProcW receives the window-procedure arguments for this message. Pointer parameters stay live for the call.
        let result = unsafe { DefWindowProcW(hwnd, u32::from(message_id), w_param, l_param) };
        if let Err(cleanup) = discard_unpublished_borrowed_execute(&state, &ingress.event) {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "classic DDE default processing completed but borrowed EXECUTE retirement failed",
            )
            .with_cleanup("retire exact unbound borrowed EXECUTE", cleanup));
        }
        ingress.globals_to_free.clear();
        ingress.globals_after_positive_ack.clear();
        ingress.packed_l_param = None;
        for lease in &mut ingress.atom_leases {
            lease.transfer_to_receiver();
        }
        return Ok(Some(result));
    }

    // Reserve the exact publication slot before binding a borrowed EXECUTE
    // transfer to this EventId. A later allocation failure must not strand a
    // transaction with no queued event or synchronous source frame.
    let reserve_publication = (|| {
        let mut worker = state.try_borrow_mut().map_err(|_| {
            invariant("classic DDE ingress publication reservation collided with worker state")
        })?;
        if !synchronous {
            let record = worker
                .classic_dde_endpoints
                .get_mut(&endpoint)
                .ok_or_else(|| {
                    invariant("classic DDE endpoint retired before queued event reservation")
                })?;
            if record.owner != owner || record.worker_generation != worker_generation {
                return Err(invariant(
                    "classic DDE endpoint changed before queued event reservation",
                ));
            }
            record.events.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve classic DDE queued event ownership",
                    error,
                )
            })?;
        } else if direct_operation.is_some() {
            let record = worker
                .classic_dde_endpoints
                .get_mut(&endpoint)
                .ok_or_else(|| {
                    invariant("classic DDE endpoint retired before callback-frame reservation")
                })?;
            if record.owner != owner || record.worker_generation != worker_generation {
                return Err(invariant(
                    "classic DDE endpoint changed before callback-frame reservation",
                ));
            }
            record.synchronous_frames.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve classic DDE synchronous callback frame",
                    error,
                )
            })?;
        } else {
            worker
                .pending_classic_dde_ingress
                .try_reserve(1)
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve parked synchronous classic DDE ingress",
                        error,
                    )
                })?;
        }
        Ok::<(), RuntimeError>(())
    })();
    if let Err(mut error) = reserve_publication {
        if let Err(cleanup) = discard_unpublished_borrowed_execute(&state, &ingress.event) {
            error = error.with_cleanup(
                "retire borrowed EXECUTE after publication reservation failure",
                cleanup,
            );
        }
        for lease in &mut ingress.atom_leases {
            if let Err(cleanup) = lease.release() {
                error = error.with_cleanup(
                    "release DDE atoms after publication reservation failure",
                    cleanup,
                );
            }
        }
        return Err(error);
    }

    let matching_transaction = transaction_for_incoming(
        state,
        endpoint,
        peer,
        conversation,
        message_id,
        &ingress.event.message,
    );
    let bound_transaction = bind_incoming_event_transaction(
        state,
        owner,
        worker_generation,
        endpoint,
        peer,
        conversation,
        message_id,
        &ingress.event.message,
        event_id,
        matching_transaction,
    );
    ingress.event.transaction = match bound_transaction {
        Ok(transaction) => transaction,
        Err(mut error) => {
            if let Err(cleanup) = discard_unpublished_borrowed_execute(&state, &ingress.event) {
                error = error.with_cleanup(
                    "retire borrowed EXECUTE transfer after event-bind failure",
                    cleanup,
                );
            }
            for lease in &mut ingress.atom_leases {
                if let Err(cleanup) = lease.release() {
                    error = error.with_cleanup(
                        "release classic DDE atom lease after transaction-bind failure",
                        cleanup,
                    );
                }
            }
            return Err(error);
        }
    };
    if !synchronous {
        if let Some((packed_message, packed_value)) = ingress.packed_l_param.take() {
            // Queued messages normally release their packed lParam during
            // capture; keep the ingress guard for any decoder that returns one.
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            unsafe { wire::free_packed_lparam(packed_message, packed_value) };
        }
        let event_for_rollback = ingress.event.clone();
        let publish = (|| {
            let mut worker = state.try_borrow_mut().map_err(|_| {
                invariant("classic DDE queued event publication collided with worker state")
            })?;
            let record = worker
                .classic_dde_endpoints
                .get_mut(&endpoint)
                .ok_or_else(|| invariant("classic DDE endpoint retired during event capture"))?;
            if record.owner != owner || record.worker_generation != worker_generation {
                return Err(invariant(
                    "classic DDE endpoint changed before queued event publication",
                ));
            }
            record.events.push_back(NativeQueuedClassicDdeEvent {
                event: ingress.event.clone(),
                atom_leases: std::mem::take(&mut ingress.atom_leases),
                globals_to_free: std::mem::take(&mut ingress.globals_to_free),
                globals_after_positive_ack: std::mem::take(&mut ingress.globals_after_positive_ack),
            });
            (crate::windows::win32_safe::set_event(worker.wake_event.as_raw_handle() as _));
            Ok::<(), RuntimeError>(())
        })();
        if let Err(mut error) = publish {
            if let Err(cleanup) = discard_unpublished_borrowed_execute(&state, &event_for_rollback)
            {
                error = error.with_cleanup(
                    "retire borrowed EXECUTE after queued-event publication failure",
                    cleanup,
                );
            }
            for lease in &mut ingress.atom_leases {
                if let Err(cleanup) = lease.release() {
                    error = error.with_cleanup(
                        "release DDE atoms after queued-event publication failure",
                        cleanup,
                    );
                }
            }
            return Err(error);
        }
        // Wake the native worker/runtime owner. This is transport readiness;
        // only PollOwner exposes the event and only EventId ACK consumes it.
        return Ok(Some(0));
    }

    if let Some(identity) = direct_operation {
        let event_for_rollback = ingress.event.clone();
        let step = match publish_host_callback(state, identity, ingress) {
            Ok(step) => step,
            Err(mut error) => {
                if !has_retained_synchronous_source(state, endpoint, identity, frame, event_id) {
                    if let Err(cleanup) =
                        discard_unpublished_borrowed_execute(&state, &event_for_rollback)
                    {
                        error = error.with_cleanup(
                            "retire borrowed EXECUTE after pre-publication callback failure",
                            cleanup,
                        );
                    }
                }
                return Err(error);
            }
        };
        let result = wait_for_callback_reply(state, identity, &step)?;
        return apply_synchronous_reply(state, hwnd, step, result);
    }

    let pending = {
        let mut worker = state.borrow_mut();
        worker.pending_classic_dde_ingress.push_back(ingress);
        worker
            .pending_classic_dde_ingress
            .back()
            .map(|entry| (entry.endpoint, entry.event.event_id))
            .ok_or_else(|| invariant("parked classic DDE ingress insertion was lost"))?
    };
    publish_user_wait_pending_work(state)?;
    wait_for_parked_callback_reply(state, endpoint, pending.1)?;
    let (identity, step, result) = find_replied_external_callback(state, endpoint, pending.1)?;
    let _ = identity;
    apply_synchronous_reply(state, hwnd, step, result)
}

pub(super) fn message_id(message: &Win16ClassicDdeMessage) -> u16 {
    match message {
        Win16ClassicDdeMessage::Initiate { .. } => runtime::WM_DDE_INITIATE,
        Win16ClassicDdeMessage::Terminate => runtime::WM_DDE_TERMINATE,
        Win16ClassicDdeMessage::Advise { .. } => runtime::WM_DDE_ADVISE,
        Win16ClassicDdeMessage::Unadvise { .. } => runtime::WM_DDE_UNADVISE,
        Win16ClassicDdeMessage::Ack { .. } => runtime::WM_DDE_ACK,
        Win16ClassicDdeMessage::Data { .. } => runtime::WM_DDE_DATA,
        Win16ClassicDdeMessage::Request { .. } => runtime::WM_DDE_REQUEST,
        Win16ClassicDdeMessage::Poke { .. } => runtime::WM_DDE_POKE,
        Win16ClassicDdeMessage::Execute { .. } => runtime::WM_DDE_EXECUTE,
    }
}

pub(super) fn native_peer_for_hwnd(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
) -> Result<Win16HostClassicDdePeer, RuntimeError> {
    if hwnd.is_null() || { crate::windows::win32_safe::is_window(hwnd) } == 0 {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "classic DDE peer HWND is not a live native window",
        ));
    }
    let mut worker = state.borrow_mut();
    if let Some(endpoint) = worker.classic_dde_endpoints_by_native.get(&(hwnd as usize)) {
        return Ok(Win16HostClassicDdePeer::Endpoint(*endpoint));
    }
    if let Some(identity) = worker.windows_by_native.get(&(hwnd as usize)) {
        return Ok(Win16HostClassicDdePeer::GuestWindow(identity.window));
    }
    if let Some((token, peer)) = worker
        .classic_dde_native_peers
        .iter()
        .find(|(_, peer)| peer.hwnd == hwnd)
    {
        // PID/TID are observations associated with this opaque token. They
        // help detect ordinary stale-handle changes but do not prove HWND
        // incarnation across native handle reuse.
        let mut process_id = 0;
        // SAFETY: GetWindowThreadProcessId optionally writes a caller-owned process id.
        let thread_id = unsafe { GetWindowThreadProcessId(hwnd, &mut process_id) };
        if thread_id == peer.thread_id && process_id == peer.process_id {
            return Ok(Win16HostClassicDdePeer::NativeWindow(*token));
        }
        return Err(invariant(
            "classic DDE peer HWND observation changed during its token lifetime",
        ));
    }
    let mut process_id = 0;
    // SAFETY: GetWindowThreadProcessId optionally writes a caller-owned process id.
    let thread_id = unsafe { GetWindowThreadProcessId(hwnd, &mut process_id) };
    if thread_id == 0 || process_id == 0 {
        return Err(last_error("identify the native classic DDE peer"));
    }
    worker
        .classic_dde_native_peers
        .try_reserve(1)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve an opaque native classic DDE peer",
                error,
            )
        })?;
    let token = Win16HostClassicDdeNativeWindow(allocate_identity_from(&worker.identity_source)?);
    worker.classic_dde_native_peers.insert(
        token,
        super::super::state::NativeClassicDdePeer {
            hwnd,
            process_id,
            thread_id,
        },
    );
    Ok(Win16HostClassicDdePeer::NativeWindow(token))
}

pub(super) fn allocate_identity_from(
    source: &std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> Result<u64, RuntimeError> {
    use std::sync::atomic::Ordering;
    let allocated = source
        .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(1).filter(|next| *next != 0)
        })
        .map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "shared native classic-DDE identity space is exhausted",
            )
        })?;
    if allocated == 0 {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "shared identity source issued the reserved zero classic-DDE identity",
        ));
    }
    Ok(allocated)
}

pub(super) fn conversation_for_peer(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16HostClassicDdeEndpoint,
    peer: Win16HostClassicDdePeer,
) -> Option<Win16ClassicDdeConversationId> {
    let worker = state.borrow();
    let record = worker.classic_dde_endpoints.get(&endpoint)?;
    let mut matches = record
        .conversations
        .iter()
        .filter(|(_, conversation)| conversation.peer == peer);
    let first = *matches.next()?.0;
    if matches.next().is_some() {
        None
    } else {
        Some(first)
    }
}

pub(super) fn decode_atom(
    state: &Rc<RefCell<WorkerState>>,
    native: u16,
) -> Result<
    (
        Option<Win16ClassicDdeAtom>,
        Option<wire::NativeGlobalAtomLease>,
    ),
    RuntimeError,
> {
    if native == 0 {
        return Ok((None, None));
    }
    if native < 0xc000 {
        return Ok((Some(Win16ClassicDdeAtom::Integer(native)), None));
    }
    let codec = state.borrow().text_codec;
    let (bytes, lease) = wire::NativeGlobalAtomLease::retain(native, codec)?;
    Ok((
        Some(Win16ClassicDdeAtom::Name {
            guest_value: None,
            name_bytes: bytes,
        }),
        lease,
    ))
}

pub(super) fn decode_borrowed_atom(
    state: &Rc<RefCell<WorkerState>>,
    native: u16,
) -> Result<
    (
        Option<Win16ClassicDdeAtom>,
        Option<wire::NativeGlobalAtomLease>,
    ),
    RuntimeError,
> {
    if native == 0 {
        return Ok((None, None));
    }
    if native < 0xc000 {
        return Ok((Some(Win16ClassicDdeAtom::Integer(native)), None));
    }
    let codec = state.borrow().text_codec;
    let bytes = wire::NativeGlobalAtomLease::snapshot_name(native, codec)?;
    Ok((
        Some(Win16ClassicDdeAtom::Name {
            guest_value: None,
            name_bytes: bytes,
        }),
        None,
    ))
}

pub(super) fn decode_incoming_message(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16HostClassicDdeEndpoint,
    peer: Win16HostClassicDdePeer,
    message: u16,
    l_param: LPARAM,
    synchronous: bool,
) -> Result<
    (
        Win16ClassicDdeMessage,
        Vec<wire::NativeGlobalAtomLease>,
        Vec<HGLOBAL>,
        Vec<HGLOBAL>,
        Option<(u16, LPARAM)>,
    ),
    RuntimeError,
> {
    let mut atom_leases = Vec::new();
    let mut globals_to_free = Vec::new();
    let mut globals_after_positive_ack = Vec::new();
    let mut packed = None;
    let conversation = conversation_for_peer(state, endpoint, peer);
    let mut decode = || -> Result<Win16ClassicDdeMessage, RuntimeError> {
        Ok(match message {
            runtime::WM_DDE_INITIATE => {
                let (application_id, topic_id) = wire::split_raw_atom_pair(l_param);
                let (application, _) = decode_borrowed_atom(state, application_id)?;
                let (topic, _) = decode_borrowed_atom(state, topic_id)?;
                Win16ClassicDdeMessage::Initiate { application, topic }
            }
            runtime::WM_DDE_TERMINATE => Win16ClassicDdeMessage::Terminate,
            runtime::WM_DDE_EXECUTE => {
                // Win32 DDE uses PackDDElParam for EXECUTE; the high field is the
                // sender-owned command HGLOBAL and the low field is zero.
                let (low, high) = if synchronous {
                    wire::unpack_without_free(message, l_param)?
                } else {
                    wire::unpack_and_free(message, l_param)?
                };
                if synchronous {
                    packed = Some((message, l_param));
                }
                if low != 0 {
                    return Err(RuntimeError::new(
                        Kind::InvalidInput,
                        "WM_DDE_EXECUTE packed low word must be zero",
                    ));
                }
                let handle = high as HGLOBAL;
                let bytes = wire::snapshot_global_block(handle)?;
                // Validate/copy the sender-owned block before publishing a
                // borrowed transfer identity. An unreadable block must not leave
                // an orphan transfer in the endpoint ledger.
                let transfer = track_incoming_execute(state, endpoint, peer, conversation, handle)?;
                Win16ClassicDdeMessage::Execute {
                    global: runtime::Win16ClassicDdeGlobalBlock {
                        transfer: Some(transfer),
                        guest_global: None,
                        bytes,
                    },
                }
            }
            runtime::WM_DDE_ACK if is_initiate(state, endpoint, peer) => {
                let (application_id, topic_id) = wire::split_raw_atom_pair(l_param);
                let (application, app_lease) = decode_atom(state, application_id)?;
                let (topic, topic_lease) = decode_atom(state, topic_id)?;
                if let Some(lease) = app_lease {
                    atom_leases.push(lease);
                }
                if let Some(lease) = topic_lease {
                    atom_leases.push(lease);
                }
                Win16ClassicDdeMessage::Ack {
                    status: Win16ClassicDdeAckStatus {
                        raw: 0,
                        application_return_code: 0,
                        reserved: 0,
                        busy: false,
                        acknowledged: true,
                    },
                    value: Win16ClassicDdeAckValue::InitiateAtoms { application, topic },
                }
            }
            _ if wire::uses_packed_lparam(message) => {
                let (low, high) = if synchronous {
                    wire::unpack_without_free(message, l_param)?
                } else {
                    wire::unpack_and_free(message, l_param)?
                };
                if synchronous {
                    packed = Some((message, l_param));
                }
                decode_packed_message(
                    state,
                    endpoint,
                    peer,
                    conversation,
                    message,
                    low,
                    high,
                    &mut atom_leases,
                    &mut globals_to_free,
                    &mut globals_after_positive_ack,
                )?
            }
            _ => {
                return Err(RuntimeError::new(
                    Kind::InvalidInput,
                    "unsupported native WM_DDE message identifier",
                ));
            }
        })
    };
    let decoded_result = decode();
    drop(decode);
    let decoded = match decoded_result {
        Ok(decoded) => decoded,
        Err(mut error) => {
            for lease in &mut atom_leases {
                if let Err(cleanup) = lease.release() {
                    error = error.with_cleanup(
                        "release classic DDE atom lease after decode failure",
                        cleanup,
                    );
                }
            }
            if let Some((packed_message, packed_value)) = packed.take() {
                // SAFETY: UnpackDDElParam succeeded for this exact synchronous
                // payload; no frame/default procedure acquired its lease.
                unsafe { wire::free_packed_lparam(packed_message, packed_value) };
            }
            return Err(error);
        }
    };
    Ok((
        decoded,
        atom_leases,
        globals_to_free,
        globals_after_positive_ack,
        packed,
    ))
}

pub(super) fn track_incoming_execute(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16HostClassicDdeEndpoint,
    peer: Win16HostClassicDdePeer,
    conversation: Option<Win16ClassicDdeConversationId>,
    handle: HGLOBAL,
) -> Result<Win16ClassicDdeTransferId, RuntimeError> {
    if handle.is_null() {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "WM_DDE_EXECUTE command HGLOBAL is NULL",
        ));
    }
    let transfer = Win16ClassicDdeTransferId(allocate_identity(state)?);
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
    if record
        .transfers
        .values()
        .any(|active| active.handle == handle)
    {
        return Err(invariant(
            "native WM_DDE_EXECUTE HGLOBAL is already leased by this endpoint",
        ));
    }
    record.transfers.insert(
        transfer,
        NativeClassicDdeTransfer {
            // The sender retains the command HGLOBAL until it receives our exact
            // ACK. Keep only a borrowed handle identity until the source EventId
            // retires; the receiver must never GlobalFree the sender's block.
            handle,
            peer,
            conversation,
            owns_handle: false,
            release_after_receive: false,
            protocol_ack_posted: false,
            message: runtime::WM_DDE_EXECUTE,
            atom_leases: Vec::new(),
        },
    );
    Ok(transfer)
}

pub(super) fn is_initiate(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16HostClassicDdeEndpoint,
    peer: Win16HostClassicDdePeer,
) -> bool {
    let worker = state.borrow();
    let endpoint_owner = worker
        .classic_dde_endpoints
        .get(&endpoint)
        .map(|record| record.owner);
    worker
        .active_classic_dde_operations
        .iter()
        .rev()
        .any(|active| {
            matches!(&active.call, Win16HostClassicDdeCall::Send {
                owner, endpoint: call_endpoint, target, conversation: None,
                message: Win16ClassicDdeMessage::Initiate { .. }, ..
            } if *owner == active.identity.owner && *call_endpoint == endpoint
                && match target {
                    runtime::Win16HostClassicDdeTarget::BroadcastInitiate => true,
                    runtime::Win16HostClassicDdeTarget::Peer(target_peer) => *target_peer == peer,
                })
                && active.identity.worker_generation == worker.worker_retirement_id
                && Some(active.identity.owner) == endpoint_owner
                && peer != Win16HostClassicDdePeer::Endpoint(endpoint)
        })
}

pub(super) fn decode_packed_message(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16HostClassicDdeEndpoint,
    peer: Win16HostClassicDdePeer,
    conversation: Option<Win16ClassicDdeConversationId>,
    message: u16,
    low: usize,
    high: usize,
    atom_leases: &mut Vec<wire::NativeGlobalAtomLease>,
    globals_to_free: &mut Vec<HGLOBAL>,
    globals_after_positive_ack: &mut Vec<HGLOBAL>,
) -> Result<Win16ClassicDdeMessage, RuntimeError> {
    match message {
        runtime::WM_DDE_ACK => {
            let raw = low as u16;
            let status = Win16ClassicDdeAckStatus {
                raw,
                application_return_code: (raw & 0x00ff) as u8,
                reserved: ((raw >> 8) & 0x3f) as u8,
                acknowledged: raw & 0x8000 != 0,
                busy: raw & 0x4000 != 0,
            };
            let transaction =
                find_execute_ack_transaction(state, endpoint, peer, conversation, high);
            let value = if let Some((_, transfer)) = transaction {
                Win16ClassicDdeAckValue::ExecuteTransfer(Some(transfer))
            } else if high == 0 {
                Win16ClassicDdeAckValue::ItemAtom(None)
            } else if high <= usize::from(u16::MAX) {
                let (atom, lease) = decode_atom(state, high as u16)?;
                if let Some(lease) = lease {
                    atom_leases.push(lease);
                }
                Win16ClassicDdeAckValue::ItemAtom(atom)
            } else {
                Win16ClassicDdeAckValue::Unmatched
            };
            Ok(Win16ClassicDdeMessage::Ack { status, value })
        }
        runtime::WM_DDE_ADVISE => {
            let handle = low as HGLOBAL;
            let (item, lease) = decode_atom(state, high as u16)?;
            if let Some(lease) = lease {
                atom_leases.push(lease);
            }
            let bytes = wire::snapshot_global_block(handle)?;
            let (wire_format, raw_flags) = wire::parse_advise_header(&bytes)?;
            globals_after_positive_ack.push(handle);
            Ok(Win16ClassicDdeMessage::Advise {
                item,
                format: wire_format,
                options: wire::advise_options(raw_flags),
                global: runtime::Win16ClassicDdeGlobalBlock {
                    transfer: None,
                    guest_global: None,
                    bytes,
                },
            })
        }
        runtime::WM_DDE_UNADVISE | runtime::WM_DDE_REQUEST => {
            let (item, lease) = decode_atom(state, high as u16)?;
            if let Some(lease) = lease {
                atom_leases.push(lease);
            }
            if message == runtime::WM_DDE_REQUEST {
                Ok(Win16ClassicDdeMessage::Request {
                    item,
                    format: low as u16,
                })
            } else {
                Ok(Win16ClassicDdeMessage::Unadvise {
                    item,
                    reserved: low as u16,
                })
            }
        }
        runtime::WM_DDE_POKE => {
            let handle = low as HGLOBAL;
            let (item, lease) = decode_atom(state, high as u16)?;
            if let Some(lease) = lease {
                atom_leases.push(lease);
            }
            let bytes = wire::snapshot_global_block(handle)?;
            let (format, raw_flags) = wire::parse_poke_header(&bytes)?;
            if wire::poke_flags(raw_flags).release_after_receive {
                globals_after_positive_ack.push(handle);
            }
            Ok(Win16ClassicDdeMessage::Poke {
                item,
                format,
                flags: wire::poke_flags(raw_flags),
                global: runtime::Win16ClassicDdeGlobalBlock {
                    transfer: None,
                    guest_global: None,
                    bytes,
                },
            })
        }
        runtime::WM_DDE_DATA => {
            let handle = low as HGLOBAL;
            let (item, lease) = decode_atom(state, high as u16)?;
            if let Some(lease) = lease {
                atom_leases.push(lease);
            }
            if handle.is_null() {
                // DDE warm-link notifications carry the item atom and no
                // HGLOBAL. There is no DDEDATA header, transfer, fAckReq,
                // or fRelease bit to inspect or acknowledge.
                return Ok(Win16ClassicDdeMessage::Data {
                    item,
                    format: 0,
                    flags: runtime::Win16ClassicDdeDataFlags {
                        raw_flags: 0,
                        unused_bits: 0,
                        response: false,
                        release_after_receive: false,
                        reserved: false,
                        acknowledge_requested: false,
                    },
                    global: runtime::Win16ClassicDdeGlobalBlock {
                        transfer: None,
                        guest_global: None,
                        bytes: Vec::new(),
                    },
                });
            }
            let bytes = wire::snapshot_global_block(handle)?;
            let (format, raw_flags) = wire::parse_data_header(&bytes)?;
            let flags = wire::data_flags(raw_flags);
            if !flags.release_after_receive && !flags.acknowledge_requested {
                return Err(RuntimeError::new(
                    Kind::InvalidInput,
                    "DDEDATA cannot clear both fRelease and fAckReq",
                ));
            }
            if flags.release_after_receive {
                if flags.acknowledge_requested {
                    globals_after_positive_ack.push(handle);
                } else {
                    globals_to_free.push(handle);
                }
            }
            let transfer =
                find_item_transaction(state, endpoint, peer, conversation, item.as_ref());
            Ok(Win16ClassicDdeMessage::Data {
                item,
                format,
                flags,
                global: runtime::Win16ClassicDdeGlobalBlock {
                    transfer,
                    guest_global: None,
                    bytes,
                },
            })
        }
        _ => Err(RuntimeError::new(
            Kind::InvalidInput,
            "packed WM_DDE message decoder received an unsupported message",
        )),
    }
}
