use super::*;

pub(super) fn reply_initiate(
    state: &Rc<RefCell<WorkerState>>,
    identity: Win16ClassicDdeOperationIdentity,
    owner: guest_core::OwnerId,
    endpoint: Win16HostClassicDdeEndpoint,
    worker_generation: u64,
    operation_id: Win16ClassicDdeOperationId,
    callback: Win16HostCallback,
    frame: Win16HostClassicDdeCallbackFrame,
    event_id: Win16ClassicDdeEventId,
    peer: Win16HostClassicDdePeer,
    accepted: bool,
    application_atom: Option<&Win16ClassicDdeAtom>,
    topic_atom: Option<&Win16ClassicDdeAtom>,
) -> Result<runtime::Win16HostClassicDdeInitiateReplyReceipt, RuntimeError> {
    if identity.owner != owner || identity.worker_generation != worker_generation {
        return Err(invariant("ReplyInitiate host operation crossed its callback owner/generation"));
    }
    exact_initiate_frame(state, endpoint, owner, worker_generation,
        operation_id, callback, frame, event_id, peer)?;
    let Win16ClassicDdeMessage::Initiate { application, topic } =
        exact_event_message(state, endpoint, operation_id, frame)?
    else { unreachable!() };
    if !atoms_equal(application.as_ref(), application_atom)
        || !atoms_equal(topic.as_ref(), topic_atom)
    {
        return Err(invariant("ReplyInitiate atom names changed from the exact incoming INITIATE"));
    }
    if !accepted {
        return Ok(runtime::Win16HostClassicDdeInitiateReplyReceipt {
            owner, endpoint, event_id, peer, accepted: false,
            application_atom: application_atom.cloned(), topic_atom: topic_atom.cloned(),
            native_result: None, conversation: None,
        });
    }
    let target = native_peer_hwnd(state, peer, owner, worker_generation)?;
    let response_hwnd = endpoint_hwnd(state, endpoint, owner, worker_generation)?;
    let codec = state.borrow().text_codec;
    let (application_id, mut application_lease) = wire::create_native_atom(application_atom, codec)?;
    let (topic_id, mut topic_lease) = wire::create_native_atom(topic_atom, codec)?;
    if application_id == 0 || topic_id == 0 {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "positive WM_DDE_INITIATE ACK requires non-NULL response atoms"));
    }
    let conversation = create_incoming_conversation(state, owner, endpoint,
        worker_generation, peer, application_atom, topic_atom)?;
    // A positive response owns fresh GlobalAddAtom references. The receiving
    // client deletes these ACK atoms; it must not reuse or consume the
    // borrowed WM_DDE_INITIATE atom references from the suspended frame.
    let l_param = wire::raw_atom_pair(application_id, topic_id);
    // SAFETY: This answers the exact live synchronous INITIATE frame using
    // the newly created response atom references and the endpoint's HWND.
    let native_result = unsafe { SendMessageW(target, u32::from(runtime::WM_DDE_ACK),
        response_hwnd as usize, l_param) };
    if let Some(lease) = application_lease.as_mut() { lease.transfer_to_receiver(); }
    if let Some(lease) = topic_lease.as_mut() { lease.transfer_to_receiver(); }
    Ok(runtime::Win16HostClassicDdeInitiateReplyReceipt {
        owner, endpoint, event_id, peer, accepted: true,
        application_atom: application_atom.cloned(), topic_atom: topic_atom.cloned(),
        native_result: Some(native_result), conversation: Some(conversation),
    })
}

pub(super) fn exact_initiate_frame(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16HostClassicDdeEndpoint,
    owner: guest_core::OwnerId,
    worker_generation: u64,
    operation_id: Win16ClassicDdeOperationId,
    callback: Win16HostCallback,
    frame: Win16HostClassicDdeCallbackFrame,
    event_id: Win16ClassicDdeEventId,
    peer: Win16HostClassicDdePeer,
) -> Result<(), RuntimeError> {
    let worker = state.borrow();
    let active = worker.active_classic_dde_operations.iter().rev()
        .find(|active| active.identity.id == operation_id
            && active.identity.owner == owner
            && active.identity.worker_generation == worker_generation
            && active.awaiting.as_ref().is_some_and(|step|
                step.callback == callback && step.frame == frame && step.endpoint == endpoint
                    && step.event.event_id == event_id && step.event.peer == peer))
        .ok_or_else(|| RuntimeError::new(Kind::InvalidInput,
            "ReplyInitiate does not name an exact suspended callback"))?;
    let _ = active;
    let record = worker.classic_dde_endpoints.get(&endpoint).ok_or_else(||
        RuntimeError::new(Kind::InvalidInput, "ReplyInitiate endpoint is not live"))?;
    if record.owner != owner || record.worker_generation != worker_generation {
        return Err(invariant("ReplyInitiate endpoint owner/generation changed"));
    }
    let native = record.synchronous_frames.get(&(operation_id, frame)).ok_or_else(||
        RuntimeError::new(Kind::InvalidInput, "ReplyInitiate callback frame was retired"))?;
    if native.event.event_id != event_id || native.event.peer != peer
        || !matches!(&native.event.message, Win16ClassicDdeMessage::Initiate { .. })
    {
        return Err(invariant("ReplyInitiate callback frame is not the exact WM_DDE_INITIATE"));
    }
    Ok(())
}

pub(super) fn exact_event_message(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16HostClassicDdeEndpoint,
    operation: Win16ClassicDdeOperationId,
    frame: Win16HostClassicDdeCallbackFrame,
) -> Result<Win16ClassicDdeMessage, RuntimeError> {
    state.borrow().classic_dde_endpoints.get(&endpoint)
        .and_then(|record| record.synchronous_frames.get(&(operation, frame)))
        .map(|frame| frame.event.message.clone())
        .ok_or_else(|| RuntimeError::new(Kind::InvalidInput,
            "classic DDE synchronous callback frame is not live"))
}

pub(super) fn create_incoming_conversation(
    state: &Rc<RefCell<WorkerState>>,
    owner: guest_core::OwnerId,
    endpoint: Win16HostClassicDdeEndpoint,
    worker_generation: u64,
    peer: Win16HostClassicDdePeer,
    application: Option<&Win16ClassicDdeAtom>,
    topic: Option<&Win16ClassicDdeAtom>,
) -> Result<Win16ClassicDdeConversationId, RuntimeError> {
    let codec = state.borrow().text_codec;
    let mut leases = Vec::new();
    leases.try_reserve(2).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve classic DDE server conversation atom refs", error,
    ))?;
    if let Some(Win16ClassicDdeAtom::Name { name_bytes, .. }) = application {
        leases.push(wire::NativeGlobalAtomLease::from_guest_name(name_bytes, codec)?.1);
    }
    if let Some(Win16ClassicDdeAtom::Name { name_bytes, .. }) = topic {
        leases.push(wire::NativeGlobalAtomLease::from_guest_name(name_bytes, codec)?.1);
    }
    for atom in [application, topic].into_iter().flatten() {
        if matches!(atom, Win16ClassicDdeAtom::Integer(value) if *value >= 0xc000) {
            return Err(RuntimeError::new(Kind::InvalidInput,
                "classic DDE integer atom is outside the integer-atom range"));
        }
    }
    let conversation = Win16ClassicDdeConversationId(allocate_identity(state)?);
    let mut worker = state.borrow_mut();
    let record = worker.classic_dde_endpoints.get_mut(&endpoint).ok_or_else(||
        RuntimeError::new(Kind::InvalidInput, "classic DDE endpoint retired before conversation creation"))?;
    if record.owner != owner || record.worker_generation != worker_generation {
        return Err(invariant("classic DDE server conversation crossed endpoint owner/generation"));
    }
    if record.conversations.values().any(|existing| existing.peer == peer) {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "classic DDE window pair already owns a conversation; use a distinct endpoint for another topic"));
    }
    record.conversations.insert(conversation, NativeClassicDdeConversation {
        peer, _atom_leases: leases,
    });
    Ok(conversation)
}

pub(super) fn forward_initiate_to_child(
    state: &Rc<RefCell<WorkerState>>,
    identity: Win16ClassicDdeOperationIdentity,
    owner: guest_core::OwnerId,
    parent: Win16HostClassicDdeEndpoint,
    worker_generation: u64,
    operation_id: Win16ClassicDdeOperationId,
    callback: Win16HostCallback,
    frame: Win16HostClassicDdeCallbackFrame,
    event_id: Win16ClassicDdeEventId,
    child: Win16HostClassicDdeEndpoint,
    peer: Win16HostClassicDdePeer,
    application_atom: Option<&Win16ClassicDdeAtom>,
    topic_atom: Option<&Win16ClassicDdeAtom>,
) -> Result<runtime::Win16HostClassicDdeResult, RuntimeError> {
    if identity.owner != owner || identity.worker_generation != worker_generation {
        return Err(invariant("ForwardInitiate crossed parent callback owner/generation"));
    }
    let peer_hwnd = native_peer_hwnd(state, peer, owner, worker_generation)?;
    let (raw_w_param, raw_l_param) = {
        let worker = state.borrow();
        let active = worker.active_classic_dde_operations.iter().rev()
            .find(|active| active.identity.id == operation_id
                && active.identity.owner == owner
                && active.identity.worker_generation == worker_generation
                && active.awaiting.as_ref().is_some_and(|step|
                    step.endpoint == parent && step.callback == callback && step.frame == frame
                        && step.event.event_id == event_id && step.event.peer == peer))
            .ok_or_else(|| RuntimeError::new(Kind::InvalidInput,
                "ForwardInitiate does not name an exact suspended parent callback"))?;
        let parent_record = worker.classic_dde_endpoints.get(&parent).ok_or_else(||
            RuntimeError::new(Kind::InvalidInput, "ForwardInitiate parent endpoint is not live"))?;
        let child_record = worker.classic_dde_endpoints.get(&child).ok_or_else(||
            RuntimeError::new(Kind::InvalidInput, "ForwardInitiate child endpoint is not live"))?;
        if parent_record.owner != owner || parent_record.worker_generation != worker_generation
            || child_record.owner != owner || child_record.worker_generation != worker_generation
            || child_record.parent != Some(parent)
        {
            return Err(invariant("ForwardInitiate child is not owned by the exact parent endpoint"));
        }
        let native = parent_record.synchronous_frames.get(&(operation_id, frame)).ok_or_else(||
            RuntimeError::new(Kind::InvalidInput, "ForwardInitiate parent frame was retired"))?;
        if native.event.event_id != event_id || native.event.peer != peer
            || !matches!(&native.event.message,
                Win16ClassicDdeMessage::Initiate { application, topic }
                    if atoms_equal(application.as_ref(), application_atom)
                        && atoms_equal(topic.as_ref(), topic_atom))
        {
            return Err(invariant("ForwardInitiate changed the exact original atom pair/event"));
        }
        if native.raw_w_param as HWND != peer_hwnd {
            return Err(invariant("ForwardInitiate peer HWND differs from the original wParam"));
        }
        let _ = active;
        (native.raw_w_param, native.raw_l_param)
    };
    let child_hwnd = endpoint_hwnd(state, child, owner, worker_generation)?;
    // SAFETY: This mirrors the exact nested synchronous INITIATE forwarded by
    // the OLE server window procedure, preserving the original source HWND
    // and raw atom pair while addressing the owned child endpoint.
    let native_result = unsafe { SendMessageW(child_hwnd,
        u32::from(runtime::WM_DDE_INITIATE), raw_w_param, raw_l_param) };
    Ok(runtime::Win16HostClassicDdeResult::ForwardInitiateReturned {
        owner, parent, child, peer, native_result,
    })
}

pub(super) fn create_endpoint(
    state: &Rc<RefCell<WorkerState>>,
    identity: Win16ClassicDdeOperationIdentity,
    owner: guest_core::OwnerId,
    parent: Option<Win16HostClassicDdeEndpoint>,
) -> Result<Win16HostClassicDdeEndpoint, RuntimeError> {
    if identity.owner != owner {
        return Err(invariant("classic DDE endpoint owner changed before creation"));
    }
    let endpoint = Win16HostClassicDdeEndpoint(allocate_identity(state)?);
    let parent_hwnd = {
        let worker = state.borrow();
        let parent_hwnd = match parent {
            Some(parent) => {
                let record = worker.classic_dde_endpoints.get(&parent).ok_or_else(||
                    RuntimeError::new(Kind::InvalidInput,
                        "classic DDE child endpoint parent is not live"))?;
                if record.owner != owner || record.worker_generation != identity.worker_generation {
                    return Err(invariant("classic DDE child endpoint parent owner changed"));
                }
                record.hwnd
            }
            None => std::ptr::null_mut(),
        };
        parent_hwnd
    };
    // SAFETY: A null module name requests this process's loaded module.
    let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
    if instance.is_null() {
        return Err(last_error("identify the classic DDE window module"));
    }
    let class_name = format!("Win16ClassicDde_{}_{}", identity.worker_generation, endpoint.0)
        .encode_utf16().chain(std::iter::once(0)).collect::<Vec<_>>();
    {
        // Insert the owner record before registering native resources so all
        // fallible Rust allocations precede the USER side effect.
        let mut worker = state.borrow_mut();
        worker.classic_dde_endpoints_by_native.try_reserve(1).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve native classic DDE endpoint identity", error))?;
        worker.classic_dde_endpoints.insert(endpoint, super::super::state::NativeClassicDdeEndpoint {
            owner, worker_generation: identity.worker_generation,
            hwnd: std::ptr::null_mut(), window_destroyed: false, parent,
            class_name: class_name.clone(), instance,
            events: std::collections::VecDeque::new(),
            conversations: std::collections::BTreeMap::new(),
            transfers: std::collections::BTreeMap::new(),
            transactions: std::collections::BTreeMap::new(),
            synchronous_frames: std::collections::HashMap::new(),
        });
    }
    let class = WNDCLASSEXW {
        cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
        lpfnWndProc: Some(window_proc),
        hInstance: instance,
        lpszClassName: class_name.as_ptr(),
        ..WNDCLASSEXW::default()
    };
    // SAFETY: `class_name` is NUL-terminated and `class` stays live for this
    // synchronous class-registration call on the owning USER thread.
    if unsafe { RegisterClassExW(&class) } == 0 {
        state.borrow_mut().classic_dde_endpoints.remove(&endpoint);
        return Err(last_error("register the private classic DDE endpoint class"));
    }
    let style = if parent.is_some() { WS_CHILD } else { WS_POPUP };
    // SAFETY: The class name and instance are host-owned. Root endpoints are
    // hidden top-level popup windows (never HWND_MESSAGE) so HWND_BROADCAST
    // can reach them; document endpoints are true children of their owner.
    let hwnd = unsafe { CreateWindowExW(
        0, class_name.as_ptr(), std::ptr::null(), style, 0, 0, 0, 0,
        parent_hwnd, std::ptr::null_mut(), instance, std::ptr::null(),
    ) };
    if hwnd.is_null() {
        // SAFETY: This exact class was registered above and no window was created.
        unsafe { UnregisterClassW(class_name.as_ptr(), instance) };
        state.borrow_mut().classic_dde_endpoints.remove(&endpoint);
        return Err(last_error("create the private classic DDE endpoint window"));
    }
    let mut worker = state.borrow_mut();
    let Some(record) = worker.classic_dde_endpoints.get_mut(&endpoint) else {
        drop(worker);
        // SAFETY: The newly created endpoint is still exclusively owned here.
        unsafe { DestroyWindow(hwnd) };
        // SAFETY: The class has no other endpoint window.
        unsafe { UnregisterClassW(class_name.as_ptr(), instance) };
        return Err(invariant("classic DDE endpoint record disappeared during creation"));
    };
    record.hwnd = hwnd;
    if worker.classic_dde_endpoints_by_native.insert(hwnd as usize, endpoint).is_some() {
        drop(worker);
        // SAFETY: Roll back the endpoint created by this exact operation.
        unsafe { DestroyWindow(hwnd) };
        // SAFETY: The unique class is no longer in use.
        unsafe { UnregisterClassW(class_name.as_ptr(), instance) };
        state.borrow_mut().classic_dde_endpoints.remove(&endpoint);
        return Err(invariant("native classic DDE endpoint HWND was already registered"));
    }
    Ok(endpoint)
}

pub(super) fn retire_endpoint(
    state: &Rc<RefCell<WorkerState>>,
    owner: guest_core::OwnerId,
    endpoint: Win16HostClassicDdeEndpoint,
) -> Result<runtime::Win16HostClassicDdeRetirementReceipt, RuntimeError> {
    let (mut receipt, hwnd, window_destroyed, name, instance, has_child, has_conversation_or_transaction) = {
        let worker = state.borrow();
        let record = worker.classic_dde_endpoints.get(&endpoint).ok_or_else(||
            RuntimeError::new(Kind::InvalidInput, "classic DDE endpoint is not live"))?;
        if record.owner != owner {
            return Err(invariant("classic DDE endpoint owner mismatch during retirement"));
        }
        let mut receipt = runtime::Win16HostClassicDdeRetirementReceipt {
            owner, endpoint, worker_generation: record.worker_generation, retired: false,
            pending_events: Vec::new(), retained_callbacks: Vec::new(), retained_transfers: Vec::new(),
        };
        let pending_ingress = worker.pending_classic_dde_ingress.iter().filter(|ingress|
            ingress.event.owner == owner && ingress.endpoint == endpoint
                && ingress.event.worker_generation == record.worker_generation).count();
        receipt.pending_events.try_reserve(record.events.len().saturating_add(pending_ingress)).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve classic DDE endpoint retirement event receipt", error))?;
        receipt.retained_callbacks.try_reserve(record.synchronous_frames.len()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve classic DDE endpoint callback retirement receipt", error))?;
        receipt.retained_transfers.try_reserve(record.transfers.len()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve classic DDE endpoint transfer retirement receipt", error))?;
        receipt.pending_events.extend(record.events.iter().map(|event| event.event.event_id));
        // Synchronous messages can be parked between USER dispatch and
        // runtime publication. Keep those exact EventIds visible to the
        // retirement receipt so this endpoint cannot be destroyed while the
        // ingress still owns its atom/global leases and borrowed HWND pair.
        receipt.pending_events.extend(worker.pending_classic_dde_ingress.iter().filter(|ingress|
            ingress.event.owner == owner && ingress.endpoint == endpoint
                && ingress.event.worker_generation == record.worker_generation)
            .map(|ingress| ingress.event.event_id));
        receipt.retained_callbacks.extend(record.synchronous_frames.keys()
            .map(|(_, frame)| *frame));
        receipt.retained_callbacks.sort_unstable();
        receipt.retained_transfers.extend(record.transfers.keys().copied());
        let has_child = worker.classic_dde_endpoints.values().any(|child|
            child.owner == owner && child.parent == Some(endpoint));
        (receipt, record.hwnd, record.window_destroyed, record.class_name.clone(), record.instance, has_child,
            !record.conversations.is_empty() || !record.transactions.is_empty())
    };
    if has_child || has_conversation_or_transaction
        || !receipt.pending_events.is_empty()
        || !receipt.retained_callbacks.is_empty()
        || !receipt.retained_transfers.is_empty()
    {
        return Ok(receipt);
    }
    if !window_destroyed {
        // SAFETY: The opaque token was resolved to this exact host-owned
        // endpoint on the current USER worker, and no callbacks/leases remain.
        if unsafe { DestroyWindow(hwnd) } == 0 {
            // Capture the failure before any other USER call changes it. Keep
            // the endpoint ledger intact so owner cleanup can retry.
            return Err(last_error("destroy the private classic DDE endpoint"));
        }
        let mut worker = state.borrow_mut();
        worker.classic_dde_endpoints_by_native.remove(&(hwnd as usize));
        let Some(record) = worker.classic_dde_endpoints.get_mut(&endpoint) else {
            return Err(invariant("classic DDE endpoint disappeared during retirement"));
        };
        record.hwnd = std::ptr::null_mut();
        record.window_destroyed = true;
    }
    // SAFETY: The exact endpoint's window has been destroyed and the class
    // is unique to this endpoint. On failure the retained record allows a
    // later retirement call to retry UnregisterClassW.
    if unsafe { UnregisterClassW(name.as_ptr(), instance) } == 0 {
        return Err(last_error("unregister the private classic DDE endpoint class"));
    }
    state.borrow_mut().classic_dde_endpoints.remove(&endpoint);
    receipt.retired = true;
    Ok(receipt)
}

pub(super) fn finish_operation(
    state: &Rc<RefCell<WorkerState>>,
    identity: Win16ClassicDdeOperationIdentity,
    result: Result<Win16HostClassicDdeResult, RuntimeError>,
    rejected_response: Option<Sender<Result<Win16HostClassicDdeStep, RuntimeError>>>,
) {
    let (response, callbacks) = {
        let mut worker = state.borrow_mut();
        let Some(active) = worker.active_classic_dde_operations.last()
            .filter(|active| active.identity == identity)
        else {
            if let Some(response) = rejected_response {
                let _ = response.send(Err(RuntimeError::new(Kind::InternalInvariant,
                    "classic WM_DDE terminal has no exact active operation")));
            }
            return;
        };
        let source_pending = active.awaiting.is_some() || active.replied.is_some()
            || active.callback_receipts != active.callback_retirements
            || worker.classic_dde_endpoints.values().any(|record|
                record.synchronous_frames.keys().any(|(operation, _)| *operation == identity.id))
            || worker.pending_classic_dde_ingress.iter().any(|entry|
                entry.assigned_operation == Some(identity.id));
        if source_pending {
            let response = active.response.clone();
            drop(worker);
            let cause = match result {
                Err(cause) => cause,
                Ok(_) => RuntimeError::new(Kind::HostFailure,
                    "classic WM_DDE native callback cleanup still owns its exact source frame"),
            };
            // A raw error carries no source-retirement proof. Retain the
            // operation, reply and resource ledgers for diagnosis/cleanup.
            let _ = response.send(Err(cause));
            return;
        }
        let callbacks = active.callback_retirements.clone();
        let response = active.response.clone();
        worker.active_classic_dde_operations.pop();
        (response, callbacks)
    };
    let proof = Arc::new(Win16HostClassicDdeSourceRetiredProof {
        operation: identity, callbacks,
    });
    let step = match result {
        Ok(result) => Win16HostClassicDdeStep::Complete {
            operation: identity, result, source_retired: proof,
        },
        Err(cause) => Win16HostClassicDdeStep::StartedFailure(Arc::new(
            runtime::Win16HostClassicDdeStartedFailure {
                operation: identity, cause: Arc::new(cause), source_retired: proof,
            },
        )),
    };
    let _ = response.send(Ok(step));
}

pub(super) fn call_owner(call: &Win16HostClassicDdeCall) -> guest_core::OwnerId {
    match call {
        Win16HostClassicDdeCall::QuiesceOwner { owner, .. }
        | Win16HostClassicDdeCall::CreateEndpoint { owner, .. }
        | Win16HostClassicDdeCall::RetireEndpoint { owner, .. }
        | Win16HostClassicDdeCall::BindConversation { owner, .. }
        | Win16HostClassicDdeCall::RetireConversation { owner, .. }
        | Win16HostClassicDdeCall::Send { owner, .. }
        | Win16HostClassicDdeCall::Post { owner, .. }
        | Win16HostClassicDdeCall::Poll { owner, .. }
        | Win16HostClassicDdeCall::PollOwner { owner }
        | Win16HostClassicDdeCall::AcknowledgeEvent { owner, .. }
        | Win16HostClassicDdeCall::ReplyInitiate { owner, .. }
        | Win16HostClassicDdeCall::ForwardInitiateToChild { owner, .. } => *owner,
    }
}

pub(super) fn allocate_identity(state: &Rc<RefCell<WorkerState>>) -> Result<u64, RuntimeError> {
    use std::sync::atomic::Ordering;
    let source = Arc::clone(&state.borrow().identity_source);
    let allocated = source.try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        current.checked_add(1).filter(|next| *next != 0)
    }).map_err(|_| RuntimeError::new(
        Kind::ResourceExhausted, "shared native classic-DDE identity space is exhausted",
    ))?;
    if allocated == 0 {
        return Err(RuntimeError::new(Kind::ResourceExhausted,
            "shared identity source issued the reserved zero classic-DDE identity"));
    }
    Ok(allocated)
}

pub(super) fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}

pub(super) fn last_error(context: &'static str) -> RuntimeError {
    // SAFETY: Read the calling USER worker's native error immediately after
    // the failed Win32 operation.
    let code = unsafe { GetLastError() };
    RuntimeError::new(Kind::HostFailure, format!("{context} failed with Windows error {code}"))
}

pub(super) fn endpoint_hwnd(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16HostClassicDdeEndpoint,
    owner: guest_core::OwnerId,
    worker_generation: u64,
) -> Result<HWND, RuntimeError> {
    let worker = state.borrow();
    let record = worker.classic_dde_endpoints.get(&endpoint).ok_or_else(||
        RuntimeError::new(Kind::InvalidInput, "classic DDE endpoint is not live"))?;
    if record.owner != owner || record.worker_generation != worker_generation
        || record.window_destroyed || record.hwnd.is_null()
    {
        return Err(invariant("classic DDE endpoint identity changed during operation"));
    }
    Ok(record.hwnd)
}
