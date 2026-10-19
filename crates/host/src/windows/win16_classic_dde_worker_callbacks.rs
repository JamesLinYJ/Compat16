use super::*;

pub(super) fn take_pending_ingress(
    state: &Rc<RefCell<WorkerState>>,
    call: &Win16HostClassicDdeCall,
    identity: Win16ClassicDdeOperationIdentity,
) -> Result<Option<PendingSynchronousClassicDdeIngress>, RuntimeError> {
    let requested = match call {
        Win16HostClassicDdeCall::Poll { owner, endpoint } => Some((*owner, Some(*endpoint))),
        Win16HostClassicDdeCall::PollOwner { owner } => Some((*owner, None)),
        _ => None,
    };
    let Some((owner, endpoint)) = requested else {
        return Ok(None);
    };
    if owner != identity.owner {
        return Err(invariant("classic DDE poll owner changed"));
    }
    let mut worker = state.borrow_mut();
    let index = worker.pending_classic_dde_ingress.iter().position(|entry| {
        entry.event.owner == owner
            && endpoint.is_none_or(|endpoint| entry.endpoint == endpoint)
            && entry.assigned_operation.is_none()
    });
    let Some(index) = index else {
        return Ok(None);
    };
    let mut ingress = worker
        .pending_classic_dde_ingress
        .remove(index)
        .ok_or_else(|| invariant("classic DDE pending ingress disappeared"))?;
    ingress.assigned_operation = Some(identity.id);
    ingress.event.delivery = Win16ClassicDdeDeliveryKind::Synchronous {
        operation_id: identity.id,
        callback: ingress.callback,
        frame: ingress.frame,
    };
    Ok(Some(ingress))
}

pub(super) fn publish_external_callback(
    state: &Rc<RefCell<WorkerState>>,
    identity: Win16ClassicDdeOperationIdentity,
    mut ingress: PendingSynchronousClassicDdeIngress,
) -> Result<(), RuntimeError> {
    let endpoint = ingress.endpoint;
    if ingress.event.owner != identity.owner
        || ingress.assigned_operation != Some(identity.id)
        || ingress.event.worker_generation != identity.worker_generation
    {
        return Err(invariant(
            "parked classic DDE ingress changed before publication",
        ));
    }
    let causal_parents = callback_causal_parents(state, identity)?;
    let step = Arc::new(Win16HostClassicDdeCallbackStep {
        owner: identity.owner,
        endpoint,
        worker_generation: identity.worker_generation,
        operation_id: identity.id,
        callback: ingress.callback,
        frame: ingress.frame,
        source: Win16ClassicDdeCallbackSource::ParkedUserWait,
        causal_parents,
        event: ingress.event.clone(),
    });
    let response = {
        let mut worker = state.try_borrow_mut().map_err(|_| {
            invariant("classic DDE parked callback publication collided with worker state")
        })?;
        let active_valid = worker
            .active_classic_dde_operations
            .last()
            .is_some_and(|active| active.identity == identity && active.awaiting.is_none());
        if !active_valid {
            return Err(invariant(
                "classic DDE parked callback has a conflicting operation owner",
            ));
        }
        let frame = NativeSynchronousClassicDdeFrame {
            event: ingress.event.clone(),
            callback_step: Arc::clone(&step),
            atom_leases: std::mem::take(&mut ingress.atom_leases),
            globals_to_free: std::mem::take(&mut ingress.globals_to_free),
            globals_after_positive_ack: std::mem::take(&mut ingress.globals_after_positive_ack),
            raw_w_param: ingress.raw_w_param,
            raw_l_param: ingress.raw_l_param,
            packed_l_param: ingress.packed_l_param.take(),
        };
        let endpoint_record = worker
            .classic_dde_endpoints
            .get_mut(&endpoint)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InvalidInput,
                    "classic DDE endpoint retired before callback publication",
                )
            })?;
        if endpoint_record
            .synchronous_frames
            .insert((identity.id, ingress.frame), frame)
            .is_some()
        {
            return Err(invariant("classic DDE callback frame identity was reused"));
        }
        let active = worker
            .active_classic_dde_operations
            .last_mut()
            .ok_or_else(|| invariant("classic DDE parked callback operation disappeared"))?;
        active.external_ingress = Some((endpoint, step.event.event_id, step.frame));
        active.awaiting = Some(Arc::clone(&step));
        active.response.clone()
    };
    response
        .send(Ok(Win16HostClassicDdeStep::Callback(step)))
        .map_err(|_| {
            RuntimeError::new(
                Kind::HostFailure,
                "runtime dropped a parked classic DDE callback",
            )
        })
}

pub(super) fn publish_host_callback(
    state: &Rc<RefCell<WorkerState>>,
    identity: Win16ClassicDdeOperationIdentity,
    mut ingress: PendingSynchronousClassicDdeIngress,
) -> Result<Arc<Win16HostClassicDdeCallbackStep>, RuntimeError> {
    ingress.event.delivery = Win16ClassicDdeDeliveryKind::Synchronous {
        operation_id: identity.id,
        callback: ingress.callback,
        frame: ingress.frame,
    };
    let causal_parents = callback_causal_parents(state, identity)?;
    let step = Arc::new(Win16HostClassicDdeCallbackStep {
        owner: identity.owner,
        endpoint: ingress.endpoint,
        worker_generation: identity.worker_generation,
        operation_id: identity.id,
        callback: ingress.callback,
        frame: ingress.frame,
        source: Win16ClassicDdeCallbackSource::HostOperation,
        causal_parents,
        event: ingress.event.clone(),
    });
    {
        let mut worker = state.try_borrow_mut().map_err(|_| {
            invariant("classic DDE host callback publication collided with worker state")
        })?;
        if !worker
            .active_classic_dde_operations
            .last()
            .is_some_and(|active| {
                active.identity == identity && active.awaiting.is_none() && active.replied.is_none()
            })
        {
            return Err(invariant(
                "classic DDE host callback has no exact active operation owner",
            ));
        }
        let frame = NativeSynchronousClassicDdeFrame {
            event: ingress.event.clone(),
            callback_step: Arc::clone(&step),
            atom_leases: std::mem::take(&mut ingress.atom_leases),
            globals_to_free: std::mem::take(&mut ingress.globals_to_free),
            globals_after_positive_ack: std::mem::take(&mut ingress.globals_after_positive_ack),
            raw_w_param: ingress.raw_w_param,
            raw_l_param: ingress.raw_l_param,
            packed_l_param: ingress.packed_l_param.take(),
        };
        let endpoint_record = worker
            .classic_dde_endpoints
            .get_mut(&ingress.endpoint)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InvalidInput,
                    "classic DDE endpoint retired during callback publication",
                )
            })?;
        if endpoint_record.owner != identity.owner
            || endpoint_record.worker_generation != identity.worker_generation
        {
            return Err(invariant(
                "classic DDE callback endpoint owner changed before publication",
            ));
        }
        if endpoint_record
            .synchronous_frames
            .insert((identity.id, ingress.frame), frame)
            .is_some()
        {
            return Err(invariant("classic DDE callback frame identity was reused"));
        }
        let active = worker
            .active_classic_dde_operations
            .last_mut()
            .ok_or_else(|| {
                invariant("classic DDE active operation disappeared during callback publication")
            })?;
        active.awaiting = Some(Arc::clone(&step));
        active
            .response
            .send(Ok(Win16HostClassicDdeStep::Callback(Arc::clone(&step))))
            .map_err(|_| {
                RuntimeError::new(
                    Kind::HostFailure,
                    "runtime dropped a synchronous classic DDE callback",
                )
            })?;
    }
    Ok(step)
}

pub(super) fn active_causal_parents(
    state: &Rc<RefCell<WorkerState>>,
    identity: Win16ClassicDdeOperationIdentity,
) -> Result<Vec<Win16ClassicDdeOperationIdentity>, RuntimeError> {
    let worker = state.borrow();
    let Some(parent) = worker.active_classic_dde_operations.last() else {
        return Ok(Vec::new());
    };
    if parent.identity.owner != identity.owner
        || parent.identity.worker_generation != identity.worker_generation
    {
        // A synchronous DDE call may cross Win16 task owners. Do not assert
        // same-owner causality across that boundary; the native protocol
        // fields remain the only available correlation evidence there.
        return Ok(Vec::new());
    }
    let same_owner_count = worker
        .active_classic_dde_operations
        .iter()
        .rev()
        .take_while(|active| {
            active.identity.owner == identity.owner
                && active.identity.worker_generation == identity.worker_generation
        })
        .count();
    let mut causal_parents = Vec::new();
    causal_parents
        .try_reserve(same_owner_count)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact classic DDE causal ancestry",
                error,
            )
        })?;
    for active in worker
        .active_classic_dde_operations
        .iter()
        .rev()
        .take_while(|active| {
            active.identity.owner == identity.owner
                && active.identity.worker_generation == identity.worker_generation
        })
    {
        if active.awaiting.is_none() {
            return Err(invariant(
                "nested classic DDE operation parent is not suspended on an exact callback",
            ));
        }
        causal_parents.push(active.identity);
    }
    Ok(causal_parents)
}

pub(super) fn callback_causal_parents(
    state: &Rc<RefCell<WorkerState>>,
    identity: Win16ClassicDdeOperationIdentity,
) -> Result<Vec<Win16ClassicDdeOperationIdentity>, RuntimeError> {
    let worker = state.borrow();
    let active = worker
        .active_classic_dde_operations
        .iter()
        .find(|active| active.identity == identity)
        .ok_or_else(|| invariant("classic DDE callback lost its active operation ancestry"))?;
    let mut parents = Vec::new();
    parents
        .try_reserve(active.causal_parents.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "copy exact classic DDE callback ancestry",
                error,
            )
        })?;
    parents.extend_from_slice(&active.causal_parents);
    Ok(parents)
}

pub(super) fn wait_for_callback_reply(
    state: &Rc<RefCell<WorkerState>>,
    identity: Win16ClassicDdeOperationIdentity,
    step: &Win16HostClassicDdeCallbackStep,
) -> Result<Win16HostClassicDdeCallbackResult, RuntimeError> {
    loop {
        {
            let worker = state.borrow();
            let active = worker
                .active_classic_dde_operations
                .last()
                .ok_or_else(|| invariant("classic DDE callback owner disappeared before reply"))?;
            if active.identity != identity {
                return Err(invariant(
                    "classic DDE callback reply crossed nested operation identity",
                ));
            }
            if let Some(result) = active.replied.clone() {
                return Ok(result);
            }
            if active.awaiting.as_deref() != Some(step) {
                return Err(invariant(
                    "classic DDE callback no longer owns its exact suspended frame",
                ));
            }
        }
        let command = super::super::super::win16_message_loop::wait_for_worker_command(state)?;
        super::super::process_command(state, command);
    }
}

pub(super) fn apply_synchronous_reply(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    step: Arc<Win16HostClassicDdeCallbackStep>,
    result: Win16HostClassicDdeCallbackResult,
) -> Result<Option<LRESULT>, RuntimeError> {
    let translated = matches!(
        &result,
        Win16HostClassicDdeCallbackResult::WindowProcedure(_)
    );
    let native_result = match result {
        Win16HostClassicDdeCallbackResult::WindowProcedure(value) => value as LRESULT,
        Win16HostClassicDdeCallbackResult::Untranslated => {
            // Preserve the original native message/LPARAM until the exact
            // default procedure has consumed it.
            // SAFETY: DefWindowProcW receives the window-procedure arguments for this message. Pointer parameters stay live for the call.
            let result = unsafe {
                DefWindowProcW(
                    hwnd,
                    u32::from(message_id(&step.event.message)),
                    frame_wparam(state, &step)?,
                    frame_lparam(state, &step)?,
                )
            };
            let mut worker = state.borrow_mut();
            let endpoint = worker
                .classic_dde_endpoints
                .get_mut(&step.endpoint)
                .ok_or_else(|| {
                    invariant("classic DDE endpoint retired during default processing")
                })?;
            let frame = endpoint
                .synchronous_frames
                .get_mut(&(step.operation_id, step.frame))
                .ok_or_else(|| {
                    invariant("classic DDE native frame disappeared during default processing")
                })?;
            frame.packed_l_param = None;
            frame.globals_to_free.clear();
            frame.globals_after_positive_ack.clear();
            for lease in &mut frame.atom_leases {
                lease.transfer_to_receiver();
            }
            result
        }
    };
    if step.source == Win16ClassicDdeCallbackSource::HostOperation {
        retire_callback_event_after_reply(
            state,
            step.endpoint,
            &step.event,
            (step.operation_id, step.frame),
            translated,
        )?;
        retire_callback_frame_after_cleanup(state, &step)?;
    } else {
        // Queue the marker only after default processing and the native reply
        // are ready to return. Posting during reply acceptance could let a
        // nested default-procedure pump consume it while this WndProc is live.
        // No message pump runs between this post and the WndProc return.
        // SAFETY: PostMessageW queues scalar message parameters. Any pointer in lParam stays valid until the receiving window procedure returns.
        if unsafe {
            PostMessageW(
                hwnd,
                AFTER_CALLBACK_MESSAGE,
                step.operation_id.0 as usize,
                step.event.event_id.0 as LPARAM,
            )
        } == 0
        {
            return Err(last_error("post classic WM_DDE callback-retirement marker"));
        }
    }
    Ok(Some(native_result))
}

pub(super) fn frame_wparam(
    state: &Rc<RefCell<WorkerState>>,
    step: &Win16HostClassicDdeCallbackStep,
) -> Result<WPARAM, RuntimeError> {
    let worker = state.borrow();
    worker
        .classic_dde_endpoints
        .get(&step.endpoint)
        .and_then(|endpoint| {
            endpoint
                .synchronous_frames
                .get(&(step.operation_id, step.frame))
        })
        .map(|frame| frame.raw_w_param)
        .ok_or_else(|| invariant("classic DDE callback has no exact native wParam frame"))
}

pub(super) fn frame_lparam(
    state: &Rc<RefCell<WorkerState>>,
    step: &Win16HostClassicDdeCallbackStep,
) -> Result<LPARAM, RuntimeError> {
    let worker = state.borrow();
    worker
        .classic_dde_endpoints
        .get(&step.endpoint)
        .and_then(|endpoint| {
            endpoint
                .synchronous_frames
                .get(&(step.operation_id, step.frame))
        })
        .map(|frame| frame.raw_l_param)
        .ok_or_else(|| invariant("classic DDE callback has no exact native lParam frame"))
}

pub(super) fn publish_user_wait_pending_work(
    state: &Rc<RefCell<WorkerState>>,
) -> Result<(), RuntimeError> {
    let (wait_id, response) = {
        let worker = state.borrow();
        let (wait_id, _) = *worker
            .active_user_waits
            .last()
            .ok_or_else(|| invariant("parked classic DDE ingress lost its USER wait"))?;
        let active = worker
            .active_operations
            .iter()
            .find(|active| active.id == wait_id)
            .ok_or_else(|| invariant("parked classic DDE ingress lost its USER operation"))?;
        (wait_id, active.response.clone())
    };
    let generation = allocate_identity(state)?;
    response
        .send(Ok(Win16WindowStep::PendingGuestWork {
            operation_id: Win16HostWindowOperationId(wait_id),
            generation,
        }))
        .map_err(|_| {
            RuntimeError::new(
                Kind::HostFailure,
                "runtime dropped a parked classic DDE USER wait",
            )
        })
}

pub(super) fn wait_for_parked_callback_reply(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16HostClassicDdeEndpoint,
    event_id: Win16ClassicDdeEventId,
) -> Result<(), RuntimeError> {
    loop {
        let replied = state
            .borrow()
            .active_classic_dde_operations
            .iter()
            .any(|active| {
                active
                    .external_ingress
                    .is_some_and(|(candidate, event, _)| candidate == endpoint && event == event_id)
                    && active.replied.is_some()
                    && active.awaiting.is_none()
            });
        if replied {
            return Ok(());
        }
        let command = super::super::super::win16_message_loop::wait_for_worker_command(state)?;
        match command {
            WorkerCommand::ContinueGetMessage { .. }
            | WorkerCommand::ContinueWaitMessage { .. } => {
                return Err(invariant(
                    "USER wait continued before parked classic DDE callback replied",
                ));
            }
            command => super::super::process_command(state, command),
        }
    }
}

pub(super) fn find_replied_external_callback(
    state: &Rc<RefCell<WorkerState>>,
    endpoint: Win16HostClassicDdeEndpoint,
    event_id: Win16ClassicDdeEventId,
) -> Result<
    (
        Win16ClassicDdeOperationIdentity,
        Arc<Win16HostClassicDdeCallbackStep>,
        Win16HostClassicDdeCallbackResult,
    ),
    RuntimeError,
> {
    let worker = state.borrow();
    let active = worker
        .active_classic_dde_operations
        .iter()
        .find(|active| {
            active
                .external_ingress
                .is_some_and(|(candidate, event, _)| candidate == endpoint && event == event_id)
        })
        .ok_or_else(|| invariant("parked classic DDE event lost its exact callback operation"))?;
    let (_, _, frame) = active.external_ingress.expect("predicate checked ingress");
    let result = active
        .replied
        .clone()
        .ok_or_else(|| invariant("parked classic DDE callback has no runtime reply"))?;
    let frame_record = worker
        .classic_dde_endpoints
        .get(&endpoint)
        .and_then(|record| record.synchronous_frames.get(&(active.identity.id, frame)))
        .ok_or_else(|| invariant("parked classic DDE callback lost its native frame"))?;
    Ok((
        active.identity,
        Arc::clone(&frame_record.callback_step),
        result,
    ))
}

pub(super) fn poll_endpoint(
    state: &Rc<RefCell<WorkerState>>,
    owner: guest_core::OwnerId,
    endpoint: Option<Win16HostClassicDdeEndpoint>,
) -> Result<Option<Win16HostClassicDdeEvent>, RuntimeError> {
    let worker = state.borrow();
    let selected = if let Some(endpoint) = endpoint {
        let record = worker.classic_dde_endpoints.get(&endpoint).ok_or_else(|| {
            RuntimeError::new(Kind::InvalidInput, "classic DDE poll endpoint is not live")
        })?;
        if record.owner != owner {
            return Err(invariant("classic DDE poll crossed endpoint owner"));
        }
        Some(record)
    } else {
        worker
            .classic_dde_endpoints
            .values()
            .filter(|record| record.owner == owner)
            .find(|record| !record.events.is_empty())
    };
    Ok(selected.and_then(|record| record.events.front().map(|entry| entry.event.clone())))
}

pub(super) fn bind_conversation(
    state: &Rc<RefCell<WorkerState>>,
    owner: guest_core::OwnerId,
    endpoint: Win16HostClassicDdeEndpoint,
    peer: Win16HostClassicDdePeer,
    source_operation: Win16ClassicDdeOperationIdentity,
    initiate_event_id: Win16ClassicDdeEventId,
    application: Option<&Win16ClassicDdeAtom>,
    topic: Option<&Win16ClassicDdeAtom>,
) -> Result<runtime::Win16HostClassicDdeConversationReceipt, RuntimeError> {
    if source_operation.owner != owner {
        return Err(invariant(
            "classic DDE conversation binding changed task owner",
        ));
    }
    let (codec, expected_app, expected_topic) = {
        let worker = state.borrow();
        let endpoint_record = worker.classic_dde_endpoints.get(&endpoint).ok_or_else(|| {
            RuntimeError::new(Kind::InvalidInput, "classic DDE endpoint is not live")
        })?;
        if endpoint_record.owner != owner
            || endpoint_record.worker_generation != source_operation.worker_generation
        {
            return Err(invariant(
                "classic DDE conversation binding crossed endpoint owner/generation",
            ));
        }
        let source_operation_record = worker
            .active_classic_dde_operations
            .iter()
            .find(|active| active.identity == source_operation)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InvalidInput,
                    "classic DDE conversation binding has no exact live source operation",
                )
            })?;
        let source = source_operation_record.awaiting.as_ref().ok_or_else(|| {
            RuntimeError::new(
                Kind::InvalidInput,
                "classic DDE conversation binding has no exact suspended INITIATE callback",
            )
        })?;
        let event = &source.event;
        if source.endpoint != endpoint
            || event.event_id != initiate_event_id
            || event.peer != peer
            || event.owner != owner
            || source.source != Win16ClassicDdeCallbackSource::HostOperation
            || !matches!(&source_operation_record.call,
                Win16HostClassicDdeCall::Send {
                    owner: call_owner,
                    endpoint: call_endpoint,
                    target: runtime::Win16HostClassicDdeTarget::BroadcastInitiate,
                    conversation: None,
                    message: Win16ClassicDdeMessage::Initiate { .. },
                    ..
                } if *call_owner == owner && *call_endpoint == endpoint)
        {
            return Err(invariant(
                "classic DDE conversation binding does not match its exact ACK event",
            ));
        }
        let Win16ClassicDdeMessage::Ack {
            value:
                Win16ClassicDdeAckValue::InitiateAtoms {
                    application: ack_app,
                    topic: ack_topic,
                },
            ..
        } = &event.message
        else {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "classic DDE conversation binding source is not an INITIATE ACK",
            ));
        };
        (worker.text_codec, ack_app.clone(), ack_topic.clone())
    };
    if !atoms_equal(expected_app.as_ref(), application)
        || !atoms_equal(expected_topic.as_ref(), topic)
    {
        return Err(invariant(
            "classic DDE conversation atom request differs from exact responder",
        ));
    }
    let mut atom_leases = Vec::new();
    atom_leases.try_reserve(2).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve native atom refs for classic DDE conversation",
            error,
        )
    })?;
    match application {
        Some(Win16ClassicDdeAtom::Name { name_bytes, .. }) => {
            atom_leases.push(wire::NativeGlobalAtomLease::from_guest_name(name_bytes, codec)?.1);
        }
        Some(Win16ClassicDdeAtom::Integer(value)) if *value < 0xc000 => {}
        Some(Win16ClassicDdeAtom::Integer(_)) => {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "classic DDE integer atom is outside the integer-atom range",
            ));
        }
        None => {}
    }
    match topic {
        Some(Win16ClassicDdeAtom::Name { name_bytes, .. }) => {
            atom_leases.push(wire::NativeGlobalAtomLease::from_guest_name(name_bytes, codec)?.1);
        }
        Some(Win16ClassicDdeAtom::Integer(value)) if *value < 0xc000 => {}
        Some(Win16ClassicDdeAtom::Integer(_)) => {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "classic DDE integer atom is outside the integer-atom range",
            ));
        }
        None => {}
    }
    let conversation = Win16ClassicDdeConversationId(allocate_identity(state)?);
    let mut worker = state.borrow_mut();
    let record = worker
        .classic_dde_endpoints
        .get_mut(&endpoint)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InvalidInput,
                "classic DDE endpoint retired before binding",
            )
        })?;
    if record.owner != owner || record.worker_generation != source_operation.worker_generation {
        return Err(invariant(
            "classic DDE endpoint changed before conversation bind",
        ));
    }
    if record
        .conversations
        .values()
        .any(|existing| existing.peer == peer)
    {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "classic DDE window pair already owns a conversation; use a distinct endpoint for another topic",
        ));
    }
    record.conversations.insert(
        conversation,
        NativeClassicDdeConversation {
            peer,
            _atom_leases: atom_leases,
        },
    );
    Ok(runtime::Win16HostClassicDdeConversationReceipt {
        owner,
        endpoint,
        conversation,
        peer,
        application: application.cloned(),
        topic: topic.cloned(),
        source_operation,
        initiate_event_id,
    })
}

pub(super) fn retire_conversation(
    state: &Rc<RefCell<WorkerState>>,
    owner: guest_core::OwnerId,
    endpoint: Win16HostClassicDdeEndpoint,
    conversation: Win16ClassicDdeConversationId,
    peer: Win16HostClassicDdePeer,
) -> Result<(), RuntimeError> {
    let mut worker = state.borrow_mut();
    let record = worker
        .classic_dde_endpoints
        .get(&endpoint)
        .ok_or_else(|| RuntimeError::new(Kind::InvalidInput, "classic DDE endpoint is not live"))?;
    if record.owner != owner {
        return Err(invariant(
            "classic DDE conversation retirement crossed owner",
        ));
    }
    let live = record.conversations.get(&conversation).ok_or_else(|| {
        RuntimeError::new(Kind::InvalidInput, "classic DDE conversation is not live")
    })?;
    if live.peer != peer {
        return Err(invariant(
            "classic DDE conversation peer changed before retirement",
        ));
    }
    if record
        .transactions
        .values()
        .any(|transaction| transaction.conversation == conversation)
        || record
            .transfers
            .values()
            .any(|transfer| transfer.conversation == Some(conversation))
        || record
            .events
            .iter()
            .any(|entry| entry.event.conversation == Some(conversation))
        || record
            .synchronous_frames
            .values()
            .any(|frame| frame.event.conversation == Some(conversation))
        || worker.pending_classic_dde_ingress.iter().any(|ingress| {
            ingress.endpoint == endpoint
                && ingress.event.owner == owner
                && ingress.event.worker_generation == record.worker_generation
                && ingress.event.conversation == Some(conversation)
        })
    {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "classic DDE conversation still owns pending events, callbacks, transactions, or transfers",
        ));
    }
    let record = worker
        .classic_dde_endpoints
        .get_mut(&endpoint)
        .ok_or_else(|| {
            invariant("classic DDE endpoint disappeared before conversation atom-lease release")
        })?;
    let live = record.conversations.get_mut(&conversation).ok_or_else(|| {
        invariant("classic DDE conversation disappeared before atom-lease release")
    })?;
    for lease in &mut live._atom_leases {
        lease.release()?;
    }
    record.conversations.remove(&conversation);
    Ok(())
}

pub(super) fn acknowledge_event(
    state: &Rc<RefCell<WorkerState>>,
    owner: guest_core::OwnerId,
    endpoint: Win16HostClassicDdeEndpoint,
    event_id: Win16ClassicDdeEventId,
) -> Result<Win16ClassicDdeEventId, RuntimeError> {
    let mut worker = state.borrow_mut();
    let record = worker
        .classic_dde_endpoints
        .get_mut(&endpoint)
        .ok_or_else(|| {
            RuntimeError::new(Kind::InvalidInput, "classic DDE event endpoint is not live")
        })?;
    if record.owner != owner {
        return Err(invariant("classic DDE event ACK crossed endpoint owner"));
    }
    if record
        .events
        .front()
        .is_none_or(|entry| entry.event.event_id != event_id)
    {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "classic DDE event ACK does not identify the exact oldest event",
        ));
    }
    let event = record
        .events
        .front()
        .ok_or_else(|| invariant("classic DDE exact event disappeared before terminal inspection"))?
        .event
        .clone();
    let terminal = inspect_event_transaction_terminal(record, &event)?;
    let entry = record.events.front_mut().ok_or_else(|| {
        invariant("classic DDE exact event disappeared before ACK release settlement")
    })?;
    if let Some(accepted) = terminal.local_acknowledged {
        settle_incoming_global_release(&mut entry.globals_after_positive_ack, accepted)?;
    }
    if let Some(transfer_id) = terminal.transfer {
        settle_global_transfer(record, transfer_id, terminal.transfer_accepted)?;
    }
    free_owned_incoming_globals(
        &mut record
            .events
            .front_mut()
            .ok_or_else(|| {
                invariant("classic DDE event disappeared before receiver-owned HGLOBAL release")
            })?
            .globals_to_free,
    )?;
    let entry = record
        .events
        .front_mut()
        .ok_or_else(|| invariant("classic DDE event disappeared before atom-lease release"))?;
    for lease in &mut entry.atom_leases {
        lease.release()?;
    }
    record.events.pop_front();
    if let Some(transaction) = terminal.transaction {
        record.transactions.remove(&transaction);
    }
    if let Some(transfer) = terminal.transfer {
        record.transfers.remove(&transfer);
    }
    Ok(event_id)
}

pub(super) fn finish_external_callback_after_unwind(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    operation_raw: u64,
    event_raw: u64,
) -> Result<(), RuntimeError> {
    let (identity, endpoint, frame, event, step, translated) = {
        let worker = state.borrow();
        let endpoint = worker
            .classic_dde_endpoints_by_native
            .get(&(hwnd as usize))
            .copied()
            .ok_or_else(|| invariant("classic DDE callback retirement marker has no endpoint"))?;
        let active = worker
            .active_classic_dde_operations
            .iter()
            .find(|active| {
                active.identity.id.0 == operation_raw
                    && active
                        .external_ingress
                        .is_some_and(|(entry_endpoint, event_id, _)| {
                            entry_endpoint == endpoint && event_id.0 == event_raw
                        })
            })
            .ok_or_else(|| {
                invariant("classic DDE callback retirement marker lost its exact operation")
            })?;
        let (_, _, frame) = active
            .external_ingress
            .expect("predicate checked exact ingress");
        if active.replied.is_none() || active.awaiting.is_some() {
            return Err(invariant(
                "classic DDE callback retired before its exact reply",
            ));
        }
        let native = worker
            .classic_dde_endpoints
            .get(&endpoint)
            .and_then(|record| record.synchronous_frames.get(&(active.identity.id, frame)))
            .ok_or_else(|| {
                invariant("classic DDE external callback frame disappeared before unwind")
            })?;
        if worker.pending_classic_dde_ingress.iter().any(|entry| {
            entry.endpoint == endpoint
                && entry.assigned_operation == Some(active.identity.id)
                && entry.event.event_id.0 == event_raw
        }) {
            return Err(invariant(
                "classic DDE ingress exists twice at callback retirement",
            ));
        }
        (
            active.identity,
            endpoint,
            frame,
            native.event.clone(),
            Arc::clone(&native.callback_step),
            active.replied.as_ref().is_some_and(|reply| {
                matches!(reply, Win16HostClassicDdeCallbackResult::WindowProcedure(_))
            }),
        )
    };
    retire_callback_event_after_reply(state, endpoint, &event, (identity.id, frame), translated)?;
    retire_callback_frame_after_cleanup(state, &step)?;
    finish_operation(
        state,
        identity,
        Ok(Win16HostClassicDdeResult::CallbackResumed(frame)),
        None,
    );
    Ok(())
}
