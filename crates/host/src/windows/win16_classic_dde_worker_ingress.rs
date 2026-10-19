use super::*;

pub(in crate::windows::win16_windows) fn begin_operation(
    state: &Rc<RefCell<WorkerState>>,
    identity: Win16ClassicDdeOperationIdentity,
    call: Win16HostClassicDdeCall,
    response: Sender<Result<Win16HostClassicDdeStep, RuntimeError>>,
) {
    let preflight = (|| {
        let causal_parents = active_causal_parents(state, identity)?;
        let mut worker = state.borrow_mut();
        if identity.owner != call_owner(&call)
            || identity.worker_generation != worker.worker_retirement_id
            || identity.id.0 == 0
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "classic WM_DDE operation identity changed before worker entry",
            ));
        }
        validate_quiescence_call(&worker, identity, &call)?;
        worker
            .active_classic_dde_operations
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve classic WM_DDE operation owner",
                    error,
                )
            })?;
        worker
            .active_classic_dde_operations
            .push(ActiveClassicDdeOperation {
                identity,
                causal_parents,
                call: call.clone(),
                response: response.clone(),
                callback_receipts: Vec::new(),
                callback_retirements: Vec::new(),
                awaiting: None,
                replied: None,
                external_ingress: None,
            });
        Ok(())
    })();
    if let Err(error) = preflight {
        let proof = Arc::new(Win16HostClassicDdeSourceRetiredProof {
            operation: identity,
            callbacks: Vec::new(),
        });
        let failure = Arc::new(runtime::Win16HostClassicDdeStartedFailure {
            operation: identity,
            cause: Arc::new(error),
            source_retired: proof,
        });
        let _ = response.send(Ok(Win16HostClassicDdeStep::StartedFailure(failure)));
        return;
    }
    match take_pending_ingress(state, &call, identity) {
        Ok(Some(event)) => {
            if let Err(error) = publish_external_callback(state, identity, event) {
                finish_operation(state, identity, Err(error), None);
            }
        }
        Ok(None) => match execute_call(state, identity, &call) {
            Ok(result) => finish_operation(state, identity, Ok(result), None),
            Err(error) => finish_operation(state, identity, Err(error), None),
        },
        Err(error) => finish_operation(state, identity, Err(error), None),
    }
}

/// After the owner barrier is installed, permit only operations that retire
/// existing events, conversations and endpoints, or send the protocol ACK/
/// TERMINATE needed to retire an already live conversation. New endpoints,
/// bindings, broadcasts and application data sends are rejected on this same
/// worker before their native side effect.
pub(super) fn validate_quiescence_call(
    worker: &WorkerState,
    identity: Win16ClassicDdeOperationIdentity,
    call: &Win16HostClassicDdeCall,
) -> Result<(), RuntimeError> {
    let Some(barrier) = worker.classic_dde_quiescing_owners.get(&identity.owner) else {
        if matches!(
            call,
            Win16HostClassicDdeCall::QuiesceOwner { id: Some(_), .. }
        ) {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "classic DDE quiescence retry names no installed owner barrier",
            ));
        }
        return Ok(());
    };
    if barrier.worker_generation != identity.worker_generation {
        return Err(invariant(
            "classic DDE owner barrier belongs to another worker generation",
        ));
    }
    let allowed = match call {
        Win16HostClassicDdeCall::QuiesceOwner { owner, id } => {
            *owner == identity.owner && id.is_none_or(|requested| requested == barrier.id)
        }
        Win16HostClassicDdeCall::Poll { owner, endpoint } => {
            *owner == identity.owner
                && worker
                    .classic_dde_endpoints
                    .get(endpoint)
                    .is_some_and(|record| {
                        record.owner == identity.owner
                            && record.worker_generation == identity.worker_generation
                    })
        }
        Win16HostClassicDdeCall::PollOwner { owner } => *owner == identity.owner,
        Win16HostClassicDdeCall::AcknowledgeEvent {
            owner,
            endpoint,
            event_id,
        } => {
            *owner == identity.owner
                && worker
                    .classic_dde_endpoints
                    .get(endpoint)
                    .is_some_and(|record| {
                        record.owner == identity.owner
                            && record.worker_generation == identity.worker_generation
                            && record
                                .events
                                .iter()
                                .any(|event| event.event.event_id == *event_id)
                    })
        }
        Win16HostClassicDdeCall::RetireEndpoint { owner, endpoint } => {
            *owner == identity.owner
                && worker
                    .classic_dde_endpoints
                    .get(endpoint)
                    .is_some_and(|record| {
                        record.owner == identity.owner
                            && record.worker_generation == identity.worker_generation
                    })
        }
        Win16HostClassicDdeCall::RetireConversation {
            owner,
            endpoint,
            conversation,
            peer,
        } => {
            *owner == identity.owner
                && worker
                    .classic_dde_endpoints
                    .get(endpoint)
                    .is_some_and(|record| {
                        record.owner == identity.owner
                            && record.worker_generation == identity.worker_generation
                            && record
                                .conversations
                                .get(conversation)
                                .is_some_and(|entry| entry.peer == *peer)
                    })
        }
        Win16HostClassicDdeCall::Post {
            owner,
            endpoint,
            target,
            conversation,
            transaction,
            message,
        } => {
            if *owner != identity.owner {
                false
            } else if let Some(record) = worker.classic_dde_endpoints.get(endpoint) {
                let conversation_live = record.owner == identity.owner
                    && record.worker_generation == identity.worker_generation
                    && record
                        .conversations
                        .get(conversation)
                        .is_some_and(|live| live.peer == *target);
                let transaction_live = transaction.as_ref().is_none_or(|transaction| {
                    record.transactions.get(transaction).is_some_and(|live| {
                        live.peer == *target && live.conversation == *conversation
                    })
                });
                conversation_live
                    && transaction_live
                    && match message {
                        Win16ClassicDdeMessage::Terminate => true,
                        Win16ClassicDdeMessage::Ack {
                            value: runtime::Win16ClassicDdeAckValue::ItemAtom(_),
                            ..
                        } => true,
                        Win16ClassicDdeMessage::Ack {
                            value: runtime::Win16ClassicDdeAckValue::ExecuteTransfer(Some(transfer)),
                            ..
                        } => record.transfers.get(transfer).is_some_and(|live| {
                            live.peer == *target
                                && live.conversation == Some(*conversation)
                                && live.message == runtime::WM_DDE_EXECUTE
                        }),
                        _ => false,
                    }
            } else {
                false
            }
        }
        Win16HostClassicDdeCall::ReplyInitiate {
            owner,
            endpoint,
            operation_id,
            frame,
            event_id,
            peer,
            accepted: false,
            ..
        } => {
            *owner == identity.owner
                && worker
                    .classic_dde_endpoints
                    .get(endpoint)
                    .is_some_and(|record| {
                        record.owner == identity.owner
                            && record.worker_generation == identity.worker_generation
                            && record
                                .synchronous_frames
                                .get(&(*operation_id, *frame))
                                .is_some_and(|entry| {
                                    entry.event.event_id == *event_id && entry.event.peer == *peer
                                })
                    })
        }
        _ => false,
    };
    let proof_retry = matches!(call, Win16HostClassicDdeCall::QuiesceOwner { .. });
    if !allowed || (barrier.quiesced && !proof_retry) {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "classic DDE owner producer is stopped by its exact shutdown barrier",
        ));
    }
    Ok(())
}

pub(in crate::windows::win16_windows) fn resume_operation(
    state: &Rc<RefCell<WorkerState>>,
    identity: Win16ClassicDdeOperationIdentity,
    reply: Win16HostClassicDdeCallbackReply,
) -> Result<(), RuntimeError> {
    {
        let mut worker = state.try_borrow_mut().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "classic WM_DDE resume collided with worker state borrow",
            )
        })?;
        let Some(active) = worker.active_classic_dde_operations.last_mut() else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "classic WM_DDE callback reply has no active operation",
            ));
        };
        if active.identity != identity {
            return Err(invariant(
                "classic WM_DDE callback reply changed its exact operation",
            ));
        }
        let Some(step) = active.awaiting.as_ref() else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "classic WM_DDE callback reply has no exact awaiting step",
            ));
        };
        validate_callback_reply(&active.identity, step, &reply)?;
        active.callback_receipts.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve accepted classic WM_DDE callback reply",
                error,
            )
        })?;
        active
            .callback_retirements
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve classic WM_DDE callback retirement",
                    error,
                )
            })?;
        // Reply acceptance releases the wait, but the native source still
        // owns its frame and cleanup. Only its returned frame can publish a
        // source-retirement receipt.
        active.callback_receipts.push(callback_retirement(&reply));
        active.awaiting = None;
        active.replied = Some(reply.result.clone());
    }
    Ok(())
}

// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
pub(super) unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    if message == AFTER_CALLBACK_MESSAGE {
        if let Some(state) = super::super::worker_context() {
            if let Err(error) =
                finish_external_callback_after_unwind(&state, hwnd, w_param as u64, l_param as u64)
            {
                fail_worker(&state, error);
            }
        }
        return 0;
    }
    if message == WM_NCDESTROY {
        // SAFETY: DefWindowProcW receives the window-procedure arguments for this message. Pointer parameters stay live for the call.
        return unsafe { DefWindowProcW(hwnd, message, w_param, l_param) };
    }
    if !(u32::from(runtime::WM_DDE_INITIATE)..=u32::from(runtime::WM_DDE_EXECUTE))
        .contains(&message)
    {
        // SAFETY: DefWindowProcW receives the window-procedure arguments for this message. Pointer parameters stay live for the call.
        return unsafe { DefWindowProcW(hwnd, message, w_param, l_param) };
    }
    let Some(state) = super::super::worker_context() else {
        // SAFETY: DefWindowProcW receives the window-procedure arguments for this message. Pointer parameters stay live for the call.
        return unsafe { DefWindowProcW(hwnd, message, w_param, l_param) };
    };
    match catch_unwind(AssertUnwindSafe(|| {
        receive_message(&state, hwnd, message as u16, w_param, l_param)
    })) {
        Ok(Ok(value)) => value.unwrap_or(0),
        Ok(Err(error)) => {
            fail_worker(&state, error);
            0
        }
        Err(_) => {
            fail_worker(
                &state,
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "classic WM_DDE endpoint WndProc panicked",
                ),
            );
            0
        }
    }
}

pub(in crate::windows::win16_windows) fn pump_internal_messages(
    state: &Rc<RefCell<WorkerState>>,
) -> Result<(), RuntimeError> {
    let endpoints = state
        .borrow()
        .classic_dde_endpoints
        .values()
        .map(|endpoint| endpoint.hwnd)
        .collect::<Vec<_>>();
    for hwnd in endpoints {
        loop {
            // SAFETY: The type is a C struct of integers and raw pointers, so the all-zero bit pattern is a valid value.
            let mut message = unsafe { std::mem::zeroed() };
            // SAFETY: PeekMessageW writes into a caller-owned MSG that outlives the call.
            if unsafe {
                PeekMessageW(
                    &mut message,
                    hwnd,
                    u32::from(runtime::WM_DDE_INITIATE),
                    u32::from(runtime::WM_DDE_EXECUTE),
                    windows_sys::Win32::UI::WindowsAndMessaging::PM_REMOVE,
                )
            } == 0
            {
                break;
            }
            // SAFETY: DispatchMessageW reads a caller-owned MSG for this call only.
            unsafe { DispatchMessageW(&message) };
        }
        loop {
            // SAFETY: The type is a C struct of integers and raw pointers, so the all-zero bit pattern is a valid value.
            let mut message = unsafe { std::mem::zeroed() };
            // SAFETY: PeekMessageW writes into a caller-owned MSG that outlives the call.
            if unsafe {
                PeekMessageW(
                    &mut message,
                    hwnd,
                    AFTER_CALLBACK_MESSAGE,
                    AFTER_CALLBACK_MESSAGE,
                    windows_sys::Win32::UI::WindowsAndMessaging::PM_REMOVE,
                )
            } == 0
            {
                break;
            }
            // SAFETY: DispatchMessageW reads a caller-owned MSG for this call only.
            unsafe { DispatchMessageW(&message) };
        }
    }
    Ok(())
}
