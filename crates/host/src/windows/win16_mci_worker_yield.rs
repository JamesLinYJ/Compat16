use super::*;

fn pump_until_resume(
    state: &Arc<WorkerThreadState>,
    operation: Win16HostMciOperationId,
    frame: Win16HostMciYieldFrame,
    device: runtime::Win16HostMciDevice,
) -> u16 {
    loop {
        if let Some(value) = state.resumes.borrow_mut().remove(&(operation, frame)) {
            return value;
        }
        drain_commands(state);
        if let Some(value) = state.resumes.borrow_mut().remove(&(operation, frame)) {
            return value;
        }
        let timeout = if state.shutdown_requested.get() {
            RETIRE_RETRY
        } else {
            Duration::from_millis(u32::MAX as u64)
        };
        wait_for_input(
            state,
            timeout,
            MciWorkerWaitPhase::Yield {
                operation,
                frame,
                device,
            },
        );
    }
}

pub(in crate::windows::win16_mci_owner::worker) unsafe extern "system" fn mci_yield_proc(
    native_device: u32,
    data: u32,
) -> u32 {
    let invocation = ACTIVE_YIELDS.with(|active| {
        active.borrow().last().map(|entry| YieldInvocation {
            state: Arc::clone(&entry.state),
            operation: entry.operation,
            response: entry.response.clone(),
            failure_slot: Arc::clone(&entry.failure_slot),
            active_yield: entry.active_yield,
            last_returned_yield: entry.last_returned_yield,
        })
    });
    let Some(invocation) = invocation else {
        retain_native_yield_without_owner();
    };
    let owner = {
        let registry = invocation
            .state
            .devices
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match registry.existing_identity(native_device) {
            Some(device) => match registry.current_yield_registration(device) {
                Some(registration) => Ok((device, registration)),
                None => Err((Some(device), MciEnteredYieldFailurePhase::ResolveRegistration,
                    MciEnteredYieldFailureCause::RegistrationMissing)),
            },
            None => Err((None, MciEnteredYieldFailurePhase::ResolveNativeDevice,
                MciEnteredYieldFailureCause::NativeDeviceUnowned)),
        }
    };
    let (device, registration) = match owner {
        Ok(owner) => owner,
        Err((device, phase, cause)) => retain_and_park_entered_yield(
            &invocation,
            MciEnteredYieldFailure {
                operation: invocation.operation,
                native_device,
                device,
                registration: None,
                frame: None,
                data,
                phase,
                cause,
                returned_yield: invocation.last_returned_yield,
            },
        ),
    };
    let frame = match invocation
        .state
        .next_frame
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |value: u64| value.checked_add(1))
    {
        Ok(value) => Win16HostMciYieldFrame(value),
        Err(_) => retain_and_park_entered_yield(
            &invocation,
            MciEnteredYieldFailure {
                operation: invocation.operation,
                native_device,
                device: Some(device),
                registration: Some(registration),
                frame: None,
                data,
                phase: MciEnteredYieldFailurePhase::AllocateFrameIdentity,
                cause: MciEnteredYieldFailureCause::FrameIdentityExhausted,
                returned_yield: invocation.last_returned_yield,
            },
        ),
    };
    let active_yield = Win16HostMciActiveYield {
        operation: invocation.operation,
        frame,
        device,
    };
    if let Err(error) = invocation
        .state
        .returned_yields
        .borrow_mut()
        .try_reserve(2)
    {
        retain_and_park_entered_yield(
            &invocation,
            MciEnteredYieldFailure {
                operation: invocation.operation,
                native_device,
                device: Some(device),
                registration: Some(registration),
                frame: Some(frame),
                data,
                phase: MciEnteredYieldFailurePhase::ReserveReturnReceipt,
                cause: MciEnteredYieldFailureCause::ReturnReceiptAllocation(Arc::new(
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve native MCI YIELD return receipt capacity",
                        error,
                    ),
                )),
                returned_yield: invocation.last_returned_yield,
            },
        );
    }
    let previous_returned_yield = ACTIVE_YIELDS.with(|active| {
        active
            .borrow_mut()
            .iter_mut()
            .rev()
            .find(|current| current.operation == invocation.operation)
            .and_then(|current| current.last_returned_yield.take())
    });
    if let Some(returned) = previous_returned_yield {
        invocation.state.returned_yields.borrow_mut().push(returned);
    }
    ACTIVE_YIELDS.with(|active| {
        if let Some(current) = active
            .borrow_mut()
            .iter_mut()
            .rev()
            .find(|current| current.operation == invocation.operation)
        {
            current.active_yield = Some(active_yield);
        }
    });
    let worker_step = MciWorkerStep {
        step: Win16HostMciStep::Yield(Win16HostMciYieldEvent {
            operation: invocation.operation,
            frame,
            device,
            registration,
            data,
        }),
        returned_yield: previous_returned_yield,
    };
    if let Err(error) = invocation.response.send(Ok(worker_step)) {
        let channel_failure = Arc::new(RuntimeError::with_source(
            Kind::HostFailure,
            "deliver exact native MCI YIELD event to its original operation client",
            error,
        ));
        retain_and_park_entered_yield(
            &invocation,
            MciEnteredYieldFailure {
                operation: invocation.operation,
                native_device,
                device: Some(device),
                registration: Some(registration),
                frame: Some(frame),
                data,
                phase: MciEnteredYieldFailurePhase::DeliverYieldStep,
                cause: MciEnteredYieldFailureCause::YieldResponseDisconnected(channel_failure),
                returned_yield: previous_returned_yield,
            },
        );
    }
    let guest_return = pump_until_resume(
        &invocation.state,
        invocation.operation,
        frame,
        device,
    );
    let returned_yield = Win16HostMciYieldReturn {
        owner: active_yield,
        guest_return,
    };
    ACTIVE_YIELDS.with(|active| {
        if let Some(current) = active
            .borrow_mut()
            .iter_mut()
            .rev()
            .find(|current| current.operation == invocation.operation)
        {
            if current.active_yield == Some(active_yield) {
                current.active_yield = None;
            }
            current.last_returned_yield = Some(returned_yield);
        }
    });
    u32::from(guest_return)
}

fn retain_and_park_entered_yield(
    invocation: &YieldInvocation,
    failure: MciEnteredYieldFailure,
) -> ! {
    let failure = invocation.failure_slot.retain_first(failure);
    let cause = Arc::new(RuntimeError::with_source(
        failure.kind(),
        "native MCI YIELDPROC failed after entry; its exact operation and native stack remain owned",
        failure,
    ));
    invocation
        .state
        .notifications
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .retain_entered_yield_failure(Arc::clone(&cause));
    publish_entered_yield_wake(&invocation.state);
    let client_error = RuntimeError::with_source(
        cause.kind(),
        "entered native MCI YIELDPROC has a retained typed failure; no guest WORD was invented",
        super::super::quarantine::RetainedMciRuntimeError::new(Arc::clone(&cause)),
    );
    if let Err(error) = invocation.response.send(Err(client_error)) {
        invocation
            .state
            .notifications
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain_entered_yield_client_failure(RuntimeError::with_source(
                Kind::HostFailure,
                "deliver entered MCI YIELD failure to its original operation client",
                error,
            ));
    }
    loop {
        let pending = invocation
            .state
            .notifications
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entered_yield_wake_pending();
        if !pending {
            break;
        }
        thread::park_timeout(RETIRE_RETRY);
        publish_entered_yield_wake(&invocation.state);
    }
    loop {
        thread::park();
    }
}

fn publish_entered_yield_wake(state: &WorkerThreadState) {
    let pending = state
        .notifications
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entered_yield_wake_pending();
    if !pending {
        return;
    }
    match state.multimedia_wake.signal() {
        // The cause stays pending until a USER/MCI read snapshots it.
        Ok(()) => {}
        Err(error) => state
            .notifications
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain_entered_yield_wake_failure(error),
    }
}

fn retain_native_yield_without_owner() -> ! {
    // Returning zero would be an invented guest YIELDPROC result and can let
    // the native operation continue. Keep this owner thread and frame alive.
    loop {
        thread::park();
    }
}
