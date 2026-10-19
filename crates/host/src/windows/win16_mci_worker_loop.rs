//! Owner-thread event pump, notification window, and nested yield continuations.

use super::super::combine_failure_kind;
use super::cleanup::{MciCloseFailure, close_failure_result};
use super::*;

#[path = "win16_mci_worker_producer_quiesce.rs"]
mod producer_quiesce;
#[path = "win16_mci_worker_quiesce.rs"]
mod quiesce;
#[path = "win16_mci_worker_shutdown.rs"]
mod shutdown;
#[path = "win16_mci_worker_wait_failure.rs"]
mod wait_failure;
#[path = "win16_mci_worker_yield.rs"]
mod yield_callback;
use wait_failure::{MciWorkerWaitPhase, retain_wait_failure, retry_worker_wait_wake};
#[path = "win16_mci_worker_loop_window.rs"]
mod notification_window;
use notification_window::{
    MciStartupFailure, create_notify_window, retire_notification_window, retire_registered_class,
};
pub(super) use yield_callback::mci_yield_proc;

pub(super) fn worker_main(
    receiver: Receiver<WorkerCommand>,
    wake_event: Arc<OwnedHandle>,
    notifications: Arc<Mutex<MciNotificationLedger>>,
    multimedia_wake: MultimediaWakeSender,
    identity_source: Arc<AtomicU64>,
    ready: mpsc::SyncSender<Result<u32, RuntimeError>>,
    shutdown_progress: Arc<Mutex<Option<MciWorkerShutdownReceipt>>>,
    text_codec: GuestTextCodec,
) {
    let thread_id = crate::windows::win32_safe::current_thread_id();
    let mut resolved_causes = Vec::new();
    if let Err(error) = resolved_causes.try_reserve_exact(4) {
        let _ = ready.send(Err(RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve native MCI shutdown resolved-cause receipt storage",
            error,
        )));
        return;
    }
    let mut first_message = MSG::default();
    // SAFETY: PeekMessageW writes into a caller-owned MSG that outlives the call.
    unsafe {
        PeekMessageW(&mut first_message, ptr::null_mut(), 0, 0, PM_REMOVE);
    }
    let devices = Arc::new(Mutex::new(NativeDeviceRegistry::default()));
    let notify_context = Box::new(NotifyWindowContext {
        notifications: Arc::clone(&notifications),
        devices: Arc::clone(&devices),
        multimedia_wake: multimedia_wake.clone(),
    });
    let (sink, class_name, instance) = match create_notify_window(&notify_context) {
        Ok(value) => value,
        Err(failure) => {
            let startup_error = match failure.cleanup {
                Some(cleanup) => RuntimeError::with_source(
                    combine_failure_kind(failure.primary.kind(), cleanup.kind()),
                    "create MCI notification window and retain its class cleanup owner",
                    MciStartupFailure {
                        primary: failure.primary,
                        cleanup,
                    },
                ),
                None => failure.primary,
            };
            let _ = ready.send(Err(startup_error));
            if let Some(class) = failure.registered_class {
                retire_registered_class(class, &notify_context);
            }
            return;
        }
    };
    let state = Arc::new(WorkerThreadState {
        receiver: RefCell::new(receiver),
        wake_event,
        multimedia_wake,
        notifications,
        devices,
        identity_source,
        text_codec,
        resumes: RefCell::new(HashMap::new()),
        returned_yields: RefCell::new(Vec::new()),
        completed_operations: RefCell::new(Vec::new()),
        yield_source_evidence: RefCell::new(Vec::new()),
        next_frame: AtomicU64::new(1),
        shutdown_requested: Cell::new(false),
        producer_admission_closed: Cell::new(false),
        shutdown_response: RefCell::new(None),
        shutdown_failure: RefCell::new(None),
        sink,
    });
    if ready.send(Ok(thread_id)).is_err() {
        let _ = retire_notification_window(
            sink,
            &class_name,
            instance,
            &notify_context,
            &mut resolved_causes,
        );
        return;
    }
    worker_loop(Arc::clone(&state));
    let (notification_window_destroyed, notification_class_unregistered) =
        retire_notification_window(
            sink,
            &class_name,
            instance,
            &notify_context,
            &mut resolved_causes,
        );
    if let Some(cause) = state.shutdown_failure.borrow_mut().take() {
        resolved_causes.push(cause);
    }
    let disabled_yield_sources = std::mem::take(&mut *state.yield_source_evidence.borrow_mut());
    let devices = state.devices.lock().unwrap_or_else(PoisonError::into_inner);
    let mut closed_devices = Vec::new();
    let mut first_snapshot_failure = None;
    loop {
        match devices.retired_snapshot(&mut closed_devices) {
            Ok(()) => break,
            Err(error) => {
                first_snapshot_failure.get_or_insert_with(|| Arc::new(error));
                // The registry and callback context remain owned by this
                // worker until its exact retired-device snapshot is stored.
                thread::sleep(RETIRE_RETRY);
            }
        }
    }
    drop(devices);
    if let Some(error) = first_snapshot_failure {
        resolved_causes.push(error);
    }
    let notification_ledger_drained = state
        .notifications
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .can_retire_sink();
    let yield_source_history_complete = state
        .devices
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .retired_yield_registrations
        .iter()
        .all(|retired_owner| {
            disabled_yield_sources.iter().any(|evidence| {
                matches!(
                    evidence,
                    Win16HostMciQuiescenceEvidence::YieldSourceDisabled {
                        owner,
                        observed_installed: false,
                        ..
                    } if owner == retired_owner
                )
            })
        });
    let device_registry_drained = yield_source_history_complete
        && state
            .devices
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty();
    let receipt = MciWorkerShutdownReceipt {
        closed_devices,
        disabled_yield_sources,
        yield_source_history_complete,
        device_registry_drained,
        notification_ledger_drained,
        notification_window_destroyed,
        notification_class_unregistered,
        owner_loop_returned: true,
        owner_thread_joined: false,
        resolved_causes,
    };
    *shutdown_progress
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(receipt.clone());
    if let Some(response) = state.shutdown_response.borrow_mut().take() {
        let _ = response.send(Ok(receipt));
    }
    // `notify_context` remains live until both the HWND and its class are gone.
    drop(notify_context);
}

fn worker_loop(state: Arc<WorkerThreadState>) {
    loop {
        drain_commands(&state);
        if state.shutdown_requested.get() {
            let result = quiesce::close_all_devices(&state);
            let empty = state
                .devices
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty();
            let notifications_retired = state
                .notifications
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .can_retire_sink();
            if empty && notifications_retired {
                return;
            }
            if let Err(error) = result {
                let detail = error.to_string();
                let mut first = state.shutdown_failure.borrow_mut();
                if first.is_none() {
                    *first = Some(Arc::new(error));
                }
                eprintln!(
                    "runtime: MCI owner retains {} native device(s) for retry: {detail}",
                    state
                        .devices
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .by_identity
                        .len()
                );
            }
            wait_for_input(&state, RETIRE_RETRY, MciWorkerWaitPhase::ShutdownRetry);
        } else {
            wait_for_input(
                &state,
                Duration::from_millis(u32::MAX as u64),
                MciWorkerWaitPhase::OwnerLoop,
            );
        }
    }
}

fn drain_commands(state: &Arc<WorkerThreadState>) {
    loop {
        let command = match state.receiver.borrow_mut().try_recv() {
            Ok(command) => command,
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
        };
        match command {
            WorkerCommand::Begin {
                operation,
                call,
                response,
            } => {
                if state.producer_admission_closed.get() || state.shutdown_requested.get() {
                    let _ = response.send(Err(RuntimeError::new(
                        Kind::CompatibilityGap,
                        "native MCI Begin was refused before side effects because source admission is closed",
                    )));
                    continue;
                }
                if let Err(error) = state.completed_operations.borrow_mut().try_reserve(1) {
                    let _ = response.send(Err(RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve native MCI completion tombstone before call",
                        error,
                    )));
                    continue;
                }
                if let Err(error) = ACTIVE_YIELDS.with(|active| active.borrow_mut().try_reserve(1))
                {
                    let _ = response.send(Err(RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve native MCI operation owner before call",
                        error,
                    )));
                    continue;
                }
                let failure_slot = Arc::new(MciEnteredYieldFailureSlot(Mutex::new(None)));
                let context = MciNativeContext::new(Arc::clone(state));
                ACTIVE_YIELDS.with(|active| {
                    active.borrow_mut().push(YieldInvocation {
                        state: Arc::clone(state),
                        operation,
                        response: response.clone(),
                        failure_slot,
                        active_yield: None,
                        last_returned_yield: None,
                    })
                });
                let result = native::execute(context, call);
                let returned_yield = ACTIVE_YIELDS.with(|active| {
                    active
                        .borrow_mut()
                        .pop()
                        .and_then(|mut invocation| invocation.last_returned_yield.take())
                });
                if let Some(returned) = returned_yield {
                    state.returned_yields.borrow_mut().push(returned);
                }
                let result = result.map(|step| {
                    if let Win16HostMciStep::Complete(result) = &step {
                        state.completed_operations.borrow_mut().push(
                            Win16HostMciOperationCompletion {
                                operation,
                                native_return_value: result.return_value,
                            },
                        );
                    }
                    MciWorkerStep {
                        step,
                        returned_yield,
                    }
                });
                let _ = response.send(result);
            }
            WorkerCommand::Resume { resume, accepted } => {
                let mut responses = state.resumes.borrow_mut();
                let result = if responses.contains_key(&(resume.operation, resume.frame)) {
                    Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "duplicate MCI yield-frame response",
                    ))
                } else if let Err(error) = responses.try_reserve(1) {
                    Err(RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "retain MCI yield-frame response",
                        error,
                    ))
                } else {
                    responses.insert((resume.operation, resume.frame), resume.return_value);
                    Ok(())
                };
                let _ = accepted.send(result);
            }
            WorkerCommand::Quiesce { request, response } => {
                let result = quiesce::quiesce_requested(state, request);
                let _ = response.send(result);
            }
            WorkerCommand::QuiesceProducers { request, response } => {
                let result = producer_quiesce::quiesce_producers_requested(state, request);
                let _ = response.send(result);
            }
            WorkerCommand::Shutdown(response) => {
                state.shutdown_requested.set(true);
                state.producer_admission_closed.set(true);
                state
                    .notifications
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .close_source_admission();
                if ACTIVE_YIELDS.with(|active| !active.borrow().is_empty()) {
                    let _ = response.send(Err(shutdown::active_yield_shutdown_error(state)));
                } else {
                    let mut pending = state.shutdown_response.borrow_mut();
                    if pending.is_some() {
                        let _ = response.send(Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "duplicate MCI shutdown receipt",
                        )));
                    } else {
                        *pending = Some(response);
                    }
                }
            }
        }
    }
}

fn wait_for_input(state: &WorkerThreadState, timeout: Duration, phase: MciWorkerWaitPhase) {
    retry_worker_wait_wake(state);
    let retry_pending = state
        .notifications
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .worker_wait_wake_pending();
    let timeout = if retry_pending && timeout > RETIRE_RETRY {
        RETIRE_RETRY
    } else {
        timeout
    };
    let millis = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX - 1);
    let handle = state.wake_event.as_raw_handle() as HANDLE;
    // SAFETY: MsgWaitForMultipleObjects reads a caller-owned handle span.
    let result = unsafe { MsgWaitForMultipleObjects(1, &handle, 0, millis, QS_ALLINPUT) };
    if result == WAIT_FAILED {
        let last_error = crate::windows::win32_safe::last_error();
        retain_wait_failure(state, phase, result, Some(last_error));
        thread::sleep(RETIRE_RETRY);
    } else if result != WAIT_OBJECT_0 && result != WAIT_OBJECT_0 + 1 && result != WAIT_TIMEOUT {
        retain_wait_failure(state, phase, result, None);
        thread::sleep(RETIRE_RETRY);
    }
    // The worker event is auto-reset; an explicit ResetEvent could erase a concurrent wake.
    pump_messages();
}

fn pump_messages() {
    loop {
        let mut message = MSG::default();
        // SAFETY: PeekMessageW writes into a caller-owned MSG that outlives the call.
        if unsafe { PeekMessageW(&mut message, ptr::null_mut(), 0, 0, PM_REMOVE) } == 0 {
            break;
        }
        if message.message == 0x0012 {
            continue;
        }
        // SAFETY: TranslateMessage reads a caller-owned MSG for this call only. DispatchMessageW reads a caller-owned MSG for this call only.
        unsafe {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}

// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn mci_notification_window_proc(
    window: HWND,
    message: u32,
    w_param: usize,
    l_param: LPARAM,
) -> isize {
    if message == WM_NCCREATE {
        let create = l_param as *const CREATESTRUCTW;
        if create.is_null() {
            return 0;
        }
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        let context = unsafe { (*create).lpCreateParams };
        if context.is_null() {
            return 0;
        }
        // SAFETY: SetWindowLongPtrW writes one window-long slot owned by this window.
        unsafe {
            crate::windows::win32_safe::set_last_error(0);
            SetWindowLongPtrW(window, GWLP_USERDATA, context as isize);
            if crate::windows::win32_safe::last_error() != 0 {
                return 0;
            }
        }
    }
    if message == MM_MCINOTIFY {
        let context =
            // SAFETY: GetWindowLongPtrW reads one window-long slot. The HWND is a window this thread created or was given by Windows.
            unsafe { GetWindowLongPtrW(window, GWLP_USERDATA) } as *const NotifyWindowContext;
        if !context.is_null() {
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            let context = unsafe { &*context };
            let native_id = l_param as u32;
            let dispatch = match context
                .notifications
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .next_dispatch(native_id)
            {
                Ok(Some(dispatch)) => dispatch,
                Ok(None) => {
                    retain_callback_failure(
                        context,
                        native_id,
                        None,
                        w_param,
                        RuntimeError::new(
                            Kind::CompatibilityGap,
                            "MM_MCINOTIFY arrived without an exact retained MCI route; its source cannot be inferred",
                        ),
                    );
                    return 0;
                }
                Err(error) => {
                    retain_callback_failure(context, native_id, None, w_param, error);
                    return 0;
                }
            };
            if dispatch.tombstone {
                let consumed = context
                    .notifications
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .consume_tombstone(native_id, dispatch.id);
                if !consumed {
                    context
                        .notifications
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .retain_wake_failure(RuntimeError::new(
                            Kind::InternalInvariant,
                            "MCI late notification did not match its retained tombstone",
                        ));
                }
                return 0;
            }
            let device = match dispatch.device {
                Some(device) => {
                    let devices = context
                        .devices
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    match devices.existing_identity(native_id) {
                        Some(current) if current != device => Err(RuntimeError::new(
                            Kind::CompatibilityGap,
                            "MM_MCINOTIFY exposes a reused native device ID but no generation or command identity; the original route remains retained",
                        )),
                        _ => Ok(device),
                    }
                }
                None if dispatch.allow_new_device => dispatch
                    .source_id
                    .ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "native MCI OPEN notification has no pre-reserved shared source ID",
                        )
                    })
                    .and_then(|source_id| {
                        context
                            .devices
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .identity(native_id, None, source_id)
                    }),
                None => Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "native MCI notification route lost its exact device generation",
                )),
            };
            let device = match device {
                Ok(device) => device,
                Err(error) => {
                    retain_callback_failure(context, native_id, Some(dispatch.id), w_param, error);
                    return 0;
                }
            };
            let status = match u16::try_from(w_param) {
                Ok(status) => status,
                Err(_) => {
                    retain_callback_failure(
                        context,
                        native_id,
                        Some(dispatch.id),
                        w_param,
                        RuntimeError::new(
                            Kind::InvalidInput,
                            "native MCI callback status exceeds the Win16 notification ABI",
                        ),
                    );
                    return 0;
                }
            };
            let source_id = match dispatch.source_id {
                Some(source_id) if source_id != 0 && source_id != u64::MAX => {
                    let active_source = context
                        .devices
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .notification_source_id(device);
                    if active_source.is_some_and(|active| active != source_id) {
                        retain_callback_failure(
                            context,
                            native_id,
                            Some(dispatch.id),
                            w_param,
                            RuntimeError::new(
                                Kind::InternalInvariant,
                                "retained MCI route source disagrees with its still-live device generation",
                            ),
                        );
                        return 0;
                    }
                    source_id
                }
                _ => {
                    retain_callback_failure(
                        context,
                        native_id,
                        Some(dispatch.id),
                        w_param,
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "native MCI notification route lost its pre-reserved shared source identity",
                        ),
                    );
                    return 0;
                }
            };
            let delivered = context
                .notifications
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .deliver(native_id, dispatch.id, Some(device), source_id, status);
            if delivered {
                if let Err(error) = context.multimedia_wake.signal() {
                    context
                        .notifications
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .retain_wake_failure(error);
                }
            } else {
                retain_callback_failure(
                    context,
                    native_id,
                    Some(dispatch.id),
                    w_param,
                    RuntimeError::new(
                        Kind::CompatibilityGap,
                        "MCI notification could not be assigned to the exact retained route; its owner was not retired",
                    ),
                );
            }
            return 0;
        }
    }
    if message == WM_NCDESTROY {
        // SAFETY: SetWindowLongPtrW writes one window-long slot owned by this window.
        unsafe {
            SetWindowLongPtrW(window, GWLP_USERDATA, 0);
        }
    }
    // SAFETY: DefWindowProcW receives the window-procedure arguments for this message. Pointer parameters stay live for the call.
    unsafe { DefWindowProcW(window, message, w_param, l_param) }
}

fn retain_callback_failure(
    context: &NotifyWindowContext,
    native_id: u32,
    notification: Option<Win16HostMciNotificationId>,
    status: usize,
    error: RuntimeError,
) {
    context
        .notifications
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .retain_callback_failure(native_id, notification, status, error);
    if let Err(error) = context.multimedia_wake.signal() {
        context
            .notifications
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain_wake_failure(error);
    }
}

pub(super) fn last_error(context: &'static str) -> RuntimeError {
    let code = crate::windows::win32_safe::last_error();
    RuntimeError::with_source(
        Kind::HostFailure,
        context,
        std::io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX)),
    )
}
