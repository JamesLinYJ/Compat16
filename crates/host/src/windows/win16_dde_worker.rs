//! DDEML thread owner and nested-command pump used while guest callbacks run.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TryRecvError};
use std::time::Duration;

use super::super::guest_text::GuestTextCodec;
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16DdeCallbackReply, Win16DdeCallbackReplyRole,
    Win16HostDdeCallbackFrame, Win16HostDdeInstance, Win16HostDdeOperation, Win16HostDdeOwner,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetMessageW, MSG, PM_NOREMOVE, PeekMessageW, TranslateMessage,
};

use super::{WAKE_MESSAGE, WorkerCommand, WorkerEvent, native};

#[path = "win16_dde_worker_callback_replies.rs"]
mod callback_replies;
#[path = "win16_dde_worker_window.rs"]
mod control_window;
#[path = "win16_dde_worker_shutdown.rs"]
mod shutdown;
pub(super) use callback_replies::{
    release_callback_reply_cleanup_slot, reserve_callback_reply_cleanup_slot,
    retain_failed_callback_reply,
};

thread_local! {
    /// DDEML invokes PFNCALLBACK on the initializing thread. The pointer is
    /// installed only for that thread's worker loop and cleared before exit.
    static CURRENT_WORKER: Cell<*const WorkerContext> = const { Cell::new(std::ptr::null()) };
}

struct WorkerTlsGuard(*const WorkerContext);

impl WorkerTlsGuard {
    fn clear(&mut self) {
        let pointer = self.0;
        let _ = CURRENT_WORKER.try_with(|slot| {
            if slot.get() == pointer {
                slot.set(std::ptr::null());
            }
        });
        self.0 = std::ptr::null();
    }
}

impl Drop for WorkerTlsGuard {
    fn drop(&mut self) {
        self.clear();
    }
}

pub(super) struct WorkerReady {
    pub(super) control_window: usize,
}

pub(super) struct WorkerContext {
    command_receiver: RefCell<Receiver<WorkerCommand>>,
    event_sender: Sender<WorkerEvent>,
    shutdown_completion: SyncSender<super::WorkerShutdownReport>,
    active_operations: RefCell<Vec<Win16HostDdeOperation>>,
    active_callbacks: RefCell<
        Vec<(
            Win16HostDdeCallbackFrame,
            Option<Win16HostDdeOperation>,
            Win16HostDdeInstance,
        )>,
    >,
    owner: Win16HostDdeOwner,
    worker_generation: u64,
    shutdown_request_id: Cell<Option<u64>>,
    untracked_callback_failure: Cell<bool>,
    pub(super) state: RefCell<native::NativeState>,
    identity_source: Arc<AtomicU64>,
    /// During first-time DdeInitialize, DDEML may invoke the callback before
    /// the call returns its new instance ID. The stack slot remains live for
    /// the entire synchronous initialization call on this owner thread.
    initializing_native_instances: RefCell<Vec<(runtime::Win16HostDdeInstance, *mut u32)>>,
    control_window: Cell<windows_sys::Win32::Foundation::HWND>,
    stopping: Cell<bool>,
    emergency_failure: Cell<Option<Arc<RuntimeError>>>,
    fatal_error: RefCell<Option<RuntimeError>>,
    shutdown_error: RefCell<Option<RuntimeError>>,
    reported_diagnostics: RefCell<BTreeSet<&'static str>>,
    callback_reply_cleanup: Mutex<callback_replies::CallbackReplyOwners>,
    pub(super) guest_ansi_codec: GuestTextCodec,
}

#[derive(Clone, Copy)]
pub(super) struct FailedCallbackReplyIdentity {
    pub(super) frame: Win16HostDdeCallbackFrame,
    pub(super) operation: Option<Win16HostDdeOperation>,
    pub(super) instance: Win16HostDdeInstance,
    pub(super) role: Win16DdeCallbackReplyRole,
}

pub(super) fn run(
    command_receiver: Receiver<WorkerCommand>,
    event_sender: Sender<WorkerEvent>,
    started_sender: SyncSender<Result<WorkerReady, RuntimeError>>,
    shutdown_completion: SyncSender<super::WorkerShutdownReport>,
    identity_source: Arc<AtomicU64>,
    owner: Win16HostDdeOwner,
    worker_generation: u64,
    guest_ansi_codec: GuestTextCodec,
) {
    let thread_id = unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() };
    let mut initial_message = unsafe { std::mem::zeroed::<MSG>() };
    unsafe {
        PeekMessageW(
            &mut initial_message,
            std::ptr::null_mut(),
            0,
            0,
            PM_NOREMOVE,
        )
    };
    let context = WorkerContext {
        command_receiver: RefCell::new(command_receiver),
        event_sender,
        shutdown_completion,
        active_operations: RefCell::new(Vec::new()),
        active_callbacks: RefCell::new(Vec::new()),
        owner,
        worker_generation,
        shutdown_request_id: Cell::new(None),
        untracked_callback_failure: Cell::new(false),
        state: RefCell::new(native::NativeState::new()),
        identity_source,
        initializing_native_instances: RefCell::new(Vec::new()),
        control_window: Cell::new(std::ptr::null_mut()),
        stopping: Cell::new(false),
        emergency_failure: Cell::new(None),
        fatal_error: RefCell::new(None),
        shutdown_error: RefCell::new(None),
        reported_diagnostics: RefCell::new(BTreeSet::new()),
        callback_reply_cleanup: Mutex::new(callback_replies::CallbackReplyOwners::default()),
        guest_ansi_codec,
    };
    let window = match control_window::create(&context, thread_id) {
        Ok(window) => window,
        Err(error) => {
            let _ = started_sender.send(Err(error));
            return;
        }
    };
    context.control_window.set(window.hwnd);
    CURRENT_WORKER.with(|slot| slot.set(&context as *const WorkerContext));
    // Declared after `context`, so even an unexpected unwind clears TLS
    // before the stack-backed WorkerContext is dropped.
    let mut tls_guard = WorkerTlsGuard(&context as *const WorkerContext);
    if started_sender
        .send(Ok(WorkerReady {
            control_window: window.hwnd as usize,
        }))
        .is_err()
    {
        context.stopping.set(true);
        set_shutdown_error(
            &context,
            disconnected("publish the DDE owner control window"),
        );
    }

    while !context.stopping.get() {
        drain_commands(&context);
        if context.stopping.get() {
            break;
        }
        let mut message = unsafe { std::mem::zeroed::<MSG>() };
        let status = unsafe { GetMessageW(&mut message, std::ptr::null_mut(), 0, 0) };
        if status == -1 {
            context.stopping.set(true);
            set_shutdown_error(
                &context,
                RuntimeError::new(
                    Kind::HostFailure,
                    "GetMessageW failed in the DDEML owner thread",
                ),
            );
            break;
        }
        if status == 0 {
            context.stopping.set(true);
            set_shutdown_error(
                &context,
                RuntimeError::new(
                    Kind::HostFailure,
                    "DDEML owner message loop received an unexpected WM_QUIT",
                ),
            );
            break;
        }
        unsafe {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    shutdown::finalize(&context, &mut tls_guard, window);
}

pub(super) fn with_current_worker<R>(callback: impl FnOnce(&WorkerContext) -> R) -> Option<R> {
    let pointer = CURRENT_WORKER.with(Cell::get);
    if pointer.is_null() {
        return None;
    }
    // SAFETY: the pointer is installed from `run` on this thread and remains
    // valid until the message loop and any active native callback have returned.
    Some(unsafe { callback(&*pointer) })
}

pub(super) fn allocate_frame(
    context: &WorkerContext,
) -> Result<Win16HostDdeCallbackFrame, RuntimeError> {
    super::allocate_id(&context.identity_source).map(Win16HostDdeCallbackFrame)
}

pub(super) fn report_diagnostic_once(
    context: &WorkerContext,
    key: &'static str,
    diagnostic: runtime::Diagnostic,
) -> Result<(), RuntimeError> {
    let mut reported = context.reported_diagnostics.try_borrow_mut().map_err(|_| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "DDE compatibility diagnostic set is already mutably borrowed",
        )
    })?;
    if !reported.insert(key) {
        return Ok(());
    }
    drop(reported);
    context
        .event_sender
        .send(WorkerEvent::Diagnostic(diagnostic))
        .map_err(|_| disconnected("publish a recoverable DDE compatibility diagnostic"))
}

pub(super) fn current_operation(context: &WorkerContext) -> Option<Win16HostDdeOperation> {
    context.active_operations.borrow().last().copied()
}

pub(super) fn push_initializing_instance(
    context: &WorkerContext,
    instance: runtime::Win16HostDdeInstance,
    output: *mut u32,
) -> Result<(), RuntimeError> {
    let mut stack = context
        .initializing_native_instances
        .try_borrow_mut()
        .map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "DDE initialization output stack is already mutably borrowed",
            )
        })?;
    stack.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve a nested DDE initialization output slot",
            error,
        )
    })?;
    stack.push((instance, output));
    Ok(())
}

pub(super) fn pop_initializing_instance(
    context: &WorkerContext,
    instance: runtime::Win16HostDdeInstance,
) -> Result<(), RuntimeError> {
    let mut stack = context
        .initializing_native_instances
        .try_borrow_mut()
        .map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "DDE initialization output stack is already mutably borrowed",
            )
        })?;
    if stack.last().is_none_or(|(actual, _)| *actual != instance) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "nested DDE initialization output slots completed out of order",
        ));
    }
    stack.pop();
    Ok(())
}

pub(super) fn initializing_instance_output(
    context: &WorkerContext,
    instance: runtime::Win16HostDdeInstance,
) -> Result<Option<*mut u32>, RuntimeError> {
    let stack = context
        .initializing_native_instances
        .try_borrow()
        .map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "DDE initialization output stack is mutably borrowed during callback",
            )
        })?;
    Ok(stack
        .iter()
        .rev()
        .find_map(|(owner, pointer)| (*owner == instance).then_some(*pointer)))
}

pub(super) fn publish_callback(
    context: &WorkerContext,
    callback: runtime::Win16DdeCallbackCall,
) -> Result<Option<CallbackDelivery>, RuntimeError> {
    if (context.stopping.get() && context.shutdown_request_id.get().is_none())
        || context
            .fatal_error
            .try_borrow()
            .is_ok_and(|fatal| fatal.is_some())
    {
        return Ok(None);
    }
    let frame = allocate_frame(context)?;
    let parent = current_operation(context);
    let instance = callback.host_instance;
    let mut active = context.active_callbacks.try_borrow_mut().map_err(|_| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "DDE active callback ledger is borrowed",
        )
    })?;
    if let Err(error) = active.try_reserve(1) {
        context.untracked_callback_failure.set(true);
        return Err(RuntimeError::with_source(
            Kind::ResourceExhausted,
            "retain exact DDE native callback frame before publishing it",
            error,
        ));
    }
    active.push((frame, parent, instance));
    drop(active);
    let (reply_sender, reply_receiver) = mpsc::channel();
    if context
        .event_sender
        .send(WorkerEvent::Callback {
            frame,
            parent,
            callback,
            reply: reply_sender,
        })
        .is_err()
    {
        let mut active = context.active_callbacks.borrow_mut();
        if active.last().is_some_and(|(actual, _, _)| *actual == frame) {
            active.pop();
        }
        return Err(disconnected("publish a native DDE callback to the runtime"));
    }
    Ok(Some(CallbackDelivery {
        frame,
        parent,
        reply: reply_receiver,
    }))
}

pub(super) struct CallbackDelivery {
    pub(super) frame: Win16HostDdeCallbackFrame,
    pub(super) parent: Option<Win16HostDdeOperation>,
    pub(super) reply: Receiver<Win16DdeCallbackReply>,
}

pub(super) fn wait_for_callback_reply(
    context: &WorkerContext,
    receiver: Receiver<Win16DdeCallbackReply>,
) -> Result<Option<Win16DdeCallbackReply>, RuntimeError> {
    wait_for_callback_reply_inner(context, receiver)
}

pub(super) fn complete_callback_frame(
    context: &WorkerContext,
    frame: Win16HostDdeCallbackFrame,
    parent: Option<Win16HostDdeOperation>,
    result: Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    let expected = (frame, parent);
    let matches_top = context
        .active_callbacks
        .try_borrow()
        .map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "DDE active callback ledger is borrowed",
            )
        })?
        .last()
        .is_some_and(|(actual_frame, actual_parent, _)| {
            (*actual_frame, *actual_parent) == expected
        });
    if !matches_top {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "DDE callback acknowledgement does not match the exact active native frame",
        ));
    }
    match context
        .event_sender
        .send(WorkerEvent::CallbackFrameComplete {
            frame,
            parent,
            result,
        }) {
        Ok(()) => {
            context.active_callbacks.borrow_mut().pop();
            Ok(())
        }
        Err(failed) => {
            let publication = disconnected("publish native DDE callback cleanup completion");
            match failed.0 {
                WorkerEvent::CallbackFrameComplete {
                    result: Err(primary),
                    ..
                } => Err(super::errors::combine_cleanup_errors(
                    primary,
                    publication,
                    "DDE callback cleanup completion and its publication both failed",
                )),
                _ => Err(publication),
            }
        }
    }
}

/// Extern callback failures are returned as safe NULL to DDEML, then retained
/// for the enclosing operation or reported as an owner-wide failure.
pub(super) fn latch_callback_failure(context: &WorkerContext, error: RuntimeError) {
    if current_operation(context).is_some() {
        if let Ok(mut fatal) = context.fatal_error.try_borrow_mut() {
            *fatal = Some(match fatal.take() {
                Some(primary) => super::errors::combine_cleanup_errors(
                    primary,
                    error,
                    "multiple native DDE callback failures occurred",
                ),
                None => error,
            });
        } else {
            latch_emergency_failure(context, error);
        }
    } else {
        context.stopping.set(true);
        if let Err(failed) = context.event_sender.send(WorkerEvent::Failure(error)) {
            let publication = disconnected("report an unsolicited DDE callback failure");
            let failure = match failed.0 {
                WorkerEvent::Failure(primary) => super::errors::combine_cleanup_errors(
                    primary,
                    publication,
                    "unsolicited DDE callback failure and its publication both failed",
                ),
                _ => publication,
            };
            set_shutdown_error_safely(context, failure);
        }
    }
}

/// Convert a panic from the private message-window WndProc into the same
/// typed completion path used for callback trampoline failures. The WndProc
/// itself must return safely across the system ABI and may never unwind.
pub(super) fn latch_control_panic(context: &WorkerContext) {
    let error = RuntimeError::new(
        Kind::HostFailure,
        "panic occurred while dispatching a DDE owner control message",
    );
    context.stopping.set(true);
    latch_callback_failure(context, error);
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        native::cancel_active_conversations(context)
    })) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => set_shutdown_error_safely(context, error),
        Err(_) => set_shutdown_error_safely(
            context,
            RuntimeError::new(
                Kind::HostFailure,
                "panic occurred while canceling DDE conversations after a control-window panic",
            ),
        ),
    }
}

fn drain_commands(context: &WorkerContext) {
    let mut commands = Vec::new();
    loop {
        match context.command_receiver.borrow_mut().try_recv() {
            Ok(command) => commands.push(command),
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => {
                context.stopping.set(true);
                set_shutdown_error(context, disconnected("receive commands for the DDE owner"));
                return;
            }
        }
    }
    if let Some(index) = commands
        .iter()
        .position(|command| matches!(command, WorkerCommand::Shutdown { .. }))
    {
        let command = commands.remove(index);
        process_command(context, command);
    }
    for command in commands {
        process_command(context, command);
        if context.stopping.get() {
            continue;
        }
    }
}

pub(super) fn on_control_message(context: &WorkerContext, _wparam: usize, _lparam: isize) {
    drain_commands(context);
}

fn process_command(context: &WorkerContext, command: WorkerCommand) {
    match command {
        WorkerCommand::Execute { operation, call } => {
            if context.stopping.get() {
                let result = Err(RuntimeError::new(
                    Kind::HostFailure,
                    "DDE operation was cancelled during owner shutdown",
                ));
                if let Err(error) = send_operation_completion(context, operation, false, result) {
                    set_shutdown_error(context, error);
                }
                return;
            }
            context.active_operations.borrow_mut().push(operation);
            let mut result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                native::execute_call(context, call)
            })) {
                Ok(result) => result,
                Err(_) => Err(RuntimeError::new(
                    Kind::HostFailure,
                    "panic occurred during a native DDE operation",
                )),
            };
            let fatal = take_fatal_failure(context);
            if let Some(error) = fatal {
                result = combine_call_result(
                    result,
                    error,
                    "native DDE operation and callback failure both failed",
                );
            }
            if let Some(error) = take_emergency_failure(context) {
                result = combine_call_result(
                    result,
                    error,
                    "native DDE operation and emergency callback failure both failed",
                );
            }
            let popped = context.active_operations.borrow_mut().pop();
            if popped != Some(operation) {
                context.stopping.set(true);
                let failure = RuntimeError::new(
                    Kind::InternalInvariant,
                    "DDEML active operation stack did not match its completed operation",
                );
                result = combine_call_result(
                    result,
                    failure,
                    "native DDE operation and active-operation stack validation both failed",
                );
                if let Err(error) = send_operation_completion(context, operation, true, result) {
                    set_shutdown_error(context, error);
                }
                let failure = RuntimeError::new(
                    Kind::InternalInvariant,
                    "DDEML active operation stack was corrupt during completion",
                );
                if let Err(failed) = context.event_sender.send(WorkerEvent::Failure(failure)) {
                    let publication = disconnected("report a corrupt DDEML active operation stack");
                    let failure = match failed.0 {
                        WorkerEvent::Failure(primary) => super::errors::combine_cleanup_errors(
                            primary,
                            publication,
                            "active-operation stack failure and its publication both failed",
                        ),
                        _ => publication,
                    };
                    set_shutdown_error(context, failure);
                }
                return;
            }
            if let Err(error) = send_operation_completion(context, operation, true, result) {
                context.stopping.set(true);
                set_shutdown_error(context, error);
            }
        }
        WorkerCommand::Shutdown { request_id } => {
            if request_id == 0 {
                set_shutdown_error(
                    context,
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "DDE shutdown request has a zero identity",
                    ),
                );
            }
            context.shutdown_request_id.set(Some(request_id));
            context.stopping.set(true);
            if let Err(error) = native::cancel_active_conversations(context) {
                set_shutdown_error(context, error);
            }
        }
    }
}

fn wait_for_callback_reply_inner(
    context: &WorkerContext,
    receiver: Receiver<Win16DdeCallbackReply>,
) -> Result<Option<Win16DdeCallbackReply>, RuntimeError> {
    loop {
        match receiver.recv_timeout(Duration::from_millis(8)) {
            Ok(reply) => return Ok(Some(reply)),
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(None),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if context.stopping.get() && context.shutdown_request_id.get().is_none() {
            return Ok(None);
        }
        drain_commands(context);
        if context.stopping.get() && context.shutdown_request_id.get().is_none() {
            return Ok(None);
        }
    }
}

fn set_shutdown_error(context: &WorkerContext, error: RuntimeError) {
    let mut slot = context.shutdown_error.borrow_mut();
    *slot = Some(match slot.take() {
        Some(primary) => super::errors::combine_cleanup_errors(
            primary,
            error,
            "multiple DDE owner cleanup failures occurred",
        ),
        None => error,
    });
}

fn set_shutdown_error_safely(context: &WorkerContext, error: RuntimeError) {
    if let Ok(mut slot) = context.shutdown_error.try_borrow_mut() {
        *slot = Some(match slot.take() {
            Some(primary) => super::errors::combine_cleanup_errors(
                primary,
                error,
                "multiple DDE owner cleanup failures occurred",
            ),
            None => error,
        });
    } else {
        latch_emergency_failure(context, error);
    }
}

fn latch_emergency_failure(context: &WorkerContext, error: RuntimeError) {
    context.stopping.set(true);
    let previous = context.emergency_failure.take();
    let combined = match previous {
        Some(previous) => super::errors::combine_cleanup_errors(
            RuntimeError::with_source(
                previous.kind(),
                "an earlier DDE owner failure could not be recorded in its normal slot",
                previous,
            ),
            error,
            "multiple DDE owner emergency failures occurred",
        ),
        None => error,
    };
    context.emergency_failure.set(Some(Arc::new(combined)));
}

fn take_emergency_failure(context: &WorkerContext) -> Option<RuntimeError> {
    context.emergency_failure.take().map(|failure| {
        RuntimeError::with_source(
            failure.kind(),
            "DDE owner retained this typed failure after a reentrant borrow conflict",
            failure,
        )
    })
}

fn take_fatal_failure(context: &WorkerContext) -> Option<RuntimeError> {
    match context.fatal_error.try_borrow_mut() {
        Ok(mut failure) => failure.take(),
        Err(_) => {
            latch_emergency_failure(
                context,
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "DDE owner could not retrieve its retained callback failure",
                ),
            );
            None
        }
    }
}

fn combine_call_result<T>(
    current: Result<T, RuntimeError>,
    additional: RuntimeError,
    context: &'static str,
) -> Result<T, RuntimeError> {
    match current {
        Ok(_) => Err(additional),
        Err(primary) => Err(super::errors::combine_cleanup_errors(
            primary, additional, context,
        )),
    }
}

fn send_operation_completion(
    context: &WorkerContext,
    operation: Win16HostDdeOperation,
    entered_worker: bool,
    result: Result<runtime::Win16HostDdeResult, RuntimeError>,
) -> Result<(), RuntimeError> {
    match context.event_sender.send(WorkerEvent::Complete {
        operation,
        entered_worker,
        result,
    }) {
        Ok(()) => Ok(()),
        Err(failed) => {
            let publication = disconnected("publish a DDE operation result");
            match failed.0 {
                WorkerEvent::Complete {
                    entered_worker: _,
                    result: Err(primary),
                    ..
                } => Err(super::errors::combine_cleanup_errors(
                    primary,
                    publication,
                    "DDE operation failure and its publication both failed",
                )),
                _ => Err(publication),
            }
        }
    }
}

fn take_shutdown_error(context: &WorkerContext) -> Option<RuntimeError> {
    context.shutdown_error.borrow_mut().take()
}

fn combine_result(
    current: Result<(), RuntimeError>,
    next: Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    match (current, next) {
        (Ok(()), result) => result,
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(additional)) => Err(super::errors::combine_cleanup_errors(
            error,
            additional,
            "multiple DDE owner cleanup steps failed",
        )),
    }
}

fn disconnected(context: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::HostFailure, context)
}
