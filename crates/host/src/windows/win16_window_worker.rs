//! Dedicated-thread ownership and command execution for native Win16 windows.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16CreationId, Win16HostCallback, Win16HostClass,
    Win16HostClassSpec, Win16HostCreationData, Win16HostDc, Win16HostGdiObject,
    Win16HostTaskQueue, Win16HostWindow, Win16HostWindowCreationResult, Win16HostWindowLiveness,
    Win16HostWindowOperationId, Win16NativeWindowApiReturn, Win16RegisteredClass,
    Win16WindowCreationRejection, Win16WindowOperation, Win16WindowReply, Win16WindowResult,
    Win16WindowStep,
};
use windows_sys::Win32::Foundation::{GetLastError, HWND};
use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CW_USEDEFAULT, DestroyWindow, IsWindow, ShowWindow,
};

use super::super::win16_gdi::Win16Dcs;
use super::super::win16_gdi_objects::Win16RegionLease;
use super::super::win16_images::Win16Images;
use super::ControlColorReturnSlot;
use super::win16_common_dialog_worker::ShutdownStorageGuard;
use super::win16_dialog_callbacks::host_dialog_proc;
use super::win16_window_callbacks;

#[path = "win16_window_worker_modal.rs"]
mod modal;
#[path = "win16_window_worker_state.rs"]
mod state;
pub(in crate::windows) use modal::{ModalWakeDispatcher, yield_pending_modal_guest_work};
pub(super) use state::{
    ActiveClassicDdeOperation, ActiveOperation, ClipboardViewerRegistration,
    DialogControlCreationRoute, DialogRootCreationRoute, DialogRoute, DragListOrigin,
    DragListSidecar, LiveCallback, NativeCallbackContext, NativeClass, NativeClassicDdeQuiescence,
    NativeCreateCookie, NativeDropCallbackClaim, NativeDropCallbackResolution, NativeDropOwner,
    NativeClassResource, NativeDropRetirementQueue, NativeDropRetirementQueueHandle,
    NativeTimerRecord, NativeWindowIdentity, PendingCreation, PendingDialogRoute,
    PendingWindowMenuRetirement,
    TerminalProofSnapshot, Win16GuestTimerPost, WorkerState,
};

#[path = "win16_common_controls_worker_retention.rs"]
mod bitmap_retention;
#[path = "win16_window_worker_class_menu.rs"]
mod class_menu;
#[path = "win16_window_worker_lifecycle.rs"]
mod lifecycle;
#[path = "win16_window_worker_windows.rs"]
mod native_windows;
#[path = "win16_window_worker_operations.rs"]
mod operations;
#[path = "win16_window_worker_shutdown.rs"]
mod shutdown;
#[path = "win16_window_worker_terminal_owner.rs"]
mod terminal_owner;
#[path = "win16_window_worker_terminal_responses.rs"]
mod terminal_responses;
#[path = "win16_window_worker_timer_registry.rs"]
mod timer_registry;
#[path = "win16_window_worker_timers.rs"]
mod timers;
#[path = "win16_window_worker_user_services.rs"]
mod user_services;
#[path = "win16_window_worker_retirement.rs"]
mod window_retirement;
use bitmap_retention::{combine_worker_failures, join_worker_before_ready};
use native_windows::create_window;
pub(super) use native_windows::{
    adopt_callback_dc, allocate_callback_id, allocate_window_token, destroy_quiet,
    destroy_window_operation, forget_callback_dc, identify_window, native_class_name_matches,
    registered_class_for_native, show_window, token_for_native,
};
use shutdown::ShutdownResult;
use shutdown::WorkerRetention;
use terminal_responses::worker_join_failure;
use terminal_responses::{
    CanonicalAbortResponse, PendingTerminalResponse, PendingTerminalResponseState,
    finish_terminal_response_slots, retain_canonical_abort_pending_response,
    retain_canonical_abort_response_slot, retain_pending_terminal_response,
    shared_terminal_response_failure,
};
pub(super) use window_retirement::{
    NativeWindowRetirementCandidate, WindowRetirementScope, begin_window_retirement_observation,
    capture_window_retirement_candidate, finish_window_retirement, prepare_window_retirement,
    same_candidate,
};

pub(super) use lifecycle::shutdown_all;
pub(super) use user_services::{retire_clipboard_viewer, update_clipboard_viewer_chain};

pub(super) use timer_registry::{
    allocate_host_timer_id, allocate_native_callback_timer_id, guest_timer_post,
    host_timer_proc_pointer, native_timer_record, post_guest_timer_message, register_native_timer,
    retire_native_timer, timer_record_by_host_id,
};
pub(super) use timers::remove_window_maps;

#[path = "win16_window_worker_commands.rs"]
mod commands;
pub(super) use commands::WorkerCommand;
#[path = "win16_classic_dde_worker.rs"]
mod classic_dde_worker;
pub(super) use classic_dde_worker::pump_internal_messages as pump_classic_dde_messages;

#[path = "win16_window_worker_com.rs"]
mod com_api;
#[path = "win16_com_sta_worker.rs"]
mod com_sta;

pub(super) struct WindowWorker {
    sender: Sender<WorkerCommand>,
    wake_event: Arc<OwnedHandle>,
    multimedia_wake: super::super::multimedia_wake::MultimediaWakeSender,
    // Keep the native join handle and its prestarted reaper as one lifetime token.
    thread: Option<(JoinHandle<()>, WorkerRetention)>,
    // Native modeless-dialog storage may still be used during Windows thread
    // cleanup. The outer owner retains these opaque guards until join returns.
    shutdown_storage: Arc<Mutex<Vec<ShutdownStorageGuard>>>,
    worker_retirement_id: u64,
    toolbar_bitmap_retention:
        Arc<Mutex<super::win16_common_controls_bitmap_pins::ToolbarBitmapRetention>>,
    bitmap_retention_slot_reserved: bool,
    modal_control: Arc<super::super::win16_modal::ModalWorkerControl>,
    modal_wake_dispatcher: Arc<ModalWakeDispatcher>,
    canonical_abort_response: Arc<CanonicalAbortResponse>,
    terminal_response_slots: Arc<Mutex<Vec<PendingTerminalResponse>>>,
    terminal_receipt: Option<runtime::Win16WindowAbortReceipt>,
    com_client: com_sta::Win16ComWorkerClient,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UserWaitKind {
    GetMessage,
    WaitMessage,
}

pub(super) fn begin_user_wait(
    state: &Rc<RefCell<WorkerState>>,
    operation_id: u64,
    kind: UserWaitKind,
) -> Result<(), RuntimeError> {
    let mut worker = state.try_borrow_mut().map_err(|_| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "classic DDE could not claim the exact parked USER wait",
        )
    })?;
    if !worker
        .active_operations
        .last()
        .is_some_and(|active| active.id == operation_id)
    {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "classic DDE USER wait claim does not match the active USER operation",
        ));
    }
    worker.active_user_waits.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve exact classic DDE USER wait ownership",
            error,
        )
    })?;
    worker.active_user_waits.push((operation_id, kind));
    Ok(())
}

pub(super) fn end_user_wait(
    state: &Rc<RefCell<WorkerState>>,
    operation_id: u64,
    kind: UserWaitKind,
) -> Result<(), RuntimeError> {
    let mut worker = state.try_borrow_mut().map_err(|_| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "classic DDE could not retire the exact parked USER wait",
        )
    })?;
    if worker.active_user_waits.last().copied() != Some((operation_id, kind)) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "classic DDE USER wait retirement does not match the exact active wait",
        ));
    }
    worker.active_user_waits.pop();
    Ok(())
}

pub(super) fn yield_pending_guest_work(
    state: &Rc<RefCell<WorkerState>>,
    operation_id: u64,
    generation: u64,
    kind: UserWaitKind,
    response: &Sender<Result<Win16WindowStep, RuntimeError>>,
) -> Result<(), RuntimeError> {
    if !state
        .borrow()
        .active_operations
        .last()
        .is_some_and(|active| active.id == operation_id)
    {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "pending guest work does not match the active USER wait operation",
        ));
    }
    response
        .send(Ok(Win16WindowStep::PendingGuestWork {
            operation_id: Win16HostWindowOperationId(operation_id),
            generation,
        }))
        .map_err(|_| {
            RuntimeError::new(
                Kind::HostFailure,
                "runtime dropped a suspended Win16 USER wait continuation",
            )
        })?;

    loop {
        if state.borrow().aborted {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "Win16 USER wait continuation was canceled by worker shutdown",
            ));
        }
        let command = super::win16_message_loop::wait_for_worker_command(state)?;
        match (kind, command) {
            (UserWaitKind::GetMessage, WorkerCommand::ContinueGetMessage { id })
            | (UserWaitKind::WaitMessage, WorkerCommand::ContinueWaitMessage { id })
                if id == operation_id =>
            {
                return Ok(());
            }
            (UserWaitKind::GetMessage, WorkerCommand::ContinueGetMessage { id })
            | (UserWaitKind::WaitMessage, WorkerCommand::ContinueWaitMessage { id }) => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    format!("USER wait continuation identity {id} does not match {operation_id}"),
                ));
            }
            (_, WorkerCommand::ContinueGetMessage { id })
            | (_, WorkerCommand::ContinueWaitMessage { id }) => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    format!("USER wait continuation {id} has the wrong operation kind"),
                ));
            }
            (_, command) => process_command(state, command),
        }
    }
}

impl WindowWorker {
    pub(super) fn worker_generation(&self) -> u64 {
        self.worker_retirement_id
    }

    pub(super) fn spawn(
        dcs: Win16Dcs,
        images: Win16Images,
        identity_source: Arc<AtomicU64>,
        oem_text_codec: crate::windows::guest_text::GuestTextCodec,
        native_drop_retirements: NativeDropRetirementQueueHandle,
    ) -> Result<Self, RuntimeError> {
        super::win16_common_controls_bitmap_pins::retry_retained_after_join()?;
        let worker_retirement_id =
            super::win16_common_controls_bitmap_pins::allocate_worker_retirement_id()?;
        // Auto-reset event wakes the worker's interruptible USER queue wait.
        // The owned handle is shared only inside this trusted host adapter.
        let native_event = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
        if native_event.is_null() {
            return Err(last_error("create the Win16 USER worker wake event"));
        }
        let wake_event =
            Arc::new(unsafe { OwnedHandle::from_raw_handle(native_event as RawHandle) });
        let multimedia_generation = Arc::new(AtomicU64::new(0));
        let worker_alive = Arc::new(AtomicBool::new(true));
        let (sender, receiver) = mpsc::channel();
        let worker_event = Arc::clone(&wake_event);
        let worker_generation = Arc::clone(&multimedia_generation);
        let worker_liveness = Arc::clone(&worker_alive);
        let shutdown_storage = Arc::new(Mutex::new(Vec::new()));
        let worker_storage = Arc::clone(&shutdown_storage);
        // Start the join owner before the USER thread so Drop can transfer a
        // still-live worker without spawning or allocating during unwinding.
        let retention = WorkerRetention::start()?;
        let modal_control = super::super::win16_modal::ModalWorkerControl::new()?;
        let terminal_response_slots = Arc::new(Mutex::new(Vec::new()));
        let canonical_abort_response = CanonicalAbortResponse::new();
        let modal_wake_dispatcher = Arc::new(ModalWakeDispatcher {
            sender: sender.clone(),
            wake_event: Arc::clone(&wake_event),
            modal_control: Arc::clone(&modal_control),
            terminal_response_slots: Arc::clone(&terminal_response_slots),
            canonical_abort_response: Arc::clone(&canonical_abort_response),
            abort_submission: AtomicU8::new(0),
            abort_submission_lock: Mutex::new(()),
            abort_submission_ready: Condvar::new(),
            abort_publication_failure: Mutex::new(None),
        });
        modal_control.bind_abort_dispatcher(Arc::downgrade(&modal_wake_dispatcher));
        let multimedia_wake =
            super::super::multimedia_wake::MultimediaWakeSender::from_worker_event(
                Arc::clone(&wake_event),
                Arc::clone(&multimedia_generation),
                Arc::clone(&worker_alive),
                Arc::clone(&modal_control),
                Arc::clone(&modal_wake_dispatcher),
            );
        let worker_modal_control = Arc::clone(&modal_control);
        super::win16_common_controls_bitmap_pins::reserve_worker_retention_slot()?;
        let mut bitmap_retention_slot_reserved = true;
        let toolbar_bitmap_retention = Arc::new(Mutex::new(
            super::win16_common_controls_bitmap_pins::ToolbarBitmapRetention::new(),
        ));
        let worker_toolbar_bitmap_retention = Arc::clone(&toolbar_bitmap_retention);
        // Win16Windows retains the receipt reader after worker shutdown. Move
        // this publisher handle into WorkerState with the native HDROP owners.
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let thread = match thread::Builder::new()
            .name("Win16 USER worker".to_owned())
            .spawn(move || {
                timers::worker_main(
                    receiver,
                    worker_event,
                    worker_generation,
                    worker_liveness,
                    dcs,
                    images,
                    oem_text_codec,
                    worker_storage,
                    worker_retirement_id,
                    worker_toolbar_bitmap_retention,
                    identity_source,
                    worker_modal_control,
                    native_drop_retirements,
                    ready_sender,
                )
            }) {
            Ok(thread) => thread,
            Err(error) => {
                let primary = RuntimeError::with_source(
                    Kind::HostFailure,
                    "start the Win16 native window worker",
                    error,
                );
                let result =
                    match super::win16_common_controls_bitmap_pins::release_worker_retention_slot()
                    {
                        Ok(()) => primary,
                        Err(cleanup) => combine_worker_failures(
                            primary,
                            cleanup,
                            "start the worker and release its bitmap retention reservation both failed",
                        ),
                    };
                return Err(result);
            }
        };
        let com_client = match ready_receiver.recv() {
            Ok(Ok(client)) => client,
            Ok(Err(error)) => {
                let cleanup = join_worker_before_ready(
                    thread,
                    worker_retirement_id,
                    &toolbar_bitmap_retention,
                    &mut bitmap_retention_slot_reserved,
                );
                return Err(match cleanup {
                    Ok(()) => error,
                    Err(cleanup) => combine_worker_failures(
                        error,
                        cleanup,
                        "initialize the worker and retire its bitmap lifetime both failed",
                    ),
                });
            }
            Err(error) => {
                let primary = RuntimeError::with_source(
                    Kind::HostFailure,
                    "receive Win16 USER worker readiness",
                    error,
                );
                let cleanup = join_worker_before_ready(
                    thread,
                    worker_retirement_id,
                    &toolbar_bitmap_retention,
                    &mut bitmap_retention_slot_reserved,
                );
                return Err(match cleanup {
                    Ok(()) => primary,
                    Err(cleanup) => combine_worker_failures(
                        primary,
                        cleanup,
                        "receive worker readiness and retire its bitmap lifetime both failed",
                    ),
                });
            }
        };
        Ok(Self {
            sender,
            wake_event,
            multimedia_wake,
            thread: Some((thread, retention)),
            shutdown_storage,
            worker_retirement_id,
            toolbar_bitmap_retention,
            bitmap_retention_slot_reserved,
            modal_control,
            modal_wake_dispatcher,
            canonical_abort_response,
            terminal_response_slots,
            terminal_receipt: None,
            com_client,
        })
    }

    pub(super) fn multimedia_wake_sender(
        &self,
    ) -> super::super::multimedia_wake::MultimediaWakeSender {
        self.multimedia_wake.clone()
    }

    pub(super) fn send(
        &self,
        command: WorkerCommand,
    ) -> Result<(), mpsc::SendError<WorkerCommand>> {
        let result = self.sender.send(command);
        if result.is_ok() {
            // The event remains owned until after the worker joins, so this
            // valid process-local handle cannot be closed during SetEvent.
            unsafe { SetEvent(self.wake_event.as_raw_handle() as _) };
        }
        result
    }

    pub(super) fn query_window_liveness(
        &self,
        window: Win16HostWindow,
    ) -> Result<Win16HostWindowLiveness, RuntimeError> {
        let (response, receive) = mpsc::channel();
        self.send(WorkerCommand::QueryWindowLiveness { window, response })
            .map_err(|_| {
                RuntimeError::new(
                    Kind::HostFailure,
                    "enqueue exact Win16 host-window liveness query",
                )
            })?;
        receive.recv().map_err(|error| {
            RuntimeError::with_source(
                Kind::HostFailure,
                "receive exact Win16 host-window liveness result",
                error,
            )
        })?
    }

    pub(super) fn query_window_parent(
        &self,
        window: Win16HostWindow,
    ) -> Result<runtime::Win16HostWindowParentObservation, RuntimeError> {
        let (response, receive) = mpsc::channel();
        self.send(WorkerCommand::QueryWindowParent { window, response })
            .map_err(|_| {
                RuntimeError::new(
                    Kind::HostFailure,
                    "enqueue exact Win16 host-window parent query",
                )
            })?;
        receive.recv().map_err(|error| {
            RuntimeError::with_source(
                Kind::HostFailure,
                "receive exact Win16 host-window parent result",
                error,
            )
        })?
    }

    pub(super) fn ime_profile(
        &self,
        call: runtime::Win16HostImeProfileCall,
    ) -> Result<runtime::Win16HostImeProfileResult, RuntimeError> {
        let (response, receive) = mpsc::channel();
        self.send(WorkerCommand::ImeProfile { call, response })
            .map_err(|_| {
                RuntimeError::new(Kind::HostFailure, "enqueue legacy IME profile query")
            })?;
        receive.recv().map_err(|error| {
            RuntimeError::with_source(
                Kind::HostFailure,
                "receive legacy IME profile result",
                error,
            )
        })?
    }

    pub(super) fn resume_modal_guest_work(
        &self,
        operation_id: Win16HostWindowOperationId,
        scope_id: u64,
        generation: u64,
        marker_id: Option<u64>,
        wake_generation: Option<u64>,
    ) -> Result<(), RuntimeError> {
        let queued = self.modal_control.enqueue_modal_guest_work_resume(|| {
            self.sender
                .send(WorkerCommand::ResumeModalGuestWork {
                    operation_id: operation_id.0,
                    scope_id,
                    generation,
                    marker_id,
                    wake_generation,
                })
                .map_err(|_| {
                    RuntimeError::new(
                        Kind::HostFailure,
                        "enqueue the exact Win16 modal guest-work resume tuple",
                    )
                })
        })?;
        // Serialize the exact resume against terminal enqueue. If terminal
        // already won, one checked event signal releases the hook to process
        // its queued Abort command; the native modal API still owns return.
        let operation = if queued {
            "wake the Win16 USER worker for exact modal guest-work resume"
        } else {
            "wake the Win16 USER worker to process its queued terminal request"
        };
        if unsafe { SetEvent(self.wake_event.as_raw_handle() as _) } == 0 {
            return Err(last_error(operation));
        }
        Ok(())
    }

    pub(super) fn send_begin(&self, command: WorkerCommand) -> Result<(), WorkerCommand> {
        match self.sender.send(command) {
            Ok(()) => {
                // A rejected Begin returns its owned bitmap leases to the
                // caller, which can retain them before this worker is joined.
                unsafe { SetEvent(self.wake_event.as_raw_handle() as _) };
                Ok(())
            }
            Err(error) => Err(error.0),
        }
    }

    pub(super) fn reserve_toolbar_bitmap_leases(&self, count: usize) -> Result<(), RuntimeError> {
        super::win16_common_controls_bitmap_pins::reserve_unconsumed_leases(
            &self.toolbar_bitmap_retention,
            count,
        )
    }

    pub(super) fn release_unconsumed_toolbar_bitmap_leases(
        &self,
        operation: u64,
        leases: BTreeMap<
            Win16HostGdiObject,
            Option<super::win16_gdi_bitmap_lease::Win16BitmapLease>,
        >,
    ) -> Result<(), RuntimeError> {
        super::win16_common_controls_bitmap_pins::release_unconsumed_leases(
            self.worker_retirement_id,
            operation,
            &self.toolbar_bitmap_retention,
            leases,
        )
    }

    pub(super) fn bind_task_queue(
        &self,
        owner: guest_core::OwnerId,
        guest_htask: u16,
        task_selector_generation: u64,
    ) -> Result<Option<Win16HostTaskQueue>, RuntimeError> {
        let (response, receive) = mpsc::channel();
        self.send(WorkerCommand::BindTaskQueue {
            owner,
            guest_htask,
            task_selector_generation,
            response,
        })
        .map_err(|_| {
            RuntimeError::new(
                Kind::HostFailure,
                "enqueue an exact Win16 task queue binding",
            )
        })?;
        receive.recv().map_err(|error| {
            RuntimeError::with_source(
                Kind::HostFailure,
                "receive an exact Win16 task queue binding",
                error,
            )
        })?
    }

    pub(super) fn retire_task_queue(
        &self,
        owner: guest_core::OwnerId,
        guest_htask: u16,
        task_selector_generation: u64,
        queue: Win16HostTaskQueue,
    ) -> Result<bool, RuntimeError> {
        let (response, receive) = mpsc::channel();
        self.send(WorkerCommand::RetireTaskQueue {
            owner,
            guest_htask,
            task_selector_generation,
            queue,
            response,
        })
        .map_err(|_| RuntimeError::new(Kind::HostFailure, "enqueue Win16 task queue retirement"))?;
        receive.recv().map_err(|error| {
            RuntimeError::with_source(
                Kind::HostFailure,
                "receive Win16 task queue retirement",
                error,
            )
        })
    }

    pub(super) fn has_join_handle(&self) -> bool {
        self.thread.is_some()
    }
}

impl Drop for WindowWorker {
    fn drop(&mut self) {
        if let Err(error) = self.shutdown() {
            eprintln!("runtime: {error}");
            if let Some((thread, retention)) = self.thread.take() {
                retention.retain_after_failed_shutdown(
                    thread,
                    Arc::clone(&self.shutdown_storage),
                    Arc::clone(&self.toolbar_bitmap_retention),
                    self.worker_retirement_id,
                    self.bitmap_retention_slot_reserved,
                    Arc::clone(&self.terminal_response_slots),
                );
            }
        }
    }
}

thread_local! {
    static WORKER_CONTEXT: RefCell<Option<Rc<RefCell<WorkerState>>>> = const { RefCell::new(None) };
}

pub(in crate::windows) fn worker_context() -> Option<Rc<RefCell<WorkerState>>> {
    WORKER_CONTEXT.with(|slot| slot.borrow().clone())
}

pub(in crate::windows) fn current_operation_id() -> Option<u64> {
    let state = WORKER_CONTEXT.with(|slot| {
        slot.try_borrow()
            .ok()
            .and_then(|slot| slot.as_ref().cloned())
    })?;
    let id = {
        let state = state.try_borrow().ok()?;
        state.active_operations.last().map(|active| active.id)
    };
    id
}

pub(super) fn receive_command(state: &Rc<RefCell<WorkerState>>) -> Option<WorkerCommand> {
    // Clone the receiver handle under a short RefCell borrow, then block only
    // while holding the receiver mutex. No native call runs under either.
    let receiver = { Arc::clone(&state.borrow().commands) };
    let command = receiver.lock().ok()?.recv().ok();
    command
}

pub(super) fn process_command(state: &Rc<RefCell<WorkerState>>, command: WorkerCommand) {
    if matches!(&command, WorkerCommand::Abort { .. } | WorkerCommand::Shutdown { .. }) {
        if let Err(error) = super::win16_cursor_clip::cleanup_for_exit() {
            state.borrow_mut().terminal_failures.push(Arc::new(error));
        }
    }
    match command {
        WorkerCommand::WindowEnumeration { query, response } => {
            let _ = response.send(super::win16_window_enumeration::query(state, query));
        }
        WorkerCommand::QueryControlIdentity { query, response } => {
            let _ = response.send(super::win16_standard_controls::query(state, query));
        }
        WorkerCommand::QuerySystemClass { kind, response } => {
            let result = super::win16_system_classes::query(state, kind);
            let _ = response.send(result);
        }
        WorkerCommand::RegisterClass {
            class,
            spec,
            icon,
            cursor,
            background,
            response,
        } => {
            let result = lifecycle::register_class(state, class, spec, icon, cursor, background);
            let _ = response.send(result);
        }
        WorkerCommand::UnregisterClass { class, response } => {
            let _ = response.send(lifecycle::unregister_class(state, class));
        }
        WorkerCommand::ReplaceClassResource {
            class,
            window,
            resource,
            response,
        } => {
            let result = lifecycle::replace_class_resource(state, class, window, resource);
            let _ = response.send(result);
        }
        WorkerCommand::Begin {
            id,
            operation,
            win_exec,
            control_color_return,
            native_bitmaps,
            native_font,
            toolbar_bitmap_leases,
            native_regions,
            gray_string_brush,
            response,
        } => {
            operations::run_operation(
                state,
                id,
                operation,
                win_exec,
                control_color_return,
                native_bitmaps,
                native_font,
                toolbar_bitmap_leases,
                native_regions,
                gray_string_brush,
                response,
            );
        }
        WorkerCommand::InitializeQueue { response } => {
            // worker_main creates the USER queue before accepting commands.
            let _ = response.send(Ok(()));
        }
        WorkerCommand::BindTaskQueue {
            owner,
            guest_htask,
            task_selector_generation,
            response,
        } => {
            let result = super::win16_guest_notifications::bind_task_queue(
                owner,
                guest_htask,
                task_selector_generation,
            );
            let _ = response.send(result);
        }
        WorkerCommand::RetireTaskQueue {
            owner,
            guest_htask,
            task_selector_generation,
            queue,
            response,
        } => {
            let _ = response.send(super::win16_guest_notifications::retire_task_queue(
                owner,
                guest_htask,
                task_selector_generation,
                queue,
            ));
        }
        WorkerCommand::GetKeyState { key, response } => {
            let state =
                unsafe { windows_sys::Win32::UI::Input::KeyboardAndMouse::GetKeyState(key) };
            let _ = response.send(state);
        }
        WorkerCommand::Keyboard { call, response } => {
            // Layout and dead-key state belong to this USER input queue.
            // Release the Rust borrow before invoking Windows.
            let (ansi_codec, oem_page) = {
                let state = state.borrow();
                (state.text_codec, state.oem_text_codec.code_page())
            };
            let result = crate::windows::win16_keyboard::execute(call, ansi_codec, oem_page);
            let _ = response.send(result);
        }
        WorkerCommand::ComShutdown { owner, operation, response } => {
            let com = { Rc::clone(&state.borrow().com) };
            let _ = response.send(com.shutdown(owner, operation));
        }
        WorkerCommand::ComBegin {
            owner,
            start,
            accepted,
        } => {
            com_sta::run_start(state, owner, start, accepted);
        }
        WorkerCommand::ComAcknowledgeTerminal {
            owner,
            operation,
            response,
        } => {
            let com = { Rc::clone(&state.borrow().com) };
            let _ = response.send(com.acknowledge(owner, operation));
        }
        WorkerCommand::ClassicDdeBegin {
            operation,
            call,
            response,
        } => {
            classic_dde_worker::begin_operation(state, operation, call, response);
        }
        WorkerCommand::ClassicDdeResume { operation, reply } => {
            if let Err(error) = classic_dde_worker::resume_operation(state, operation, reply) {
                let mut state = state.borrow_mut();
                state.callbacks_enabled = false;
                state.aborted = true;
                state.terminal_failures.push(Arc::new(error));
            }
        }
        WorkerCommand::Resume { .. } => {
            // Resume is consumed only by the matching suspended WndProc.
        }
        WorkerCommand::ContinueGetMessage { id } | WorkerCommand::ContinueWaitMessage { id } => {
            let error = RuntimeError::new(
                Kind::InternalInvariant,
                format!("USER wait continuation {id} escaped its suspended operation"),
            );
            let mut state = state.borrow_mut();
            state.callbacks_enabled = false;
            state.aborted = true;
            state.terminal_failures.push(Arc::new(error));
        }
        WorkerCommand::ResumeModalGuestWork {
            operation_id,
            scope_id,
            generation,
            marker_id,
            wake_generation,
        } => {
            let error = RuntimeError::new(
                Kind::InternalInvariant,
                format!(
                    "modal resume ({operation_id}, {scope_id}, {generation}, {marker_id:?}, {wake_generation:?}) escaped its suspended owner-thread hook",
                ),
            );
            let mut state = state.borrow_mut();
            state.callbacks_enabled = false;
            state.aborted = true;
            state.terminal_failures.push(Arc::new(error));
        }
        WorkerCommand::DestroyQuiet { window, response } => {
            let _ = response.send(destroy_quiet(state, window));
        }
        WorkerCommand::QueryWindowLiveness { window, response } => {
            let _ = response.send(super::win16_window_identity::liveness(state, window));
        }
        WorkerCommand::QueryWindowParent { window, response } => {
            let _ = response.send(super::win16_window_data::query_parent(state, window));
        }
        #[cfg(test)]
        WorkerCommand::TestWindowData { run, response } => {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(state)));
            let _ = response.send(result);
        }
        WorkerCommand::ImeProfile { call, response } => {
            let _ = response.send(super::win16_ime_profiles::execute(state, call));
        }
        WorkerCommand::Abort {
            request_id,
            response,
        } => {
            let com = { Rc::clone(&state.borrow().com) };
            if let Err(error) = com.close_callback_ingress("Win16 USER worker was aborted") {
                let _ = response.send(Err(Arc::new(error)));
                return;
            }
            let mut state = state.borrow_mut();
            let reservation = state.abort_waiters.try_reserve(1);
            if let Err(error) = reservation {
                let _ = response.send(Err(Arc::new(RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve Win16 USER terminal response owner",
                    error,
                ))));
                return;
            }
            if state.terminal_proof.is_none() && state.terminal_proof_error.is_none() {
                match snapshot_terminal_proof(&state) {
                    Ok(snapshot) => state.terminal_proof = Some(snapshot),
                    Err(error) => state.terminal_proof_error = Some(Arc::new(error)),
                }
            }
            state.aborted = true;
            state.callbacks_enabled = false;
            state.abort_waiters.push((request_id, response));
        }
        WorkerCommand::Shutdown {
            request_id,
            response,
        } => {
            let com = { Rc::clone(&state.borrow().com) };
            if let Err(error) = com.close_callback_ingress("Win16 USER STA is shutting down") {
                let _ = response.send(Err(Arc::new(error)));
                return;
            }
            let mut state = state.borrow_mut();
            let reservation = state.shutdown_waiters.try_reserve(1);
            if let Err(error) = reservation {
                let _ = response.send(Err(Arc::new(RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve Win16 USER shutdown response owner",
                    error,
                ))));
                return;
            }
            if state.terminal_proof.is_none() && state.terminal_proof_error.is_none() {
                match snapshot_terminal_proof(&state) {
                    Ok(snapshot) => state.terminal_proof = Some(snapshot),
                    Err(error) => state.terminal_proof_error = Some(Arc::new(error)),
                }
            }
            state.aborted = true;
            state.callbacks_enabled = false;
            state.shutdown_requested = true;
            state.shutdown_waiters.push((request_id, response));
        }
        WorkerCommand::TerminalWakePosted { request_id } => {
            state.borrow_mut().terminal_wake_requests.insert(request_id);
        }
    }
}

fn snapshot_terminal_proof(state: &WorkerState) -> Result<TerminalProofSnapshot, RuntimeError> {
    let mut active_operations = Vec::new();
    active_operations
        .try_reserve_exact(state.active_operations.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact active USER operation abort snapshot",
                error,
            )
        })?;
    active_operations.extend(state.active_operations.iter().map(|active| {
        runtime::Win16NativeWindowOperationProof {
            operation_id: runtime::Win16HostWindowOperationId(active.id),
            kind: active.kind,
        }
    }));

    let mut cancelled_callbacks = Vec::new();
    cancelled_callbacks
        .try_reserve_exact(state.live_callbacks.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact live USER callback abort snapshot",
                error,
            )
        })?;
    cancelled_callbacks.extend(state.live_callbacks.iter().map(|callback| {
        runtime::Win16NativeCallbackCancellation {
            callback: callback.callback,
            operation_id: runtime::Win16HostWindowOperationId(callback.operation),
            source: callback.source,
        }
    }));

    let mut windows = Vec::new();
    windows
        .try_reserve_exact(state.windows.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native USER window resource snapshot",
                error,
            )
        })?;
    windows.extend(state.windows.keys().copied());
    windows.sort_unstable();
    let mut menus = Vec::new();
    menus
        .try_reserve_exact(state.menus.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native USER menu resource snapshot",
                error,
            )
        })?;
    menus.extend(state.menus.keys().copied());
    let mut classes = Vec::new();
    classes
        .try_reserve_exact(state.classes.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native USER class resource snapshot",
                error,
            )
        })?;
    classes.extend(state.classes.keys().copied());

    Ok(TerminalProofSnapshot {
        active_operations,
        cancelled_callbacks,
        resources: runtime::Win16NativeWindowResourceSnapshot {
            windows,
            menus,
            classes,
        },
    })
}

fn last_error(operation: &str) -> RuntimeError {
    RuntimeError::with_source(
        Kind::HostFailure,
        operation,
        std::io::Error::from_raw_os_error(unsafe { GetLastError() } as i32),
    )
}
