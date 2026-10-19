//! COM/OLE coordinator owned by the existing Win16 USER STA.
//!
//! Native interfaces and callback proxies are created, called and retired on
//! the one `WindowWorker` thread. The client handle carries only typed IDs,
//! callback channels and copied terminal values.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, TryRecvError};
use std::sync::{Arc, Mutex};

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16ComHostContinue, Win16ComHostOperationIdentity,
    Win16ComHostOwnerIdentity, Win16ComHostShutdownOperation, Win16ComHostShutdownReceipt,
    Win16ComHostShutdownStep, Win16ComHostStep,
};
use windows_sys::Win32::Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, MSG, MsgWaitForMultipleObjectsEx, PM_REMOVE, PeekMessageW, QS_ALLINPUT,
    TranslateMessage, WM_DROPFILES,
};

use super::super::super::{
    win16_com_callback_proxy::{Win16ComCallbackIngress, Win16ComCallbackRuntime},
    win16_com_objects::{NativeComError, Win16ComObjects},
    win16_com_request_executor::{self as executor, PreparedWin16ComStart, Win16ComApartmentRefs},
};
use super::WorkerState;

// Admission is bounded at 64 accepted operations across active calls and
// unacknowledged terminals. Nested COM calls count against the same budget;
// exhaustion applies back-pressure instead of growing the owner journals.
// This caps record count, not arbitrary byte payloads owned by COM results.
const MAX_UNSETTLED_OPERATIONS: usize = 64;
static NEXT_COM_IDENTITY: AtomicU64 = AtomicU64::new(1);

pub(super) struct Win16ComWorkerClient {
    pub(super) owner: Win16ComHostOwnerIdentity,
    pub(super) owner_sealed: Arc<AtomicBool>,
    callbacks: Win16ComCallbackRuntime,
    ingress: Mutex<Win16ComCallbackIngress>,
    terminals: Arc<Mutex<VecDeque<(Win16ComHostOperationIdentity, Win16ComHostStep)>>>,
}

pub(in crate::windows::win16_windows) struct Win16ComStaState {
    owner: Win16ComHostOwnerIdentity,
    objects: Rc<Win16ComObjects>,
    callbacks: Win16ComCallbackRuntime,
    apartment_refs: Win16ComApartmentRefs,
    terminals: Arc<Mutex<VecDeque<(Win16ComHostOperationIdentity, Win16ComHostStep)>>>,
    active: RefCell<Vec<Win16ComHostOperationIdentity>>,
    unsettled: RefCell<Vec<Win16ComHostOperationIdentity>>,
    last_generation: Cell<u64>,
    ingress_closed: Cell<bool>,
    owner_sealed: Arc<AtomicBool>,
    native_objects_shutdown: Cell<bool>,
    shutdown_receipt: Cell<Option<Win16ComHostShutdownReceipt>>,
    apartment_lease: Cell<bool>,
}

impl Win16ComStaState {
    pub(super) fn initialize(
        worker_wake: Arc<OwnedHandle>,
    ) -> Result<(Rc<Self>, Win16ComWorkerClient), RuntimeError> {
        // One permanent OLE lease belongs to the USER worker lifetime. Guest
        // Initialize/Uninitialize operations are independently counted below.
        // SAFETY: OleInitialize initializes OLE on the calling thread and writes no caller pointer.
        let apartment = unsafe { windows_sys::Win32::System::Ole::OleInitialize(std::ptr::null()) };
        if apartment < 0 {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                format!(
                    "initialize the Win16 USER STA OLE apartment (HRESULT 0x{:08X})",
                    apartment as u32
                ),
            ));
        }
        let owner = match allocate_owner() {
            Some(owner) => owner,
            None => {
                (crate::windows::win32_safe::ole_uninitialize());
                return Err(RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 COM owner identity space was exhausted",
                ));
            }
        };
        let owner_sealed = Arc::new(AtomicBool::new(false));
        let objects = match Win16ComObjects::new(owner) {
            Ok(objects) => Rc::new(objects),
            Err(error) => {
                (crate::windows::win32_safe::ole_uninitialize());
                return Err(com_runtime_error(
                    "create the USER STA COM object table",
                    error,
                ));
            }
        };
        let (callbacks, ingress) = match Win16ComCallbackRuntime::new(owner, worker_wake) {
            Ok(pair) => pair,
            Err(error) => {
                let _ = objects.shutdown();
                (crate::windows::win32_safe::ole_uninitialize());
                return Err(com_runtime_error(
                    "create the USER STA callback port",
                    error,
                ));
            }
        };
        let mut terminals = VecDeque::new();
        terminals
            .try_reserve_exact(MAX_UNSETTLED_OPERATIONS)
            .map_err(|error| {
                let _ = objects.shutdown();
                (crate::windows::win32_safe::ole_uninitialize());
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve bounded Win16 COM terminal journal",
                    error,
                )
            })?;
        let terminals = Arc::new(Mutex::new(terminals));
        let mut active = Vec::new();
        active
            .try_reserve_exact(MAX_UNSETTLED_OPERATIONS)
            .map_err(|error| {
                let _ = objects.shutdown();
                (crate::windows::win32_safe::ole_uninitialize());
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve active COM operations",
                    error,
                )
            })?;
        let mut unsettled = Vec::new();
        unsettled
            .try_reserve_exact(MAX_UNSETTLED_OPERATIONS)
            .map_err(|error| {
                let _ = objects.shutdown();
                (crate::windows::win32_safe::ole_uninitialize());
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve unacknowledged COM results",
                    error,
                )
            })?;
        let sta = Rc::new(Self {
            owner,
            objects,
            callbacks: callbacks.clone(),
            apartment_refs: Win16ComApartmentRefs::new(),
            terminals: Arc::clone(&terminals),
            active: RefCell::new(active),
            unsettled: RefCell::new(unsettled),
            last_generation: Cell::new(0),
            ingress_closed: Cell::new(false),
            owner_sealed: Arc::clone(&owner_sealed),
            native_objects_shutdown: Cell::new(false),
            shutdown_receipt: Cell::new(None),
            apartment_lease: Cell::new(true),
        });
        Ok((
            sta,
            Win16ComWorkerClient {
                owner,
                owner_sealed,
                callbacks,
                ingress: Mutex::new(ingress),
                terminals,
            },
        ))
    }

    pub(super) fn reserve_start(
        &self,
        owner: Win16ComHostOwnerIdentity,
        operation: Win16ComHostOperationIdentity,
    ) -> Result<(), RuntimeError> {
        if owner != self.owner || !owner.is_valid() || !operation.is_valid() {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "COM start owner or operation identity is invalid",
            ));
        }
        if self.ingress_closed.get() {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "Win16 COM callback ingress is closed",
            ));
        }
        if operation.generation <= self.last_generation.get() {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 COM operation generation is stale or reused",
            ));
        }
        let active = self.active.borrow().len();
        let unsettled = self.unsettled.borrow().len();
        if active + unsettled >= MAX_UNSETTLED_OPERATIONS {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 COM operation/result capacity is full",
            ));
        }
        self.active.borrow_mut().push(operation);
        self.last_generation.set(operation.generation);
        Ok(())
    }

    pub(super) fn cancel_unaccepted(&self, operation: Win16ComHostOperationIdentity) {
        remove_identity(&mut self.active.borrow_mut(), operation);
    }

    pub(super) fn complete_start(
        &self,
        operation: Win16ComHostOperationIdentity,
        result: Result<Win16ComHostStep, RuntimeError>,
    ) {
        let step = match result {
            Ok(step) => step,
            Err(error) => Win16ComHostStep::OperationFailed {
                operation,
                failures: Vec::new(),
                result: None,
                execution_failure: Some(runtime::Win16ComHostExecutionFailure {
                    kind: error.kind(),
                    context: error.to_string(),
                }),
            },
        };
        remove_identity(&mut self.active.borrow_mut(), operation);
        self.unsettled.borrow_mut().push(operation);
        let mut terminals = self
            .terminals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Capacity was reserved before accepting this operation, and active +
        // unsettled is bounded. Retain the exact result even if no poller runs.
        terminals.push_back((operation, step));
    }

    pub(super) fn acknowledge(
        &self,
        owner: Win16ComHostOwnerIdentity,
        operation: Win16ComHostOperationIdentity,
    ) -> Result<(), RuntimeError> {
        if owner != self.owner || !operation.is_valid() {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "COM terminal acknowledgement names another owner",
            ));
        }
        let mut unsettled = self.unsettled.borrow_mut();
        let Some(index) = unsettled.iter().position(|item| *item == operation) else {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "COM operation has no unacknowledged terminal result",
            ));
        };
        let mut terminals = self
            .terminals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(terminal_index) = terminals.iter().position(|item| item.0 == operation) else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "COM terminal journal lost its exact result",
            ));
        };
        terminals.remove(terminal_index);
        unsettled.remove(index);
        Ok(())
    }

    pub(super) fn close_callback_ingress(&self, context: &'static str) -> Result<(), RuntimeError> {
        self.ingress_closed.set(true);
        self.owner_sealed.store(true, Ordering::Release);
        self.callbacks.seal_and_cancel_pending(context)
    }

    pub(super) fn native_stacks_quiet(&self) -> bool {
        self.active.borrow().is_empty() && self.callbacks.native_stacks_quiet()
    }

    pub(super) fn is_quiescent(&self) -> bool {
        self.native_stacks_quiet() && self.unsettled.borrow().is_empty()
    }

    pub(super) fn active_count(&self) -> usize {
        self.active.borrow().len()
    }

    pub(super) fn unsettled_count(&self) -> usize {
        self.unsettled.borrow().len()
    }

    pub(super) fn shutdown(
        &self,
        owner: Win16ComHostOwnerIdentity,
        operation: Win16ComHostShutdownOperation,
    ) -> Result<Win16ComHostShutdownStep, RuntimeError> {
        if owner != self.owner || !owner.is_valid() {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "COM owner shutdown names another owner incarnation",
            ));
        }
        if let Some(receipt) = self.shutdown_receipt.get() {
            return Ok(Win16ComHostShutdownStep::Retired(receipt));
        }
        match operation {
            Win16ComHostShutdownOperation::Seal => {
                // Permanently stop begin/com_owner admission before publishing
                // cancellation replies to callbacks nested in a native call.
                self.ingress_closed.set(true);
                self.owner_sealed.store(true, Ordering::Release);
                self.callbacks
                    .seal_and_cancel_pending("Win16 COM owner was sealed for process teardown")?;
                Ok(Win16ComHostShutdownStep::Sealed { owner })
            }
            Win16ComHostShutdownOperation::Poll => {
                if !self.ingress_closed.get() || !self.owner_sealed.load(Ordering::Acquire) {
                    return Err(RuntimeError::new(
                        Kind::InvalidInput,
                        "COM owner Poll requires an earlier exact Seal",
                    ));
                }
                if !self.native_stacks_quiet()
                    || !self.unsettled.borrow().is_empty()
                    || !self.callbacks.sealed_receipts_polled()
                    || self.callbacks.has_pending_failures()
                {
                    return Ok(Win16ComHostShutdownStep::Pending { owner });
                }
                self.shutdown_native_objects()?;
                if !self.native_stacks_quiet() || self.callbacks.has_pending_failures() {
                    return Ok(Win16ComHostShutdownStep::Pending { owner });
                }
                let receipt = Win16ComHostShutdownReceipt {
                    owner,
                    callback_ingress_closed: true,
                    native_objects_shutdown: true,
                };
                self.shutdown_receipt.set(Some(receipt));
                Ok(Win16ComHostShutdownStep::Retired(receipt))
            }
        }
    }

    fn shutdown_native_objects(&self) -> Result<(), RuntimeError> {
        if self.native_objects_shutdown.get() {
            return Ok(());
        }
        self.objects.shutdown().map_err(|error| {
            com_runtime_error("release sealed COM-owner objects and media", error)
        })?;
        self.apartment_refs.release_guest_refs();
        self.native_objects_shutdown.set(true);
        Ok(())
    }

    pub(super) fn shutdown_resources(&self) -> Result<(), RuntimeError> {
        if !self.is_quiescent() {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "COM operations or terminal results remain owned by the USER STA",
            ));
        }
        self.close_callback_ingress("Win16 USER STA is shutting down")?;
        self.shutdown_native_objects()?;
        if self.apartment_lease.replace(false) {
            (crate::windows::win32_safe::ole_uninitialize());
        }
        Ok(())
    }
}

impl Win16ComWorkerClient {
    pub(super) fn poll_callback(
        &self,
        owner: Win16ComHostOwnerIdentity,
    ) -> Result<Option<Win16ComHostStep>, RuntimeError> {
        if owner != self.owner {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "COM callback poll names another owner",
            ));
        }
        let ingress = self.ingress.lock().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "COM callback ingress lock was poisoned",
            )
        })?;
        let step = executor::next_callback(&ingress)?;
        if step
            .as_ref()
            .is_some_and(|step| step_owner(step) != Some(owner))
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "COM callback ingress returned a different owner generation",
            ));
        }
        Ok(step)
    }

    pub(super) fn continue_callback(
        &self,
        owner: Win16ComHostOwnerIdentity,
        continuation: Win16ComHostContinue,
    ) -> Result<Win16ComHostStep, RuntimeError> {
        if owner != self.owner
            || continuation
                .resume
                .as_ref()
                .is_some_and(|resume| resume.owner != owner)
        {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "COM callback continuation names another owner",
            ));
        }
        // Transport only: this call runs on the runtime thread, publishes the
        // exact typed outcome, wakes the USER STA and waits for callback receipt.
        executor::continue_operation(&self.callbacks, continuation)
    }

    pub(super) fn poll_terminal(
        &self,
        owner: Win16ComHostOwnerIdentity,
        operation: Win16ComHostOperationIdentity,
    ) -> Result<Option<Win16ComHostStep>, RuntimeError> {
        if owner != self.owner || !operation.is_valid() {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "COM terminal poll names another owner or operation",
            ));
        }
        let terminals = self.terminals.lock().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "COM terminal journal lock was poisoned",
            )
        })?;
        Ok(terminals
            .iter()
            .find(|item| item.0 == operation)
            .map(|item| item.1.clone()))
    }
}

pub(super) fn run_start(
    state: &Rc<RefCell<WorkerState>>,
    owner: Win16ComHostOwnerIdentity,
    start: PreparedWin16ComStart,
    accepted: mpsc::Sender<Result<(), RuntimeError>>,
) {
    let com = { Rc::clone(&state.borrow().com) };
    let operation = start.operation;
    if let Err(error) = com.reserve_start(owner, operation) {
        let _ = accepted.send(Err(error));
        return;
    }
    if accepted.send(Ok(())).is_err() {
        com.cancel_unaccepted(operation);
        return;
    }

    let waiter_state = Rc::clone(state);
    let waiter: Rc<dyn Fn() -> Result<(), RuntimeError>> =
        Rc::new(move || wait_for_callback_reply(&waiter_state));
    let result =
        super::super::super::win16_com_callback_proxy::callback_waiter::with_sta_callback_waiter(
            waiter,
            || {
                let objects = Rc::clone(&com.objects);
                let callbacks = com.callbacks.clone();
                let apartment = &com.apartment_refs;
                let resolve_state = Rc::clone(state);
                executor::start_prepared(&objects, &callbacks, apartment, start, |window| {
                    super::super::win16_window_identity::resolve_user_window(&resolve_state, window)
                })
            },
        );
    com.complete_start(operation, result);
}

pub(super) fn wait_for_callback_reply(
    state: &Rc<RefCell<WorkerState>>,
) -> Result<(), RuntimeError> {
    // Return to CallbackEndpoint after at most one unit of pump work. It
    // immediately retries that exact frame's reply_rx before another native
    // message or worker command can consume time.
    if pump_non_guest_native_message(state)? {
        return Ok(());
    }
    let (wake, receiver) = {
        let borrowed = state.borrow();
        (
            Arc::clone(&borrowed.wake_event),
            Arc::clone(&borrowed.commands),
        )
    };
    let handles = [wake.as_raw_handle() as HANDLE];
    let result =
        // SAFETY: `MsgWaitForMultipleObjectsEx` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        unsafe { MsgWaitForMultipleObjectsEx(1, handles.as_ptr(), INFINITE, QS_ALLINPUT, 0) };
    if result == WAIT_OBJECT_0 {
        let command = receiver
            .lock()
            .map_err(|_| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "USER worker command receiver was poisoned during COM callback wait",
                )
            })?
            .try_recv();
        match command {
            Ok(command) => {
                super::process_command(state, command);
                // The event is auto-reset. Re-signal after the bounded command
                // slice so already queued commands are not lost to coalesced
                // SetEvent calls while the callback proxy checks its reply.
                (crate::windows::win32_safe::set_event(wake.as_raw_handle() as _));
                return Ok(());
            }
            Err(TryRecvError::Empty) => return Ok(()),
            Err(TryRecvError::Disconnected) => {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    "USER worker command channel closed during COM callback",
                ));
            }
        }
    }
    if result == WAIT_OBJECT_0 + 1 {
        // One native window message is dispatched at most per callback slice.
        // The exact callback reply is checked before the next pump pass.
        let _ = pump_non_guest_native_message(state)?;
        return Ok(());
    }
    let detail = if result == WAIT_FAILED {
        format!(
            "nested Win16 USER STA wait failed with Windows error {}",
            (crate::windows::win32_safe::last_error())
        )
    } else {
        format!("nested Win16 USER STA wait returned unexpected status {result}")
    };
    Err(RuntimeError::new(Kind::HostFailure, detail))
}

fn pump_non_guest_native_message(state: &Rc<RefCell<WorkerState>>) -> Result<bool, RuntimeError> {
    // PM_REMOVE is bounded to one read per callback slice. Reserve a FIFO slot
    // first; the complete MSG can then be handed to the regular USER consumer
    // without dropping guest, thread, or WM_QUIT messages removed here.
    let reservation = super::super::win16_deferred_native_messages::reserve_slot(state)?;
    let mut native = MSG::default();
    // SAFETY: PeekMessageW writes into a caller-owned MSG that outlives the call.
    if unsafe { PeekMessageW(&mut native, std::ptr::null_mut(), 0, 0, PM_REMOVE) } == 0 {
        drop(reservation);
        return Ok(false);
    }
    let guest_window = if native.hwnd.is_null() {
        None
    } else {
        guest_window_token_for_native(state, native.hwnd as usize)?
    };
    // Guest-posted messages keep their private notification marker even when
    // their message number is WM_DROPFILES. Only native drops own an HDROP.
    if super::super::win16_guest_notifications::is_carrier_message(
        native.hwnd,
        native.message,
        native.wParam,
        native.lParam,
    ) {
        reservation.defer(native, guest_window)?;
        return Ok(true);
    }
    if native.message == WM_DROPFILES {
        let Some(window) = guest_window else {
            let rejection =
                super::super::win16_message_loop::reject_removed_native_drop(state, &native);
            return match rejection {
                Err(error) => Err(error),
                Ok(()) => Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "nested WM_DROPFILES has no exact live Win16 window cookie",
                )),
            };
        };
        super::super::win16_message_loop::retain_deferred_native_drop(state, &native, window)?;
        reservation.defer(native, Some(window))?;
        return Ok(true);
    }
    if native.hwnd.is_null() {
        reservation.defer(native, None)?;
        return Ok(true);
    }
    if let Some(window) = guest_window {
        // Shell owns any HDROP lease in its ledger. The FIFO stores only MSG
        // plus the exact window token and never clones the native owner.
        reservation.defer(native, Some(window))?;
        return Ok(true);
    }
    drop(reservation);
    // SAFETY: TranslateMessage reads a caller-owned MSG for this call only. DispatchMessageW reads a caller-owned MSG for this call only.
    unsafe {
        TranslateMessage(&native);
        DispatchMessageW(&native);
    }
    Ok(true)
}

fn guest_window_token_for_native(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: usize,
) -> Result<Option<runtime::Win16HostWindow>, RuntimeError> {
    let state = state.try_borrow().map_err(|_| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "classify a nested USER message without a conflicting worker-state borrow",
        )
    })?;
    let window = state
        .windows_by_native
        .get(&hwnd)
        .map(|identity| identity.window)
        .or_else(|| {
            state
                .dialog_routes_by_native
                .get(&hwnd)
                .map(|route| route.window)
        })
        .or_else(|| {
            state
                .dialog_children_by_native
                .values()
                .find_map(|children| children.get(&hwnd).copied())
        });
    Ok(window)
}

fn step_owner(step: &Win16ComHostStep) -> Option<Win16ComHostOwnerIdentity> {
    match step {
        Win16ComHostStep::Callback(callback) => Some(callback.owner),
        Win16ComHostStep::CallbackFrameComplete { owner, .. }
        | Win16ComHostStep::CallbackFailed { owner, .. } => Some(*owner),
        Win16ComHostStep::Running(_)
        | Win16ComHostStep::Complete(_)
        | Win16ComHostStep::OperationFailed { .. } => None,
    }
}

fn allocate_owner() -> Option<Win16ComHostOwnerIdentity> {
    let id = allocate_id()?;
    let generation = allocate_id()?;
    Some(Win16ComHostOwnerIdentity { id, generation })
}

fn allocate_id() -> Option<u64> {
    NEXT_COM_IDENTITY
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1).filter(|next| *next != 0)
        })
        .ok()
}

fn remove_identity(
    values: &mut Vec<Win16ComHostOperationIdentity>,
    identity: Win16ComHostOperationIdentity,
) {
    if let Some(index) = values.iter().position(|item| *item == identity) {
        values.remove(index);
    }
}

fn com_runtime_error(context: &'static str, error: NativeComError) -> RuntimeError {
    RuntimeError::with_source(Kind::HostFailure, context, error)
}
