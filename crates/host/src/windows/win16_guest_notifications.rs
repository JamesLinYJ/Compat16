//! Owned Win16 notification carriers for the native USER queue.
//!
//! The carrier uses a reserved 64-bit numeric tag plus a monotonic number;
//! neither native message parameter is a pointer or guest LPARAM. The sidecar
//! is local to the worker thread and retains the exact target/source receipt.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16GuestNotification,
    Win16GuestNotificationProvenance, Win16GuestNotificationSource,
    Win16GuestNotificationTarget, Win16HostQueuedMessage, Win16HostTaskQueue,
    Win16HostWindow, Win16MessageParam, Win16MessageSource, Win16HostPoint,
    Win16ScalarMessage,
};
use windows_sys::Win32::Foundation::{GetLastError, HWND};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MSG, PostMessageW, PostThreadMessageW, WM_NULL,
};

use super::win16_window_worker::WorkerState;

const CARRIER_TAG: usize = 0x5749_4e31_364e_4f54;
static NEXT_QUEUE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct TaskBinding {
    owner: guest_core::OwnerId,
    guest_htask: u16,
    selector_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetirementReason { TaskQueueRetired, TargetWindowRetired, ExactTargetChanged, DeferredOrderExhausted }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CarrierState { Queued, Deferred, Retired(RetirementReason) }

#[derive(Clone, Copy)]
struct Carrier {
    notification: Win16GuestNotification,
    hwnd: HWND,
    window_cookie: Option<usize>,
    queue: Win16HostTaskQueue,
    state: CarrierState,
    /// Ordinal of the exact PM_REMOVE that moved this carrier into a native
    /// modal loop's deferred list. Kept through retirement so stale deferred
    /// records can be purged without reviving their original HWND generation.
    deferred_order: Option<u64>,
}

#[derive(Default)]
struct QueueState {
    queue: Option<Win16HostTaskQueue>,
    active: bool,
    binding: Option<TaskBinding>,
    retired_binding: Option<(Win16HostTaskQueue, TaskBinding)>,
    carriers: HashMap<u64, Carrier>,
    source_to_carrier: HashMap<Win16GuestNotificationSource, u64>,
    next_carrier: u64,
    next_deferred_order: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GuestRetrievalIdentity {
    queue: Win16HostTaskQueue,
    operation: u64,
    flags: u32,
}

pub(super) struct GuestRetrievalGuard(GuestRetrievalIdentity);

impl Drop for GuestRetrievalGuard {
    fn drop(&mut self) {
        GUEST_RETRIEVAL.with(|slot| {
            if let Ok(mut stack) = slot.try_borrow_mut() {
                if stack.last() == Some(&self.0) {
                    stack.pop();
                } else if let Some(index) = stack.iter().rposition(|entry| *entry == self.0) {
                    stack.remove(index);
                }
            }
        });
    }
}

thread_local! {
    static QUEUE_STATE: RefCell<QueueState> = RefCell::new(QueueState::default());
    static GUEST_RETRIEVAL: RefCell<Vec<GuestRetrievalIdentity>> = const { RefCell::new(Vec::new()) };
}

pub(super) enum CarrierLookup {
    NotCarrier,
    Retired,
    Live(Win16GuestNotification),
}

pub(super) fn queued_message(
    notification: Win16GuestNotification,
    native: &MSG,
) -> Win16HostQueuedMessage {
    let provenance = Win16GuestNotificationProvenance {
        target: notification.target, source: notification.source,
    };
    let window = match notification.target {
        Win16GuestNotificationTarget::Window { window, .. } => Some(window),
        Win16GuestNotificationTarget::Task { .. } => None,
    };
    Win16HostQueuedMessage {
        source: Win16MessageSource::GuestNotification, window,
        message: notification.message, w_param: notification.w_param,
        l_param: Win16MessageParam::GuestNotification {
            provenance, l_param: notification.l_param,
        },
        time: native.time, point: Win16HostPoint { x: native.pt.x, y: native.pt.y },
    }
}

pub(super) fn initialize_queue() -> Result<Win16HostTaskQueue, RuntimeError> {
    let raw = NEXT_QUEUE_ID.try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
        next.checked_add(1)
    }).map_err(|_| RuntimeError::new(Kind::ResourceExhausted,
        "allocate a Win16 USER queue incarnation"))?;
    let queue = Win16HostTaskQueue(raw);
    QUEUE_STATE.with(|slot| {
        let mut state = slot.try_borrow_mut().map_err(|_| RuntimeError::new(
            Kind::InternalInvariant, "Win16 notification queue state is already borrowed"))?;
        if state.queue.is_some() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 USER thread initialized its queue incarnation twice"));
        }
        state.queue = Some(queue);
        state.active = true;
        state.next_carrier = 1;
        state.next_deferred_order = 1;
        Ok(queue)
    })
}

pub(super) fn bind_task_queue(
    owner: guest_core::OwnerId,
    guest_htask: u16,
    selector_generation: u64,
) -> Result<Option<Win16HostTaskQueue>, RuntimeError> {
    if guest_htask == 0 || selector_generation == 0 { return Ok(None); }
    QUEUE_STATE.with(|slot| {
        let mut state = slot.try_borrow_mut().map_err(|_| RuntimeError::new(
            Kind::InternalInvariant, "Win16 notification queue state is already borrowed"))?;
        let Some(queue) = state.queue.filter(|_| state.active) else { return Ok(None); };
        let binding = TaskBinding { owner, guest_htask, selector_generation };
        match state.binding {
            Some(existing) if existing == binding => Ok(Some(queue)),
            Some(_) => Ok(None),
            None => {
                state.binding = Some(binding);
                Ok(Some(queue))
            }
        }
    })
}

pub(super) fn retire_task_queue(
    owner: guest_core::OwnerId,
    guest_htask: u16,
    selector_generation: u64,
    queue: Win16HostTaskQueue,
) -> bool {
    let binding = TaskBinding { owner, guest_htask, selector_generation };
    QUEUE_STATE.with(|slot| {
        let Ok(mut state) = slot.try_borrow_mut() else { return false; };
        if state.retired_binding == Some((queue, binding)) { return true; }
        if state.queue != Some(queue) || !state.active || state.binding != Some(binding) {
            return false;
        }
        state.active = false;
        state.binding = None;
        state.retired_binding = Some((queue, binding));
        let QueueState { carriers, source_to_carrier, .. } = &mut *state;
        carriers.retain(|_, carrier| {
            if carrier.queue != queue { return true; }
            if carrier.deferred_order.is_some() {
                source_to_carrier.remove(&carrier.notification.source);
                return false;
            }
            if !matches!(carrier.state, CarrierState::Retired(_)) {
                carrier.state = CarrierState::Retired(RetirementReason::TaskQueueRetired);
            }
            true
        });
        true
    })
}

pub(super) fn guest_retrieval_scope(
    queue: Win16HostTaskQueue,
    flags: u32,
) -> Result<GuestRetrievalGuard, RuntimeError> {
    let operation = super::win16_window_worker::current_operation_id().ok_or_else(||
        RuntimeError::new(Kind::InternalInvariant,
            "Win16 USER queue read has no active host operation identity"))?;
    if current_queue() != Some(queue) || !is_bound_queue(queue) {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "Win16 USER queue read does not match the active task queue incarnation"));
    }
    let identity = GuestRetrievalIdentity { queue, operation, flags };
    GUEST_RETRIEVAL.with(|slot| {
        let mut stack = slot.try_borrow_mut().map_err(|_| RuntimeError::new(
            Kind::InternalInvariant, "Win16 USER retrieval scope is already borrowed"))?;
        stack.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve a Win16 USER retrieval scope", error))?;
        stack.push(identity);
        Ok(GuestRetrievalGuard(identity))
    })
}

pub(super) fn is_guest_remove_retrieval() -> bool {
    let (Some(queue), Some(operation)) = (
        current_queue(), super::win16_window_worker::current_operation_id(),
    ) else { return false; };
    GUEST_RETRIEVAL.with(|slot| slot.try_borrow().ok().is_some_and(|stack| {
        stack.last().is_some_and(|identity| identity.queue == queue
            && identity.operation == operation
            && identity.flags & windows_sys::Win32::UI::WindowsAndMessaging::PM_REMOVE != 0)
    }))
}

pub(super) fn current_queue() -> Option<Win16HostTaskQueue> {
    QUEUE_STATE.with(|slot| slot.try_borrow().ok()
        .and_then(|state| state.active.then_some(state.queue).flatten()))
}

pub(super) fn is_bound_queue(queue: Win16HostTaskQueue) -> bool {
    QUEUE_STATE.with(|slot| slot.try_borrow().ok().is_some_and(|state|
        state.active && state.queue == Some(queue) && state.binding.is_some()))
}

pub(super) fn require_bound_queue(
    queue: Option<Win16HostTaskQueue>,
) -> Option<Win16HostTaskQueue> {
    queue.filter(|queue| current_queue() == Some(*queue) && is_bound_queue(*queue))
}

pub(super) fn post(
    worker: &std::rc::Rc<std::cell::RefCell<WorkerState>>,
    notification: Win16GuestNotification,
) -> Result<bool, RuntimeError> {
    if notification.source.id == 0 || notification.source.generation == 0
        || notification.source.sequence == 0
    {
        return Ok(false);
    }
    let (hwnd, cookie) = match notification.target {
        Win16GuestNotificationTarget::Window { window, .. } => {
            let Some(hwnd) = super::win16_window_identity::resolve(worker, window) else {
                return Ok(false);
            };
            let Some(binding) = worker.borrow().window_identity_cookies.get(&window).copied()
                .filter(|binding| binding.hwnd == hwnd as usize)
            else { return Ok(false); };
            (hwnd, Some(binding.value))
        }
        Win16GuestNotificationTarget::Task { owner, guest_htask,
            task_selector_generation, queue } => {
            let exact = TaskBinding { owner, guest_htask,
                selector_generation: task_selector_generation };
            let matched = QUEUE_STATE.with(|slot| slot.try_borrow().ok().is_some_and(|state|
                state.active && state.queue == Some(queue) && state.binding == Some(exact)));
            if !matched { return Ok(false); }
            (std::ptr::null_mut(), None)
        }
    };
    let Some(queue) = current_queue().filter(|queue| is_bound_queue(*queue)) else {
        return Ok(false);
    };
    match notification.target {
        Win16GuestNotificationTarget::Window { .. } => {}
        Win16GuestNotificationTarget::Task { queue: target, .. } if target == queue => {}
        Win16GuestNotificationTarget::Task { .. } => return Ok(false),
    }
    reserve_and_post(notification, hwnd, cookie)
}

fn reserve_and_post(
    notification: Win16GuestNotification,
    hwnd: HWND,
    window_cookie: Option<usize>,
) -> Result<bool, RuntimeError> {
    let carrier_id = QUEUE_STATE.with(|slot| -> Result<Option<u64>, RuntimeError> {
        let mut state = slot.try_borrow_mut().map_err(|_| RuntimeError::new(
            Kind::InternalInvariant, "Win16 notification queue state is already borrowed"))?;
        if !state.active || state.queue.is_none()
            || state.source_to_carrier.contains_key(&notification.source)
        {
            return Ok(None);
        }
        state.carriers.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve Win16 notification carrier storage", error))?;
        state.source_to_carrier.try_reserve(1).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve Win16 notification source index", error))?;
        let id = state.next_carrier;
        let next = id.checked_add(1).filter(|next| *next <= isize::MAX as u64)
            .ok_or_else(|| RuntimeError::new(Kind::ResourceExhausted,
                "Win16 notification carrier identity space is exhausted"))?;
        let queue = state.queue.expect("checked above");
        state.next_carrier = next;
        state.carriers.insert(id, Carrier { notification, hwnd, window_cookie,
            queue, state: CarrierState::Queued, deferred_order: None });
        state.source_to_carrier.insert(notification.source, id);
        Ok(Some(id))
    })?;
    let Some(carrier_id) = carrier_id else { return Ok(false); };

    let native_l_param = isize::try_from(carrier_id).map_err(|_| RuntimeError::new(
        Kind::ResourceExhausted, "Win16 notification marker does not fit LPARAM"))?;
    let posted = if hwnd.is_null() {
        unsafe { PostThreadMessageW(GetCurrentThreadId(), u32::from(notification.message),
            CARRIER_TAG, native_l_param) }
    } else {
        unsafe { PostMessageW(hwnd, u32::from(notification.message), CARRIER_TAG,
            native_l_param) }
    };
    if posted != 0 { return Ok(true); }
    let error = unsafe { GetLastError() };
    rollback_exact(carrier_id, notification.source);
    Err(RuntimeError::with_source(Kind::HostFailure,
        "post an owned Win16 guest notification to the native USER queue",
        std::io::Error::from_raw_os_error(error as i32)))
}

fn rollback_exact(id: u64, source: Win16GuestNotificationSource) {
    QUEUE_STATE.with(|slot| {
        if let Ok(mut state) = slot.try_borrow_mut() {
            if state.carriers.get(&id).is_some_and(|carrier| carrier.notification.source == source) {
                state.carriers.remove(&id);
                state.source_to_carrier.remove(&source);
            }
        }
    });
}

pub(super) fn lookup(
    worker: &std::rc::Rc<std::cell::RefCell<WorkerState>>,
    message: &MSG,
    remove: bool,
) -> Result<CarrierLookup, RuntimeError> {
    let Some(id) = carrier_id(message) else { return Ok(CarrierLookup::NotCarrier); };
    QUEUE_STATE.with(|slot| {
        let mut state = slot.try_borrow_mut().map_err(|_| RuntimeError::new(
            Kind::InternalInvariant, "Win16 notification queue state is already borrowed"))?;
        let Some(carrier) = state.carriers.get(&id).copied() else {
            return Ok(CarrierLookup::NotCarrier);
        };
        if carrier.hwnd != message.hwnd || u32::from(carrier.notification.message) != message.message {
            return Ok(CarrierLookup::NotCarrier);
        }
        let queue_live = state.active && state.queue == Some(carrier.queue);
        let target_live = match carrier.notification.target {
            Win16GuestNotificationTarget::Task { owner, guest_htask,
                task_selector_generation, queue } => {
                state.binding == Some(TaskBinding { owner, guest_htask,
                    selector_generation: task_selector_generation })
                    && queue == carrier.queue && queue_live
            }
            Win16GuestNotificationTarget::Window { window, .. } => {
                let exact_cookie = worker.borrow().window_identity_cookies.get(&window).copied()
                    .is_some_and(|binding| binding.value == carrier.window_cookie.unwrap_or(0)
                        && binding.hwnd == message.hwnd as usize);
                exact_cookie && queue_live
                    && super::win16_window_identity::resolve(worker, window) == Some(message.hwnd)
            }
        };
        if matches!(carrier.state, CarrierState::Retired(_)) || !target_live {
            if !target_live && !matches!(carrier.state, CarrierState::Retired(_)) {
                if let Some(saved) = state.carriers.get_mut(&id) {
                    saved.state = CarrierState::Retired(RetirementReason::ExactTargetChanged);
                }
            }
            if remove { remove_exact(&mut state, id); }
            return Ok(CarrierLookup::Retired);
        }
        if remove {
            remove_exact(&mut state, id);
        }
        Ok(CarrierLookup::Live(carrier.notification))
    })
}

fn remove_exact(state: &mut QueueState, id: u64) {
    if let Some(carrier) = state.carriers.remove(&id) {
        if state.source_to_carrier.get(&carrier.notification.source) == Some(&id) {
            state.source_to_carrier.remove(&carrier.notification.source);
        }
    }
}

pub(super) fn defer_modal_message(message: &mut MSG) -> Result<bool, RuntimeError> {
    let Some(id) = carrier_id(message) else { return Ok(false); };
    let deferred = QUEUE_STATE.with(|slot| {
        let mut state = slot.try_borrow_mut().map_err(|_| RuntimeError::new(
            Kind::InternalInvariant, "Win16 notification queue state is already borrowed"))?;
        let matches = state.carriers.get(&id).is_some_and(|carrier|
            carrier.hwnd == message.hwnd
                && u32::from(carrier.notification.message) == message.message);
        if !matches { return Ok(false); }
        if state.carriers.get(&id).is_some_and(|carrier|
            matches!(carrier.state, CarrierState::Retired(_))) {
            // WH_GETMESSAGE has already removed this exact stale carrier from
            // the native queue. Consume its tombstone without reviving it.
            remove_exact(&mut state, id);
        } else if state.carriers.get(&id).is_some_and(|carrier|
            carrier.state == CarrierState::Queued) {
            let order = state.next_deferred_order;
            let Some(next) = order.checked_add(1) else {
                if let Some(carrier) = state.carriers.get_mut(&id) {
                    carrier.state = CarrierState::Retired(RetirementReason::DeferredOrderExhausted);
                }
                // This exact native marker has already been removed. Retire
                // its sidecar rather than losing it from native USER while
                // leaving a live-looking carrier behind.
                remove_exact(&mut state, id);
                return Err(RuntimeError::new(Kind::ResourceExhausted,
                    "Win16 deferred notification order is exhausted"));
            };
            state.next_deferred_order = next;
            if let Some(carrier) = state.carriers.get_mut(&id) {
                carrier.state = CarrierState::Deferred;
                carrier.deferred_order = Some(order);
            }
        }
        Ok(true)
    });
    let deferred = match deferred {
        Ok(deferred) => deferred,
        Err(error) => {
            suppress_native_message(message);
            return Err(error);
        }
    };
    if !deferred { return Ok(false); }
    suppress_native_message(message);
    Ok(true)
}

/// Route a native modal-pump removal according to its exact owned target.
/// Thread messages are swallowed by USER and stay deferred. Window carriers
/// with a guest callback route pass unchanged to that WndProc/DLGPROC; stock
/// windows receive only a sanitized scalar, or a safe zero-result no-op.
pub(super) fn handle_modal_message(
    worker: &std::rc::Rc<std::cell::RefCell<WorkerState>>,
    message: &mut MSG,
) -> Result<bool, RuntimeError> {
    let Some(id) = carrier_id(message) else { return Ok(false); };
    let carrier = QUEUE_STATE.with(|slot| slot.try_borrow().ok()
        .and_then(|state| state.carriers.get(&id).copied())
        .filter(|carrier| carrier.hwnd == message.hwnd
            && u32::from(carrier.notification.message) == message.message));
    let Some(carrier) = carrier else { return Ok(false); };
    if matches!(carrier.state, CarrierState::Retired(_)) {
        QUEUE_STATE.with(|slot| {
            if let Ok(mut state) = slot.try_borrow_mut() { remove_exact(&mut state, id); }
        });
        suppress_native_message(message);
        return Ok(true);
    }
    let Win16GuestNotificationTarget::Window { window, .. } = carrier.notification.target
    else { return defer_modal_message(message); };

    let (callbacks_enabled, guest_route) = {
        let state = worker.borrow();
        let callbacks_enabled = state.callbacks_enabled && !state.aborted;
        let native = message.hwnd as usize;
        let identity = state.windows_by_native.get(&native)
            .filter(|identity| identity.window == window);
        let wndproc = identity.and_then(|identity| identity.class)
            .and_then(|class| state.classes.get(&class))
            .is_some_and(|class| !class.system_class);
        let dlgproc = state.dialog_routes_by_native.get(&native)
            .is_some_and(|route| route.window == window);
        (callbacks_enabled, wndproc || dlgproc)
    };
    if !callbacks_enabled { return defer_modal_message(message); }
    if guest_route || super::win16_native_procedures::is_subclassed(worker, window) {
        return Ok(false);
    }

    // A stock/native window has no guest callback thunk to unwrap the marker.
    // Consume the exact sidecar here, then let USER see a defined scalar
    // numeric message. Header-bearing MMSYSTEM messages have the same zero
    // result as the stock default path, so they become WM_NULL instead.
    let notification = match lookup(worker, message, true)? {
        CarrierLookup::Live(notification) => notification,
        CarrierLookup::Retired => {
            suppress_native_message(message);
            return Ok(true);
        }
        CarrierLookup::NotCarrier => return Ok(false),
    };
    let scalar = Win16ScalarMessage::from_raw(notification.message).is_some()
        && (notification.message != Win16ScalarMessage::Timer as u16
            || notification.l_param == 0);
    let multimedia_scalar = runtime::is_multimedia_notification_message(notification.message)
        && !runtime::multimedia_notification_has_guest_far_lparam(notification.message);
    if scalar || multimedia_scalar {
        message.wParam = usize::from(notification.w_param);
        message.lParam = (notification.l_param as i32) as isize;
        return Ok(false);
    }
    suppress_native_message(message);
    if runtime::multimedia_notification_has_guest_far_lparam(notification.message) {
        return Ok(true);
    }
    Err(RuntimeError::new(Kind::CompatibilityGap,
        "native modal default route cannot safely consume this owned Win16 message family"))
}

fn suppress_native_message(message: &mut MSG) {
    message.hwnd = std::ptr::null_mut();
    message.message = WM_NULL;
    message.wParam = 0;
    message.lParam = 0;
}

pub(super) fn defer_callback_marker(
    hwnd: HWND,
    message: u32,
    w_param: usize,
    l_param: isize,
) {
    let native = MSG { hwnd, message, wParam: w_param, lParam: l_param,
        time: 0, pt: windows_sys::Win32::Foundation::POINT { x: 0, y: 0 } };
    let Some(id) = carrier_id(&native) else { return; };
    let result = QUEUE_STATE.with(|slot| {
        let mut state = slot.try_borrow_mut().map_err(|_| RuntimeError::new(
            Kind::InternalInvariant, "Win16 notification queue state is already borrowed"))?;
        let matches = state.carriers.get(&id).is_some_and(|carrier|
            carrier.hwnd == hwnd && u32::from(carrier.notification.message) == message);
        if !matches { return Ok(()); }
        if state.carriers.get(&id).is_some_and(|carrier|
            matches!(carrier.state, CarrierState::Retired(_)))
        {
            // This native dispatch consumed the last carrier reference.
            remove_exact(&mut state, id);
            return Ok(());
        }
        if !state.carriers.get(&id).is_some_and(|carrier|
            carrier.state == CarrierState::Queued)
        { return Ok(()); }
        let order = state.next_deferred_order;
        let Some(next) = order.checked_add(1) else {
            if let Some(carrier) = state.carriers.get_mut(&id) {
                carrier.state = CarrierState::Retired(RetirementReason::DeferredOrderExhausted);
            }
            remove_exact(&mut state, id);
            return Err(RuntimeError::new(Kind::ResourceExhausted,
                "Win16 deferred notification order is exhausted"));
        };
        state.next_deferred_order = next;
        if let Some(carrier) = state.carriers.get_mut(&id) {
            carrier.state = CarrierState::Deferred;
            carrier.deferred_order = Some(order);
        }
        Ok(())
    });
    if let Err(error) = result
        && let Some(worker) = super::win16_window_worker::worker_context()
    {
        super::win16_window_callbacks::fail_worker(&worker, error);
    }
}

pub(super) fn callback_notification(
    worker: &std::rc::Rc<std::cell::RefCell<WorkerState>>,
    hwnd: HWND,
    message: u32,
    w_param: usize,
    l_param: isize,
) -> Result<Option<Win16GuestNotification>, RuntimeError> {
    let native = MSG { hwnd, message, wParam: w_param, lParam: l_param,
        time: 0, pt: windows_sys::Win32::Foundation::POINT { x: 0, y: 0 } };
    match lookup(worker, &native, true)? {
        CarrierLookup::Live(notification) => Ok(Some(notification)),
        CarrierLookup::Retired => Ok(None),
        _ => Ok(None),
    }
}

pub(super) fn is_carrier_message(
    hwnd: HWND,
    message: u32,
    w_param: usize,
    l_param: isize,
) -> bool {
    let native = MSG { hwnd, message, wParam: w_param, lParam: l_param,
        time: 0, pt: windows_sys::Win32::Foundation::POINT { x: 0, y: 0 } };
    let Some(id) = carrier_id(&native) else { return false; };
    QUEUE_STATE.with(|slot| slot.try_borrow().ok().is_some_and(|state| {
        state.carriers.get(&id).is_some_and(|carrier|
            carrier.hwnd == hwnd
                && u32::from(carrier.notification.message) == message)
    }))
}

pub(super) fn mark_window_retired(window: Win16HostWindow) {
    QUEUE_STATE.with(|slot| {
        if let Ok(mut state) = slot.try_borrow_mut() {
            let QueueState { carriers, source_to_carrier, .. } = &mut *state;
            carriers.retain(|_, carrier| {
                if !matches!(carrier.notification.target,
                    Win16GuestNotificationTarget::Window { window: target, .. } if target == window)
                { return true; }
                if carrier.deferred_order.is_some() {
                    source_to_carrier.remove(&carrier.notification.source);
                    return false;
                }
                if !matches!(carrier.state, CarrierState::Retired(_)) {
                    carrier.state = CarrierState::Retired(RetirementReason::TargetWindowRetired);
                }
                true
            });
        }
    });
}

pub(super) fn requeue_deferred() -> Result<(), RuntimeError> {
    if !super::super::win16_modal::modal_stack_is_empty() { return Ok(()); }
    let worker = super::win16_window_worker::worker_context().ok_or_else(||
        RuntimeError::new(Kind::InternalInvariant,
            "Win16 deferred notification requeue has no USER worker state"))?;
    let deferred = QUEUE_STATE.with(|slot| -> Result<Vec<(u64, u64, Carrier)>, RuntimeError> {
        let state = slot.try_borrow().map_err(|_| RuntimeError::new(
            Kind::InternalInvariant, "Win16 notification queue state is already borrowed"))?;
        let mut items = Vec::new();
        items.try_reserve_exact(state.carriers.len()).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted, "reserve deferred Win16 notification requeue records", error))?;
        for (&id, carrier) in &state.carriers {
            if carrier.deferred_order.is_some() {
                items.push((carrier.deferred_order.unwrap_or(u64::MAX), id, *carrier));
            }
        }
        Ok(items)
    })?;
    let mut deferred = deferred;
    deferred.sort_unstable_by_key(|(order, _, _)| *order);
    for (order, id, carrier) in deferred {
        if matches!(carrier.state, CarrierState::Retired(_)) {
            QUEUE_STATE.with(|slot| {
                if let Ok(mut state) = slot.try_borrow_mut() { remove_exact(&mut state, id); }
            });
            continue;
        }
        if carrier.state != CarrierState::Deferred || carrier.deferred_order != Some(order) {
            continue;
        }
        let target_live = match carrier.notification.target {
            Win16GuestNotificationTarget::Task { owner, guest_htask,
                task_selector_generation, queue } => QUEUE_STATE.with(|slot| slot.try_borrow().ok()
                .is_some_and(|state| state.active && state.queue == Some(queue)
                    && state.binding == Some(TaskBinding { owner, guest_htask,
                        selector_generation: task_selector_generation }))),
            Win16GuestNotificationTarget::Window { window, .. } => {
                let exact_cookie = worker.borrow().window_identity_cookies.get(&window).copied()
                    .is_some_and(|binding| Some(binding.value) == carrier.window_cookie
                        && binding.hwnd == carrier.hwnd as usize);
                exact_cookie && super::win16_window_identity::resolve(&worker, window)
                    == Some(carrier.hwnd)
            }
        };
        if !target_live {
            QUEUE_STATE.with(|slot| {
                if let Ok(mut state) = slot.try_borrow_mut() {
                    if state.carriers.get(&id).is_some_and(|saved|
                        saved.state == CarrierState::Deferred
                            && saved.deferred_order == Some(order))
                    {
                        if let Some(saved) = state.carriers.get_mut(&id) {
                            saved.state = CarrierState::Retired(
                                RetirementReason::ExactTargetChanged,
                            );
                        }
                        // WH_GETMESSAGE already removed this carrier; target
                        // retirement cancels the accepted receipt without
                        // projecting it onto a later HWND/HTASK generation.
                        remove_exact(&mut state, id);
                    }
                }
            });
            continue;
        }
        let l_param = isize::try_from(id).map_err(|_| RuntimeError::new(
            Kind::ResourceExhausted, "deferred Win16 notification marker does not fit LPARAM"))?;
        let posted = if carrier.hwnd.is_null() {
            unsafe { PostThreadMessageW(GetCurrentThreadId(),
                u32::from(carrier.notification.message), CARRIER_TAG, l_param) }
        } else {
            unsafe { PostMessageW(carrier.hwnd, u32::from(carrier.notification.message),
                CARRIER_TAG, l_param) }
        };
        if posted == 0 {
            let error = unsafe { GetLastError() };
            return Err(RuntimeError::with_source(Kind::HostFailure,
                "requeue a deferred Win16 guest notification after a native modal loop",
                std::io::Error::from_raw_os_error(error as i32)));
        }
        QUEUE_STATE.with(|slot| {
            if let Ok(mut state) = slot.try_borrow_mut() {
                if let Some(saved) = state.carriers.get_mut(&id)
                    && saved.state == CarrierState::Deferred
                    && saved.deferred_order == Some(order)
                {
                    saved.state = CarrierState::Queued;
                    saved.deferred_order = None;
                }
            }
        });
    }
    Ok(())
}

fn carrier_id(message: &MSG) -> Option<u64> {
    if message.wParam != CARRIER_TAG || message.lParam <= 0 { return None; }
    Some(message.lParam as u64)
}
