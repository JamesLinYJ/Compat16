//! Exact per-operation routing for synchronous native DLGPROC callbacks.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostQueuedMessage,
    Win16MessageParam, Win16MessageSource, Win16ScalarMessage,
};
use windows_sys::Win32::Foundation::{HWND, LPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetParent, IsWindow, MSG, WM_CHANGECBCHAIN, WM_COMMAND, WM_INITDIALOG,
    WM_NCACTIVATE,
};

use super::super::win16_window_worker::{self as worker, DialogRoute, WorkerState};

pub(super) fn dialog_route(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    message: u32,
    l_param: LPARAM,
) -> Result<Option<DialogRoute>, RuntimeError> {
    let native = hwnd as usize;
    if message != WM_INITDIALOG {
        let route = state.borrow().dialog_routes_by_native.get(&native).copied();
        let Some(route) = route else { return Ok(None); };
        if super::super::win16_window_identity::resolve(state, route.window) == Some(hwnd) {
            return Ok(Some(route));
        }
        // HWND bits can be recycled. A stale route may retire only the
        // token-to-HWND generation it originally installed.
        worker::remove_window_maps(state, route.window, hwnd);
        return Ok(None);
    }

    let cookie = l_param as usize;
    let active_operation = state.borrow().active_operations.last()
        .map(|operation| operation.id);
    let pending = state.borrow().pending_dialog_routes.iter().rev()
        .find(|route| route.cookie == cookie
            && active_operation == Some(route.operation))
        .map(|route| (
            route.operation,
            route.creation,
            route.cookie,
            route.init_parameter,
            route.root_token,
            route.menu,
            route.root.is_some(),
        ));
    let Some((operation, creation, cookie, init_parameter, root_token, menu, needs_custom_root)) = pending else {
        return Ok(None);
    };
    super::super::win16_dialog_icon_controls::before_init(state, operation, creation, hwnd)?;
    let instance = state.borrow().pending_dialog_routes.iter()
        .find(|pending| pending.operation == operation && pending.creation == creation)
        .map(|pending| pending.guest_instance).ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "dialog initialization lost its creation instance"))?;
    let existing_route = {
        state.borrow().dialog_routes_by_native.get(&native).copied()
    };
    if let Some(existing) = existing_route {
        if existing.operation == operation
            && existing.creation == creation
            && existing.cookie == cookie
            && existing.init_parameter == init_parameter
            && super::super::win16_window_identity::resolve(state, existing.window) == Some(hwnd)
        {
            super::super::win16_window_dialog_creation::attach_template_menu(state, existing, hwnd)?;
            super::super::win16_window_instances::capture_dialog(state, hwnd, instance)?;
            mark_init_published(state, operation, creation);
            return Ok(Some(existing));
        }
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "native dialog HWND is already bound to a different creation route"));
    }

    if needs_custom_root {
        // A custom dialog class must have acquired its exact WndProc identity
        // during WM_NCCREATE. DLGPROC cannot silently adopt an untracked HWND.
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "custom dialog root reached WM_INITDIALOG without its WndProc route"));
    }

    let route = DialogRoute {
        operation,
        creation,
        cookie,
        window: root_token,
        init_parameter,
        menu,
        class_init_in_progress: false,
        class_init_default_called: false,
    };
    let route_index = {
        let mut state = state.borrow_mut();
        let Some(index) = state.pending_dialog_routes.iter().position(|pending|
            pending.operation == operation && pending.creation == creation
                && pending.cookie == cookie
        ) else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "standard dialog lost its pending creation route during WM_INITDIALOG"));
        };
        if state.pending_dialog_routes[index].root_window.is_some_and(|root| root != native) {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "standard dialog creation route already adopted a different HWND"));
        }
        state.dialog_routes_by_native.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve a standard dialog DLGPROC route", error)
        })?;
        index
    };

    // A CBT-observed root is pinned once. Losing its cookie is not permission
    // to bind a new generation with the same HWND bits.
    let prebound = state.borrow().pending_dialog_routes[route_index].root_window.is_some();
    if prebound && (super::super::win16_window_identity::resolve(state, root_token) != Some(hwnd)
        || state.borrow().windows_by_native.get(&native)
            .is_none_or(|identity| identity.window != root_token
                || identity.creation != Some(creation)))
    {
        return Err(RuntimeError::new(Kind::HostFailure,
            "prebound standard dialog root lost its exact creation identity"));
    }
    super::super::win16_window_identity::bind_dialog_root(
        state, root_token, hwnd, None, Some(creation),
    )?;
    {
        let mut borrowed = state.borrow_mut();
        if borrowed.windows_by_native.get(&native)
            .is_none_or(|identity| identity.window != root_token)
            || borrowed.pending_dialog_routes.get(route_index).is_none_or(|pending|
                pending.operation != operation || pending.creation != creation
                    || pending.cookie != cookie)
        {
            drop(borrowed);
            worker::remove_window_maps(state, root_token, hwnd);
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "native dialog HWND token changed during route installation"));
        }
        borrowed.pending_dialog_routes[route_index].root_window = Some(native);
        borrowed.dialog_routes_by_native.insert(native, route);
    }
    super::super::win16_window_identity::associate_dialog_child(state, hwnd);
    super::super::win16_window_instances::capture_dialog(state, hwnd, instance)?;
    if let Err(error) = super::super::win16_window_dialog_creation::attach_template_menu(
        state, route, hwnd,
    ) {
        // SetMenu may already have installed this HMENU when DrawMenuBar fails,
        // and its compensating SetMenu can also fail. Keep the exact HWND token,
        // dialog route, and pending owner until shared teardown confirms detach
        // or DestroyWindow; losing the map here could make cleanup destroy an
        // HMENU that is still attached to this live HWND.
        return Err(error);
    }
    mark_init_published(state, operation, creation);
    Ok(Some(route))
}

fn mark_init_published(state: &Rc<RefCell<WorkerState>>, operation: u64, creation: runtime::Win16CreationId) {
    if let Some(pending) = state.borrow_mut().pending_dialog_routes.iter_mut()
        .find(|pending| pending.operation == operation && pending.creation == creation)
    {
        pending.init_published = true;
    }
}

pub(super) fn class_init_is_active(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    route: DialogRoute,
) -> bool {
    state.borrow().dialog_routes_by_native.get(&(hwnd as usize))
        .is_some_and(|current| same_route(*current, route)
            && current.class_init_in_progress)
}

pub(super) fn class_init_default_called(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    route: DialogRoute,
) -> bool {
    state.borrow().dialog_routes_by_native.get(&(hwnd as usize))
        .is_some_and(|current| same_route(*current, route)
            && current.class_init_in_progress
            && current.class_init_default_called)
}

pub(super) fn mark_class_init_default_called(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    route: DialogRoute,
) {
    if let Some(current) = state.borrow_mut().dialog_routes_by_native
        .get_mut(&(hwnd as usize)).filter(|current| same_route(**current, route))
        && current.class_init_in_progress
    {
        current.class_init_default_called = true;
    }
}

pub(super) fn copy_native_queued_message(
    state: &Rc<RefCell<WorkerState>>,
    native: &MSG,
) -> Result<Option<Win16HostQueuedMessage>, RuntimeError> {
    if super::super::win16_guest_notifications::is_carrier_message(
        native.hwnd, native.message, native.wParam, native.lParam,
    ) {
        let notification = match super::super::win16_guest_notifications::lookup(state, native, false)? {
            super::super::win16_guest_notifications::CarrierLookup::Live(notification) => notification,
            super::super::win16_guest_notifications::CarrierLookup::Retired => return Ok(None),
            super::super::win16_guest_notifications::CarrierLookup::NotCarrier => return Ok(None),
        };
        let window = match notification.target {
            runtime::Win16GuestNotificationTarget::Window { window, .. } => Some(window),
            runtime::Win16GuestNotificationTarget::Task { .. } => None,
        };
        return Ok(Some(Win16HostQueuedMessage {
            source: runtime::Win16MessageSource::GuestNotification,
            window,
            message: notification.message,
            w_param: notification.w_param,
            l_param: runtime::Win16MessageParam::GuestNotification {
                provenance: runtime::Win16GuestNotificationProvenance {
                    target: notification.target, source: notification.source,
                },
                l_param: notification.l_param,
            },
            time: native.time,
            point: runtime::Win16HostPoint { x: native.pt.x, y: native.pt.y },
        }));
    }
    let Ok(message) = u16::try_from(native.message) else { return Ok(None); };
    let window = if native.hwnd.is_null() {
        None
    } else {
        Some(worker::token_for_native(state, native.hwnd)?)
    };
    let thread_input = native.hwnd.is_null()
        && runtime::Win16WindowInputMessage::accepts(message);
    // A copied MSG has no synchronous origin capability for native -1. Keep
    // the whole GETDLGCODE operation on its native default path instead of
    // publishing a lossy HWND16 value to the guest dialog procedure.
    if native.message == WM_NCACTIVATE && native.lParam == -1 && !native.hwnd.is_null() {
        return Ok(None);
    }
    let decoded_input = if thread_input { None } else if native.message == WM_NCACTIVATE {
        super::super::win16_window_input::decode_nonclient_activation(
            state, native.hwnd, native.wParam, native.lParam,
        )?
    } else {
        super::super::win16_window_input::decode_window_input(
        state,
        native.message,
        native.wParam,
        native.lParam,
        )?
    };
    let (w_param, l_param) = if thread_input {
        // A copied thread MSG retains guest bits just as queue retrieval does;
        // the lack of a target HWND does not turn WPARAM into a native handle.
        (native.wParam as u16, Win16MessageParam::GuestBits(native.lParam as u32))
    } else if let Some(input) = decoded_input {
        // The typed payload carries every HWND as an opaque identity token;
        // no truncated native HWND is duplicated in the scalar WORD field.
        (0, Win16MessageParam::WindowInput(input))
    } else {
        let l_param = if native.message == WM_COMMAND {
            let (control, control_parent) = if native.lParam == 0 {
                (None, None)
            } else {
                let native_control = native.lParam as HWND;
                if unsafe { IsWindow(native_control) } == 0 {
                    return Ok(None);
                } else {
                    let control = worker::token_for_native(state, native_control)?;
                    let native_parent = unsafe { GetParent(native_control) };
                    let control_parent = if native_parent.is_null() {
                        None
                    } else {
                        Some(worker::token_for_native(state, native_parent)?)
                    };
                    (Some(control), control_parent)
                }
            };
            Win16MessageParam::Command {
                control,
                notify: (native.wParam >> 16) as u16,
                control_parent,
            }
        } else if native.message == WM_CHANGECBCHAIN {
            let removed = if native.wParam == 0 {
                None
            } else {
                Some(worker::token_for_native(state, native.wParam as HWND)?)
            };
            let next = if native.lParam == 0 {
                None
            } else {
                Some(worker::token_for_native(state, native.lParam as HWND)?)
            };
            Win16MessageParam::ClipboardChainChange { removed, next }
        } else if Win16ScalarMessage::is_timer_message(message) {
            if native.lParam != 0 { return Ok(None); }
            Win16MessageParam::Scalar(native.lParam as u32)
        } else if Win16ScalarMessage::from_raw(message).is_some() {
            Win16MessageParam::Scalar(native.lParam as u32)
        } else if native.message >= 0x0400 {
            Win16MessageParam::GuestBits(native.lParam as u32)
        } else {
            return Ok(None);
        };
        let Some(w_param) = super::super::win16_character_messages::to_guest(
            state, native.message, native.wParam,
        ) else { return Ok(None); };
        (w_param, l_param)
    };
    Ok(Some(Win16HostQueuedMessage {
        source: Win16MessageSource::NativeQueue,
        window,
        message,
        w_param,
        l_param,
        time: native.time,
        point: runtime::Win16HostPoint { x: native.pt.x, y: native.pt.y },
    }))
}
fn same_route(left: DialogRoute, right: DialogRoute) -> bool {
    left.operation == right.operation
        && left.creation == right.creation
        && left.cookie == right.cookie
        && left.window == right.window
        && left.init_parameter == right.init_parameter
}
