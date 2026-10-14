//! Private-class WM_INITDIALOG delivery through the ordinary WndProc frame.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostMessage, Win16HostWindow};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::WM_INITDIALOG;

use super::super::win16_window_worker::{DialogRoute, NativeWindowIdentity, WorkerState};

pub(in crate::windows::win16_windows) struct DialogClassInitGuard {
    state: Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    route: DialogRoute,
}

pub(in crate::windows::win16_windows) fn begin_dialog_class_init(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    route: DialogRoute,
) -> Result<DialogClassInitGuard, RuntimeError> {
    let shared_state = Rc::clone(state);
    let mut state = state.borrow_mut();
    let Some(current) = state.dialog_routes_by_native.get_mut(&(hwnd as usize))
        .filter(|current| same_route(**current, route)) else {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "private dialog class lost its exact initialization route"));
    };
    if current.class_init_in_progress {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "private dialog class initialization was entered twice"));
    }
    current.class_init_in_progress = true;
    current.class_init_default_called = false;
    drop(state);
    Ok(DialogClassInitGuard { state: shared_state, hwnd, route })
}

impl Drop for DialogClassInitGuard {
    fn drop(&mut self) {
        if let Some(current) = self.state.borrow_mut().dialog_routes_by_native
            .get_mut(&(self.hwnd as usize)).filter(|current| same_route(**current, self.route))
        {
            current.class_init_in_progress = false;
            current.class_init_default_called = false;
        }
    }
}

fn same_route(left: DialogRoute, right: DialogRoute) -> bool {
    left.operation == right.operation
        && left.creation == right.creation
        && left.cookie == right.cookie
        && left.window == right.window
        && left.init_parameter == right.init_parameter
}

pub(in crate::windows::win16_windows) fn dispatch_dialog_class_init_callback(
    state: &Rc<RefCell<WorkerState>>,
    route: DialogRoute,
    identity: NativeWindowIdentity,
    hwnd: HWND,
    w_param: WPARAM,
    l_param: LPARAM,
    focus: Option<Win16HostWindow>,
    focus_ancestry: Vec<(Win16HostWindow, Win16HostWindow)>,
) -> LRESULT {
    let Some(class) = identity.class else { return 0; };
    let exact_route = {
        let state = state.borrow();
        state.dialog_routes_by_native.get(&(hwnd as usize)).is_some_and(|current| {
            current.operation == route.operation
                && current.creation == route.creation
                && current.cookie == route.cookie
                && current.window == route.window
                && current.class_init_in_progress
        }) && state.active_operations.last().is_some_and(|active|
            active.id == route.operation)
    };
    if identity.window != route.window
        || !exact_route
        || super::super::win16_window_identity::resolve(state, route.window) != Some(hwnd)
    {
        super::fail_worker(state, RuntimeError::new(Kind::InternalInvariant,
            "private dialog class initialization lost its exact HWND route"));
        return super::canceled_native_result(hwnd, WM_INITDIALOG, w_param, l_param);
    }
    let message = Win16HostMessage::InitDialog {
        focus,
        focus_ancestry,
        init_parameter: route.init_parameter,
    };
    super::dispatch_guest_callback(
        state,
        hwnd,
        identity,
        Some(class),
        WM_INITDIALOG,
        w_param,
        l_param,
        0,
        Some(route.creation),
        message,
        None,
        None,
    )
}
