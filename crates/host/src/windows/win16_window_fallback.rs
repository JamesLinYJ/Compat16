//! Native fallback for messages that have no checked Win16 representation.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::Win16WindowStep;
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DefDlgProcW, DefWindowProcW, WM_NCDESTROY,
};

use super::super::win16_window_worker::{self as worker_window, WorkerState};

pub(in crate::windows::win16_windows) fn untranslated(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    message: u32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    // SAFETY: USER supplied these native message arguments. Unsupported
    // pointer-bearing messages are consumed here and never sent to the guest.
    let is_dialog = state.borrow().dialog_routes_by_native.contains_key(&(hwnd as usize));
    let base_result = super::super::win16_native_procedures::base_fallback(
        state, hwnd, message, w_param, l_param,
    );
    let result = base_result.unwrap_or_else(|| unsafe {
        if is_dialog {
            DefDlgProcW(hwnd, message, w_param, l_param)
        } else {
            DefWindowProcW(hwnd, message, w_param, l_param)
        }
    });
    let active = {
        let state = state.borrow();
        if state.callbacks_enabled && !state.aborted {
            state.active_operations.last().cloned()
        } else { None }
    };
    if let Some(active) = active {
        let _ = active.response.send(Ok(Win16WindowStep::Untranslated { message }));
    }
    if message == WM_NCDESTROY {
        if let Some((identity, _, _, _)) = worker_window::identify_window(state, hwnd) {
            worker_window::remove_window_maps(state, identity.window, hwnd);
        }
    }
    result
}
