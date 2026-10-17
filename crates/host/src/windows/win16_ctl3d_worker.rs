//! Dialog-frame style and iconic state for `Ctl3dDlgFramePaint`.
//!
//! The query runs on the USER worker and does not call the window procedure.
//! Guest addresses are not accepted here.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{Win16HostCtl3dFrameFacts, Win16HostWindow};
use windows_sys::Win32::UI::WindowsAndMessaging::{GetWindowLongW, GWL_STYLE, IsIconic};

use super::win16_window_identity::resolve_user_window;
use super::win16_window_worker::WorkerState;

pub(super) fn frame_facts(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
) -> Option<Win16HostCtl3dFrameFacts> {
    let hwnd = resolve_user_window(state, window)?;
    // SAFETY: `hwnd` is the worker's live window for this token. These two
    // queries read style and iconic state and do not call a window procedure
    // or retain a pointer.
    let (style, iconic) = unsafe {
        (
            GetWindowLongW(hwnd, GWL_STYLE) as u32,
            IsIconic(hwnd) != 0,
        )
    };
    Some(Win16HostCtl3dFrameFacts { style, iconic })
}
