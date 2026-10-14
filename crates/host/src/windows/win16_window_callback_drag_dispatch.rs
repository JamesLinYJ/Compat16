//! MakeDragList native dispatch kept separate from the common WndProc path.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{Win16HostClass, Win16HostMessage};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};

use super::{canceled_native_result, dispatch_guest_callback, fail_worker, untranslated,
    NativeWindowIdentity, WorkerState};

pub(super) fn dispatch(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    identity: NativeWindowIdentity,
    host_class: Option<Win16HostClass>,
    message: u32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> Option<LRESULT> {
    match super::super::win16_common_controls_drag_list::classify(
        state, identity.window, message, w_param, l_param,
    ) {
        Ok(super::super::win16_common_controls_drag_list::DragListDispatch::NotDragList) => None,
        Ok(super::super::win16_common_controls_drag_list::DragListDispatch::SuppressUnprovenNativePointer) => {
            Some(untranslated(state, hwnd, message, w_param, l_param))
        }
        Ok(super::super::win16_common_controls_drag_list::DragListDispatch::Guest(notification)) => {
            Some(dispatch_guest_callback(state, hwnd, identity, host_class,
                message, w_param, l_param, 0, None,
                Win16HostMessage::DragListNotification(notification), None, None))
        }
        Err(error) => {
            fail_worker(state, error);
            Some(canceled_native_result(hwnd, message, w_param, l_param))
        }
    }
}
