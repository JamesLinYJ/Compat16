//! Exact-origin validation for a suspended MakeDragList native LPARAM.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{Win16HostDragListNotification, Win16HostWindow};
use windows_sys::Win32::Foundation::{HWND, LPARAM, WPARAM};

use super::{NativeCallbackContext, WorkerState};

pub(super) fn native_context(
    state: &Rc<RefCell<WorkerState>>,
    parent: Win16HostWindow,
    parent_hwnd: HWND,
    operation: u64,
    message: u32,
    w_param: WPARAM,
    l_param: LPARAM,
    notification: &Win16HostDragListNotification,
) -> Option<NativeCallbackContext> {
    if l_param == 0 || message != u32::from(notification.message)
        || w_param as u16 != notification.control_id
    {
        return None;
    }
    let worker = state.try_borrow().ok()?;
    let active = worker.active_operations.last()?;
    let origin = worker.drag_list_origins.last()?;
    let sidecar = worker.drag_lists.iter().rev().find(|entry| {
        entry.list_box == notification.list_box
            && entry.guest_list_box == notification.guest_list_box
            && entry.hwnd == origin.hwnd
            && entry.parent == parent
            && u32::from(entry.message) == message
            && entry.installed
    })?;
    let parent_live = worker.windows.get(&parent) == Some(&parent_hwnd)
        && worker.windows_by_native.get(&(parent_hwnd as usize))
            .is_some_and(|identity| identity.window == parent);
    let child_live = worker.windows.get(&origin.list_box)
        .is_some_and(|hwnd| *hwnd as usize == origin.hwnd)
        && worker.windows_by_native.get(&origin.hwnd)
            .is_some_and(|identity| identity.window == origin.list_box);
    if active.id != operation || !active.allows_drag_list_origin()
        || origin.operation != operation || origin.parent != parent
        || origin.list_box != notification.list_box
        || origin.message != notification.message
        || origin.owner_thread != sidecar.owner_thread
        || unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() }
            != sidecar.owner_thread
        || !parent_live || !child_live
    {
        return None;
    }
    Some(NativeCallbackContext::DragList {
        operation,
        list_box: notification.list_box,
        native_list_hwnd: origin.hwnd,
        native_l_param: l_param,
    })
}
