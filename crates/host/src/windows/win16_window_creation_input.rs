//! Copy native creation strings and project a CREATESTRUCT into owned data.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{RuntimeError, Win16HostCreationData};
use windows_sys::Win32::UI::WindowsAndMessaging::{CREATESTRUCTW, WS_CHILD};

use super::super::win16_window_worker::WorkerState;
use windows_sys::Win32::Foundation::LPARAM;

pub(super) fn copy_native_wide(
    state: &Rc<RefCell<WorkerState>>,
    l_param: LPARAM,
) -> Result<Option<Vec<u8>>, RuntimeError> {
    // WM_SETTEXT's contract supplies a readable UTF-16 string for this WndProc.
    // The copied guest bytes, never this host pointer, reach runtime.
    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
    unsafe {
        super::super::win16_window_text_context::copy_native_wide_z(state, l_param as *const u16)
    }
}

pub(super) fn creation_from_native(
    state: &Rc<RefCell<WorkerState>>,
    class: runtime::Win16HostClass,
    native: &CREATESTRUCTW,
    mut data: Win16HostCreationData,
    copy_native_title: bool,
) -> Result<Win16HostCreationData, RuntimeError> {
    data.class = class;
    data.style = native.style as u32;
    data.ex_style = native.dwExStyle;
    data.x = native.x as i16;
    data.y = native.y as i16;
    data.width = native.cx as i16;
    data.height = native.cy as i16;
    if copy_native_title {
        let native_name = native.lpszName as usize;
        // Win32 dialog templates and atom classes may supply MAKEINTATOM
        // values in CREATESTRUCT rather than readable strings. Dialog-created
        // windows preserve the already-copied guest title instead of ever
        // treating that numeric value as a host C string.
        if native_name == 0 {
            data.title = None;
        } else if native_name > usize::from(u16::MAX) {
            // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
            data.title = unsafe {
                super::super::win16_window_text_context::copy_native_wide_z(state, native.lpszName)?
            };
            if data.title.is_none() {
                data.title = Some(Vec::new());
            }
        }
    }
    data.parent = if native.hwndParent.is_null() {
        None
    } else {
        state
            .borrow()
            .windows_by_native
            .get(&(native.hwndParent as usize))
            .map(|parent| parent.window)
            .or(data.parent)
    };
    data.child_id = if data.style & WS_CHILD != 0 {
        Some(native.hMenu as usize as u16)
    } else {
        None
    };
    Ok(data)
}
