//! Owner-thread MakeDragList subclass provenance and checked notification copies.

use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostCommonControlsResult, Win16HostDragListKind,
    Win16HostDragListNotification, Win16HostWindow,
};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::UI::Controls::{
    DL_BEGINDRAG, DL_CANCELDRAG, DL_DRAGGING, DL_DROPPED, DRAGLISTINFO, MakeDragList,
};
use windows_sys::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};
use windows_sys::Win32::UI::WindowsAndMessaging::{RegisterWindowMessageW, WM_NCDESTROY};

use super::win16_window_worker::{self, DragListOrigin, DragListSidecar, WorkerState};

const DRAG_LIST_MESSAGE: &[u16] = &[
    b'c' as u16,
    b'o' as u16,
    b'm' as u16,
    b'm' as u16,
    b'c' as u16,
    b't' as u16,
    b'r' as u16,
    b'l' as u16,
    b'_' as u16,
    b'D' as u16,
    b'r' as u16,
    b'a' as u16,
    b'g' as u16,
    b'L' as u16,
    b'i' as u16,
    b's' as u16,
    b't' as u16,
    b'M' as u16,
    b's' as u16,
    b'g' as u16,
    0,
];

#[derive(Clone)]
pub(super) enum DragListDispatch {
    NotDragList,
    SuppressUnprovenNativePointer,
    Guest(Win16HostDragListNotification),
}

pub(super) fn make_drag_list(
    state: &Rc<RefCell<WorkerState>>,
    list_box: Win16HostWindow,
    guest_list_box: u16,
) -> Result<Win16HostCommonControlsResult, RuntimeError> {
    let Some(hwnd) = super::win16_window_identity::resolve_user_window(state, list_box) else {
        return Ok(Win16HostCommonControlsResult::Bool(false));
    };
    let parent_hwnd = crate::windows::win32_safe::get_parent(hwnd);
    if parent_hwnd.is_null() {
        return Ok(Win16HostCommonControlsResult::Bool(false));
    }
    let parent = super::win16_window_worker::token_for_native(state, parent_hwnd)?;
    let owner_thread = crate::windows::win32_safe::current_thread_id();
    if owner_thread == 0 {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "GetCurrentThreadId returned zero for MakeDragList owner",
        ));
    }
    // SAFETY: `RegisterWindowMessageW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    let message = unsafe { RegisterWindowMessageW(DRAG_LIST_MESSAGE.as_ptr()) };
    if !(0xc000..=u32::from(u16::MAX)).contains(&message) {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "RegisterWindowMessageW failed for MakeDragList notifications",
        ));
    }
    let message = message as u16;
    {
        let mut worker = state.borrow_mut();
        if worker
            .drag_list_message
            .is_some_and(|previous| previous != message)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "registered MakeDragList message changed during worker lifetime",
            ));
        }
        worker.drag_list_message = Some(message);
    }
    let subclass_id = usize::try_from(list_box.0).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "encode MakeDragList subclass identity",
            error,
        )
    })?;
    if subclass_id == 0 {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "MakeDragList received a zero window identity token",
        ));
    }
    let existing = state
        .borrow()
        .drag_lists
        .iter()
        .any(|entry| entry.list_box == list_box && entry.hwnd == hwnd as usize);
    if !existing {
        let mut worker = state.borrow_mut();
        worker.drag_lists.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve MakeDragList sidecar",
                error,
            )
        })?;
        worker.drag_list_origins.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve MakeDragList callback provenance",
                error,
            )
        })?;
        worker.drag_lists.push(DragListSidecar {
            list_box,
            hwnd: hwnd as usize,
            parent,
            guest_list_box,
            message,
            subclass_id,
            owner_thread,
            installed: false,
        });
    }
    // Publish identity and reserve callback capacity before the native effect:
    // setup can synchronously notify, and a pointer-bearing LPARAM must never
    // fall through to the generic guest-message path.
    // SAFETY: `MakeDragList` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    if unsafe { MakeDragList(hwnd) } == 0 {
        if !existing {
            state.borrow_mut().drag_lists.retain(|entry| {
                !(entry.list_box == list_box
                    && entry.hwnd == hwnd as usize
                    && entry.subclass_id == subclass_id)
            });
        }
        return Ok(Win16HostCommonControlsResult::Bool(false));
    }
    if super::win16_window_identity::resolve(state, list_box) != Some(hwnd) {
        if !existing {
            state.borrow_mut().drag_lists.retain(|entry| {
                !(entry.list_box == list_box
                    && entry.hwnd == hwnd as usize
                    && entry.subclass_id == subclass_id)
            });
        }
        return Ok(Win16HostCommonControlsResult::Bool(false));
    }
    let current_parent = crate::windows::win32_safe::get_parent(hwnd);
    if current_parent.is_null() {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "MakeDragList succeeded but its listbox lost its parent",
        ));
    }
    let current_parent_token = super::win16_window_worker::token_for_native(state, current_parent)?;
    if let Some(record) = state.borrow_mut().drag_lists.iter_mut().rfind(|entry| {
        entry.list_box == list_box
            && entry.hwnd == hwnd as usize
            && entry.subclass_id == subclass_id
    }) {
        record.parent = current_parent_token;
    } else {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "MakeDragList setup identity disappeared after native success",
        ));
    }
    // Register after MakeDragList so this sidecar is outermost and its exact
    // DefSubclassProc scope contains the control's synchronous parent send.
    let installed =
        // SAFETY: `SetWindowSubclass`, `Some` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        unsafe { SetWindowSubclass(hwnd, Some(drag_list_subclass_proc), subclass_id, 0) } != 0;
    if !installed {
        // Keep the uninstrumented identity so a later native pointer-bearing
        // notification can be consumed without reading or exposing LPARAM.
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "SetWindowSubclass failed after native MakeDragList succeeded",
        ));
    }
    if let Some(record) = state
        .borrow_mut()
        .drag_lists
        .iter_mut()
        .rfind(|entry| entry.list_box == list_box && entry.hwnd == hwnd as usize)
    {
        record.installed = true;
    } else {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "MakeDragList sidecar disappeared after subclass installation",
        ));
    }
    Ok(Win16HostCommonControlsResult::Bool(true))
}

pub(super) fn classify(
    state: &Rc<RefCell<WorkerState>>,
    parent: Win16HostWindow,
    message: u32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> Result<DragListDispatch, RuntimeError> {
    let (sidecar, origin, active) = {
        let worker = state.borrow();
        let recognized = worker.drag_list_message == u16::try_from(message).ok()
            || worker
                .drag_lists
                .iter()
                .any(|entry| u32::from(entry.message) == message);
        let origin = worker.drag_list_origins.last().copied();
        let Some(origin) = origin else {
            return Ok(if recognized {
                DragListDispatch::SuppressUnprovenNativePointer
            } else {
                DragListDispatch::NotDragList
            });
        };
        let Some(sidecar) = worker.drag_lists.iter().rev().find(|entry| {
            entry.list_box == origin.list_box
                && entry.hwnd == origin.hwnd
                && entry.parent == parent
                && entry.parent == origin.parent
                && u32::from(entry.message) == message
                && entry.message == origin.message
                && entry.owner_thread == origin.owner_thread
        }) else {
            return Ok(if recognized {
                DragListDispatch::SuppressUnprovenNativePointer
            } else {
                DragListDispatch::NotDragList
            });
        };
        let active = worker.active_operations.last().cloned();
        (sidecar.clone(), Some(origin), active)
    };
    let Some(origin) = origin else {
        // A registered message without our live subclass proof may have a
        // guest LPARAM. Never interpret it as native DRAGLISTINFO.
        return Ok(DragListDispatch::SuppressUnprovenNativePointer);
    };
    let Some(parent_hwnd) = super::win16_window_identity::resolve_user_window(state, parent) else {
        return Ok(DragListDispatch::SuppressUnprovenNativePointer);
    };
    if origin.parent != parent
        || origin.message != sidecar.message
        || origin.list_box != sidecar.list_box
        || origin.hwnd != sidecar.hwnd
        || origin.owner_thread != sidecar.owner_thread
        || { crate::windows::win32_safe::current_thread_id() } != sidecar.owner_thread
        || !active
            .as_ref()
            .is_some_and(|active| active.id == origin.operation && active.allows_drag_list_origin())
        || !sidecar.installed
        || super::win16_window_identity::resolve(state, sidecar.list_box)
            .is_none_or(|hwnd| hwnd as usize != sidecar.hwnd)
        || super::win16_window_identity::resolve_user_window(state, sidecar.parent)
            .is_none_or(|expected| expected != parent_hwnd)
    {
        return Ok(DragListDispatch::SuppressUnprovenNativePointer);
    }
    let native_parent = crate::windows::win32_safe::get_parent(sidecar.hwnd as HWND);
    if native_parent != parent_hwnd || {
        crate::windows::win32_safe::get_dlg_ctrl_id(sidecar.hwnd as HWND) as u16
    } != w_param as u16
    {
        return Ok(DragListDispatch::SuppressUnprovenNativePointer);
    }
    if l_param == 0 {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "verified native MakeDragList message has a null DRAGLISTINFO",
        ));
    }
    // SAFETY: The exact owner-thread subclass call is currently inside
    // DefSubclassProc, its parent/child identity and operation still match,
    // and comctl32 supplied this synchronous pointer-bearing payload.
    let info = unsafe { *(l_param as *const DRAGLISTINFO) };
    if info.hWnd as usize != sidecar.hwnd {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "MakeDragList notification names a different native listbox",
        ));
    }
    let kind = match info.uNotification {
        DL_BEGINDRAG => Win16HostDragListKind::BeginDrag,
        DL_DRAGGING => Win16HostDragListKind::Dragging,
        DL_DROPPED => Win16HostDragListKind::Dropped,
        DL_CANCELDRAG => Win16HostDragListKind::CancelDrag,
        _ => return Ok(DragListDispatch::SuppressUnprovenNativePointer),
    };
    Ok(DragListDispatch::Guest(Win16HostDragListNotification {
        message: sidecar.message,
        control_id: w_param as u16,
        list_box: sidecar.list_box,
        guest_list_box: sidecar.guest_list_box,
        kind,
        cursor_x: info.ptCursor.x as i16,
        cursor_y: info.ptCursor.y as i16,
    }))
}

pub(super) fn retire_all(state: &Rc<RefCell<WorkerState>>) -> Result<(), RuntimeError> {
    let entries = {
        let worker = state.borrow();
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(worker.drag_lists.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "snapshot MakeDragList subclass cleanup",
                    error,
                )
            })?;
        entries.extend(worker.drag_lists.iter().cloned());
        entries
    };
    let mut first_error = None;
    for entry in entries.into_iter().rev() {
        if !entry.installed {
            remove_sidecar(state, &entry);
            continue;
        }
        let hwnd = entry.hwnd as HWND;
        if super::win16_window_identity::resolve(state, entry.list_box) != Some(hwnd) {
            remove_sidecar(state, &entry);
            continue;
        }
        // SAFETY: `RemoveWindowSubclass`, `Some` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        if unsafe { RemoveWindowSubclass(hwnd, Some(drag_list_subclass_proc), entry.subclass_id) }
            != 0
            || super::win16_window_identity::resolve(state, entry.list_box) != Some(hwnd)
        {
            remove_sidecar(state, &entry);
        } else {
            let cleanup = RuntimeError::new(
                Kind::HostFailure,
                "RemoveWindowSubclass failed while retiring MakeDragList",
            );
            first_error = Some(match first_error.take() {
                None => cleanup,
                Some(primary) => RuntimeError::with_source(
                    Kind::HostFailure,
                    "multiple MakeDragList subclasses failed to retire",
                    DragListCleanupFailure { primary, cleanup },
                ),
            });
        }
    }
    state.borrow_mut().drag_list_origins.clear();
    first_error.map_or(Ok(()), Err)
}

// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn drag_list_subclass_proc(
    hwnd: HWND,
    message: u32,
    w_param: WPARAM,
    l_param: LPARAM,
    subclass_id: usize,
    _reference_data: usize,
) -> LRESULT {
    let result = catch_unwind(AssertUnwindSafe(|| {
        dispatch_drag_list_subclass(hwnd, message, w_param, l_param, subclass_id)
    }));
    match result {
        Ok(value) => value,
        Err(_) => {
            if let Some(state) = win16_window_worker::worker_context() {
                super::win16_window_callbacks::fail_worker(
                    &state,
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "MakeDragList subclass panicked on the USER owner thread",
                    ),
                );
            }
            // SAFETY: DefSubclassProc forwards this subclass message. Pointer parameters stay live for the call.
            unsafe { DefSubclassProc(hwnd, message, w_param, l_param) }
        }
    }
}

fn dispatch_drag_list_subclass(
    hwnd: HWND,
    message: u32,
    w_param: WPARAM,
    l_param: LPARAM,
    subclass_id: usize,
) -> LRESULT {
    let Some(state) = win16_window_worker::worker_context() else {
        // SAFETY: DefSubclassProc forwards this subclass message. Pointer parameters stay live for the call.
        return unsafe { DefSubclassProc(hwnd, message, w_param, l_param) };
    };
    let frame = {
        let mut worker = state.borrow_mut();
        let Some(sidecar) = worker
            .drag_lists
            .iter()
            .rev()
            .find(|entry| {
                entry.hwnd == hwnd as usize && entry.subclass_id == subclass_id && entry.installed
            })
            .cloned()
        else {
            drop(worker);
            // SAFETY: DefSubclassProc forwards this subclass message. Pointer parameters stay live for the call.
            return unsafe { DefSubclassProc(hwnd, message, w_param, l_param) };
        };
        let active = worker.active_operations.last().cloned();
        let owner_thread = crate::windows::win32_safe::current_thread_id();
        if let Some(active) = active
            .filter(|frame| frame.allows_drag_list_origin() && sidecar.owner_thread == owner_thread)
        {
            if worker.drag_list_origins.try_reserve(1).is_err() {
                drop(worker);
                super::win16_window_callbacks::fail_worker(
                    &state,
                    RuntimeError::new(
                        Kind::ResourceExhausted,
                        "reserve MakeDragList callback origin",
                    ),
                );
                // SAFETY: DefSubclassProc forwards this subclass message. Pointer parameters stay live for the call.
                return unsafe { DefSubclassProc(hwnd, message, w_param, l_param) };
            }
            let origin = DragListOrigin {
                list_box: sidecar.list_box,
                hwnd: sidecar.hwnd,
                parent: sidecar.parent,
                operation: active.id,
                message: sidecar.message,
                owner_thread: sidecar.owner_thread,
            };
            worker.drag_list_origins.push(origin);
            Some(origin)
        } else {
            None
        }
    };
    // SAFETY: DefSubclassProc forwards this subclass message. Pointer parameters stay live for the call.
    let result = unsafe { DefSubclassProc(hwnd, message, w_param, l_param) };
    if let Some(frame) = frame {
        let popped = {
            let mut worker = state.borrow_mut();
            if worker.drag_list_origins.last() == Some(&frame) {
                worker.drag_list_origins.pop();
                true
            } else {
                false
            }
        };
        if !popped {
            super::win16_window_callbacks::fail_worker(
                &state,
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "MakeDragList subclass frame did not balance",
                ),
            );
        }
    }
    if message == WM_NCDESTROY {
        let retired =
            // SAFETY: `RemoveWindowSubclass`, `Some` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
            unsafe { RemoveWindowSubclass(hwnd, Some(drag_list_subclass_proc), subclass_id) };
        let is_live = (crate::windows::win32_safe::is_window(hwnd)) != 0;
        if retired != 0 || !is_live {
            state
                .borrow_mut()
                .drag_lists
                .retain(|entry| !(entry.hwnd == hwnd as usize && entry.subclass_id == subclass_id));
        } else {
            super::win16_window_callbacks::fail_worker(
                &state,
                RuntimeError::new(
                    Kind::HostFailure,
                    "RemoveWindowSubclass failed at MakeDragList WM_NCDESTROY",
                ),
            );
        }
    }
    result
}

fn remove_sidecar(state: &Rc<RefCell<WorkerState>>, removed: &DragListSidecar) {
    state.borrow_mut().drag_lists.retain(|entry| {
        !(entry.list_box == removed.list_box
            && entry.hwnd == removed.hwnd
            && entry.subclass_id == removed.subclass_id)
    });
}

#[derive(Debug)]
struct DragListCleanupFailure {
    primary: RuntimeError,
    cleanup: RuntimeError,
}

impl std::fmt::Display for DragListCleanupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}; cleanup also failed: {}", self.primary, self.cleanup)
    }
}

impl std::error::Error for DragListCleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
