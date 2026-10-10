//! Typed native forwarding for the Win32-backed USER window fields.
//!
//! Win16 window procedures, instance handles, and extra bytes are runtime
//! state. This module accepts only the scalar native fields and opaque parent
//! targets selected by the runtime; guest indexes and handle bits never reach
//! the Win32 APIs directly.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostWindow, Win16HostWindowLiveness,
    Win16HostWindowParentObservation, Win16WindowDataCall, Win16WindowDataField,
    Win16WindowDataResult, Win16WindowTarget,
};
use windows_sys::Win32::Foundation::{GetLastError, HWND, SetLastError};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GWL_EXSTYLE, GWL_STYLE, GWLP_HWNDPARENT, GWLP_ID, GetParent, GetWindowLongPtrW, SetParent,
    SetWindowLongPtrW, WS_CHILD,
};

use super::win16_window_identity as identity;
use super::win16_window_worker::{self as worker, WorkerState};

type SharedWorker = Rc<RefCell<WorkerState>>;

/// Observe only the child-parent edge of this exact native incarnation.
/// Unlike an ordinary USER scalar return, an unavailable observation is an
/// error, not proof that the window retired or has no child parent.
pub(super) fn query_parent(
    state: &SharedWorker,
    window: Win16HostWindow,
) -> Result<Win16HostWindowParentObservation, RuntimeError> {
    match identity::liveness(state, window)? {
        Win16HostWindowLiveness::Retired => Ok(Win16HostWindowParentObservation::Retired),
        Win16HostWindowLiveness::Live => {
            let native = identity::resolve_user_window(state, window).ok_or_else(|| {
                RuntimeError::new(Kind::HostFailure,
                    "resolve the exact live Win16 window before querying its child parent")
            })?;
            let child_parent = read_child_parent_token(state, native)?;
            Ok(Win16HostWindowParentObservation::Live { child_parent })
        }
    }
}

/// Execute one native-backed window-data operation on the HWND-owning thread.
///
/// This helper releases each state borrow before calling USER. Calls such as
/// SetParent may synchronously dispatch messages and reenter the worker's
/// callback path.
pub(super) fn execute(
    state: &SharedWorker,
    call: Win16WindowDataCall,
) -> Result<Win16WindowDataResult, RuntimeError> {
    use Win16WindowDataCall as Call;
    use Win16WindowDataResult as ResultValue;

    match call {
        Call::Get { window, field } => {
            let value = resolve_window(state, window).and_then(|native| read_scalar(native, field));
            Ok(ResultValue::Value(value))
        }
        Call::Set {
            window,
            field,
            value,
            mask,
        } => {
            let value = resolve_window(state, window)
                .and_then(|native| write_scalar(native, field, value, mask));
            Ok(ResultValue::Value(value))
        }
        Call::GetParent { window } => {
            let Some(native) = resolve_window(state, window) else {
                return Ok(ResultValue::Parent {
                    succeeded: false,
                    previous: None,
                    child_parent: None,
                });
            };
            let Some(previous) = read_parent(native) else {
                return Ok(ResultValue::Parent {
                    succeeded: false,
                    previous: None,
                    child_parent: None,
                });
            };
            let previous = token_for_native(state, previous)?;
            let child_parent = child_parent_token(state, window)?;
            Ok(ResultValue::Parent {
                succeeded: true,
                previous,
                child_parent,
            })
        }
        Call::SetParent { window, parent } => {
            let (Some(native), Some(new_parent)) =
                (resolve_window(state, window), resolve_window(state, parent))
            else {
                return Ok(ResultValue::Parent {
                    succeeded: false,
                    previous: None,
                    child_parent: None,
                });
            };
            // Capture the previous parent's token before SetParent can call
            // guest code. Its raw returned HWND may already name a different
            // incarnation when the synchronous native call returns.
            let previous_native = read_parent(native);
            let previous_token = match previous_native {
                Some(previous) => token_for_native(state, previous)?,
                None => None,
            };
            let Some(returned_previous) = set_parent(native, new_parent) else {
                return Ok(ResultValue::Parent {
                    succeeded: false,
                    previous: None,
                    child_parent: None,
                });
            };
            let previous = previous_token.filter(|token| {
                previous_native == Some(returned_previous)
                    && identity::resolve_user_window(state, *token) == Some(returned_previous)
            });
            // A retired previous parent has no safely reusable guest alias.
            // Project it to zero rather than adopt the post-callback raw HWND;
            // the native operation's real success remains authoritative.
            let child_parent = child_parent_token(state, window)?;
            Ok(ResultValue::Parent {
                succeeded: true,
                previous,
                child_parent,
            })
        }
    }
}

fn resolve_window(state: &SharedWorker, target: Win16WindowTarget) -> Option<HWND> {
    match target {
        Win16WindowTarget::Null => Some(std::ptr::null_mut()),
        Win16WindowTarget::Invalid => None,
        Win16WindowTarget::Mapped(token) => identity::resolve_user_window(state, token),
    }
}

fn read_scalar(native: HWND, field: Win16WindowDataField) -> Option<u32> {
    let index = field_index(field);
    // SAFETY: `native` is resolved on the USER worker and the index is one of
    // the fixed native scalar fields admitted by `Win16WindowDataField`.
    unsafe { SetLastError(0) };
    let value = unsafe { GetWindowLongPtrW(native, index) };
    let error = unsafe { GetLastError() };
    if value == 0 && error != 0 {
        None
    } else {
        // These fields are 32-bit USER values even when LONG_PTR is wider.
        Some(value as u32)
    }
}

fn write_scalar(native: HWND, field: Win16WindowDataField, value: u32, mask: u32) -> Option<u32> {
    if !matches!(mask, 0x0000_ffff | 0xffff_0000 | u32::MAX) {
        return None;
    }

    let index = field_index(field);
    let replacement = if mask == u32::MAX {
        value
    } else {
        let current = read_scalar(native, field)?;
        (current & !mask) | (value & mask)
    };

    // SAFETY: `native` is resolved on the USER worker; only a fixed scalar
    // field is selected. `replacement` contains the 32-bit field bits, not a
    // guest pointer or a Win16 handle.
    unsafe { SetLastError(0) };
    // On x86 windows-sys selects SetWindowLongW's i32 parameter; on 64-bit
    // hosts the same binding uses isize. Preserve the scalar's native bits.
    let previous = unsafe { SetWindowLongPtrW(native, index, replacement as _) };
    let error = unsafe { GetLastError() };
    if previous == 0 && error != 0 {
        None
    } else {
        Some(previous as u32)
    }
}

fn field_index(field: Win16WindowDataField) -> i32 {
    match field {
        Win16WindowDataField::Style => GWL_STYLE,
        Win16WindowDataField::ExStyle => GWL_EXSTYLE,
        Win16WindowDataField::ControlId => GWLP_ID,
    }
}

fn read_parent(native: HWND) -> Option<HWND> {
    // GWLP_HWNDPARENT follows the Win16 GWW_HWNDPARENT mapping and returns
    // either a child parent or a top-level owner. A zero value with no last
    // error is a successful window with no parent/owner.
    unsafe { SetLastError(0) };
    let parent = unsafe { GetWindowLongPtrW(native, GWLP_HWNDPARENT) };
    let error = unsafe { GetLastError() };
    if parent == 0 && error != 0 {
        None
    } else {
        Some(parent as HWND)
    }
}

fn child_parent_token(
    state: &SharedWorker,
    window: Win16WindowTarget,
) -> Result<Option<Win16HostWindow>, RuntimeError> {
    // SetParent may synchronously destroy and recycle the original child.
    // Validate its original token again before making any ancestry query.
    let Some(native) = resolve_window(state, window) else {
        return Ok(None);
    };
    read_child_parent_token(state, native)
}

fn read_child_parent_token(
    state: &SharedWorker,
    native: HWND,
) -> Result<Option<Win16HostWindow>, RuntimeError> {
    let style = read_scalar(native, Win16WindowDataField::Style).ok_or_else(|| {
        RuntimeError::new(Kind::HostFailure,
            "read the live native style for an exact Win16 child-parent observation")
    })?;
    if style & WS_CHILD == 0 {
        return Ok(None);
    }

    // GetParent is the native parent only for WS_CHILD windows. Keep an
    // observed desktop HWND as its real alias; never replace it with null or
    // use a top-level owner as a child-parent edge.
    unsafe { SetLastError(0) };
    let parent = unsafe { GetParent(native) };
    if parent.is_null() && unsafe { GetLastError() } != 0 {
        return Err(RuntimeError::new(Kind::HostFailure,
            "query the live native parent for an exact Win16 child-parent observation"));
    }
    token_for_native(state, parent)
}

fn set_parent(native: HWND, new_parent: HWND) -> Option<HWND> {
    // Windows distinguishes the parent of a WS_CHILD window from the owner
    // of a top-level window. The API choice is based on the current native
    // style; this operation deliberately does not alter WS_CHILD/WS_POPUP.
    let style = read_scalar(native, Win16WindowDataField::Style)?;
    if style & WS_CHILD != 0 {
        // SAFETY: both HWNDs were resolved on the USER worker. SetParent may
        // synchronously dispatch messages, and no RefCell borrow is held.
        unsafe { SetLastError(0) };
        let previous = unsafe { SetParent(native, new_parent) };
        let error = unsafe { GetLastError() };
        if previous.is_null() && error != 0 {
            None
        } else {
            Some(previous)
        }
    } else {
        // GWLP_HWNDPARENT sets the owner for top-level windows. Unlike
        // SetParent, this API's return is pointer-sized and zero can be a
        // successful previous value when the window had no owner.
        unsafe { SetLastError(0) };
        let previous = unsafe { SetWindowLongPtrW(native, GWLP_HWNDPARENT, new_parent as _) };
        let error = unsafe { GetLastError() };
        if previous == 0 && error != 0 {
            None
        } else {
            Some(previous as HWND)
        }
    }
}

fn token_for_native(
    state: &SharedWorker,
    native: HWND,
) -> Result<Option<Win16HostWindow>, RuntimeError> {
    if native.is_null() {
        return Ok(None);
    }
    worker::token_for_native(state, native).map(Some)
}

#[cfg(test)]
#[path = "win16_window_data_tests.rs"]
mod tests;
