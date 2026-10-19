//! Status-window creation and ownership on the native USER worker.

use std::cell::RefCell;
use std::ptr;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostCommonControlsResult as ResultValue,
    Win16HostWindow,
};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Controls::{CreateStatusWindowW, InitCommonControls};

use super::super::win16_window_worker::WorkerState;

pub(super) fn create_status_window(
    state: &Rc<RefCell<WorkerState>>,
    style: u32,
    text: &[u8],
    parent: Option<Win16HostWindow>,
    id: u16,
) -> Result<ResultValue, RuntimeError> {
    if text.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "status-control text contains an embedded terminator",
        ));
    }
    let text = state.borrow().text_codec.to_wide_z(text)?;
    let parent_hwnd = match parent {
        None => ptr::null_mut(),
        Some(token) => match super::super::win16_window_identity::resolve_user_window(state, token)
        {
            Some(hwnd) => hwnd,
            None => return Ok(created_window(None, None)),
        },
    };

    // SAFETY: This API has no pointer arguments and initializes the common-
    // control classes on the owning UI worker.
    unsafe { InitCommonControls() };
    // SAFETY: `text` is UTF-16 NUL terminated and the optional parent is either NULL
    // or a mapped USER window. No RefCell borrow is active across this call.
    let native =
        unsafe { CreateStatusWindowW(style as i32, text.as_ptr(), parent_hwnd, u32::from(id)) };
    let Some(window) = register_owned_window(state, native)? else {
        return Ok(created_window(None, None));
    };

    // Creation may synchronously run native callbacks which reparent the new
    // control. Revalidate its exact cookie, then report USER's current parent.
    if super::super::win16_window_identity::resolve(state, window) != Some(native) {
        cleanup_created_window(state, window, native).map_err(|error| {
            error.with_context("retire a status control whose HWND became stale")
        })?;
        return Ok(created_window(None, None));
    }
    // SAFETY: The status control still resolves to this exact live HWND on the
    // worker thread. GetParent returns a native identity that is adopted below.
    let actual_parent = crate::windows::win32_safe::get_parent(native);
    let parent = if actual_parent.is_null() {
        None
    } else {
        match super::super::win16_window_worker::token_for_native(state, actual_parent) {
            Ok(parent) => Some(parent),
            Err(error) => {
                return Err(preserve_error_after_cleanup(
                    state,
                    window,
                    native,
                    error,
                    "record the status control's current native parent",
                ));
            }
        }
    };
    Ok(created_window(Some(window), parent))
}

fn created_window(window: Option<Win16HostWindow>, parent: Option<Win16HostWindow>) -> ResultValue {
    ResultValue::CreatedWindow { window, parent }
}

pub(super) fn register_owned_window(
    state: &Rc<RefCell<WorkerState>>,
    window: HWND,
) -> Result<Option<Win16HostWindow>, RuntimeError> {
    if window.is_null() {
        return Ok(None);
    }
    let previous_identity = {
        state
            .borrow()
            .windows_by_native
            .get(&(window as usize))
            .copied()
    };
    // A synchronous parent callback may already have adopted this new
    // control through GetDlgItem. Reuse that exact live identity instead of
    // rejecting the normal reentrant creation path.
    let token = match super::super::win16_window_identity::adopt(state, window) {
        Ok(token) => token,
        Err(error) => {
            let cleanup = cleanup_after_adopt_failure(state, window, previous_identity);
            return Err(contextualize_cleanup(
                error,
                cleanup,
                "adopt the newly created COMMCTRL status-control identity",
            ));
        }
    };

    let promoted = {
        let mut state = state.borrow_mut();
        let native = window as usize;
        let has_cookie = state
            .window_identity_cookies
            .get(&token)
            .is_some_and(|binding| binding.hwnd == native && binding.value != 0);
        let exact_mapping = state.windows.get(&token).copied() == Some(window)
            && state
                .windows_by_native
                .get(&native)
                .is_some_and(|identity| identity.window == token);
        if has_cookie && exact_mapping {
            if let Some(identity) = state.windows_by_native.get_mut(&native) {
                identity.owned = true;
                true
            } else {
                false
            }
        } else {
            false
        }
    };
    if !promoted {
        let error = RuntimeError::new(
            Kind::HostFailure,
            "COMMCTRL status-control identity could not be promoted to owned",
        );
        let cleanup = cleanup_created_window(state, token, window);
        return Err(contextualize_cleanup(
            error,
            cleanup,
            "clean up the status control after identity promotion failed",
        ));
    }
    if super::super::win16_window_identity::resolve(state, token) != Some(window) {
        cleanup_created_window(state, token, window)
            .map_err(|error| error.with_context("retire the stale status-control identity"))?;
        return Ok(None);
    }
    Ok(Some(token))
}

pub(super) fn cleanup_created_window(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostWindow,
    window: HWND,
) -> Result<(), RuntimeError> {
    if super::super::win16_window_identity::resolve(state, token) == Some(window) {
        // SAFETY: The private cookie still proves this is the exact HWND
        // created and registered by this operation. The identity check and
        // native call are separate with no state borrow held across USER.
        if (crate::windows::win32_safe::destroy_window(window)) == 0
            && super::super::win16_window_identity::resolve(state, token) == Some(window)
        {
            // Keep the owned identity intact so the worker can retry cleanup.
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "DestroyWindow failed while the status-control identity remained live",
            ));
        }
    }
    retire_created_sidecar(state, token, window);
    Ok(())
}

fn cleanup_after_adopt_failure(
    state: &Rc<RefCell<WorkerState>>,
    window: HWND,
    previous_identity: Option<super::super::win16_window_worker::NativeWindowIdentity>,
) -> Result<(), RuntimeError> {
    let current_identity = {
        state
            .borrow()
            .windows_by_native
            .get(&(window as usize))
            .copied()
    };
    if let Some(identity) = current_identity {
        if super::super::win16_window_identity::resolve(state, identity.window) != Some(window) {
            retire_created_sidecar(state, identity.window, window);
        }
        // A current mapping is either a live identity that must be preserved,
        // or stale sidecar state already retired above. Never raw-delete it.
        return Ok(());
    }
    if let Some(identity) = previous_identity {
        // `adopt` may already have retired a cookie-mismatched old mapping.
        // Its former presence forbids deleting a possibly recycled HWND value.
        retire_created_sidecar(state, identity.window, window);
        return Ok(());
    }

    if super::super::win16_window_identity::belongs_to_worker(window) == Some(true) {
        // No token or prior native mapping exists, so this is still the
        // unregistered HWND returned by this synchronous CreateStatusWindowW.
        // This bridge has no safe native identity to retry with on failure.
        if (crate::windows::win32_safe::destroy_window(window)) == 0 {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "DestroyWindow failed for an unregistered COMMCTRL status control",
            ));
        }
    }
    Ok(())
}

fn retire_created_sidecar(state: &Rc<RefCell<WorkerState>>, token: Win16HostWindow, window: HWND) {
    let token_not_rebound = {
        let state = state.borrow();
        state
            .windows
            .get(&token)
            .is_none_or(|mapped| *mapped == window)
    };
    if token_not_rebound {
        super::super::win16_window_worker::remove_window_maps(state, token, window);
    } else {
        // The token now names another HWND. Retire only this exact old cookie.
        super::super::win16_window_identity::retire(state, token, window);
    }
}

fn preserve_error_after_cleanup(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostWindow,
    window: HWND,
    error: RuntimeError,
    context: &'static str,
) -> RuntimeError {
    let cleanup = cleanup_created_window(state, token, window);
    contextualize_cleanup(error, cleanup, context)
}

fn contextualize_cleanup(
    error: RuntimeError,
    cleanup: Result<(), RuntimeError>,
    context: &'static str,
) -> RuntimeError {
    match cleanup {
        Ok(()) => error.with_context(context),
        Err(cleanup_error) => error.with_context(format!(
            "{context}; control cleanup also failed: {cleanup_error}"
        )),
    }
}
