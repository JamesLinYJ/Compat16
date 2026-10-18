//! Retain an early property-bound alias when USER proves dialog ownership.

use super::{win16_window_identity as identity, win16_window_worker::WorkerState};
use runtime::{DiagnosticKind as Kind, RuntimeError, Win16CreationId, Win16HostWindow};
use std::cell::RefCell;
use std::rc::Rc;
use windows_sys::Win32::Foundation::HWND;

fn error(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::HostFailure, message)
}

/// Call only after the exact INIT cookie or an owned template-control payload
/// proves this standard root belongs to the pending creation. Parent notify
/// can expose it earlier. Keep that alias's token and cookie; never replace
/// its generation with the otherwise unused reservation.
pub(super) fn bind_standard_root(
    state: &Rc<RefCell<WorkerState>>,
    operation: u64,
    creation: Win16CreationId,
    hwnd: HWND,
) -> Result<Win16HostWindow, RuntimeError> {
    let (reserved, pinned) = {
        let borrowed = state.borrow();
        if borrowed.active_operations.last().map(|active| active.id) != Some(operation) {
            return Err(error(
                "standard dialog root proof is outside its active operation",
            ));
        }
        let pending = borrowed
            .pending_dialog_routes
            .iter()
            .find(|pending| pending.operation == operation && pending.creation == creation)
            .ok_or_else(|| error("standard dialog root proof lost its exact pending creation"))?;
        if pending.root.is_some() {
            return Err(error(
                "custom dialog root cannot use standard-root adoption",
            ));
        }
        (pending.root_token, pending.root_window)
    };
    if let Some(pinned) = pinned {
        if pinned != hwnd as usize
            || identity::resolve(state, reserved) != Some(hwnd)
            || state
                .borrow()
                .windows_by_native
                .get(&pinned)
                .is_none_or(|current| {
                    current.window != reserved || current.creation != Some(creation)
                })
        {
            return Err(error(
                "pinned standard dialog root lost its exact HWND generation",
            ));
        }
        identity::bind_dialog_root(state, reserved, hwnd, None, Some(creation))?;
        return Ok(reserved);
    }
    let existing = state
        .borrow()
        .windows_by_native
        .get(&(hwnd as usize))
        .copied();
    let token = match existing {
        Some(current) if current.window != reserved => {
            if current.owned
                || current.class.is_some()
                || current.creation.is_some()
                || identity::resolve(state, current.window) != Some(hwnd)
                || state.borrow().windows.contains_key(&reserved)
                || state
                    .borrow()
                    .window_identity_cookies
                    .contains_key(&reserved)
            {
                return Err(error(
                    "early dialog alias cannot replace an owned or stale generation",
                ));
            }
            current.window
        }
        _ => reserved,
    };
    identity::bind_dialog_root(state, token, hwnd, None, Some(creation))?;
    // No native callback or fallible allocation occurs between promotion and
    // recording the root for this creation's normal teardown.
    let mut borrowed = state.borrow_mut();
    let pending = borrowed
        .pending_dialog_routes
        .iter_mut()
        .find(|pending| {
            pending.operation == operation
                && pending.creation == creation
                && pending.root_token == reserved
                && pending.root_window.is_none()
        })
        .ok_or_else(|| error("standard dialog route changed during root ownership transfer"))?;
    pending.root_token = token;
    pending.root_window = Some(hwnd as usize);
    Ok(token)
}

#[cfg(test)]
#[path = "win16_dialog_root_identity_tests.rs"]
mod tests;
