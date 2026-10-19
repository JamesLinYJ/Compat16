//! Install once, after the predefined STATIC finishes its first WM_CREATE.
use super::*;
use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use windows_sys::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    SendMessageW, WM_CREATE, WM_NCCREATE, WM_NCDESTROY,
};
const STM_SETICON: u32 = 0x0170;
const STM_GETICON: u32 = 0x0171;

// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
pub(super) unsafe extern "system" fn icon_proc(
    hwnd: HWND,
    message: u32,
    w: usize,
    l: isize,
    id: usize,
    _data: usize,
) -> isize {
    // If a post-default check fails or panics, never dispatch the native message
    // twice. No Rust unwind may cross the subclass ABI.
    let forwarded = Cell::new(None);
    let result = catch_unwind(AssertUnwindSafe(|| {
        dispatch(hwnd, message, w, l, id, &forwarded)
    }));
    match result {
        Ok(result) => result,
        Err(_) => {
            observer::latch_panic();
            let _ = catch_unwind(AssertUnwindSafe(|| {
                if let Some(state) = worker::worker_context() {
                    fail(
                        &state,
                        Win16HostWindow(id as u64),
                        "panic in template STATIC icon subclass",
                    );
                }
            }));
            if message == WM_CREATE {
                -1
            } else if message == WM_NCCREATE {
                0
            } else {
                forwarded.get().unwrap_or(0)
            }
        }
    }
}
fn dispatch(
    hwnd: HWND,
    message: u32,
    w: usize,
    l: isize,
    id: usize,
    forwarded: &Cell<Option<isize>>,
) -> isize {
    let call_default = || {
        // SAFETY: DefSubclassProc forwards this subclass message. Pointer parameters stay live for the call.
        let result = unsafe { DefSubclassProc(hwnd, message, w, l) };
        forwarded.set(Some(result));
        result
    };
    let Some(state) = worker::worker_context() else {
        return call_default();
    };
    let window = Win16HostWindow(id as u64);
    let snapshot = {
        let borrowed = state.borrow();
        borrowed
            .dialog_icon_sidecars
            .by_window(window)
            .filter(|sidecar| sidecar.hwnd == Some(hwnd as usize))
            .map(|sidecar| (sidecar.phase, Arc::clone(&sidecar.owner)))
    };
    let Some((phase, owner)) = snapshot else {
        return call_default();
    };
    if message == STM_SETICON || (message == 0x0172 && w == 1) {
        let mut borrowed = state.borrow_mut();
        if let Some(sidecar) = borrowed.dialog_icon_sidecars.by_window_mut(window) {
            if message == STM_SETICON && sidecar.initial_set_pending {
                sidecar.initial_set_pending = false;
            } else {
                sidecar.replacement_seen = true;
            }
        }
        drop(borrowed);
        return call_default();
    }
    if message == WM_NCDESTROY {
        // This message is sendable. Removal is harmless, but it is NOT a
        // destruction receipt and neither the sidecar nor its owner is freed.
        if phase != Phase::Ready {
            set_phase(&state, window, Phase::Failed);
        }
        // SAFETY: `RemoveWindowSubclass`, `Some` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        if unsafe { RemoveWindowSubclass(hwnd, Some(icon_proc), id) } == 0 {
            fail(&state, window, "remove template STATIC subclass");
        }
        return call_default();
    }
    if message == WM_NCCREATE && phase == Phase::Bound {
        set_phase(&state, window, Phase::NonclientCreating);
        let result = call_default();
        if result != 0
            && live(&state, window, hwnd)
            && has_phase(&state, window, Phase::NonclientCreating)
        {
            set_phase(&state, window, Phase::NonclientCreated);
        } else {
            set_phase(&state, window, Phase::Failed);
        }
        return result;
    }
    if message != WM_CREATE || phase != Phase::NonclientCreated {
        return call_default();
    }
    set_phase(&state, window, Phase::Creating);
    let result = call_default();
    if result == -1 {
        set_phase(&state, window, Phase::Failed);
        return result;
    }
    if !live(&state, window, hwnd) || !has_phase(&state, window, Phase::Creating) {
        fail(
            &state,
            window,
            "template STATIC changed generation during WM_CREATE",
        );
        return -1;
    }
    set_phase(&state, window, Phase::Installing);
    // SAFETY: SendMessageW runs synchronously on the window thread. Pointer arguments are caller-owned records that stay live for the call and are not guest addresses.
    let previous = unsafe { SendMessageW(hwnd, STM_GETICON, 0, 0) };
    if !live(&state, window, hwnd) || !has_phase(&state, window, Phase::Installing) {
        fail(
            &state,
            window,
            "template STATIC changed during initial icon readback",
        );
        return -1;
    }
    // A reentrant native observer may already have supplied an icon. Preserve
    // it, and never destroy or adopt a handle returned by native readback here.
    let replaced_before_install = state
        .borrow()
        .dialog_icon_sidecars
        .by_window(window)
        .is_some_and(|sidecar| sidecar.replacement_seen);
    if installation_needed(previous, replaced_before_install) {
        {
            let mut borrowed = state.borrow_mut();
            if let Some(sidecar) = borrowed.dialog_icon_sidecars.by_window_mut(window) {
                sidecar.initial_set_pending = true;
                sidecar.replacement_seen = false;
            }
        }
        // SAFETY: SendMessageW runs synchronously on the window thread. Pointer arguments are caller-owned records that stay live for the call and are not guest addresses.
        unsafe {
            SendMessageW(hwnd, STM_SETICON, owner.native() as usize, 0);
        }
        if !live(&state, window, hwnd) || !has_phase(&state, window, Phase::Installing) {
            fail(
                &state,
                window,
                "template STATIC changed during icon installation",
            );
            return -1;
        }
        // SAFETY: SendMessageW runs synchronously on the window thread. Pointer arguments are caller-owned records that stay live for the call and are not guest addresses.
        let current = unsafe { SendMessageW(hwnd, STM_GETICON, 0, 0) };
        if !live(&state, window, hwnd) || !has_phase(&state, window, Phase::Installing) {
            fail(
                &state,
                window,
                "template STATIC changed during installed icon readback",
            );
            return -1;
        }
        // SET may reenter and replace or clear the image. Its final state wins;
        // the initial owner remains conservatively pinned until HWND retirement.
        let accepted = state
            .borrow()
            .dialog_icon_sidecars
            .by_window(window)
            .is_some_and(|sidecar| {
                installation_accepted(
                    current,
                    owner.native() as isize,
                    sidecar.initial_set_pending,
                    sidecar.replacement_seen,
                )
            });
        if !accepted {
            fail(
                &state,
                window,
                "template STATIC did not retain its initial icon",
            );
            return -1;
        }
    }
    set_phase(&state, window, Phase::Ready);
    result
}
fn live(state: &Rc<RefCell<WorkerState>>, window: Win16HostWindow, hwnd: HWND) -> bool {
    super::super::win16_window_identity::resolve(state, window) == Some(hwnd)
}
fn has_phase(state: &Rc<RefCell<WorkerState>>, window: Win16HostWindow, phase: Phase) -> bool {
    state
        .borrow()
        .dialog_icon_sidecars
        .by_window(window)
        .is_some_and(|sidecar| sidecar.phase == phase)
}
fn set_phase(state: &Rc<RefCell<WorkerState>>, window: Win16HostWindow, phase: Phase) {
    if let Some(sidecar) = state
        .borrow_mut()
        .dialog_icon_sidecars
        .by_window_mut(window)
    {
        sidecar.phase = phase;
    }
}
fn fail(state: &Rc<RefCell<WorkerState>>, window: Win16HostWindow, message: &'static str) {
    let provenance = {
        let mut borrowed = state.borrow_mut();
        borrowed
            .dialog_icon_sidecars
            .by_window_mut(window)
            .map(|sidecar| {
                sidecar.phase = Phase::Failed;
                (sidecar.operation, sidecar.creation)
            })
    };
    if let Some((operation, creation)) = provenance {
        observer::report(operation, creation, error(message));
    }
}

fn installation_needed(previous: isize, replacement_seen: bool) -> bool {
    previous == 0 && !replacement_seen
}
fn installation_accepted(
    current: isize,
    initial: isize,
    pending: bool,
    replacement_seen: bool,
) -> bool {
    !pending && (current == initial || replacement_seen)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dialog_icon_initial_install_preserves_prior_replacement_or_clear() {
        assert!(installation_needed(0, false));
        assert!(!installation_needed(7, false));
        assert!(!installation_needed(0, true));
        assert!(!installation_needed(7, true));
    }
    #[test]
    fn dialog_icon_readback_requires_success_or_observed_reentrant_mutation() {
        assert!(installation_accepted(7, 7, false, false));
        assert!(!installation_accepted(0, 7, false, false));
        assert!(!installation_accepted(8, 7, false, false));
        assert!(installation_accepted(0, 7, false, true));
        assert!(installation_accepted(8, 7, false, true));
        assert!(!installation_accepted(7, 7, true, true));
    }
}
