//! Native drop-message projection and exact lease retirement.

use super::super::win16_window_worker::NativeDropRetirementQueue;

pub(super) fn retire_if_native_drop(
    state: &Rc<RefCell<WorkerState>>,
    native: &MSG,
    removed: bool,
) -> Result<(), RuntimeError> {
    if removed
        && native.message == WM_DROPFILES
        && !super::super::win16_guest_notifications::is_carrier_message(
            native.hwnd,
            native.message,
            native.wParam,
            native.lParam,
        )
    {
        retire_removed_drop_message(state, native, true)?;
    }
    Ok(())
}
use super::WorkerState;
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostQueuedDelivery, Win16HostQueuedMessage,
    Win16HostWindow, Win16MessageParam, Win16MessageSource,
};
use std::cell::RefCell;
use std::rc::Rc;
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{MSG, PM_REMOVE, PeekMessageW, WM_DROPFILES};

/// Copy a native queued HDROP without dispatching it. A no-remove peek keeps
/// the exact HDROP owner in the worker queue ledger; removing the native MSG
/// transfers that owner into a runtime delivery and releases it after copy.
pub(in super::super) fn expose_native_drop_files(
    state: &Rc<RefCell<WorkerState>>,
    native: MSG,
    removed: bool,
) -> Result<Option<Win16HostQueuedDelivery>, RuntimeError> {
    let hdrop = native.wParam;
    let mapping = if native.hwnd.is_null() {
        None
    } else {
        let state = state.borrow();
        state
            .windows_by_native
            .get(&(native.hwnd as usize))
            .and_then(|identity| {
                (state.windows.get(&identity.window) == Some(&native.hwnd))
                    .then_some(identity.window)
            })
    };
    let Some(window) = mapping else {
        retire_removed_drop_message(state, &native, removed)?;
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "queued WM_DROPFILES has no exact live Win16 HWND owner",
        ));
    };
    // resolve checks the token mapping, property cookie, owner thread and
    // native HWND liveness together. Raw HWND equality alone cannot distinguish
    // a recycled handle from the incarnation which accepted this queued drop.
    if super::super::win16_window_identity::resolve(state, window) != Some(native.hwnd) {
        retire_removed_drop_message(state, &native, removed)?;
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "queued WM_DROPFILES target HWND changed its exact cookie-bound generation",
        ));
    }
    if native.lParam != 0 || hdrop == 0 {
        retire_removed_drop_message(state, &native, removed)?;
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "queued WM_DROPFILES does not carry the documented HDROP parameter shape",
        ));
    }
    if (crate::windows::win32_safe::is_window(native.hwnd)) == 0 {
        retire_removed_drop_message(state, &native, removed)?;
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "queued WM_DROPFILES target HWND was destroyed before projection",
        ));
    }
    let codec = state.borrow().text_codec;
    let identity_source = std::sync::Arc::clone(&state.borrow().identity_source);
    let (retirement_queue, existing_receipt) = {
        let state = state.borrow();
        (
            std::sync::Arc::clone(&state.native_drop_retirements),
            state.native_drop_files.retirement_for_message(&native)?,
        )
    };
    if existing_receipt.is_some_and(|receipt| receipt.window != window) {
        if removed {
            retire_removed_drop_message(state, &native, true)?;
        }
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "queued WM_DROPFILES lease belongs to a different HWND cookie generation",
        ));
    }
    let reservation = if removed {
        existing_receipt
            .map(|_| NativeDropRetirementQueue::reserve(&retirement_queue))
            .transpose()?
    } else {
        None
    };
    let queued = state.borrow_mut().native_drop_files.expose(
        &native,
        window,
        hdrop,
        removed,
        || super::super::win16_windows_dde::allocate_shared_identity(&identity_source),
        || {
            super::super::win16_window_callbacks::snapshot_native_drop_files(
                hdrop as windows_sys::Win32::UI::Shell::HDROP,
                codec,
            )
        },
    )?;
    if let (Some(receipt), Some(reservation)) = (existing_receipt, reservation) {
        if queued.lease != receipt.lease || !queued.native_removed {
            reservation.publish(receipt);
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "removed WM_DROPFILES projection changed its pre-reserved exact lease",
            ));
        }
        reservation.publish(receipt);
    }
    let message = Win16HostQueuedMessage {
        source: Win16MessageSource::NativeQueue,
        window: Some(window),
        message: WM_DROPFILES as u16,
        w_param: 0,
        // This is a private placeholder only. Runtime replaces it with the
        // exact guest HGLOBAL16 in WPARAM; the native HDROP never crosses.
        l_param: Win16MessageParam::Scalar(0),
        time: native.time,
        point: runtime::Win16HostPoint {
            x: native.pt.x,
            y: native.pt.y,
        },
    };
    Ok(Some(Win16HostQueuedDelivery {
        message: Some(message),
        drop_files: Some(queued),
    }))
}

/// A nested native pump may remove a guest-targeted WM_DROPFILES message
/// before the worker's regular GetMessage/PeekMessage adapter sees it. Keep
/// the exact HDROP in the same full-MSG ledger used by PM_NOREMOVE so the
/// deferred FIFO stores only MSG data and later PM_REMOVE claims this owner.
pub(in super::super) fn retain_deferred_native_drop(
    state: &Rc<RefCell<WorkerState>>,
    native: &MSG,
    window: Win16HostWindow,
) -> Result<(), RuntimeError> {
    let hdrop = native.wParam;
    if native.message != WM_DROPFILES {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "deferred native-drop owner hook received a non-WM_DROPFILES MSG",
        ));
    }
    if native.hwnd.is_null() || hdrop == 0 || native.lParam != 0 {
        retire_removed_drop_message(state, native, true)?;
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "nested WM_DROPFILES removal did not carry the documented HWND/HDROP parameter shape",
        ));
    }
    let mapping = {
        let state = state.borrow();
        state
            .windows_by_native
            .get(&(native.hwnd as usize))
            .and_then(|identity| {
                (identity.window == window
                    && state.windows.get(&identity.window) == Some(&native.hwnd))
                .then_some(identity.window)
            })
    };
    if mapping != Some(window)
        || super::super::win16_window_identity::resolve(state, window) != Some(native.hwnd)
        || { crate::windows::win32_safe::is_window(native.hwnd) } == 0
    {
        retire_removed_drop_message(state, native, true)?;
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "nested WM_DROPFILES target no longer has the exact live cookie-bound HWND generation",
        ));
    }

    let codec = state.borrow().text_codec;
    let identity_source = std::sync::Arc::clone(&state.borrow().identity_source);
    state.borrow_mut().native_drop_files.retain_removed(
        native,
        window,
        hdrop,
        || super::super::win16_windows_dde::allocate_shared_identity(&identity_source),
        || {
            super::super::win16_window_callbacks::snapshot_native_drop_files(
                hdrop as windows_sys::Win32::UI::Shell::HDROP,
                codec,
            )
        },
    )
}

/// Release a WM_DROPFILES MSG which a nested queue pump removed before it
/// could prove an exact live Win16 HWND cookie. The caller must not defer or
/// release this MSG again: this helper reuses the same full-MSG ledger owner
/// and the same raw-owner DragFinish path as ordinary rejection.
pub(in super::super) fn reject_removed_native_drop(
    state: &Rc<RefCell<WorkerState>>,
    native: &MSG,
) -> Result<(), RuntimeError> {
    if native.message != WM_DROPFILES {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "removed native-drop rejection received a non-WM_DROPFILES MSG",
        ));
    }
    retire_removed_drop_message(state, native, true)?;
    Err(RuntimeError::new(
        Kind::CompatibilityGap,
        "nested WM_DROPFILES was removed without an exact live guest HWND cookie owner",
    ))
}

pub(super) fn retire_removed_drop_message(
    state: &Rc<RefCell<WorkerState>>,
    native: &MSG,
    removed: bool,
) -> Result<(), RuntimeError> {
    if !removed {
        return Ok(());
    }
    let (receipt, reservation, retired) = {
        let mut state = state.borrow_mut();
        let receipt = state.native_drop_files.retirement_for_message(native)?;
        let reservation = receipt
            .map(|_| NativeDropRetirementQueue::reserve(&state.native_drop_retirements))
            .transpose()?;
        let retired = state.native_drop_files.retire_message(native)?;
        if receipt != retired {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "removed WM_DROPFILES changed its exact pre-reserved ledger retirement receipt",
            ));
        }
        (receipt, reservation, retired)
    };
    if let (Some(receipt), Some(reservation)) = (receipt, reservation) {
        debug_assert_eq!(retired, Some(receipt));
        reservation.publish(receipt);
    } else if retired.is_none() && native.wParam != 0 {
        // The native queue transferred this message to the worker. It was
        // rejected before a persistent lease existed, so release the exact
        // transferred HDROP here instead of forwarding its pointer.
        // SAFETY: DragFinish releases an HDROP Windows passed for this drop.
        unsafe {
            windows_sys::Win32::UI::Shell::DragFinish(
                native.wParam as windows_sys::Win32::UI::Shell::HDROP,
            );
        }
    }
    Ok(())
}

pub(in super::super) fn retire_drop_files_for_window(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostWindow,
    hwnd: HWND,
) -> Result<(), RuntimeError> {
    let mut retirement_failure = None;
    // Only drain a raw HWND queue while its exact property cookie still proves
    // this is the retiring incarnation. If USER already recycled the numeric
    // handle, touching that queue could steal a new window's drop messages.
    if super::super::win16_window_identity::resolve(state, token) == Some(hwnd) {
        loop {
            let mut native = MSG::default();
            let found =
                // SAFETY: PeekMessageW writes into a caller-owned MSG that outlives the call.
                unsafe { PeekMessageW(&mut native, hwnd, WM_DROPFILES, WM_DROPFILES, PM_REMOVE) };
            if found == 0 {
                break;
            }
            if super::super::win16_guest_notifications::is_carrier_message(
                native.hwnd,
                native.message,
                native.wParam,
                native.lParam,
            ) {
                // This queue removal retires the private marker, not an HDROP.
                if let Err(error) =
                    super::super::win16_guest_notifications::lookup(state, &native, true)
                {
                    if retirement_failure.is_none() {
                        retirement_failure = Some(error);
                    }
                }
                continue;
            }
            if let Err(error) = retire_removed_drop_message(state, &native, true) {
                if retirement_failure.is_none() {
                    retirement_failure = Some(error);
                }
            }
        }
    }
    if let Some(error) = retirement_failure {
        return Err(error);
    }
    let mut state = state.borrow_mut();
    state.native_drop_files.retire_window(token);
    state.drop_accepting_windows.remove(&token);
    Ok(())
}
