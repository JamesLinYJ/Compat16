//! Native and Win16 packing for focus, activation, and cursor messages.
//!
//! The Windows 3.1 SDK `WINDOWSX.H` `HANDLE_WM_*` and `FORWARD_WM_*` macros
//! for WM_SETFOCUS, WM_KILLFOCUS, WM_ACTIVATE, WM_NCACTIVATE, WM_SETCURSOR,
//! and WM_MOUSEACTIVATE define the guest WORD layout. Native Win32 WM_ACTIVATE
//! instead puts state/minimized in WPARAM and carries the full-width other
//! HWND in LPARAM; the guest view packs the other 16-bit HWND and minimized
//! WORD into LPARAM.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostActivationApp, Win16HostControlColor,
    Win16HostParentNotification, Win16HostParentNotificationData, Win16HostWindow,
    Win16WindowInputMessage,
};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    WM_ACTIVATE, WM_KILLFOCUS, WM_MOUSEACTIVATE, WM_NCACTIVATE, WM_SETCURSOR, WM_SETFOCUS,
};

use super::win16_window_worker::{self as worker, WorkerState};

const WM_CREATE: u16 = 0x0001;
const WM_DESTROY: u16 = 0x0002;

pub(super) fn decode_activation_app(
    w_param: usize,
    l_param: isize,
) -> Option<Win16HostActivationApp> {
    let thread_id = u32::try_from(l_param).ok()?;
    let other_task_queue = if thread_id == 0 {
        None
    } else if thread_id == (crate::windows::win32_safe::current_thread_id()) {
        Some(super::win16_guest_notifications::require_bound_queue(
            super::win16_guest_notifications::current_queue(),
        )?)
    } else {
        // Native TIDs outside this worker need a WOW-style HTASK alias table;
        // this bridge has no such task-query/retirement contract yet.
        return None;
    };
    Some(Win16HostActivationApp {
        active: u16::from(w_param != 0),
        other_task_queue,
    })
}

pub(super) fn decode_parent_notification(
    state: &Rc<RefCell<WorkerState>>,
    w_param: usize,
    l_param: isize,
) -> Result<Option<Win16HostParentNotification>, RuntimeError> {
    let Ok(packed_w_param) = u32::try_from(w_param) else {
        return Ok(None);
    };
    let event = packed_w_param as u16;
    let data = if matches!(event, WM_CREATE | WM_DESTROY) {
        let Some(child) = token_for_optional_hwnd(state, l_param as HWND)? else {
            return Ok(None);
        };
        Win16HostParentNotificationData::Child {
            child,
            id: (packed_w_param >> 16) as u16,
        }
    } else if is_parent_mouse_event(event) {
        let coordinates = l_param as u32;
        let raw_l_param = l_param as i64;
        let has_exact_packed_coordinates = (raw_l_param >= 0
            && raw_l_param as u64 == u64::from(coordinates))
            || raw_l_param == i64::from(coordinates as i32);
        if !has_exact_packed_coordinates {
            return Ok(None);
        }
        Win16HostParentNotificationData::Mouse { coordinates }
    } else {
        return Ok(None);
    };
    Ok(Some(Win16HostParentNotification { event, data }))
}

pub(super) fn decode_control_color(
    state: &Rc<RefCell<WorkerState>>,
    window: runtime::Win16HostWindow,
    message: u32,
    w_param: usize,
    l_param: isize,
) -> Result<Option<Win16HostControlColor>, RuntimeError> {
    let Some(kind) = control_color_kind(message) else {
        return Ok(None);
    };
    let Some(control) = token_for_optional_hwnd(state, l_param as HWND)? else {
        return Ok(None);
    };
    let dc = if w_param == 0 {
        None
    } else {
        Some(
            worker::adopt_callback_dc(state, window, w_param)?.ok_or_else(|| {
                RuntimeError::new(
                    Kind::HostFailure,
                    "native control-color HDC could not be leased for its callback",
                )
            })?,
        )
    };
    Ok(Some(Win16HostControlColor { kind, dc, control }))
}

pub(super) fn encode_activation_app(input: Win16HostActivationApp) -> Option<(usize, isize)> {
    let thread_id = match input.other_task_queue {
        None => 0,
        Some(queue)
            if super::win16_guest_notifications::require_bound_queue(
                super::win16_guest_notifications::current_queue(),
            ) == Some(queue) =>
        {
            crate::windows::win32_safe::current_thread_id()
        }
        Some(_) => return None,
    };
    Some((usize::from(input.active != 0), thread_id as isize))
}

pub(super) fn encode_parent_notification(
    state: &Rc<RefCell<WorkerState>>,
    input: Win16HostParentNotification,
) -> Result<Option<(usize, isize)>, RuntimeError> {
    match input.data {
        Win16HostParentNotificationData::Child { child, id }
            if matches!(input.event, WM_CREATE | WM_DESTROY) =>
        {
            let Some(child) = resolve_optional_hwnd(state, child) else {
                return Ok(None);
            };
            let w_param = usize::from(input.event) | (usize::from(id) << 16);
            Ok(Some((w_param, child as isize)))
        }
        Win16HostParentNotificationData::Mouse { coordinates }
            if is_parent_mouse_event(input.event) =>
        {
            Ok(Some((
                usize::from(input.event),
                (coordinates as i32) as isize,
            )))
        }
        _ => Ok(None),
    }
}

pub(super) const fn control_color_kind(message: u32) -> Option<u16> {
    if message >= 0x0132 && message <= 0x0138 {
        Some((message - 0x0132) as u16)
    } else {
        None
    }
}

pub(super) const fn is_parent_mouse_event(event: u16) -> bool {
    // Win16 has no XBUTTON parent-notify layout; native WM_XBUTTONDOWN uses
    // the high word of WPARAM for the button identity, not packed coordinates.
    matches!(event, 0x0201 | 0x0204 | 0x0207)
}

/// Copy the native HWND-bearing fields into host tokens and the documented
/// message WORDs. No native handle or borrowed state crosses to the runtime.
pub(super) fn decode_window_input(
    state: &Rc<RefCell<WorkerState>>,
    message: u32,
    w_param: usize,
    l_param: isize,
) -> Result<Option<Win16WindowInputMessage>, RuntimeError> {
    let Ok(message_word) = u16::try_from(message) else {
        return Ok(None);
    };
    // This generic decoder has no receiver HWND, so it cannot derive the
    // receiver's minimized state. Call decode_nonclient_activation instead.
    if message == WM_NCACTIVATE {
        return Ok(None);
    }
    if !Win16WindowInputMessage::accepts(message_word) {
        return Ok(None);
    }

    let copied = match message {
        WM_SETFOCUS | WM_KILLFOCUS => {
            let Some(other) = token_for_optional_hwnd(state, w_param as HWND)? else {
                return Ok(None);
            };
            Win16WindowInputMessage::Focus {
                gained: message == WM_SETFOCUS,
                other,
            }
        }
        WM_ACTIVATE => {
            // Native Win32 uses LOWORD/HIWORD(WPARAM) for state and minimized
            // and LPARAM itself for the other HWND. The Win16 cracker packs
            // that HWND into LOWORD(LPARAM), with minimized in HIWORD.
            let activation = w_param as u32;
            let Some(other) = token_for_optional_hwnd(state, l_param as HWND)? else {
                return Ok(None);
            };
            Win16WindowInputMessage::Activate {
                state: activation as u16,
                minimized: (activation >> 16) as u16,
                other,
            }
        }
        WM_SETCURSOR => {
            let packed = l_param as u32;
            let Some(target) = token_for_optional_hwnd(state, w_param as HWND)? else {
                return Ok(None);
            };
            Win16WindowInputMessage::SetCursor {
                target,
                hit_test: packed as u16,
                mouse_message: (packed >> 16) as u16,
            }
        }
        WM_MOUSEACTIVATE => {
            let packed = l_param as u32;
            let Some(parent) = token_for_optional_hwnd(state, w_param as HWND)? else {
                return Ok(None);
            };
            Win16WindowInputMessage::MouseActivate {
                parent,
                hit_test: packed as u16,
                mouse_message: (packed >> 16) as u16,
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(copied))
}

/// Decode native WM_NCACTIVATE using its actual receiver for the minimized
/// state. The caller retains any native-only suppression context separately.
pub(super) fn decode_nonclient_activation(
    state: &Rc<RefCell<WorkerState>>,
    receiver: HWND,
    w_param: usize,
    l_param: isize,
) -> Result<Option<Win16WindowInputMessage>, RuntimeError> {
    // Compatibility inference only: Windows 3.1 Vol. 3 p. 159 does not assign
    // the high-WORD BOOL's window ownership; WINDOWSX.H establishes only the
    // low-HWND/high-BOOL packing. Modern host remarks make IsIconic(receiver)
    // plausible, but original Windows 3.1 behavior still needs validation.
    let other = if l_param == -1 {
        // Win32's private suppression sentinel is not a Win16 HWND value.
        // Preserve -1 only in the exact callback context for nested defaulting.
        None
    } else {
        let Some(other) = token_for_optional_hwnd(state, l_param as HWND)? else {
            return Ok(None);
        };
        other
    };

    let active = if w_param != 0 { 1 } else { 0 };
    let minimized = if (crate::windows::win32_safe::is_iconic(receiver)) != 0 {
        1
    } else {
        0
    };
    Ok(Some(Win16WindowInputMessage::NonClientActivate {
        active,
        minimized,
        other,
    }))
}

/// Reconstruct native Win32 parameters after validating every token. `None`
/// tokens preserve the Win16 NULL HWND; stale non-null tokens fail closed.
pub(super) fn encode_window_input(
    state: &Rc<RefCell<WorkerState>>,
    input: Win16WindowInputMessage,
) -> Result<Option<(u32, usize, isize)>, RuntimeError> {
    let message = u32::from(input.message_id());
    let encoded = match input {
        Win16WindowInputMessage::Focus { other, .. } => {
            let Some(other) = resolve_optional_hwnd(state, other) else {
                return Ok(None);
            };
            (message, other as usize, 0)
        }
        Win16WindowInputMessage::Activate {
            state: activation,
            minimized,
            other,
        } => {
            let Some(other) = resolve_optional_hwnd(state, other) else {
                return Ok(None);
            };
            // Native Win32's LPARAM is the full HWND. State/minimized occupy
            // the low/high WORDs of WPARAM on the native ABI.
            let native_w = usize::from(activation) | (usize::from(minimized) << 16);
            (message, native_w, other as isize)
        }
        Win16WindowInputMessage::NonClientActivate { active, other, .. } => {
            let Some(other) = resolve_optional_hwnd(state, other) else {
                return Ok(None);
            };
            // Native WM_NCACTIVATE carries the activation BOOL in WPARAM and
            // the full HWND in LPARAM. Its native ABI has no minimized field.
            (message, usize::from(active), other as isize)
        }
        Win16WindowInputMessage::SetCursor {
            target,
            hit_test,
            mouse_message,
        } => {
            let Some(target) = resolve_optional_hwnd(state, target) else {
                return Ok(None);
            };
            (
                message,
                target as usize,
                pack_words(hit_test, mouse_message),
            )
        }
        Win16WindowInputMessage::MouseActivate {
            parent,
            hit_test,
            mouse_message,
        } => {
            let Some(parent) = resolve_optional_hwnd(state, parent) else {
                return Ok(None);
            };
            (
                message,
                parent as usize,
                pack_words(hit_test, mouse_message),
            )
        }
    };
    Ok(Some(encoded))
}

fn token_for_optional_hwnd(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
) -> Result<Option<Option<Win16HostWindow>>, RuntimeError> {
    if hwnd.is_null() {
        return Ok(Some(None));
    }
    if (crate::windows::win32_safe::is_window(hwnd)) == 0 {
        return Ok(None);
    }
    match worker::token_for_native(state, hwnd) {
        Ok(token) => Ok(Some(Some(token))),
        Err(error)
            if error.kind() == Kind::InvalidInput
                && (crate::windows::win32_safe::is_window(hwnd)) == 0 =>
        {
            // The HWND was valid before adoption but was destroyed during the
            // check. Treat only that race as an untranslated message; cookie
            // and identity-ledger failures remain fatal.
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn resolve_optional_hwnd(
    state: &Rc<RefCell<WorkerState>>,
    token: Option<Win16HostWindow>,
) -> Option<HWND> {
    match token {
        Some(token) => super::win16_window_identity::resolve_user_window(state, token),
        None => Some(std::ptr::null_mut()),
    }
}

fn pack_words(low: u16, high: u16) -> isize {
    ((u32::from(low) | (u32::from(high) << 16)) as i32) as isize
}
