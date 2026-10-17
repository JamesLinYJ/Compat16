//! Small USER queries and setters backed by native User32 services.
//!
//! These adapters preserve the Win16 result width even where the native
//! Win32 declaration uses `UINT` or `BOOL` (both 32-bit on Windows).

use win16_abi::exports::Win16UserSystemRequest;

use crate::{RuntimeError, RuntimeHost};

/// Dispatch the nested USER system-query request group from the export
/// decoder. Keeping this match beside the group helpers lets the shared
/// export dispatcher route one typed family arm without duplicating the
/// native call and result-width rules.
pub(crate) fn dispatch(
    state: &mut super::Win16State,
    request: Win16UserSystemRequest,
    host: &mut impl RuntimeHost,
) -> Result<u32, RuntimeError> {
    match request {
        Win16UserSystemRequest::SetDoubleClickTime { milliseconds } => {
            set_double_click_time(host, milliseconds)
        }
        Win16UserSystemRequest::GetDoubleClickTime => get_double_click_time(host),
        Win16UserSystemRequest::SetCaretBlinkTime { milliseconds } => {
            set_caret_blink_time(host, milliseconds)
        }
        Win16UserSystemRequest::GetCaretBlinkTime => get_caret_blink_time(host),
        Win16UserSystemRequest::GetSysColor { index } => get_sys_color(host, index),
        Win16UserSystemRequest::SetSysColors { .. } => Err(RuntimeError::new(
            crate::DiagnosticKind::InternalInvariant,
            "callback-capable SetSysColors requires a USER worker operation",
        )),
        Win16UserSystemRequest::SwapMouseButton { swap } => {
            Ok(u32::from(host.win16_swap_mouse_button(swap)?))
        }
        Win16UserSystemRequest::GetDialogBaseUnits => get_dialog_base_units(host),
        Win16UserSystemRequest::AnyPopup => Ok(u32::from(host.win16_any_popup()?)),
        Win16UserSystemRequest::IconSize => super::user_drag::icon_size(host),
        Win16UserSystemRequest::DragObject { .. } => Ok(super::user_drag::drag_object()),
        Win16UserSystemRequest::DragDetect { window, x, y } => {
            super::user_drag::drag_detect(host, window, x, y)
        }
        Win16UserSystemRequest::SetSysModalWindow { window } => {
            Ok(u32::from(set_sysmodal_window(state, window)))
        }
        Win16UserSystemRequest::GetSysModalWindow => Ok(u32::from(sysmodal_window(state))),
        Win16UserSystemRequest::GetSysColorBrush { index } => Ok(u32::from(sys_color_brush(index))),
        Win16UserSystemRequest::GetFreeSystemResources { selector } => {
            Ok(u32::from(free_system_resources(selector)))
        }
    }
}

/// Windows 3.1 COLOR_SCROLLBAR through COLOR_BTNHIGHLIGHT.
const WIN16_LAST_SYS_COLOR: i16 = 20;
/// NT WOW reports this percentage because the 16-bit USER and GDI heaps
/// are not present. The three SDK selectors share it.
const WOW_FREE_RESOURCE_PERCENT: u16 = 90;
const GFSR_SYSTEM_RESOURCES: u16 = 0;
const GFSR_GDI_RESOURCES: u16 = 1;
const GFSR_USER_RESOURCES: u16 = 2;

fn set_sysmodal_window(state: &mut super::Win16State, window: u16) -> u16 {
    let previous = sysmodal_window(state);
    if window == 0 {
        state.sysmodal_window = None;
        return previous;
    }
    if !state.window_handles.contains_key(&window) {
        return 0;
    }
    state.sysmodal_window = Some(window);
    previous
}

fn sysmodal_window(state: &mut super::Win16State) -> u16 {
    match state.sysmodal_window {
        Some(window) if state.window_handles.contains_key(&window) => window,
        Some(_) => {
            state.sysmodal_window = None;
            0
        }
        None => 0,
    }
}

/// USER.281 returns the COLOR_*+1 pseudo-brush already used for class
/// backgrounds and WM_CTLCOLOR. No GDI object is allocated.
fn sys_color_brush(index: i16) -> u16 {
    if (0..=WIN16_LAST_SYS_COLOR).contains(&index) {
        u16::from(index as u16) + 1
    } else {
        0
    }
}

/// USER.284. Unknown selectors stay zero rather than a percentage.
fn free_system_resources(selector: u16) -> u16 {
    match selector {
        GFSR_SYSTEM_RESOURCES | GFSR_GDI_RESOURCES | GFSR_USER_RESOURCES => {
            WOW_FREE_RESOURCE_PERCENT
        }
        _ => 0,
    }
}

/// USER.21 `GetDoubleClickTime`: Win16 `UINT` is returned as a 16-bit word.
pub(crate) fn get_double_click_time(
    host: &mut impl RuntimeHost,
) -> Result<u32, RuntimeError> {
    Ok(host.win16_get_double_click_time()? as u16 as u32)
}

/// USER.20 `SetDoubleClickTime`: the SDK declares a void result.
/// Keep the native BOOL internal; guest register preservation is the project
/// Void policy, not a historical guarantee about undefined AX/DX values.
pub(crate) fn set_double_click_time(
    host: &mut impl RuntimeHost,
    milliseconds: u16,
) -> Result<u32, RuntimeError> {
    Ok(host.win16_set_double_click_time(u32::from(milliseconds))? as u16 as u32)
}

/// USER.169 `GetCaretBlinkTime`: preserve the Win16 16-bit result.
pub(crate) fn get_caret_blink_time(
    host: &mut impl RuntimeHost,
) -> Result<u32, RuntimeError> {
    Ok(host.win16_get_caret_blink_time()? as u16 as u32)
}

/// USER.168 `SetCaretBlinkTime`: the SDK declares a void result.
/// Keep the native BOOL internal; guest register preservation is the project
/// Void policy, not a historical guarantee about undefined AX/DX values.
pub(crate) fn set_caret_blink_time(
    host: &mut impl RuntimeHost,
    milliseconds: u16,
) -> Result<u32, RuntimeError> {
    Ok(host.win16_set_caret_blink_time(u32::from(milliseconds))? as u16 as u32)
}

/// USER.180 `GetSysColor`: its guest argument is a word, while the documented
/// `COLORREF` result occupies the full 32-bit Win16 return value.
pub(crate) fn get_sys_color(
    host: &mut impl RuntimeHost,
    index: u16,
) -> Result<u32, RuntimeError> {
    host.win16_get_sys_color(i32::from(index))
}

/// USER.243 `GetDialogBaseUnits` returns horizontal and vertical units packed
/// in the low and high words of its 32-bit result.
pub(crate) fn get_dialog_base_units(
    host: &mut impl RuntimeHost,
) -> Result<u32, RuntimeError> {
    host.win16_get_dialog_base_units()
}

#[cfg(test)]
#[path = "win16_dispatch_any_popup_tests.rs"]
mod any_popup_tests;
