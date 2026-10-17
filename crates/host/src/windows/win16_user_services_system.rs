//! Native Windows system-color, timing and input adapters.

use windows_sys::Win32::Graphics::Gdi::{GetSysColor, SetSysColors};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetDoubleClickTime, SetDoubleClickTime, SwapMouseButton,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AnyPopup, GetCaretBlinkTime, GetDialogBaseUnits, SetCaretBlinkTime,
};

pub(super) fn get_double_click_time() -> u32 {
    // SAFETY: This scalar USER query has no pointer or handle preconditions.
    unsafe { GetDoubleClickTime() }
}

pub(super) fn set_double_click_time(milliseconds: u32) -> bool {
    // SAFETY: The native API accepts the scalar millisecond interval directly.
    unsafe { SetDoubleClickTime(milliseconds) != 0 }
}

pub(super) fn get_caret_blink_time() -> u32 {
    // SAFETY: This scalar USER query has no pointer or handle preconditions.
    unsafe { GetCaretBlinkTime() }
}

pub(super) fn set_caret_blink_time(milliseconds: u32) -> bool {
    // SAFETY: The native API accepts the scalar millisecond interval directly.
    unsafe { SetCaretBlinkTime(milliseconds) != 0 }
}

pub(super) fn get_sys_color(index: i32) -> u32 {
    // SAFETY: The native API consumes a scalar system-color index and returns
    // the documented 32-bit RGB value; invalid indices return zero.
    unsafe { GetSysColor(index) }
}

pub(super) fn set_sys_colors(indices: &[i32], colors: &[u32]) -> Result<bool, runtime::RuntimeError> {
    // The USER worker establishes the callback operation before invoking this
    // adapter. No worker RefCell borrow may survive the synchronous native call.
    // SAFETY: the helper validates matching lengths and retains both arrays,
    // or live dummy values for zero count, until this native call returns.
    set_sys_colors_with(indices, colors, |count, indices, colors| unsafe {
        SetSysColors(count, indices, colors)
    })
}

fn set_sys_colors_with(
    indices: &[i32], colors: &[u32],
    apply: impl FnOnce(i32, *const i32, *const u32) -> i32,
) -> Result<bool, runtime::RuntimeError> {
    if indices.len() != colors.len() {
        return Err(runtime::RuntimeError::new(runtime::DiagnosticKind::InternalInvariant,
            "native system-color arrays have different lengths"));
    }
    let count = i32::try_from(indices.len()).map_err(|_| runtime::RuntimeError::new(
        runtime::DiagnosticKind::InternalInvariant, "native system-color count exceeds INT"))?;
    let empty_index = 0_i32;
    let empty_color = 0_u32;
    let indices_ptr = indices.first().unwrap_or(&empty_index);
    let colors_ptr = colors.first().unwrap_or(&empty_color);
    // Both slices remain owned for the complete synchronous call, including
    // nested callbacks. Zero count uses live dummy values without reading them.
    Ok(apply(count, indices_ptr, colors_ptr) != 0)
}

pub(super) fn swap_mouse_button(swap: bool) -> bool {
    // SAFETY: This API accepts one scalar BOOL and returns the previous mapping.
    unsafe { SwapMouseButton(i32::from(swap)) != 0 }
}

pub(super) fn get_dialog_base_units() -> u32 {
    // SAFETY: This scalar USER query has no pointer or handle preconditions.
    unsafe { GetDialogBaseUnits() as u32 }
}

/// USER.52 retains the native compatibility API's desktop-wide semantics:
/// owned top-level windows with WS_VISIBLE, including completely covered ones.
/// Do not restrict this query to guest windows or substitute popup style tests.
/// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-anypopup
pub(super) fn any_popup() -> bool {
    // SAFETY: The native read-only query takes no pointers or handles.
    any_popup_with(|| unsafe { AnyPopup() })
}

fn any_popup_with(query: impl FnOnce() -> i32) -> bool {
    query() != 0
}

#[cfg(test)]
#[path = "win16_any_popup_tests.rs"]
mod any_popup_tests;

#[cfg(test)]
#[path = "win16_system_colors_adapter_tests.rs"]
mod system_colors_adapter_tests;
