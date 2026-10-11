//! Native Windows implementations of scalar Win16 USER system queries.

use windows_sys::Win32::Graphics::Gdi::GetSysColor;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetDoubleClickTime, SetDoubleClickTime,
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
