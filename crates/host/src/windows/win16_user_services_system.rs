//! Native Windows implementations of scalar Win16 USER system queries.

use windows_sys::Win32::Graphics::Gdi::GetSysColor;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetDoubleClickTime, SetDoubleClickTime,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetCaretBlinkTime, GetDialogBaseUnits, SetCaretBlinkTime,
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
