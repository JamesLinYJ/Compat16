//! Output projection from guest-byte text replies into native UTF-16 buffers.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{Win16HostMessageOutput as Output, Win16HostMessageResult, Win16HostWindow};
use windows_sys::Win32::Foundation::{HWND, LPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    WM_GETMINMAXINFO, WM_GETTEXT, WM_NCCALCSIZE, WM_WINDOWPOSCHANGED,
    WM_WINDOWPOSCHANGING, MINMAXINFO,
};

use super::super::win16_window_worker::WorkerState;

pub(in crate::windows::win16_windows) fn write_native_output(
    state: &Rc<RefCell<WorkerState>>,
    message: u32,
    l_param: LPARAM,
    capacity: usize,
    receiver: Option<(Win16HostWindow, HWND)>,
    original_nonclient_position: Option<*mut windows_sys::Win32::UI::WindowsAndMessaging::WINDOWPOS>,
    original_native_high_flags: Option<u32>,
    result: &Win16HostMessageResult,
) -> bool {
    if matches!(&result.output, Output::FindReplace { .. }) {
        return super::super::win16_common_dialog_callbacks::write_output(
            state, message, l_param, receiver, &result.output,
        );
    }
    match (message, &result.output) {
        (windows_sys::Win32::UI::WindowsAndMessaging::WM_MEASUREITEM,
            Output::OwnerDrawMeasure { width, height }) => {
            super::super::win16_owner_draw_callbacks::write_measure(l_param, *width, *height)
        }
        (WM_NCCALCSIZE, Output::NonClientCalcSize(data)) => {
            super::write_nonclient_output(
                state, receiver, capacity, l_param, original_nonclient_position,
                original_native_high_flags, *data,
            )
        }
        (WM_WINDOWPOSCHANGING, Output::WindowPosition(data)) => {
            let Some(original_native_high_flags) = original_native_high_flags else {
                return false;
            };
            super::super::win16_window_position::write_output(
                state, receiver, l_param, *data, original_native_high_flags,
            )
        }
        (WM_WINDOWPOSCHANGING, Output::None) => {
            super::super::win16_window_position::report_missing_changing_output(
                state, receiver, l_param,
            )
        }
        (WM_WINDOWPOSCHANGED, Output::WindowPosition(_) | Output::None) => true,
        (WM_GETMINMAXINFO, Output::MinMaxInfo(data)) if l_param != 0 => {
            // The native MINMAXINFO remains writable for this suspended
            // WndProc. All fields come from an owned, typed reply.
            unsafe {
                *(l_param as *mut MINMAXINFO) =
                    super::super::win16_window_geometry::native_minmax(*data);
            }
            true
        }
        // WM_GETTEXT uses the separately checked UTF-16 writer below.
        (WM_GETTEXT, _) => false,
        (_, Output::None) if message != WM_GETTEXT && message != WM_GETMINMAXINFO => true,
        _ => false,
    }
}

pub(in crate::windows::win16_windows) fn write_native_text_output(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: HWND,
    l_param: LPARAM,
    native_capacity_units: usize,
    guest_result_count: u32,
    output: &Output,
) -> Option<isize> {
    let (guest_capacity, buffer_is_null) = super::super::win16_window_text_context::guest_capacity(
        state, window, hwnd, WM_GETTEXT, native_capacity_units, l_param == 0,
    ).ok()?;
    match output {
        Output::None if guest_result_count == 0 => Some(0),
        Output::None if guest_result_count == u32::MAX => Some(-1),
        Output::Text(bytes) if native_capacity_units == 0 => {
            bytes.is_empty().then_some(0)
        }
        Output::Text(bytes) => {
            let guest_count = usize::try_from(guest_result_count).ok()?;
            if buffer_is_null
                || l_param == 0
                || bytes.len() > usize::from(guest_capacity)
                || bytes.last() != Some(&0)
                || bytes[..bytes.len().saturating_sub(1)].contains(&0)
                || guest_count.checked_add(1) != Some(bytes.len())
            {
                return None;
            }
            let (wide, native_count) = super::super::win16_window_text_context::guest_z_to_native_prefix(
                state, bytes, native_capacity_units,
            ).ok()?;
            if wide.len() > native_capacity_units {
                return None;
            }
            // SAFETY: the native WndProc supplied this writable UTF-16 buffer
            // and cch; conversion guarantees the copied NUL-terminated output
            // fits the same number of UTF-16 code units.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    wide.as_ptr(), l_param as *mut u16, wide.len(),
                );
            }
            Some(native_count as isize)
        }
        _ => None,
    }
}
