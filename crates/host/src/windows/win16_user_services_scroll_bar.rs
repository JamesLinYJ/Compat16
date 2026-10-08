//! Native USER forwarding for the Win16 scroll-bar APIs.
//!
//! The worker resolves an opaque window token immediately before each native
//! call. No worker-state borrow is held across USER, which may synchronously
//! reenter the guest when a redraw is requested.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    RuntimeError,
    Win16HostScrollBarOperation as Operation,
    Win16HostScrollBarResult as ResultValue,
};
use windows_sys::Win32::Foundation::{GetLastError, SetLastError, HWND, ERROR_NO_SCROLLBARS};
use windows_sys::Win32::UI::Controls::{
    EnableScrollBar, SetScrollPos, SetScrollRange, ShowScrollBar,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetScrollPos, GetScrollRange,
};

use super::win16_window_worker::WorkerState;

type SharedWorker = Rc<RefCell<WorkerState>>;

/// Execute a pointer-free Win16 scroll-bar operation on the HWND-owning worker.
pub(super) fn execute(
    state: &SharedWorker,
    operation: Operation,
) -> Result<ResultValue, RuntimeError> {
    use Operation as Call;
    use ResultValue as Result;

    match operation {
        Call::SetPosition { window, bar, position, redraw } => {
            let Some(hwnd) = resolve_window(state, window) else {
                return Ok(Result::Unavailable);
            };
            let previous = unsafe { SetScrollPos(
                hwnd, i32::from(bar), i32::from(position), i32::from(redraw),
            ) };
            Ok(Result::Position(previous))
        }
        Call::GetPosition { window, bar } => {
            let Some(hwnd) = resolve_window(state, window) else {
                return Ok(Result::Unavailable);
            };
            let position = unsafe { GetScrollPos(hwnd, i32::from(bar)) };
            Ok(Result::Position(position))
        }
        Call::SetRange { window, bar, minimum, maximum, redraw } => {
            let Some(hwnd) = resolve_window(state, window) else {
                return Ok(Result::Unavailable);
            };
            // Windows 3.1 WINDOWS.H declares SetScrollRange as `void`; the
            // current host binding's BOOL must never become the guest result.
            unsafe { SetScrollRange(
                hwnd, i32::from(bar), i32::from(minimum), i32::from(maximum),
                i32::from(redraw),
            ); }
            Ok(Result::Void)
        }
        Call::GetRange { window, bar } => {
            let Some(hwnd) = resolve_window(state, window) else {
                return Ok(Result::Unavailable);
            };
            let mut minimum = 0_i32;
            let mut maximum = 0_i32;
            // SDK 3.1 declares GetScrollRange as void and specifies zero
            // outputs for a valid window without the requested scrollbar.
            // Reset native last-error so a FALSE result is not classified
            // using a stale error from an earlier host call.
            let succeeded = unsafe {
                SetLastError(0);
                GetScrollRange(hwnd, i32::from(bar), &mut minimum, &mut maximum) != 0
            };
            if succeeded {
                return Ok(Result::Range(Some((minimum, maximum))));
            }
            let error = unsafe { GetLastError() };
            if resolve_window(state, window) != Some(hwnd) {
                return Ok(Result::Unavailable);
            }
            if error == ERROR_NO_SCROLLBARS {
                return Ok(Result::Range(Some((0, 0))));
            }
            super::win16_window_position::report_diagnostic(state,
                runtime::DiagnosticKind::HostFailure,
                "native GetScrollRange failed; guest output was left unchanged");
            Ok(Result::Range(None))
        }
        Call::Show { window, bar, show } => {
            let Some(hwnd) = resolve_window(state, window) else {
                return Ok(Result::Unavailable);
            };
            // ShowScrollBar is `void` in the guest SDK contract. Do not expose
            // the host's BOOL as AX or a typed guest word result.
            unsafe { ShowScrollBar(hwnd, i32::from(bar), i32::from(show)); }
            Ok(Result::Void)
        }
        Call::Enable { window, bar, flags } => {
            let Some(hwnd) = resolve_window(state, window) else {
                return Ok(Result::Unavailable);
            };
            // The SDK's Win16 `int` is a signed 16-bit value, while this
            // binding takes UINT. Preserve the same bit pattern when widening.
            let enabled = unsafe {
                EnableScrollBar(hwnd, i32::from(bar) as u32, u32::from(flags)) != 0
            };
            Ok(Result::Enabled(enabled))
        }
    }
}

fn resolve_window(
    state: &SharedWorker,
    window: runtime::Win16HostWindow,
) -> Option<HWND> {
    super::win16_window_identity::resolve_user_window(state, window)
        .filter(|hwnd| !hwnd.is_null())
}
