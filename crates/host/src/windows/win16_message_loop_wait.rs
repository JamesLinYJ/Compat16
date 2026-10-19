//! USER input waits with exact multimedia wake-generation observation.

use std::cell::RefCell;
use std::os::windows::io::AsRawHandle;
use std::rc::Rc;
use std::sync::Arc;

use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::Foundation::{HANDLE, WAIT_ABANDONED_0, WAIT_FAILED, WAIT_OBJECT_0};
use windows_sys::Win32::UI::WindowsAndMessaging::{MsgWaitForMultipleObjectsEx, QS_ALLINPUT};

use super::{NativeFilter, WaitResult, WorkerState, wait_command::try_receive_command};

pub(in crate::windows::win16_windows) fn wait_for_input_or_command(
    state: &Rc<RefCell<WorkerState>>,
) -> Result<WaitResult, RuntimeError> {
    wait_for_input_or_command_with_filter(state, None)
}

pub(super) fn wait_for_input_or_command_with_filter(
    state: &Rc<RefCell<WorkerState>>,
    filter: Option<NativeFilter>,
) -> Result<WaitResult, RuntimeError> {
    loop {
        if let Some(command) = try_receive_command(state)? {
            return Ok(WaitResult::Command(command));
        }
        if let Some(generation) = take_pending_guest_work_generation(state) {
            return Ok(WaitResult::PendingGuestWork { generation });
        }
        let native_filter = filter.map(|filter| (filter.hwnd, filter.min, filter.max));
        if super::super::win16_deferred_native_messages::observe_new_matching(state, native_filter)?
        {
            return Ok(WaitResult::NativeInput);
        }
        let event = {
            let state = state.borrow();
            Arc::clone(&state.wake_event)
        };
        let handle = event.as_raw_handle() as HANDLE;
        let handles = [handle];
        // SAFETY: `MsgWaitForMultipleObjectsEx` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        let result = unsafe {
            MsgWaitForMultipleObjectsEx(
                1,
                handles.as_ptr(),
                windows_sys::Win32::System::Threading::INFINITE,
                QS_ALLINPUT,
                0,
            )
        };
        if result == WAIT_OBJECT_0 {
            if let Some(command) = try_receive_command(state)? {
                return Ok(WaitResult::Command(command));
            }
            super::super::win16_window_worker::pump_classic_dde_messages(state)?;
            if let Some(generation) = take_pending_guest_work_generation(state) {
                return Ok(WaitResult::PendingGuestWork { generation });
            }
            continue;
        }
        if result == WAIT_OBJECT_0 + 1 {
            if let Some(command) = try_receive_command(state)? {
                return Ok(WaitResult::Command(command));
            }
            super::super::win16_window_worker::pump_classic_dde_messages(state)?;
            if let Some(generation) = take_pending_guest_work_generation(state) {
                return Ok(WaitResult::PendingGuestWork { generation });
            }
            return Ok(WaitResult::NativeInput);
        }
        let detail = match result {
            WAIT_FAILED => format!(
                "Win16 USER queue wait failed with Windows error {}",
                (crate::windows::win32_safe::last_error())
            ),
            WAIT_ABANDONED_0 => "Win16 USER wake event was abandoned".to_owned(),
            _ => format!("Win16 USER queue wait returned unexpected status {result}"),
        };
        return Err(RuntimeError::new(Kind::HostFailure, detail));
    }
}

pub(super) fn take_pending_guest_work_generation(state: &Rc<RefCell<WorkerState>>) -> Option<u64> {
    let mut state = state.borrow_mut();
    let current = state
        .multimedia_generation
        .load(std::sync::atomic::Ordering::Acquire);
    if current == state.multimedia_generation_seen {
        return None;
    }
    state.multimedia_generation_seen = current;
    Some(current)
}
