//! Blocking command wait for a suspended Win16 USER operation.

use std::cell::RefCell;
use std::os::windows::io::AsRawHandle;
use std::rc::Rc;
use std::sync::Arc;

use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::Foundation::{WAIT_ABANDONED_0, WAIT_FAILED, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::Win32::UI::WindowsAndMessaging::{MsgWaitForMultipleObjectsEx, QS_ALLINPUT};

use super::{WorkerCommand, WorkerState};

pub(in crate::windows::win16_windows) fn wait_for_worker_command(
    state: &Rc<RefCell<WorkerState>>,
) -> Result<WorkerCommand, RuntimeError> {
    loop {
        // A classic DDE SendMessage may be blocked in a private endpoint
        // WndProc while the USER worker waits for its exact callback reply.
        // Pump only private endpoint messages here; ordinary guest windows
        // and the parked USER MSG queue remain owned by their outer loop.
        super::super::win16_window_worker::pump_classic_dde_messages(state)?;
        if let Some(command) = try_receive_command(state)? {
            return Ok(command);
        }
        let event = Arc::clone(&state.borrow().wake_event);
        let handles = [event.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE];
        // SAFETY: `MsgWaitForMultipleObjectsEx` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        let result =
            unsafe { MsgWaitForMultipleObjectsEx(1, handles.as_ptr(), INFINITE, QS_ALLINPUT, 0) };
        if result == WAIT_OBJECT_0 {
            continue;
        }
        if result == WAIT_OBJECT_0 + 1 {
            continue;
        }
        let code = crate::windows::win32_safe::last_error();
        let detail = match result {
            WAIT_FAILED => {
                format!("wait for a Win16 USER continuation failed with Windows error {code}")
            }
            WAIT_ABANDONED_0 => "Win16 USER continuation wait event was abandoned".to_owned(),
            _ => format!("wait for a Win16 USER continuation returned unexpected status {result}"),
        };
        return Err(RuntimeError::with_source(
            Kind::HostFailure,
            detail,
            std::io::Error::from_raw_os_error(code as i32),
        ));
    }
}

pub(super) fn try_receive_command(
    state: &Rc<RefCell<WorkerState>>,
) -> Result<Option<WorkerCommand>, RuntimeError> {
    let receiver = Arc::clone(&state.borrow().commands);
    let result = receiver
        .lock()
        .map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 worker command receiver lock was poisoned",
            )
        })?
        .try_recv();
    match result {
        Ok(command) => Ok(Some(command)),
        Err(std::sync::mpsc::TryRecvError::Empty) => Ok(None),
        Err(std::sync::mpsc::TryRecvError::Disconnected) => Err(RuntimeError::new(
            Kind::HostFailure,
            "Win16 native worker command channel closed",
        )),
    }
}
