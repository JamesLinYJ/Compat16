//! Registered common-dialog messages at suspended native callback boundaries.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostFindReplaceNotification,
    Win16HostMessageOutput, Win16HostWindow};
use windows_sys::Win32::Foundation::HWND;

use super::win16_common_dialog_worker::{self as dialogs, RegisteredCommonDialogMessage};
use super::win16_window_worker::{NativeCallbackContext, WorkerState};

/// The captured termination state stays authoritative even when guest code
/// edits Flags or destroys its owner during the suspended callback.
pub(super) struct TerminalNotificationGuard {
    state: Rc<RefCell<WorkerState>>,
    notification: Option<Win16HostFindReplaceNotification>,
}

pub(super) fn terminal_guard(
    state: &Rc<RefCell<WorkerState>>,
    notification: Option<&Win16HostFindReplaceNotification>,
) -> TerminalNotificationGuard {
    TerminalNotificationGuard {
        state: Rc::clone(state),
        notification: notification.filter(|value| value.dialog_terminated).cloned(),
    }
}

impl Drop for TerminalNotificationGuard {
    fn drop(&mut self) {
        if let Some(notification) = self.notification.as_ref() {
            if let Err(error) = dialogs::finish_terminal(&self.state, notification) {
                super::win16_window_callbacks::fail_worker(&self.state, error);
            }
        }
    }
}

pub(super) fn classify(
    state: &Rc<RefCell<WorkerState>>,
    owner: Win16HostWindow,
    message: u32,
    native_l_param: isize,
) -> Result<RegisteredCommonDialogMessage, RuntimeError> {
    // RegisterWindowMessage assigns process-independent IDs in 0xC000..=0xFFFF.
    // Ordinary USER messages need neither registration nor family lookup.
    if !(0xC000..=u32::from(u16::MAX)).contains(&message) {
        return Ok(RegisteredCommonDialogMessage::NotFamily);
    }
    dialogs::classify_registered_message(state, owner, message as u16, native_l_param)
}

pub(super) fn write_output(
    state: &Rc<RefCell<WorkerState>>,
    message: u32,
    native_l_param: isize,
    receiver: Option<(Win16HostWindow, HWND)>,
    output: &Win16HostMessageOutput,
) -> bool {
    let Win16HostMessageOutput::FindReplace { request_id, update } = output else {
        return false;
    };
    let exact_source = {
        let state = state.borrow();
        state.live_callbacks.last().is_some_and(|frame| {
            frame.identity.is_some_and(|identity| {
                receiver == Some((identity.window, frame.hwnd))
            })
                && frame.message == Some(message)
                && frame.native_message_context == Some(NativeCallbackContext::FindReplace {
                    request_id: *request_id, native_l_param,
                })
        })
    };
    if !exact_source {
        return false;
    }
    match dialogs::apply_find_replace_update(
        state, *request_id, native_l_param, update.as_ref(),
    ) {
        Ok(true) => true,
        Ok(false) => {
            super::win16_window_position::report_diagnostic(state, Kind::CompatibilityGap,
                "Find/Replace callback output belongs to a retired dialog; output omitted");
            true
        }
        Err(error) => {
            super::win16_window_callbacks::fail_worker(state, error);
            false
        }
    }
}
