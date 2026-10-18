//! Native USER family routing and callback-sensitive lifecycle tracking.

use std::cell::RefCell;
use std::rc::Rc;

use super::super::super::win16_modal::NativeModalOperationOutcome;
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostClipboardOperation as ClipboardOperation,
    Win16HostClipboardResult as ClipboardResult, Win16HostDialogOperation as DialogOperation,
    Win16HostDialogResult, Win16HostUserServiceOperation as UserServiceOperation,
    Win16HostSessionOperation as SessionOperation, Win16HostSessionResult,
    Win16HostUserServiceResult as UserServiceResult, Win16WindowResult,
};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::System::DataExchange::ChangeClipboardChain;
use windows_sys::Win32::UI::WindowsAndMessaging::IsWindow;

use super::{ClipboardViewerRegistration, WorkerState};

#[path = "win16_shutdown_dialog.rs"]
mod shutdown_dialog;

pub(super) fn execute(
    state: &Rc<RefCell<WorkerState>>,
    operation_id: u64,
    operation: UserServiceOperation,
    control_color_return: Option<&super::ControlColorReturnSlot>,
) -> Result<NativeModalOperationOutcome, RuntimeError> {
    match operation {
        UserServiceOperation::Dialog(DialogOperation::FatalAppExitMessage { message }) => {
            let codec = state.borrow().text_codec;
            super::super::super::win16_kernel_diagnostics::fatal_app_exit_message(
                codec,
                operation_id,
                &message,
            )
        }
        UserServiceOperation::Dialog(DialogOperation::FatalExitPrompt {
            error_code,
            caller_selector,
            caller_offset,
        }) => super::super::super::win16_kernel_diagnostics::fatal_exit_prompt(
            operation_id,
            error_code,
            caller_selector,
            caller_offset,
        ),
        operation => execute_regular(state, operation_id, operation, control_color_return)
            .map(NativeModalOperationOutcome::Returned),
    }
}

fn execute_regular(
    state: &Rc<RefCell<WorkerState>>,
    operation_id: u64,
    operation: UserServiceOperation,
    control_color_return: Option<&super::ControlColorReturnSlot>,
) -> Result<Win16WindowResult, RuntimeError> {
    match operation {
        UserServiceOperation::Dialog(DialogOperation::MessageBox {
            owner,
            text,
            caption,
            style,
        }) => super::super::win16_user_services_dialog::message_box(
            state,
            owner,
            text.as_deref(),
            caption.as_deref(),
            style,
        )
        .map(dialog_result),
        UserServiceOperation::Dialog(DialogOperation::Create {
            creation,
            guest_instance,
            owner,
            template,
            modal,
            init_parameter,
        }) => create_dialog(
            state,
            operation_id,
            creation,
            guest_instance,
            owner,
            template,
            modal,
            init_parameter,
        )
        .map(dialog_result),
        UserServiceOperation::Dialog(DialogOperation::End { dialog, result }) => Ok(dialog_result(
            super::super::win16_user_services_dialog::end(state, dialog, result),
        )),
        UserServiceOperation::Dialog(DialogOperation::IsMessage { dialog, message }) => {
            super::super::win16_user_services_dialog::is_message(state, dialog, message)
                .map(dialog_result)
        }
        UserServiceOperation::Dialog(DialogOperation::GetBaseUnits) => Ok(dialog_result(
            super::super::win16_user_services_dialog::base_units(),
        )),
        UserServiceOperation::Dialog(DialogOperation::DefaultProcedure {
            dialog,
            callback,
            message,
        }) => super::super::win16_user_services_dialog::default_procedure(
            state, dialog, callback, &message, control_color_return,
        )
        .map(dialog_result),
        UserServiceOperation::DialogControl(operation) => {
            super::super::win16_user_services_controls::execute(state, operation).map(|result| {
                Win16WindowResult::UserService(UserServiceResult::DialogControl(result))
            })
        }
        UserServiceOperation::Clipboard(operation) => execute_clipboard(state, operation),
        UserServiceOperation::SystemParameters(request) => {
            let codec = state.borrow().text_codec;
            super::super::win16_user_services_system_parameters::execute(codec, request).map(
                |result| {
                    Win16WindowResult::UserService(UserServiceResult::SystemParameters(result))
                },
            )
        }
        UserServiceOperation::Session(operation) => execute_session(operation).map(|result| {
            Win16WindowResult::UserService(UserServiceResult::Session(result))
        }),
        _ => Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "Win16 USER worker service has no connected native adapter",
        )),
    }
}

fn execute_session(operation: SessionOperation) -> Result<Win16HostSessionResult, RuntimeError> {
    match operation {
        SessionOperation::ShowShutdownDialog => Ok(shutdown_dialog::show()),
        SessionOperation::LegacyOldExitWindows => Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "USER ordinal 2 OldExitWindows is a local API without a documented host session mapping",
        )),
        SessionOperation::RestartWin16Session => Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "legacy ExitWindows EW_RESTARTWINDOWS requests restarting Win16 Windows, which has no single modern host session operation",
        )),
        SessionOperation::RunAfterWin16Restart { .. } => Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "legacy ExitWindowsExec requires the Windows-to-DOS-to-Windows launcher protocol, which has no connected host implementation",
        )),
        SessionOperation::UnsupportedLegacyExitCode { code } => Err(RuntimeError::new(
            Kind::CompatibilityGap,
            format!("legacy ExitWindows return/restart code 0x{code:08X} has no documented host mapping"),
        )),
    }
}

fn dialog_result(result: Win16HostDialogResult) -> Win16WindowResult {
    Win16WindowResult::UserService(UserServiceResult::Dialog(result))
}

fn create_dialog(
    state: &Rc<RefCell<WorkerState>>,
    operation: u64,
    creation: runtime::Win16CreationId,
    guest_instance: u16,
    owner: Option<runtime::Win16HostWindow>,
    template: runtime::Win16HostDialogTemplate,
    modal: bool,
    init_parameter: u32,
) -> Result<Win16HostDialogResult, RuntimeError> {
    // The dialog adapter encodes the native template first so each custom
    // control route can bind the exact host-owned creation-data address. It
    // installs that complete route before entering User32, which can invoke
    // the DLGPROC and custom class WndProcs synchronously.
    let result = super::super::win16_user_services_dialog::create(
        state,
        operation,
        creation,
        guest_instance,
        owner,
        template,
        modal,
        init_parameter,
        Some(super::host_dialog_proc),
    );
    let mut result = result?;
    if let Win16HostDialogResult::Created { mut creation, menu } = result {
        if let Some(window) = creation.live_window {
            let native = state.borrow().windows.get(&window).copied();
            if !native.is_some_and(|hwnd| !hwnd.is_null() && unsafe { IsWindow(hwnd) } != 0) {
                if let Some(native) = native {
                    super::remove_window_maps(state, window, native);
                }
                creation.live_window = None;
                result = Win16HostDialogResult::Created {
                    creation,
                    menu: None,
                };
            } else {
                result = Win16HostDialogResult::Created { creation, menu };
            }
        } else {
            result = Win16HostDialogResult::Created {
                creation,
                menu: None,
            };
        }
    }

    // DialogBox has completed its modal lifetime. A late or missing
    // WM_NCDESTROY must not leave a native route referring to a retired call.
    if modal {
        retire_dialog_routes_for_operation(state, operation);
    }
    Ok(result)
}

fn retire_dialog_routes_for_operation(state: &Rc<RefCell<WorkerState>>, operation: u64) {
    let retired = {
        let mut state = state.borrow_mut();
        let mut retired = Vec::new();
        state.dialog_routes_by_native.retain(|native, route| {
            if route.operation == operation {
                retired.push((*native, route.window));
                false
            } else {
                true
            }
        });
        retired
    };
    for (native, window) in retired {
        super::remove_window_maps(state, window, native as _);
    }
}

fn execute_clipboard(
    state: &Rc<RefCell<WorkerState>>,
    operation: ClipboardOperation,
) -> Result<Win16WindowResult, RuntimeError> {
    let result = super::super::win16_user_services_clipboard::execute(state, operation.clone())?;
    let raw_result = match &result {
        ClipboardResult::Sequenced { result, .. } => result.as_ref(),
        // Some checked stale-window failures are intentionally returned before
        // the sequence wrapper is constructed. Preserve those guest failures.
        unsequenced => unsequenced,
    };
    match (&operation, raw_result) {
        (ClipboardOperation::Open { .. }, ClipboardResult::Bool(true)) => {
            state.borrow_mut().clipboard_open = true;
        }
        (ClipboardOperation::Close, ClipboardResult::Bool(true)) => {
            state.borrow_mut().clipboard_open = false;
        }
        (
            ClipboardOperation::SetViewer {
                viewer: Some(window),
            },
            ClipboardResult::Window(next),
        ) => {
            let (native, next_native) = {
                let state = state.borrow();
                let native = state.windows.get(window).copied();
                let next_native = next.and_then(|next| state.windows.get(&next).copied());
                (native, next_native)
            };
            if let Some(native) = native.filter(|hwnd| unsafe { IsWindow(*hwnd) } != 0) {
                state.borrow_mut().clipboard_viewers.insert(
                    *window,
                    ClipboardViewerRegistration {
                        window: native as usize,
                        next_viewer: next_native.unwrap_or(std::ptr::null_mut()) as usize,
                    },
                );
            }
        }
        (ClipboardOperation::ChangeViewerChain { remove, .. }, ClipboardResult::Bool(true)) => {
            state.borrow_mut().clipboard_viewers.remove(remove);
        }
        _ => {}
    }
    Ok(Win16WindowResult::UserService(
        UserServiceResult::Clipboard(result),
    ))
}

pub(in super::super) fn update_clipboard_viewer_chain(
    state: &Rc<RefCell<WorkerState>>,
    viewer: runtime::Win16HostWindow,
    removed: HWND,
    next: HWND,
) {
    let mut state = state.borrow_mut();
    if let Some(registration) = state.clipboard_viewers.get_mut(&viewer) {
        if registration.next_viewer == removed as usize {
            registration.next_viewer = next as usize;
        }
    }
}

/// Remove a worker-owned guest viewer before its native HWND is destroyed.
/// ChangeClipboardChain may synchronously notify the next viewer, so no state
/// borrow is held while Windows sends that message.
pub(in super::super) fn retire_clipboard_viewer(
    state: &Rc<RefCell<WorkerState>>,
    viewer: runtime::Win16HostWindow,
) {
    let registration = state.borrow().clipboard_viewers.get(&viewer).copied();
    let Some(registration) = registration else {
        return;
    };
    let hwnd = registration.window as HWND;
    let removed = unsafe { IsWindow(hwnd) } == 0
        || unsafe { ChangeClipboardChain(hwnd, registration.next_viewer as HWND) != 0 };
    if removed {
        let mut state = state.borrow_mut();
        if state.clipboard_viewers.get(&viewer).is_some_and(|current| {
            current.window == registration.window && current.next_viewer == registration.next_viewer
        }) {
            state.clipboard_viewers.remove(&viewer);
        }
    }
}
