//! Native KERNEL diagnostic adapters. Fatal UI is called only by the USER worker.

use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostDialogResult, Win16HostFatalExitChoice,
    Win16HostUserServiceResult, Win16NativeModalCancelSignal, Win16NativeModalCancellation,
    Win16WindowResult,
};
use windows_sys::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DLGTEMPLATE, DialogBoxIndirectParamW, EndDialog, MessageBoxW, WM_CLOSE, WM_COMMAND,
    WM_INITDIALOG,
};

use super::win16_modal::{
    ModalCancellationSignal, ModalDisposition, ModalScope, NativeModalInvocation,
    NativeModalOperationOutcome,
};
#[path = "win16_kernel_diagnostics_template.rs"]
mod template;
use template::{
    FATAL_EXIT_ABORT_ID, FATAL_EXIT_BREAK_ID, FATAL_EXIT_IGNORE_ID, fatal_exit_template,
};

// The supported Windows hosts are 64-bit; WORD dialog IDs fit losslessly in
// the pointer-sized native dialog result.
const IDCANCEL_ID: u16 = 2;
const FATAL_APP_EXIT_IDOK: i32 = 1;
const FATAL_APP_EXIT_STYLE: u32 = 0x0010; // MB_ICONHAND | MB_OK
const FATAL_APP_EXIT_CAPTION: &[u8] = b"Application Error";

struct FatalExitCallbackState {
    dialog: HWND,
    failure: Option<RuntimeError>,
    modal_scope: Option<ModalScope>,
}

thread_local! {
    // FatalExit prompts can nest during guest reentry on the owner thread.
    static ACTIVE_FATAL_EXIT_DIALOGS: RefCell<Vec<*mut FatalExitCallbackState>> = const {
        RefCell::new(Vec::new())
    };
}

/// Guest bytes are decoded using the instance code page into owned UTF-16;
/// guest memory is never passed to the native debugging channel.
pub(super) fn output_debug_string(
    codec: super::guest_text::GuestTextCodec,
    message: &[u8],
) -> Result<(), RuntimeError> {
    if message.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 OutputDebugString received an embedded NUL",
        ));
    }
    let owned = codec.to_wide_z(message)?;

    // SAFETY: `owned` is an owned NUL-terminated UTF-16 buffer and stays live
    // for this synchronous Windows API call.
    unsafe { OutputDebugStringW(owned.as_ptr()) };
    Ok(())
}

/// FatalAppExit has a stricter contract than the general USER MessageBox
/// service: only IDOK acknowledges the task-ending request, while zero is a
/// native failure and must retain its immediate last-error value.
pub(super) fn fatal_app_exit_message(
    codec: super::guest_text::GuestTextCodec,
    operation_id: u64,
    message: &[u8],
) -> Result<NativeModalOperationOutcome, RuntimeError> {
    let text_z = wide_z(codec, message, "Win16 FatalAppExit text")?;
    let caption_z = wide_z(codec, FATAL_APP_EXIT_CAPTION, "Win16 FatalAppExit caption")?;

    let call = super::win16_modal::with_message_box(operation_id, || {
        // SAFETY: both arguments are host-owned NUL-terminated UTF-16 buffers
        // held across this synchronous USER-worker call; there is no HWND.
        let value = unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                text_z.as_ptr(),
                caption_z.as_ptr(),
                FATAL_APP_EXIT_STYLE,
            )
        };
        // Capture this before modal-hook cleanup or any subsequent Win32 call.
        let last_error = (value == 0).then(|| crate::windows::win32_safe::last_error());
        (value, last_error)
    })?;
    let call = match call {
        NativeModalInvocation::NotStarted { operation_id } => {
            return Ok(cancelled_modal_outcome(
                operation_id,
                None,
                None,
                Win16NativeModalCancelSignal::BeforeEntry,
                None,
                Vec::new(),
                None,
            ));
        }
        NativeModalInvocation::Returned(call) => call,
    };
    let (value, last_error) = call.value;
    if let ModalDisposition::Cancelled { signal, scope_id } = call.disposition {
        return Ok(cancelled_modal_outcome(
            operation_id,
            Some(i64::from(value)),
            last_error,
            host_cancel_signal(signal),
            Some(scope_id),
            call.retired_guest_work,
            call.cleanup_error,
        ));
    }
    let mut failure = match (value, last_error) {
        (0, Some(last_error)) => Some(RuntimeError::with_source(
            Kind::HostFailure,
            "show the Win16 FatalAppExit message box",
            NativeModalError { last_error },
        )),
        (0, None) => Some(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 FatalAppExit failure omitted its immediate last-error capture",
        )),
        (result, _) if result != FATAL_APP_EXIT_IDOK => Some(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 FatalAppExit message box returned a non-IDOK result",
        )),
        _ => None,
    };
    if let Some(cleanup) = call.cleanup_error {
        failure = Some(match failure {
            Some(primary) => combine_fatal_exit_failures(
                primary,
                cleanup,
                "Win16 FatalAppExit message and modal cleanup both failed",
            ),
            None => cleanup,
        });
    }
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(NativeModalOperationOutcome::Returned(
        Win16WindowResult::UserService(Win16HostUserServiceResult::Dialog(
            Win16HostDialogResult::FatalAppExitAcknowledged,
        )),
    ))
}

fn wide_z(
    codec: super::guest_text::GuestTextCodec,
    message: &[u8],
    operation: &'static str,
) -> Result<Vec<u16>, RuntimeError> {
    if message.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            format!("{operation} contains an embedded NUL"),
        ));
    }
    codec.to_wide_z(message)
}

/// Present the three documented FatalExit choices on the active USER worker.
/// The caller passes a checked guest return address, not a host address or a
/// fabricated complete stack trace. SDK 3.1 describes the prompt for debug
/// Windows; this adapter intentionally models that choice workflow.
pub(super) fn fatal_exit_prompt(
    operation_id: u64,
    error_code: i16,
    caller_selector: u16,
    caller_offset: u16,
) -> Result<NativeModalOperationOutcome, RuntimeError> {
    let stack_error = if error_code == -1 {
        " (-1 is reserved for stack overflow)"
    } else {
        ""
    };
    let text = format!(
        "FatalExit error {error_code}{stack_error} at guest return address {caller_selector:04X}:{caller_offset:04X}.\nA complete symbolic stack trace is unavailable."
    );
    let template = fatal_exit_template(&text)?;
    let modal_scope = match ModalScope::begin_dialog(operation_id)? {
        Some(scope) => scope,
        None => {
            return Ok(cancelled_modal_outcome(
                operation_id,
                None,
                None,
                Win16NativeModalCancelSignal::BeforeEntry,
                None,
                Vec::new(),
                None,
            ));
        }
    };
    let mut callback_state = Box::new(FatalExitCallbackState {
        dialog: std::ptr::null_mut(),
        failure: None,
        modal_scope: Some(modal_scope),
    });
    let callback_state_pointer = (&mut *callback_state) as *mut FatalExitCallbackState;
    ACTIVE_FATAL_EXIT_DIALOGS.with(|active| {
        let mut active = active.try_borrow_mut().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 FatalExit callback-state stack is already borrowed",
            )
        })?;
        active.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "track nested Win16 FatalExit dialog callback state",
                error,
            )
        })?;
        active.push(callback_state_pointer);
        Ok::<(), RuntimeError>(())
    })?;
    let native_call_started = callback_state
        .modal_scope
        .as_mut()
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 FatalExit modal scope disappeared before DialogBox entry",
            )
        })
        .and_then(ModalScope::native_call_started);
    let entered = match native_call_started {
        Ok(entered) => entered,
        Err(error) => {
            return Err(match pop_fatal_exit_dialog_state(callback_state_pointer) {
                Ok(()) => error,
                Err(cleanup) => combine_fatal_exit_failures(
                    error,
                    cleanup,
                    "Win16 FatalExit modal preparation and callback-state cleanup both failed",
                ),
            });
        }
    };
    if !entered {
        drop(callback_state.modal_scope.take());
        return match pop_fatal_exit_dialog_state(callback_state_pointer) {
            Ok(()) => Ok(cancelled_modal_outcome(
                operation_id,
                None,
                None,
                Win16NativeModalCancelSignal::BeforeEntry,
                None,
                Vec::new(),
                None,
            )),
            Err(error) => Err(error),
        };
    }
    // SAFETY: `template` is DWORD-aligned owned storage and remains alive for
    // DialogBoxIndirectParamW's synchronous owner-thread modal dispatch. The
    // callback is static code, and its host-owned state is registered above.
    let result = unsafe {
        DialogBoxIndirectParamW(
            std::ptr::null_mut(),
            template.as_ptr().cast::<DLGTEMPLATE>(),
            std::ptr::null_mut(),
            Some(fatal_exit_dialog_proc),
            0,
        )
    };
    // Read last-error before scope.finish can unhook or call another Win32 API.
    let dialog_error = (result == -1).then(|| crate::windows::win32_safe::last_error());
    let (mut scope_disposition, scope_result) = match callback_state.modal_scope.take() {
        Some(scope) => {
            let disposition = scope.disposition();
            (Some(disposition), scope.finish())
        }
        None => (
            None,
            Err(super::win16_modal::ModalScopeFinishError {
                cause: RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 FatalExit modal scope disappeared before DialogBox returned",
                ),
                retired_guest_work: Vec::new(),
            }),
        ),
    };
    let pop_result = pop_fatal_exit_dialog_state(callback_state_pointer);
    let mut cleanup_error = callback_state.failure.take();
    let retired_guest_work = match scope_result {
        Ok(retirement) => {
            if matches!(retirement.disposition, ModalDisposition::Cancelled { .. }) {
                scope_disposition = Some(retirement.disposition);
            }
            retirement.retired_guest_work
        }
        Err(mut cleanup) => {
            merge_fatal_exit_failure(
                &mut cleanup_error,
                cleanup.cause,
                "Win16 FatalExit callback and modal cleanup both failed",
            );
            std::mem::take(&mut cleanup.retired_guest_work)
        }
    };
    if let Err(cleanup) = pop_result {
        merge_fatal_exit_failure(
            &mut cleanup_error,
            cleanup,
            "Win16 FatalExit operation and callback-state cleanup both failed",
        );
    }
    let cancellation_signal = match scope_disposition {
        Some(ModalDisposition::Cancelled { signal, .. }) => Some(host_cancel_signal(signal)),
        _ => None,
    };
    if let Some(signal) = cancellation_signal {
        if let Some(native_failure) = native_failure_for_dialog_result(result, dialog_error) {
            merge_fatal_exit_failure(
                &mut cleanup_error,
                native_failure,
                "Win16 FatalExit cancellation and native prompt failure both occurred",
            );
        }
        let scope_id = match scope_disposition {
            Some(ModalDisposition::Cancelled { scope_id, .. }) => Some(scope_id),
            _ => None,
        };
        return Ok(cancelled_modal_outcome(
            operation_id,
            Some(result as i64),
            dialog_error,
            signal,
            scope_id,
            retired_guest_work,
            cleanup_error,
        ));
    }
    if let Some(native_failure) = native_failure_for_dialog_result(result, dialog_error) {
        return Err(match cleanup_error {
            Some(cleanup) => combine_fatal_exit_failures(
                native_failure,
                cleanup,
                "Win16 FatalExit native prompt and cleanup both failed",
            ),
            None => native_failure,
        });
    }
    if let Some(cleanup) = cleanup_error {
        return Err(cleanup);
    }
    if !matches!(scope_disposition, Some(ModalDisposition::Returned)) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 FatalExit prompt returned without a modal disposition",
        ));
    }
    let choice = match result {
        value if value == FATAL_EXIT_ABORT_ID as isize => Win16HostFatalExitChoice::Abort,
        value if value == FATAL_EXIT_BREAK_ID as isize => Win16HostFatalExitChoice::Break,
        value if value == FATAL_EXIT_IGNORE_ID as isize || value == IDCANCEL_ID as isize => {
            Win16HostFatalExitChoice::Ignore
        }
        -1 => Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 FatalExit modal failure had no captured native cause",
        ))?,
        _ => Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 FatalExit prompt returned an unknown choice",
        ))?,
    };
    Ok(NativeModalOperationOutcome::Returned(
        Win16WindowResult::UserService(Win16HostUserServiceResult::Dialog(
            Win16HostDialogResult::FatalExitChoice(choice),
        )),
    ))
}

fn native_failure_for_dialog_result(result: isize, error: Option<u32>) -> Option<RuntimeError> {
    if result != -1 {
        return None;
    }
    Some(match error {
        Some(last_error) => RuntimeError::with_source(
            Kind::HostFailure,
            "create the Win16 FatalExit prompt on the USER worker",
            NativeModalError { last_error },
        ),
        None => RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 FatalExit DialogBox failure omitted its immediate last-error capture",
        ),
    })
}

#[derive(Debug)]
struct NativeModalError {
    last_error: u32,
}

impl std::fmt::Display for NativeModalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "native modal API failed with last error {}",
            self.last_error
        )
    }
}

impl std::error::Error for NativeModalError {}

fn cancelled_modal_outcome(
    operation_id: u64,
    native_result: Option<i64>,
    native_last_error: Option<u32>,
    signal: Win16NativeModalCancelSignal,
    scope_id: Option<u64>,
    retired_guest_work: Vec<runtime::Win16NativeModalGuestWorkRetirement>,
    cleanup_error: Option<RuntimeError>,
) -> NativeModalOperationOutcome {
    NativeModalOperationOutcome::Cancelled {
        receipt: Win16NativeModalCancellation {
            operation_id,
            scope_id,
            native_result,
            native_last_error,
            signal,
            retired_guest_work,
        },
        cleanup_error,
    }
}

fn host_cancel_signal(signal: ModalCancellationSignal) -> Win16NativeModalCancelSignal {
    match signal {
        ModalCancellationSignal::OwnerThreadPostQuit => {
            Win16NativeModalCancelSignal::OwnerThreadQuit
        }
        ModalCancellationSignal::DialogEndDialog => Win16NativeModalCancelSignal::DialogEnd,
    }
}

fn merge_fatal_exit_failure(
    destination: &mut Option<RuntimeError>,
    additional: RuntimeError,
    context: &'static str,
) {
    *destination = Some(match destination.take() {
        Some(primary) => combine_fatal_exit_failures(primary, additional, context),
        None => additional,
    });
}

// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn fatal_exit_dialog_proc(
    dialog: HWND,
    message: u32,
    w_param: WPARAM,
    _l_param: LPARAM,
) -> isize {
    match catch_unwind(AssertUnwindSafe(|| {
        fatal_exit_dialog_message(dialog, message, w_param)
    })) {
        Ok(result) => result,
        Err(_) => {
            record_fatal_exit_dialog_failure(
                RuntimeError::new(
                    Kind::HostFailure,
                    "Win16 FatalExit dialog callback panicked",
                ),
                dialog,
                message == WM_INITDIALOG,
            );
            if let Err(cleanup) = close_fatal_exit_dialog_after_callback_failure(dialog) {
                record_fatal_exit_dialog_failure(cleanup, dialog, message == WM_INITDIALOG);
            }
            0
        }
    }
}

fn fatal_exit_dialog_message(dialog: HWND, message: u32, w_param: WPARAM) -> isize {
    if message == WM_INITDIALOG {
        if let Err(error) = bind_fatal_exit_dialog(dialog) {
            record_fatal_exit_dialog_failure(error, dialog, true);
            if let Err(cleanup) = close_fatal_exit_dialog_after_callback_failure(dialog) {
                record_fatal_exit_dialog_failure(cleanup, dialog, true);
            }
            return 0;
        }
        return 1;
    }
    match handle_fatal_exit_modal_message(dialog, message, w_param) {
        Ok(true) => return 1,
        Ok(false) => {}
        Err(error) => {
            record_fatal_exit_dialog_failure(error, dialog, false);
            if let Err(cleanup) = close_fatal_exit_dialog_after_callback_failure(dialog) {
                record_fatal_exit_dialog_failure(cleanup, dialog, false);
            }
            return 0;
        }
    }
    let chosen = if message == WM_COMMAND {
        match (w_param & 0xffff) as u16 {
            FATAL_EXIT_ABORT_ID => Some(FATAL_EXIT_ABORT_ID),
            FATAL_EXIT_BREAK_ID => Some(FATAL_EXIT_BREAK_ID),
            FATAL_EXIT_IGNORE_ID | IDCANCEL_ID => Some(FATAL_EXIT_IGNORE_ID),
            _ => None,
        }
    } else if message == WM_CLOSE {
        Some(FATAL_EXIT_IGNORE_ID)
    } else {
        None
    };
    if let Some(result) = chosen {
        // SAFETY: User32 supplied the live modal dialog HWND to its DLGPROC.
        if unsafe { EndDialog(dialog, result as isize) } == 0 {
            let error = crate::windows::win32_safe::last_error();
            record_fatal_exit_dialog_failure(
                RuntimeError::with_source(
                    Kind::HostFailure,
                    "close the Win16 FatalExit dialog",
                    std::io::Error::from_raw_os_error(error as i32),
                ),
                dialog,
                false,
            );
            return 0;
        }
        1
    } else {
        0
    }
}

fn bind_fatal_exit_dialog(dialog: HWND) -> Result<(), RuntimeError> {
    ACTIVE_FATAL_EXIT_DIALOGS.with(|active| {
        let active = active.try_borrow().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 FatalExit callback-state stack is already borrowed",
            )
        })?;
        let state = active.last().copied().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 FatalExit initialization has no registered prompt state",
            )
        })?;
        // SAFETY: every registered pointer targets a Box kept alive until its
        // synchronous DialogBoxIndirectParamW call returns.
        unsafe {
            if !(*state).dialog.is_null() {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 FatalExit state was bound to more than one dialog",
                ));
            }
            (*state)
                .modal_scope
                .as_mut()
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 FatalExit modal scope disappeared during WM_INITDIALOG",
                    )
                })?
                .bind_dialog(dialog)?;
            (*state).dialog = dialog;
        }
        Ok(())
    })
}

fn handle_fatal_exit_modal_message(
    dialog: HWND,
    message: u32,
    w_param: WPARAM,
) -> Result<bool, RuntimeError> {
    let state = ACTIVE_FATAL_EXIT_DIALOGS.with(|active| {
        active.try_borrow().ok().and_then(|active| {
            active
                .iter()
                .rev()
                .copied()
                // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                .find(|state| !state.is_null() && unsafe { (**state).dialog == dialog })
        })
    });
    let Some(state) = state else {
        return Ok(false);
    };
    // SAFETY: HWND lookup found the Box-backed prompt state bound by its
    // WM_INITDIALOG, and this callback runs before its native modal call returns.
    unsafe {
        (*state)
            .modal_scope
            .as_ref()
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 FatalExit modal scope disappeared in its DLGPROC",
                )
            })?
            .handle_cancel(dialog, message, w_param)
    }
}

fn close_fatal_exit_dialog_after_callback_failure(dialog: HWND) -> Result<(), RuntimeError> {
    // SAFETY: this is the live HWND supplied by User32 for our DLGPROC.
    let result = unsafe { EndDialog(dialog, IDCANCEL_ID as isize) };
    if result != 0 {
        return Ok(());
    }
    let error = crate::windows::win32_safe::last_error();
    Err(RuntimeError::with_source(
        Kind::HostFailure,
        "close the Win16 FatalExit dialog after a callback failure",
        std::io::Error::from_raw_os_error(error as i32),
    ))
}

fn record_fatal_exit_dialog_failure(error: RuntimeError, dialog: HWND, initializing: bool) {
    let state = ACTIVE_FATAL_EXIT_DIALOGS.with(|active| {
        active.try_borrow().ok().and_then(|active| {
            let matching_dialog = active.iter().rev().copied().find(|state| {
                // SAFETY: entries remain Box-backed until their synchronous
                // DialogBoxIndirectParamW call returns.
                !state.is_null() && unsafe { (**state).dialog == dialog }
            });
            let pending_creation = || {
                let pending_creation = active.last().copied().filter(|state| {
                    // Messages may arrive before WM_INITDIALOG records the HWND.
                    // The unbound top cookie belongs to the innermost creation.
                    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
                    !state.is_null() && unsafe { (**state).dialog.is_null() }
                });
                pending_creation
            };
            if initializing {
                matching_dialog.or_else(|| active.last().copied().filter(|state| !state.is_null()))
            } else {
                matching_dialog.or_else(pending_creation)
            }
        })
    });
    if let Some(state) = state {
        // SAFETY: DialogBoxIndirectParamW invokes this callback synchronously;
        // the matched HWND belongs to this Box-backed live prompt state.
        unsafe {
            (*state).failure = Some(match (*state).failure.take() {
                Some(primary) => combine_fatal_exit_failures(
                    primary,
                    error,
                    "Win16 FatalExit callback and dialog cleanup both failed",
                ),
                None => error,
            });
        }
    }
}

fn combine_fatal_exit_failures(
    primary: RuntimeError,
    additional: RuntimeError,
    context: &'static str,
) -> RuntimeError {
    let kind = primary.kind().with_cleanup(additional.kind());
    RuntimeError::with_source(
        kind,
        context,
        FatalExitFailurePair {
            primary,
            additional,
        },
    )
}

#[derive(Debug)]
struct FatalExitFailurePair {
    primary: RuntimeError,
    additional: RuntimeError,
}

impl std::fmt::Display for FatalExitFailurePair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; additional failure: {}",
            self.primary, self.additional
        )
    }
}

impl std::error::Error for FatalExitFailurePair {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}

fn pop_fatal_exit_dialog_state(expected: *mut FatalExitCallbackState) -> Result<(), RuntimeError> {
    ACTIVE_FATAL_EXIT_DIALOGS.with(|active| {
        let mut active = active.try_borrow_mut().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 FatalExit callback-state stack is already borrowed",
            )
        })?;
        let popped = active.pop();
        if popped == Some(expected) {
            return Ok(());
        }
        if let Some(popped) = popped {
            active.push(popped);
        }
        if let Some(index) = active.iter().rposition(|state| *state == expected) {
            active.remove(index);
        }
        Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 FatalExit dialog callback states did not unwind in stack order",
        ))
    })
}
