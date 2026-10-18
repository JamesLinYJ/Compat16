//! HWND resolution and diagnostics around the owned native printer call.
use super::*;
use runtime::{Win16HostPrinterMode, Win16HostPrinterModeResult};

pub(super) fn execute(
    state: &Rc<RefCell<WorkerState>>,
    request: Win16HostPrinterMode,
) -> Result<ResultValue, RuntimeError> {
    let failure = || {
        ResultValue::PrinterMode(Win16HostPrinterModeResult {
            value: -1,
            output: None,
        })
    };
    let owner = match request.owner {
        Some(token) => match win16_window_identity::resolve_user_window(state, token) {
            Some(owner) => owner,
            None => return Ok(failure()),
        },
        None => ptr::null_mut(),
    };
    // A property sheet can call back into this worker. Never hold a RefCell
    // guard across the native operation.
    let codec = { state.borrow().text_codec };
    match crate::windows::win16_printer_mode::execute(request, owner, codec) {
        Ok(outcome) => {
            for (needed, message) in [
                (
                    outcome.truncated,
                    "ExtDeviceMode fixed names were truncated to Win16 byte fields",
                ),
                (
                    outcome.used_default_char,
                    "ExtDeviceMode fixed names used guest-code-page replacement characters",
                ),
            ] {
                if needed {
                    super::super::win16_window_position::report_diagnostic(
                        state,
                        Kind::CompatibilityGap,
                        message,
                    );
                }
            }
            Ok(ResultValue::PrinterMode(outcome.result))
        }
        Err(error)
            if matches!(
                error.kind(),
                Kind::InvalidInput
                    | Kind::CompatibilityGap
                    | Kind::HostFailure
                    | Kind::ResourceExhausted
            ) =>
        {
            super::super::win16_window_position::report_diagnostic(
                state,
                error.kind(),
                &format!("ExtDeviceMode could not return printer settings: {error}"),
            );
            Ok(failure())
        }
        Err(error) => Err(error),
    }
}
