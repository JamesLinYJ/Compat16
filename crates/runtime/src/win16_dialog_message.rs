//! Marshal guest MSG16 values for the native dialog manager.

use win16_abi::{user_abi::Msg16, Win16ReturnKind};

use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win16HostDialogOperation as DialogOperation, Win16HostPoint,
    Win16HostQueuedMessage, Win16HostUserServiceOperation, Win16MessageParam,
    Win16MessageSource, Win16ScalarMessage, Win16WindowInputMessage,
};

use super::{FamilyCompletion, Win16State, Win16UserFamilyPreparation};

/// Convert a dialog and guest MSG16 into an owned host operation. Any
/// unsupported or unmapped guest value returns the documented false result;
/// the host never receives guest pointer or HWND bits as native values.
pub(super) fn prepare(
    state: &mut Win16State,
    dialog: u16,
    message: Msg16,
    host: &mut impl RuntimeHost,
    return_kind: Win16ReturnKind,
) -> Result<Win16UserFamilyPreparation, RuntimeError> {
    let Some(dialog) = state.dialog_window(dialog) else {
        return Ok(Win16UserFamilyPreparation::immediate(0, return_kind));
    };
    let window = match state.dialog_window(message.hwnd) {
        Some(window) => Some(window),
        None if message.hwnd == 0 => None,
        None => return Ok(Win16UserFamilyPreparation::immediate(0, return_kind)),
    };
    let parameter = if Win16WindowInputMessage::accepts(message.message) {
        let Some(input) = state.window_input_from_guest(
            message.message,
            message.w_param,
            message.l_param,
        ) else {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                format!("IsDialogMessage 0x{:04X} has an unmapped HWND parameter",
                    message.message),
            ));
            return Ok(Win16UserFamilyPreparation::immediate(0, return_kind));
        };
        Win16MessageParam::WindowInput(input)
    } else if message.message == 0x0111 {
        let command = super::super::messages::unpack_win16_command(
            message.w_param, message.l_param,
        );
        let control = if command.control == 0 {
            None
        } else if let Some(control) = state.window_handles.get(&command.control).copied() {
            Some(control)
        } else {
            host.report_diagnostic(&Diagnostic::warning(
                Kind::CompatibilityGap,
                format!("IsDialogMessage WM_COMMAND refers to unmapped HWND16 0x{:04X}",
                    command.control),
            ));
            return Ok(Win16UserFamilyPreparation::immediate(0, return_kind));
        };
        Win16MessageParam::Command {
            control,
            notify: command.notify,
            control_parent: None,
        }
    } else if Win16ScalarMessage::is_timer_message(message.message) && message.l_param != 0 {
        // A queued Win16 timer may carry a guest TIMERPROC FAR address.
        // Native IsDialogMessage can dispatch the MSG, so never let that
        // guest address become a native TIMERPROC.
        host.report_diagnostic(&Diagnostic::warning(
            Kind::CompatibilityGap,
            "IsDialogMessage timer callback needs timer-aware dispatch",
        ));
        return Ok(Win16UserFamilyPreparation::immediate(0, return_kind));
    } else if Win16ScalarMessage::from_raw(message.message).is_some() {
        Win16MessageParam::Scalar(message.l_param)
    } else if message.message >= 0x0400 {
        // Application-defined messages remain opaque guest bits. The host
        // adapter must not dereference their LPARAM.
        Win16MessageParam::GuestBits(message.l_param)
    } else {
        // Other standard messages can carry guest pointers, handles or nested
        // structures that do not have an owned conversion yet.
        host.report_diagnostic(&Diagnostic::warning(
            Kind::CompatibilityGap,
            format!("IsDialogMessage cannot safely marshal Win16 message 0x{:04X}",
                message.message),
        ));
        return Ok(Win16UserFamilyPreparation::immediate(0, return_kind));
    };

    Ok(Win16UserFamilyPreparation::window(
        Win16HostUserServiceOperation::Dialog(DialogOperation::IsMessage {
            dialog,
            message: Win16HostQueuedMessage {
                source: Win16MessageSource::GuestMessage,
                window,
                message: message.message,
                w_param: message.w_param,
                l_param: parameter,
                time: message.time,
                point: Win16HostPoint {
                    x: i32::from(message.pt.x),
                    y: i32::from(message.pt.y),
                },
            },
        }),
        return_kind,
        FamilyCompletion::DialogIsMessage,
    ))
}
