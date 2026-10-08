//! USER exit/session ABI policy and generic host-session requests.

use win16_abi::{Win16ReturnKind, Win16UserSessionRequest};

use super::{FamilyCompletion, Win16UserFamilyPreparation};
use crate::{Win16HostSessionOperation as SessionOperation, Win16HostUserServiceOperation};

pub(super) fn prepare(
    request: Win16UserSessionRequest,
    return_kind: Win16ReturnKind,
) -> Result<Win16UserFamilyPreparation, crate::RuntimeError> {
    use Win16UserFamilyPreparation as Prepared;

    let operation = match request {
        Win16UserSessionRequest::OldExitWindows => SessionOperation::LegacyOldExitWindows,
        Win16UserSessionRequest::ExitWindows { return_code, reserved } => {
            if reserved != 0 || return_code >> 16 != 0 {
                return Ok(Prepared::immediate(0, return_kind));
            }
            // The modern ExitWindows compatibility macro maps (0, 0) to
            // ExitWindowsEx(EWX_LOGOFF, 0); legacy nonzero codes are handled
            // only where the Win16 contract supplies a verified mapping.
            match return_code as u16 {
                0 => SessionOperation::RequestLogoff,
                // Windows 3.1 SDK Programmer's Reference, Volume 2 documents
                // 42h as restart Windows and 43h as reboot the system.
                0x0042 => SessionOperation::RestartWin16Session,
                0x0043 => SessionOperation::RequestReboot,
                code => SessionOperation::UnsupportedLegacyExitCode {
                    code: u32::from(code),
                },
            }
        }
        Win16UserSessionRequest::ExitWindowsExec { program, parameters } => {
            let Some(program) = program else {
                return Ok(Prepared::immediate(0, return_kind));
            };
            // The SDK lengths include the trailing NUL: 128 bytes for the
            // executable and 127 for the nullable parameter string.
            if program.is_empty()
                || program.len() > 127
                || parameters.as_ref().is_some_and(|value| value.len() > 126)
            {
                return Ok(Prepared::immediate(0, return_kind));
            }
            SessionOperation::RunAfterWin16Restart { program, parameters }
        }
    };

    Ok(Prepared::window(
        Win16HostUserServiceOperation::Session(operation),
        return_kind,
        FamilyCompletion::Session,
    ))
}
