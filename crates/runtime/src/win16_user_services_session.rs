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
        Win16UserSessionRequest::ExitWindows {
            return_code,
            reserved,
        } => {
            if reserved != 0 || return_code >> 16 != 0 {
                return Ok(Prepared::immediate(0, return_kind));
            }
            // A legacy session request must not authorize a host session
            // change. Let the person using Windows choose an action instead.
            match return_code as u16 {
                0 | 0x0043 => SessionOperation::ShowShutdownDialog,
                // Restarting the Win16 environment itself still requires a
                // separate runtime protocol rather than a host session action.
                0x0042 => SessionOperation::RestartWin16Session,
                code => SessionOperation::UnsupportedLegacyExitCode {
                    code: u32::from(code),
                },
            }
        }
        Win16UserSessionRequest::ExitWindowsExec {
            program,
            parameters,
        } => {
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
            SessionOperation::RunAfterWin16Restart {
                program,
                parameters,
            }
        }
    };

    Ok(Prepared::window(
        Win16HostUserServiceOperation::Session(operation),
        return_kind,
        FamilyCompletion::Session,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_exit_normal_and_reboot_requests_require_the_shell_chooser() {
        for return_code in [0, 0x0043] {
            let prepared = prepare(
                Win16UserSessionRequest::ExitWindows {
                    return_code,
                    reserved: 0,
                },
                Win16ReturnKind::Word,
            )
            .unwrap();
            assert!(matches!(
                prepared,
                Win16UserFamilyPreparation::WindowService {
                    operation: Win16HostUserServiceOperation::Session(
                        SessionOperation::ShowShutdownDialog
                    ),
                    ..
                }
            ));
        }
    }

    #[test]
    fn session_exit_invalid_frames_return_false_without_a_host_request() {
        for (return_code, reserved) in [(0, 1), (0x10000, 0), (0x10043, 0)] {
            let prepared = prepare(
                Win16UserSessionRequest::ExitWindows {
                    return_code,
                    reserved,
                },
                Win16ReturnKind::Word,
            )
            .unwrap();
            assert!(matches!(
                prepared,
                Win16UserFamilyPreparation::Immediate { value: 0, .. }
            ));
        }
    }
}
