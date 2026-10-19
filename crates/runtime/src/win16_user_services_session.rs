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
        Win16UserSessionRequest::OldExitWindows => {
            return Ok(Prepared::TerminateTask { status: 0 });
        }
        Win16UserSessionRequest::ExitWindows {
            return_code,
            reserved,
        } => SessionOperation::ExitWindows {
            return_code,
            reserved,
        },
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
    fn session_exit_wow_bridge_preserves_both_original_arguments() {
        for (return_code, reserved) in [
            (0, 0),
            (0x0042, 0),
            (0x0043, 0),
            (0x1234_5678, 0x9abc),
            (u32::MAX, u16::MAX),
        ] {
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
                Win16UserFamilyPreparation::WindowService {
                    operation: Win16HostUserServiceOperation::Session(
                        SessionOperation::ExitWindows {
                            return_code: forwarded_dword,
                            reserved: forwarded_word,
                        }
                    ),
                    ..
                } if forwarded_dword == return_code && forwarded_word == reserved
            ));
        }
    }
}
