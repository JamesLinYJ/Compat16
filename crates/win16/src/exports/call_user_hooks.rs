//! Typed stack decoding for the Win16 USER hook API family.

use super::super::Win16ExportId;
use super::super::request::Win16ApiRequest;
use super::call_helpers::{dword_argument, word_argument};
use super::{Win16UserHooksRequest, Win16UserRequest};
use crate::{Win16Argument, Win16Error};

/// Decode hook arguments without dereferencing any FAR value. MSG16 and the
/// DefHookProc previous-procedure slot remain guest addresses for checked
/// runtime handling.
pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[Win16Argument],
) -> Result<Win16ApiRequest, Win16Error> {
    let request = match export {
        Win16ExportId::UserSetWindowsHook => Win16UserHooksRequest::SetWindowsHook {
            hook_type: word_argument(arguments, 0)? as i16,
            procedure: dword_argument(arguments, 1)?,
        },
        Win16ExportId::UserCallMsgFilter => Win16UserHooksRequest::CallMsgFilter {
            message: dword_argument(arguments, 0)?,
            code: word_argument(arguments, 1)? as i16,
        },
        Win16ExportId::UserUnhookWindowsHook => Win16UserHooksRequest::UnhookWindowsHook {
            hook_type: word_argument(arguments, 0)? as i16,
            procedure: dword_argument(arguments, 1)?,
        },
        Win16ExportId::UserDefHookProc => Win16UserHooksRequest::DefHookProc {
            code: word_argument(arguments, 0)? as i16,
            w_param: word_argument(arguments, 1)?,
            l_param: dword_argument(arguments, 2)?,
            hook_slot: dword_argument(arguments, 3)?,
        },
        Win16ExportId::UserSetWindowsHookEx => Win16UserHooksRequest::SetWindowsHookEx {
            hook_type: word_argument(arguments, 0)? as i16,
            procedure: dword_argument(arguments, 1)?,
            instance: word_argument(arguments, 2)?,
            task: word_argument(arguments, 3)?,
        },
        Win16ExportId::UserUnhookWindowsHookEx => Win16UserHooksRequest::UnhookWindowsHookEx {
            hook: dword_argument(arguments, 0)?,
        },
        Win16ExportId::UserCallNextHookEx => Win16UserHooksRequest::CallNextHookEx {
            hook: dword_argument(arguments, 0)?,
            code: word_argument(arguments, 1)? as i16,
            w_param: word_argument(arguments, 2)?,
            l_param: dword_argument(arguments, 3)?,
        },
        _ => return Err(Win16Error::InvalidRange),
    };

    Ok(Win16ApiRequest::User(Win16UserRequest::Hooks(request)))
}
