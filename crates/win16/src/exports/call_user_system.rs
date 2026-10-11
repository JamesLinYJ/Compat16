//! Stack argument decoding for USER time, input-state, and metrics exports.

use super::super::Win16ExportId;
use super::super::request::Win16ApiRequest;
use super::call_helpers::word_argument;
use crate::Win16Error;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[crate::Win16Argument],
) -> Result<Win16ApiRequest, Win16Error> {
    Ok(match export {
        Win16ExportId::UserWNetGetCaps => Win16ApiRequest::User(super::Win16UserRequest::Runtime(
            super::Win16UserRuntimeRequest::WNetGetCaps { index: word_argument(arguments, 0)? },
        )),
        Win16ExportId::UserGetTickCount => Win16ApiRequest::User(super::Win16UserRequest::Runtime(
            super::Win16UserRuntimeRequest::GetTickCount,
        )),
        Win16ExportId::UserGetCurrentTime => Win16ApiRequest::User(
            super::Win16UserRequest::Runtime(super::Win16UserRuntimeRequest::GetCurrentTime),
        ),
        Win16ExportId::UserMessageBeep => Win16ApiRequest::User(super::Win16UserRequest::Runtime(
            super::Win16UserRuntimeRequest::MessageBeep {
                beep_type: word_argument(arguments, 0)?,
            },
        )),
        Win16ExportId::UserGetKeyState => Win16ApiRequest::User(super::Win16UserRequest::Runtime(
            super::Win16UserRuntimeRequest::GetKeyState {
                virtual_key: word_argument(arguments, 0)? as i16,
            },
        )),
        Win16ExportId::UserGetSystemMetrics => Win16ApiRequest::User(
            super::Win16UserRequest::Runtime(super::Win16UserRuntimeRequest::GetSystemMetrics {
                index: word_argument(arguments, 0)? as i16,
            }),
        ),
        Win16ExportId::UserGetAsyncKeyState => Win16ApiRequest::User(
            super::Win16UserRequest::Runtime(super::Win16UserRuntimeRequest::GetAsyncKeyState {
                virtual_key: word_argument(arguments, 0)? as i16,
            }),
        ),
        Win16ExportId::UserSetMessageQueue => Win16ApiRequest::User(
            super::Win16UserRequest::Messages(super::Win16UserMessagesRequest::SetMessageQueue {
                message_count: word_argument(arguments, 0)? as i16,
            }),
        ),
        _ => return Err(Win16Error::InvalidRange),
    })
}

#[cfg(test)]
#[path = "call_user_void_tests.rs"]
mod void_tests;
