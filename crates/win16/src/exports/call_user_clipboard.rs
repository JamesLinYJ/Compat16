//! Stack argument decoding for clipboard and registered message-name APIs.

use super::super::Win16ExportId;
use super::super::request::Win16ApiRequest;
use super::{dword_argument, read_nullable_far_string, word_argument};
use crate::{SelectorTable, Win16Error};
use guest_core::GuestMemory;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[crate::Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    match export {
        Win16ExportId::UserRegisterWindowMessage => {
            Ok(Win16ApiRequest::User(super::Win16UserRequest::Messages(
                super::Win16UserMessagesRequest::RegisterWindowMessage {
                    name: read_nullable_far_string(
                        dword_argument(arguments, 0)?,
                        selectors,
                        memory,
                    )?,
                },
            )))
        }
        Win16ExportId::UserRegisterClipboardFormat => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Text(super::Win16UserTextRequest::RegisterClipboardFormat {
                name: read_nullable_far_string(dword_argument(arguments, 0)?, selectors, memory)?,
            }),
        )),
        Win16ExportId::UserGetClipboardFormatName => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Text(super::Win16UserTextRequest::GetClipboardFormatName {
                format: word_argument(arguments, 0)?,
                output: dword_argument(arguments, 1)?,
                count: word_argument(arguments, 2)? as i16,
            }),
        )),
        _ => Err(Win16Error::InvalidRange),
    }
}
