//! Stack argument decoding for Win16 window-text exports.

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
        Win16ExportId::UserGetWindowText => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::GetWindowText {
                window: word_argument(arguments, 0)?,
                output: dword_argument(arguments, 1)?,
                count: word_argument(arguments, 2)? as i16,
            }),
        )),
        Win16ExportId::UserSetWindowText => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::SetWindowText {
                window: word_argument(arguments, 0)?,
                text: read_nullable_far_string(dword_argument(arguments, 1)?, selectors, memory)?,
            }),
        )),
        Win16ExportId::UserGetWindowTextLength => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::GetWindowTextLength {
                window: word_argument(arguments, 0)?,
            }),
        )),
        _ => Err(Win16Error::InvalidRange),
    }
}
