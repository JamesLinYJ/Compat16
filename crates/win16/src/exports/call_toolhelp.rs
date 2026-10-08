//! Raw argument decoding for TOOLHELP global-memory queries.
//!
//! Structure pointers remain guest FAR values. The runtime owns structure
//! sizing and access checks because each caller-provided structure begins with
//! a `dwSize` field that the decoder must not read before ABI dispatch.

use super::{Win16ApiRequest, Win16ExportId, dword_argument, word_argument};
use crate::{Win16Argument, Win16Error};

pub(super) fn decode(
    id: Win16ExportId,
    arguments: &[Win16Argument],
) -> Result<Win16ApiRequest, Win16Error> {
    let request = match id {
        Win16ExportId::ToolhelpGlobalHandleToSel => {
            Win16ApiRequest::Libraries(super::Win16LibraryRequest::Toolhelp(
                super::Win16LibraryToolhelpRequest::ToolhelpGlobalHandleToSel {
                    handle: word_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::ToolhelpGlobalFirst => {
            Win16ApiRequest::Libraries(super::Win16LibraryRequest::Toolhelp(
                super::Win16LibraryToolhelpRequest::ToolhelpGlobalFirst {
                    output: dword_argument(arguments, 0)?,
                    flags: word_argument(arguments, 1)?,
                },
            ))
        }
        Win16ExportId::ToolhelpGlobalNext => {
            Win16ApiRequest::Libraries(super::Win16LibraryRequest::Toolhelp(
                super::Win16LibraryToolhelpRequest::ToolhelpGlobalNext {
                    output: dword_argument(arguments, 0)?,
                    flags: word_argument(arguments, 1)?,
                },
            ))
        }
        Win16ExportId::ToolhelpGlobalInfo => {
            Win16ApiRequest::Libraries(super::Win16LibraryRequest::Toolhelp(
                super::Win16LibraryToolhelpRequest::ToolhelpGlobalInfo {
                    output: dword_argument(arguments, 0)?,
                },
            ))
        }
        Win16ExportId::ToolhelpGlobalEntryHandle => {
            Win16ApiRequest::Libraries(super::Win16LibraryRequest::Toolhelp(
                super::Win16LibraryToolhelpRequest::ToolhelpGlobalEntryHandle {
                    output: dword_argument(arguments, 0)?,
                    handle: word_argument(arguments, 1)?,
                },
            ))
        }
        Win16ExportId::ToolhelpGlobalEntryModule => {
            Win16ApiRequest::Libraries(super::Win16LibraryRequest::Toolhelp(
                super::Win16LibraryToolhelpRequest::ToolhelpGlobalEntryModule {
                    output: dword_argument(arguments, 0)?,
                    module: word_argument(arguments, 1)?,
                    segment: word_argument(arguments, 2)?,
                },
            ))
        }
        Win16ExportId::ToolhelpInterruptRegister => {
            Win16ApiRequest::Libraries(super::Win16LibraryRequest::Interrupts(
                super::Win16LibraryInterruptsRequest::InterruptRegister {
                    task_handle: word_argument(arguments, 0)?,
                    callback: dword_argument(arguments, 1)?,
                },
            ))
        }
        Win16ExportId::ToolhelpInterruptUnregister => {
            Win16ApiRequest::Libraries(super::Win16LibraryRequest::Interrupts(
                super::Win16LibraryInterruptsRequest::InterruptUnregister {
                    task_handle: word_argument(arguments, 0)?,
                },
            ))
        }
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(request)
}
