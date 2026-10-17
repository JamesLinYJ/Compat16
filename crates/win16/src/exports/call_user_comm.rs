//! Decode USER.200–215 and USER.245 into owned communications requests.

use super::super::Win16ExportId;
use super::super::request::{Win16ApiRequest, Win16UserCommRequest as Win16UserComm};
use super::{dword_argument, read_far_bytes, read_far_string, word_argument};
use crate::comm_abi::DCB16_LEN;
use crate::{SelectorTable, Win16Argument, Win16Error};
use guest_core::GuestMemory;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    let request = match export {
        Win16ExportId::UserOpenComm => Win16UserComm::Open {
            device: read_far_string(dword_argument(arguments, 0)?, selectors, memory)?,
            in_queue: word_argument(arguments, 1)?,
            out_queue: word_argument(arguments, 2)?,
        },
        Win16ExportId::UserSetCommState => Win16UserComm::SetState {
            dcb: read_far_bytes(dword_argument(arguments, 0)?, DCB16_LEN, selectors, memory)?,
        },
        Win16ExportId::UserGetCommState => Win16UserComm::GetState {
            id: word_argument(arguments, 0)?,
            dcb: dword_argument(arguments, 1)?,
        },
        Win16ExportId::UserGetCommError => Win16UserComm::GetError {
            id: word_argument(arguments, 0)?,
            status: dword_argument(arguments, 1)?,
        },
        Win16ExportId::UserReadComm => Win16UserComm::Read {
            id: word_argument(arguments, 0)?,
            buffer: dword_argument(arguments, 1)?,
            count: word_argument(arguments, 2)? as i16,
        },
        Win16ExportId::UserWriteComm => {
            let count = word_argument(arguments, 2)? as i16;
            let bytes = if count > 0 {
                read_far_bytes(
                    dword_argument(arguments, 1)?,
                    usize::from(count as u16),
                    selectors,
                    memory,
                )?
            } else {
                Vec::new()
            };
            Win16UserComm::Write {
                id: word_argument(arguments, 0)?,
                bytes,
            }
        }
        Win16ExportId::UserTransmitCommChar => Win16UserComm::Transmit {
            id: word_argument(arguments, 0)?,
            byte: byte_argument(arguments, 1)?,
        },
        Win16ExportId::UserCloseComm => Win16UserComm::Close {
            id: word_argument(arguments, 0)?,
        },
        Win16ExportId::UserSetCommEventMask => Win16UserComm::SetEventMask {
            id: word_argument(arguments, 0)?,
            mask: word_argument(arguments, 1)?,
        },
        Win16ExportId::UserGetCommEventMask => Win16UserComm::GetEventMask {
            id: word_argument(arguments, 0)?,
            clear: word_argument(arguments, 1)?,
        },
        Win16ExportId::UserSetCommBreak => Win16UserComm::SetBreak {
            id: word_argument(arguments, 0)?,
        },
        Win16ExportId::UserClearCommBreak => Win16UserComm::ClearBreak {
            id: word_argument(arguments, 0)?,
        },
        Win16ExportId::UserUngetCommChar => Win16UserComm::Unget {
            id: word_argument(arguments, 0)?,
            byte: byte_argument(arguments, 1)?,
        },
        Win16ExportId::UserBuildCommDcb => Win16UserComm::BuildDcb {
            definition: read_far_string(dword_argument(arguments, 0)?, selectors, memory)?,
            dcb: dword_argument(arguments, 1)?,
        },
        Win16ExportId::UserEscapeCommFunction => Win16UserComm::Escape {
            id: word_argument(arguments, 0)?,
            function: word_argument(arguments, 1)? as i16,
        },
        Win16ExportId::UserFlushComm => Win16UserComm::Flush {
            id: word_argument(arguments, 0)?,
            queue: word_argument(arguments, 1)? as i16,
        },
        Win16ExportId::UserEnableCommNotification => Win16UserComm::EnableNotification {
            id: word_argument(arguments, 0)?,
            window: word_argument(arguments, 1)?,
            input_threshold: word_argument(arguments, 2)? as i16,
            output_threshold: word_argument(arguments, 3)? as i16,
        },
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(Win16ApiRequest::User(super::Win16UserRequest::Comm(
        request,
    )))
}

fn byte_argument(arguments: &[Win16Argument], index: usize) -> Result<u8, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Byte(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

#[cfg(test)]
#[path = "call_user_comm_tests.rs"]
mod tests;
