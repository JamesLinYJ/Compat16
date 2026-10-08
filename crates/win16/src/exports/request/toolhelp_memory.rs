//! Typed ToolHelp guest memory-information requests.

use crate::{Win16Argument, Win16Error};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16ToolhelpMemoryRequest {
    SystemHeapInfo { output: u32 },
    MemManInfo { output: u32 },
}

pub fn decode_toolhelp_memory(
    ordinal: u16,
    arguments: &[Win16Argument],
) -> Result<Option<Win16ToolhelpMemoryRequest>, Win16Error> {
    match (ordinal, arguments) {
        (71, [Win16Argument::Dword(output)]) => {
            Ok(Some(Win16ToolhelpMemoryRequest::SystemHeapInfo { output: *output }))
        }
        (71, _) => Err(Win16Error::InvalidRange),
        (72, [Win16Argument::Dword(output)]) => {
            Ok(Some(Win16ToolhelpMemoryRequest::MemManInfo { output: *output }))
        }
        (72, _) => Err(Win16Error::InvalidRange),
        _ => Ok(None),
    }
}
