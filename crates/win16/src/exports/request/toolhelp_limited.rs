//! Public ToolHelp task-control requests not implemented by the runtime model.

use crate::{Win16Argument, Win16Error};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16ToolhelpLimitedRequest {
    TaskSetCsip { task: u16, code_segment: u16, instruction_pointer: u16 },
    TaskSwitch { task: u16, new_cs_ip: u32 },
}

/// Decode the public task-control prototypes.
pub fn decode_toolhelp_limited(
    ordinal: u16,
    arguments: &[Win16Argument],
) -> Result<Option<Win16ToolhelpLimitedRequest>, Win16Error> {
    let request = match (ordinal, arguments) {
        (81, [
            Win16Argument::Word(task),
            Win16Argument::Word(code_segment),
            Win16Argument::Word(instruction_pointer),
        ]) => Win16ToolhelpLimitedRequest::TaskSetCsip {
            task: *task,
            code_segment: *code_segment,
            instruction_pointer: *instruction_pointer,
        },
        (83, [Win16Argument::Word(task), Win16Argument::Dword(new_cs_ip)]) => {
            Win16ToolhelpLimitedRequest::TaskSwitch { task: *task, new_cs_ip: *new_cs_ip }
        }
        (81 | 83, _) => return Err(Win16Error::InvalidRange),
        _ => return Ok(None),
    };
    Ok(Some(request))
}
