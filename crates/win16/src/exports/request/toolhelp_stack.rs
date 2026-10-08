//! Typed ToolHelp stack-trace requests whose pointers remain guest FAR values.

use crate::{Win16Argument, Win16Error};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16ToolhelpStackRequest {
    StackTraceFirst { output: u32, task: u16 },
    StackTraceCsipFirst {
        output: u32,
        stack_segment: u16,
        code_segment: u16,
        instruction_pointer: u16,
        base_pointer: u16,
    },
    StackTraceNext { output: u32 },
}

/// Decode only the three known Win16 ToolHelp stack-trace prototypes.
pub fn decode_toolhelp_stack(
    ordinal: u16,
    arguments: &[Win16Argument],
) -> Result<Option<Win16ToolhelpStackRequest>, Win16Error> {
    let request = match (ordinal, arguments) {
        (66, [Win16Argument::Dword(output), Win16Argument::Word(task)]) => {
            Win16ToolhelpStackRequest::StackTraceFirst { output: *output, task: *task }
        }
        (67, [
            Win16Argument::Dword(output),
            Win16Argument::Word(stack_segment),
            Win16Argument::Word(code_segment),
            Win16Argument::Word(instruction_pointer),
            Win16Argument::Word(base_pointer),
        ]) => Win16ToolhelpStackRequest::StackTraceCsipFirst {
            output: *output,
            stack_segment: *stack_segment,
            code_segment: *code_segment,
            instruction_pointer: *instruction_pointer,
            base_pointer: *base_pointer,
        },
        (68, [Win16Argument::Dword(output)]) => {
            Win16ToolhelpStackRequest::StackTraceNext { output: *output }
        }
        (66..=68, _) => return Err(Win16Error::InvalidRange),
        _ => return Ok(None),
    };
    Ok(Some(request))
}
