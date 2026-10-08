//! Typed TOOLHELP family requests whose runtime state is owned by Win16.
//!
//! This module is intentionally independent of the shared export request enum
//! and dispatcher. The integration owner can route the listed ordinals without
//! changing the checked guest ABI or exposing host pointers.

use crate::{SelectorTable, Win16Argument, Win16Error};
use guest_core::GuestMemory;

pub const NF_NORMAL: u16 = 0;
pub const NF_TASKSWITCH: u16 = 1;
pub const NF_RIP: u16 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ToolhelpRequest {
    LocalInfo { output: u32, heap: u16 },
    LocalFirst { output: u32, heap: u16 },
    LocalNext { output: u32 },
    ModuleFirst { output: u32 },
    ModuleNext { output: u32 },
    ModuleFindName { output: u32, name: Vec<u8> },
    ModuleFindHandle { output: u32, module: u16 },
    TaskFirst { output: u32 },
    TaskNext { output: u32 },
    TaskFindHandle { output: u32, task: u16 },
    TaskGetCSIP { task: u16 },
    NotifyRegister { task: u16, callback: u32, flags: u16 },
    NotifyUnregister { task: u16 },
    ClassFirst { output: u32 },
    ClassNext { output: u32 },
    TimerCount { output: u32 },
    SystemHeapInfo { output: u32 },
    MemManInfo { output: u32 },
    TaskSetCsip { task: u16, code_segment: u16, instruction_pointer: u16 },
    TaskSwitch { task: u16, new_cs_ip: u32 },
    MemoryRead { selector: u16, offset: u32, output: u32, count: u32 },
    MemoryWrite { selector: u16, offset: u32, input: u32, count: u32 },
    TerminateApp { task: u16, exit_code: u16 },
}

/// Decode the implementation-owned subset of TOOLHELP's stack parameters.
/// `None` means the ordinal belongs to another family or awaits the shared
/// callback/scheduler/host contract; no default-success request is invented.
pub fn decode_toolhelp(
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16ToolhelpRequest>, Win16Error> {
    let request = match ordinal {
        56 => Win16ToolhelpRequest::LocalInfo {
            output: dword(arguments, 0)?, heap: word(arguments, 1)?,
        },
        57 => Win16ToolhelpRequest::LocalFirst {
            output: dword(arguments, 0)?, heap: word(arguments, 1)?,
        },
        58 => Win16ToolhelpRequest::LocalNext { output: dword(arguments, 0)? },
        59 => Win16ToolhelpRequest::ModuleFirst { output: dword(arguments, 0)? },
        60 => Win16ToolhelpRequest::ModuleNext { output: dword(arguments, 0)? },
        61 => Win16ToolhelpRequest::ModuleFindName {
            output: dword(arguments, 0)?,
            name: far_string(dword(arguments, 1)?, selectors, memory)?,
        },
        62 => Win16ToolhelpRequest::ModuleFindHandle {
            output: dword(arguments, 0)?, module: word(arguments, 1)?,
        },
        63 => Win16ToolhelpRequest::TaskFirst { output: dword(arguments, 0)? },
        64 => Win16ToolhelpRequest::TaskNext { output: dword(arguments, 0)? },
        65 => Win16ToolhelpRequest::TaskFindHandle {
            output: dword(arguments, 0)?, task: word(arguments, 1)?,
        },
        73 if arguments.len() == 3 => Win16ToolhelpRequest::NotifyRegister {
            task: word(arguments, 0)?, callback: dword(arguments, 1)?, flags: word(arguments, 2)?,
        },
        74 if arguments.len() == 1 => Win16ToolhelpRequest::NotifyUnregister {
            task: word(arguments, 0)?,
        },
        82 => Win16ToolhelpRequest::TaskGetCSIP { task: word(arguments, 0)? },
        69 => Win16ToolhelpRequest::ClassFirst { output: dword(arguments, 0)? },
        70 => Win16ToolhelpRequest::ClassNext { output: dword(arguments, 0)? },
        80 => Win16ToolhelpRequest::TimerCount { output: dword(arguments, 0)? },
        71 => Win16ToolhelpRequest::SystemHeapInfo { output: dword(arguments, 0)? },
        72 => Win16ToolhelpRequest::MemManInfo { output: dword(arguments, 0)? },
        81 => Win16ToolhelpRequest::TaskSetCsip {
            task: word(arguments, 0)?,
            code_segment: word(arguments, 1)?,
            instruction_pointer: word(arguments, 2)?,
        },
        83 => Win16ToolhelpRequest::TaskSwitch {
            task: word(arguments, 0)?, new_cs_ip: dword(arguments, 1)?,
        },
        78 => Win16ToolhelpRequest::MemoryRead {
            selector: word(arguments, 0)?, offset: dword(arguments, 1)?,
            output: dword(arguments, 2)?, count: dword(arguments, 3)?,
        },
        79 => Win16ToolhelpRequest::MemoryWrite {
            selector: word(arguments, 0)?, offset: dword(arguments, 1)?,
            input: dword(arguments, 2)?, count: dword(arguments, 3)?,
        },
        77 => Win16ToolhelpRequest::TerminateApp {
            task: word(arguments, 0)?, exit_code: word(arguments, 1)?,
        },
        73 | 74 => return Err(Win16Error::InvalidRange),
        _ => return Ok(None),
    };
    Ok(Some(request))
}

fn word(arguments: &[Win16Argument], index: usize) -> Result<u16, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Word(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn dword(arguments: &[Win16Argument], index: usize) -> Result<u32, Win16Error> {
    match arguments.get(index) {
        Some(Win16Argument::Dword(value)) => Ok(*value),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn far_string(
    raw: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    const MAX_STRING_BYTES: usize = 64 * 1024;
    let mut pointer = selectors.pointer_from_far(raw)?;
    let mut value = Vec::new();
    value.try_reserve(64).map_err(|_| Win16Error::OutOfMemory)?;
    for _ in 0..MAX_STRING_BYTES {
        let mut byte = [0_u8; 1];
        selectors.read(memory, pointer, &mut byte)?;
        if byte[0] == 0 {
            return Ok(value);
        }
        value.push(byte[0]);
        pointer = selectors.add_bytes(pointer, 1)?;
    }
    Err(Win16Error::InvalidRange)
}
