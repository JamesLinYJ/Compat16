//! Typed Win16 SHELL execution, association, and About-dialog inputs.

use guest_core::GuestMemory;

use crate::strings::read_ansi_z;
use crate::{SelectorTable, Win16Argument, Win16Error};

const MAX_SHELL_STRING_BYTES: usize = crate::MAX_WIN16_STRING_BYTES;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16ShellExecutionRequest {
    Execute {
        owner: u16,
        operation: Option<Vec<u8>>,
        file: Vec<u8>,
        parameters: Option<Vec<u8>>,
        directory: Option<Vec<u8>>,
        show: i16,
    },
    FindExecutable {
        file: Vec<u8>,
        directory: Option<Vec<u8>>,
        output_far: u32,
    },
    About {
        owner: u16,
        app_far: u32,
        app: Vec<u8>,
        other_stuff: Option<Vec<u8>>,
        icon: u16,
    },
}

pub(in crate::exports) fn decode_shell_execution_export(
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ShellExecutionRequest, Win16Error> {
    let request = match ordinal {
        20 => Win16ShellExecutionRequest::Execute {
            owner: word(arguments, 0)?,
            operation: nullable_string(arguments, 1, selectors, memory)?,
            file: string(arguments, 2, selectors, memory)?,
            parameters: nullable_string(arguments, 3, selectors, memory)?,
            directory: nullable_string(arguments, 4, selectors, memory)?,
            show: word(arguments, 5)? as i16,
        },
        21 => Win16ShellExecutionRequest::FindExecutable {
            file: string(arguments, 0, selectors, memory)?,
            directory: nullable_string(arguments, 1, selectors, memory)?,
            output_far: dword(arguments, 2)?,
        },
        22 => Win16ShellExecutionRequest::About {
            owner: word(arguments, 0)?,
            app_far: dword(arguments, 1)?,
            app: string(arguments, 1, selectors, memory)?,
            other_stuff: nullable_string(arguments, 2, selectors, memory)?,
            icon: word(arguments, 3)?,
        },
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(request)
}

fn string(
    arguments: &[Win16Argument],
    index: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    read_ansi_z(
        selectors,
        memory,
        dword(arguments, index)?,
        MAX_SHELL_STRING_BYTES,
    )
}

fn nullable_string(
    arguments: &[Win16Argument],
    index: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Vec<u8>>, Win16Error> {
    let far = dword(arguments, index)?;
    if far == 0 {
        Ok(None)
    } else {
        string(arguments, index, selectors, memory).map(Some)
    }
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
