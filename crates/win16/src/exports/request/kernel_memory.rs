//! Typed KERNEL pointer-validation API arguments.

use crate::{Win16Argument, Win16Error};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16KernelMemoryRequest {
    IsBadReadPointer { pointer: u32, length: u32 },
    IsBadWritePointer { pointer: u32, length: u32 },
    IsBadCodePointer { pointer: u32 },
    IsBadStringPointer { pointer: u32, maximum: u16 },
    IsBadHugeReadPointer { pointer: u32, length: u32 },
    IsBadHugeWritePointer { pointer: u32, length: u32 },
}

/// Decode KERNEL's selector-checked pointer probes. `None` leaves every other
/// KERNEL ordinal to its existing family owner or to an explicit gap.
pub fn decode_kernel_memory(
    ordinal: u16,
    arguments: &[Win16Argument],
) -> Result<Option<Win16KernelMemoryRequest>, Win16Error> {
    let request = match ordinal {
        334 => Win16KernelMemoryRequest::IsBadReadPointer {
            pointer: dword(arguments, 0)?, length: u32::from(word(arguments, 1)?),
        },
        335 => Win16KernelMemoryRequest::IsBadWritePointer {
            pointer: dword(arguments, 0)?, length: u32::from(word(arguments, 1)?),
        },
        336 => Win16KernelMemoryRequest::IsBadCodePointer { pointer: dword(arguments, 0)? },
        337 => Win16KernelMemoryRequest::IsBadStringPointer {
            pointer: dword(arguments, 0)?, maximum: word(arguments, 1)?,
        },
        346 => Win16KernelMemoryRequest::IsBadHugeReadPointer {
            pointer: dword(arguments, 0)?, length: dword(arguments, 1)?,
        },
        347 => Win16KernelMemoryRequest::IsBadHugeWritePointer {
            pointer: dword(arguments, 0)?, length: dword(arguments, 1)?,
        },
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
