//! Typed KERNEL bounded string-copy requests.

use crate::{SelectorTable, Win16Argument, Win16Error};
use guest_core::GuestMemory;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16KernelStringRequest {
    Lstrcatn { destination: u32, source: Vec<u8>, limit: u16 },
    Lstrcpyn { destination: u32, source: Vec<u8>, limit: u16 },
}

pub fn decode_kernel_string(
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16KernelStringRequest>, Win16Error> {
    let request = match ordinal {
        352 => Win16KernelStringRequest::Lstrcatn {
            destination: dword(arguments, 0)?,
            source: far_string(dword(arguments, 1)?, selectors, memory)?,
            limit: word(arguments, 2)?,
        },
        353 => {
            let destination = dword(arguments, 0)?;
            let source = dword(arguments, 1)?;
            let limit = word(arguments, 2)?;
            let source = if (limit as i16) > 0 {
                far_string_prefix(source, usize::from(limit - 1), selectors, memory)?
            } else {
                far_string(source, selectors, memory)?
            };
            Win16KernelStringRequest::Lstrcpyn { destination, source, limit }
        },
        _ => return Ok(None),
    };
    Ok(Some(request))
}

/// lstrcpyn reads at most n-1 source bytes; its destination terminator is
/// supplied by the runtime. A full prefix needs no readable source NUL, and
/// n=1 must not dereference the source at all. Counts remain guest bytes.
fn far_string_prefix(
    raw: u32,
    count: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    let mut value = Vec::new();
    if count == 0 { return Ok(value); }
    let start = selectors.pointer_from_far(raw)?;
    value.try_reserve_exact(count).map_err(|_| Win16Error::OutOfMemory)?;
    for offset in 0..count {
        let pointer = selectors.add_bytes(start, offset as u32)?;
        let mut byte = [0_u8; 1];
        selectors.read(memory, pointer, &mut byte)?;
        if byte[0] == 0 { break; }
        value.push(byte[0]);
    }
    Ok(value)
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
        if byte[0] == 0 { return Ok(value); }
        value.push(byte[0]);
        pointer = selectors.add_bytes(pointer, 1)?;
    }
    Err(Win16Error::InvalidRange)
}

#[cfg(test)]
#[path = "kernel_string_tests.rs"]
mod tests;
