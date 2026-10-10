//! Bounded guest ANSI-string reads shared by API and message marshalling.

use guest_core::GuestMemory;
use crate::{SelectorTable, Win16Error};

/// Count bytes before NUL without allocating or copying the string.
/// As with `read_ansi_z`, every byte (including NUL) must be readable within
/// the same owned selector allocation, and `max_bytes` includes the NUL.
pub fn count_ansi_z(
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
    far: u32,
    max_bytes: usize,
) -> Result<usize, Win16Error> {
    let start = selectors.pointer_from_far(far)?;
    for length in 0..max_bytes {
        let offset = u32::try_from(length).map_err(|_| Win16Error::InvalidRange)?;
        let pointer = selectors.add_bytes(start, offset)?;
        let mut byte = [0];
        selectors.read(memory, pointer, &mut byte)?;
        if byte[0] == 0 { return Ok(length); }
    }
    Err(Win16Error::InvalidRange)
}

/// Copy a NUL-terminated FAR string without retaining a guest-memory borrow.
/// The selector limit and read permission apply to every byte, including NUL.
pub fn read_ansi_z(
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
    far: u32,
    max_bytes: usize,
) -> Result<Vec<u8>, Win16Error> {
    let start = selectors.pointer_from_far(far)?;
    let mut result = Vec::new();
    result.try_reserve(max_bytes.min(128)).map_err(|_| Win16Error::OutOfMemory)?;
    for offset in 0..max_bytes {
        let offset = u32::try_from(offset).map_err(|_| Win16Error::InvalidRange)?;
        let pointer = selectors.add_bytes(start, offset)?;
        let mut byte = [0];
        selectors.read(memory, pointer, &mut byte)?;
        if byte[0] == 0 { return Ok(result); }
        result.try_reserve(1).map_err(|_| Win16Error::OutOfMemory)?;
        result.push(byte[0]);
    }
    Err(Win16Error::InvalidRange)
}

#[cfg(test)]
#[path = "strings_tests.rs"]
mod tests;
