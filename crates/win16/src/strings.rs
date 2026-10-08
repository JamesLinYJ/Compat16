//! Bounded guest ANSI-string copies shared by API and message marshalling.

use guest_core::GuestMemory;
use crate::{SelectorTable, Win16Error};

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
