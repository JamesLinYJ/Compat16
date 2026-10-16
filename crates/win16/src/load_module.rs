//! Windows 3.1 LoadModule's 14-byte EXECBLOCK and pointed-to guest values.

use guest_core::{GuestMemory, Selector};
use zerocopy::byteorder::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{Access, SelectorTable, Win16Error};

// KERNEL EXECBLOCK is the DOS EXEC layout, with a selector WORD rather than
// a native environment pointer. For Windows tasks FCB1 points to {2,nCmdShow};
// FCB2 is reserved. These are wire fields, never host pointers.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct ExecBlock {
    environment: U16,
    command: U32,
    show: U32,
    reserved: U32,
}

const _: () = assert!(core::mem::size_of::<ExecBlock>() == 14);

#[derive(Debug, Eq, PartialEq)]
pub struct LoadModuleParameters {
    pub command_tail: Vec<u8>,
    pub environment: Option<Vec<u8>>,
    pub show: u16,
}

impl LoadModuleParameters {
    /// Copy every executable input before the loader can enter guest code.
    pub fn read(
        raw: u32,
        selectors: &SelectorTable,
        memory: &impl GuestMemory,
    ) -> Result<Self, Win16Error> {
        let mut bytes = [0; 14];
        selectors.read(memory, selectors.pointer_from_far(raw)?, &mut bytes)?;
        let block = ExecBlock::read_from_bytes(&bytes).map_err(|_| Win16Error::InvalidRange)?;
        let command_tail = if block.command.get() == 0 {
            Vec::new()
        } else {
            let start = selectors.pointer_from_far(block.command.get())?;
            let mut length = [0];
            selectors.read(memory, start, &mut length)?;
            if length[0] > 126 {
                return Err(Win16Error::InvalidRange);
            }
            let mut tail = vec![0; usize::from(length[0])];
            if !tail.is_empty() {
                let start = selectors.add_bytes(start, 1)?;
                selectors.read(memory, start, &mut tail)?;
            }
            tail
        };
        let show = if block.show.get() == 0 {
            1
        } else {
            let mut bytes = [0; 4];
            selectors.read(
                memory,
                selectors.pointer_from_far(block.show.get())?,
                &mut bytes,
            )?;
            if u16::from_le_bytes([bytes[0], bytes[1]]) != 2 {
                return Err(Win16Error::InvalidRange);
            }
            u16::from_le_bytes([bytes[2], bytes[3]])
        };
        let environment = if block.environment.get() == 0 {
            None
        } else {
            Some(read_environment(
                block.environment.get(),
                selectors,
                memory,
            )?)
        };
        Ok(Self {
            command_tail,
            environment,
            show,
        })
    }
}

fn read_environment(
    selector: u16,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    let start = selectors.pointer_from_raw(Selector(selector), 0)?;
    let descriptor = selectors.describe(start.selector())?;
    let length = descriptor
        .limit
        .checked_add(1)
        .filter(|length| (2..=65_536).contains(length))
        .ok_or(Win16Error::InvalidRange)? as usize;
    // A selector must own the complete scan span; its limit cannot authorize
    // reading an adjacent allocation or a native address.
    selectors.translate(start, Access::Read, length, memory)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Win16Error::OutOfMemory)?;
    bytes.resize(length, 0);
    selectors.read(memory, start, &mut bytes)?;
    let end = bytes
        .windows(2)
        .position(|pair| pair == [0, 0])
        .map(|offset| offset + 2)
        .ok_or(Win16Error::InvalidRange)?;
    bytes.truncate(end);
    Ok(bytes)
}

#[cfg(test)]
mod tests;
