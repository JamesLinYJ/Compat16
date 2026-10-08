//! Stack decoder for `DISPDIB.1 DisplayDib`.

use crate::{Win16Argument, Win16Error};
use super::request::display_dib::Win16DisplayDibRequest;

pub fn decode(
    module: &[u8],
    ordinal: u16,
    arguments: &[Win16Argument],
) -> Result<Option<Win16DisplayDibRequest>, Win16Error> {
    if !module.eq_ignore_ascii_case(b"DISPDIB") || ordinal != 1 {
        return Ok(None);
    }
    Ok(Some(Win16DisplayDibRequest {
        info: dword(arguments, 0)?,
        bits: dword(arguments, 1)?,
        flags: word(arguments, 2)?,
    }))
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
