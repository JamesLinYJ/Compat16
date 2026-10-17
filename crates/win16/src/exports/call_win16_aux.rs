//! Decoding for MMSYSTEM auxiliary-audio calls.

use super::Win16ExportDescriptor;
use super::call::call_helpers::{dword_argument, word_argument};
use super::request::Win16AuxRequest;
use crate::{Win16Argument, Win16Error};

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[Win16Argument],
) -> Result<Win16AuxRequest, Win16Error> {
    if !descriptor.module().eq_ignore_ascii_case("MMSYSTEM") {
        return Err(Win16Error::InvalidRange);
    }
    match descriptor.ordinal() {
        350 if arguments.is_empty() => Ok(Win16AuxRequest::GetNumDevs),
        351 => Ok(Win16AuxRequest::GetDevCaps {
            device: word_argument(arguments, 0)?,
            output: dword_argument(arguments, 1)?,
            size: word_argument(arguments, 2)?,
        }),
        352 => Ok(Win16AuxRequest::GetVolume {
            device: word_argument(arguments, 0)?,
            output: dword_argument(arguments, 1)?,
        }),
        353 => Ok(Win16AuxRequest::SetVolume {
            device: word_argument(arguments, 0)?,
            value: dword_argument(arguments, 1)?,
        }),
        354 => Ok(Win16AuxRequest::OutMessage {
            device: word_argument(arguments, 0)?,
            message: word_argument(arguments, 1)?,
            parameter1: dword_argument(arguments, 2)?,
            parameter2: dword_argument(arguments, 3)?,
        }),
        _ => Err(Win16Error::InvalidRange),
    }
}
