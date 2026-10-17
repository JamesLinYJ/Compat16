//! Decoding for MMSYSTEM mixer ordinals 800–809.

use super::call::call_helpers::{dword_argument, word_argument};
use super::request::Win16MixerRequest;
use super::Win16ExportDescriptor;
use crate::{Win16Argument, Win16Error};

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[Win16Argument],
) -> Result<Win16MixerRequest, Win16Error> {
    if !descriptor.module().eq_ignore_ascii_case("MMSYSTEM") {
        return Err(Win16Error::InvalidRange);
    }
    match descriptor.ordinal() {
        800 if arguments.is_empty() => Ok(Win16MixerRequest::GetNumDevs),
        801 => Ok(Win16MixerRequest::GetDevCaps {
            device: word_argument(arguments, 0)?,
            capabilities: dword_argument(arguments, 1)?,
            size: word_argument(arguments, 2)?,
        }),
        802 => Ok(Win16MixerRequest::Open {
            handle_out: dword_argument(arguments, 0)?,
            device: word_argument(arguments, 1)?,
            callback: dword_argument(arguments, 2)?,
            instance: dword_argument(arguments, 3)?,
            flags: dword_argument(arguments, 4)?,
        }),
        803 => Ok(Win16MixerRequest::Close { handle: word_argument(arguments, 0)? }),
        804 => Ok(Win16MixerRequest::Message {
            handle: word_argument(arguments, 0)?,
            message: word_argument(arguments, 1)?,
            param1: dword_argument(arguments, 2)?,
            param2: dword_argument(arguments, 3)?,
        }),
        805 => Ok(Win16MixerRequest::GetLineInfo {
            object: word_argument(arguments, 0)?,
            line: dword_argument(arguments, 1)?,
            flags: dword_argument(arguments, 2)?,
        }),
        806 => Ok(Win16MixerRequest::GetId {
            object: word_argument(arguments, 0)?,
            device_id: dword_argument(arguments, 1)?,
            flags: dword_argument(arguments, 2)?,
        }),
        807 => Ok(Win16MixerRequest::GetLineControls {
            object: word_argument(arguments, 0)?,
            controls: dword_argument(arguments, 1)?,
            flags: dword_argument(arguments, 2)?,
        }),
        808 => Ok(Win16MixerRequest::GetControlDetails {
            object: word_argument(arguments, 0)?,
            details: dword_argument(arguments, 1)?,
            flags: dword_argument(arguments, 2)?,
        }),
        809 => Ok(Win16MixerRequest::SetControlDetails {
            object: word_argument(arguments, 0)?,
            details: dword_argument(arguments, 1)?,
            flags: dword_argument(arguments, 2)?,
        }),
        _ => Err(Win16Error::InvalidRange),
    }
}
