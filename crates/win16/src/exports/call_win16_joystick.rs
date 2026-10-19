//! Decoding for MMSYSTEM joystick calls.

use super::Win16ExportDescriptor;
use super::call::call_helpers::{dword_argument, word_argument};
use super::request::Win16JoystickRequest;
use crate::{Win16Argument, Win16Error};

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[Win16Argument],
) -> Result<Win16JoystickRequest, Win16Error> {
    if !descriptor.module().eq_ignore_ascii_case("MMSYSTEM") {
        return Err(Win16Error::InvalidRange);
    }
    match descriptor.ordinal() {
        101 if arguments.is_empty() => Ok(Win16JoystickRequest::GetNumDevs),
        102 => Ok(Win16JoystickRequest::GetDevCaps {
            device: word_argument(arguments, 0)?,
            caps: dword_argument(arguments, 1)?,
            size: word_argument(arguments, 2)?,
        }),
        103 => Ok(Win16JoystickRequest::GetPos {
            device: word_argument(arguments, 0)?,
            info: dword_argument(arguments, 1)?,
        }),
        104 => Ok(Win16JoystickRequest::GetThreshold {
            device: word_argument(arguments, 0)?,
            threshold: dword_argument(arguments, 1)?,
        }),
        105 => Ok(Win16JoystickRequest::ReleaseCapture {
            device: word_argument(arguments, 0)?,
        }),
        106 => Ok(Win16JoystickRequest::SetCapture {
            window: word_argument(arguments, 0)?,
            device: word_argument(arguments, 1)?,
            period: word_argument(arguments, 2)?,
            changed: word_argument(arguments, 3)?,
        }),
        107 => Ok(Win16JoystickRequest::SetThreshold {
            device: word_argument(arguments, 0)?,
            threshold: word_argument(arguments, 1)?,
        }),
        109 => Ok(Win16JoystickRequest::SetCalibration {
            device: word_argument(arguments, 0)?,
        }),
        110 => Ok(Win16JoystickRequest::GetPosEx {
            device: word_argument(arguments, 0)?,
            info: dword_argument(arguments, 1)?,
        }),
        111 => Ok(Win16JoystickRequest::ConfigChanged {
            flags: dword_argument(arguments, 0)?,
        }),
        _ => Err(Win16Error::InvalidRange),
    }
}
