//! Decoder for the directly routed Win16 waveform-audio export family.

use super::call::call_helpers::{dword_argument, word_argument};
use super::request::{
    Win16WaveControl as Control, Win16WaveDirection as Direction, Win16WaveParameter as Parameter,
    Win16WaveRequest as Request,
};
use crate::{Win16Argument, Win16Error};
use super::{Win16ExportDescriptor, Win16ExportId};

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[Win16Argument],
) -> Result<Request, Win16Error> {
    use Win16ExportId as Id;
    let direction = match descriptor.id {
        Id::MmsystemWaveOutGetNumDevs
        | Id::MmsystemWaveOutGetDevCaps
        | Id::MmsystemWaveOutGetErrorText
        | Id::MmsystemWaveOutOpen
        | Id::MmsystemWaveOutClose
        | Id::MmsystemWaveOutPrepareHeader
        | Id::MmsystemWaveOutUnprepareHeader
        | Id::MmsystemWaveOutWrite
        | Id::MmsystemWaveOutPause
        | Id::MmsystemWaveOutRestart
        | Id::MmsystemWaveOutReset
        | Id::MmsystemWaveOutBreakLoop
        | Id::MmsystemWaveOutGetPitch
        | Id::MmsystemWaveOutSetPitch
        | Id::MmsystemWaveOutGetVolume
        | Id::MmsystemWaveOutSetVolume
        | Id::MmsystemWaveOutGetPlaybackRate
        | Id::MmsystemWaveOutSetPlaybackRate
        | Id::MmsystemWaveOutGetID
        | Id::MmsystemWaveOutMessage
        | Id::MmsystemWaveOutGetPosition => Direction::Output,
        Id::MmsystemWaveInGetNumDevs
        | Id::MmsystemWaveInGetDevCaps
        | Id::MmsystemWaveInGetErrorText
        | Id::MmsystemWaveInOpen
        | Id::MmsystemWaveInClose
        | Id::MmsystemWaveInPrepareHeader
        | Id::MmsystemWaveInUnprepareHeader
        | Id::MmsystemWaveInAddBuffer
        | Id::MmsystemWaveInStart
        | Id::MmsystemWaveInStop
        | Id::MmsystemWaveInReset
        | Id::MmsystemWaveInGetID
        | Id::MmsystemWaveInMessage
        | Id::MmsystemWaveInGetPosition => Direction::Input,
        _ => return Err(Win16Error::InvalidRange),
    };
    match descriptor.id {
        Id::MmsystemWaveOutGetNumDevs | Id::MmsystemWaveInGetNumDevs if arguments.is_empty() => {
            Ok(Request::DeviceCount { direction })
        }
        Id::MmsystemWaveOutGetDevCaps | Id::MmsystemWaveInGetDevCaps => {
            Ok(Request::DeviceCapabilities {
                direction,
                device: word_argument(arguments, 0)?,
                output: dword_argument(arguments, 1)?,
                size: word_argument(arguments, 2)?,
            })
        }
        Id::MmsystemWaveOutGetErrorText | Id::MmsystemWaveInGetErrorText => {
            Ok(Request::ErrorText {
                direction,
                error: word_argument(arguments, 0)?,
                output: dword_argument(arguments, 1)?,
                size: word_argument(arguments, 2)?,
            })
        }
        Id::MmsystemWaveOutGetPitch | Id::MmsystemWaveOutGetPlaybackRate => {
            Ok(Request::GetParameter {
                direction,
                handle: word_argument(arguments, 0)?,
                parameter: match descriptor.id {
                    Id::MmsystemWaveOutGetPitch => Parameter::Pitch,
                    _ => Parameter::PlaybackRate,
                },
                output: dword_argument(arguments, 1)?,
            })
        }
        Id::MmsystemWaveOutGetVolume => Ok(Request::GetDeviceVolume {
            device_id: word_argument(arguments, 0)?,
            output: dword_argument(arguments, 1)?,
        }),
        Id::MmsystemWaveOutSetPitch | Id::MmsystemWaveOutSetPlaybackRate => {
            Ok(Request::SetParameter {
                direction,
                handle: word_argument(arguments, 0)?,
                parameter: match descriptor.id {
                    Id::MmsystemWaveOutSetPitch => Parameter::Pitch,
                    _ => Parameter::PlaybackRate,
                },
                value: dword_argument(arguments, 1)?,
            })
        }
        Id::MmsystemWaveOutSetVolume => Ok(Request::SetDeviceVolume {
            device_id: word_argument(arguments, 0)?,
            value: dword_argument(arguments, 1)?,
        }),
        Id::MmsystemWaveOutGetID | Id::MmsystemWaveInGetID => Ok(Request::GetDeviceId {
            direction,
            handle: word_argument(arguments, 0)?,
            output: dword_argument(arguments, 1)?,
        }),
        Id::MmsystemWaveOutMessage | Id::MmsystemWaveInMessage => Ok(Request::Message {
            direction,
            device_or_handle: word_argument(arguments, 0)?,
            message: word_argument(arguments, 1)?,
            parameter1: dword_argument(arguments, 2)?,
            parameter2: dword_argument(arguments, 3)?,
        }),
        Id::MmsystemWaveOutOpen | Id::MmsystemWaveInOpen => Ok(Request::Open {
            direction,
            output_handle: dword_argument(arguments, 0)?,
            device: word_argument(arguments, 1)?,
            format: dword_argument(arguments, 2)?,
            callback: dword_argument(arguments, 3)?,
            instance: dword_argument(arguments, 4)?,
            flags: dword_argument(arguments, 5)?,
        }),
        Id::MmsystemWaveOutPrepareHeader | Id::MmsystemWaveInPrepareHeader => {
            decode_header(arguments, direction, HeaderOperation::Prepare)
        }
        Id::MmsystemWaveOutUnprepareHeader | Id::MmsystemWaveInUnprepareHeader => {
            decode_header(arguments, direction, HeaderOperation::Unprepare)
        }
        Id::MmsystemWaveOutWrite | Id::MmsystemWaveInAddBuffer => {
            decode_header(arguments, direction, HeaderOperation::Submit)
        }
        Id::MmsystemWaveOutGetPosition | Id::MmsystemWaveInGetPosition => {
            Ok(Request::GetPosition {
                direction,
                handle: word_argument(arguments, 0)?,
                time: dword_argument(arguments, 1)?,
                size: word_argument(arguments, 2)?,
            })
        }
        Id::MmsystemWaveOutClose | Id::MmsystemWaveInClose => Ok(Request::Control {
            direction,
            handle: word_argument(arguments, 0)?,
            command: Control::Close,
        }),
        Id::MmsystemWaveOutPause => control(arguments, direction, Control::Pause),
        Id::MmsystemWaveOutRestart => control(arguments, direction, Control::Restart),
        Id::MmsystemWaveOutReset | Id::MmsystemWaveInReset => {
            control(arguments, direction, Control::Reset)
        }
        Id::MmsystemWaveOutBreakLoop => control(arguments, direction, Control::BreakLoop),
        Id::MmsystemWaveInStart => control(arguments, direction, Control::Start),
        Id::MmsystemWaveInStop => control(arguments, direction, Control::Stop),
        _ => Err(Win16Error::InvalidRange),
    }
}

#[derive(Clone, Copy)]
enum HeaderOperation {
    Prepare,
    Unprepare,
    Submit,
}

fn decode_header(
    arguments: &[Win16Argument],
    direction: Direction,
    operation: HeaderOperation,
) -> Result<Request, Win16Error> {
    let handle = word_argument(arguments, 0)?;
    let header = dword_argument(arguments, 1)?;
    let size = word_argument(arguments, 2)?;
    Ok(match operation {
        HeaderOperation::Prepare => Request::PrepareHeader {
            direction,
            handle,
            header,
            size,
        },
        HeaderOperation::Unprepare => Request::UnprepareHeader {
            direction,
            handle,
            header,
            size,
        },
        HeaderOperation::Submit => Request::SubmitBuffer {
            direction,
            handle,
            header,
            size,
        },
    })
}

fn control(
    arguments: &[Win16Argument],
    direction: Direction,
    command: Control,
) -> Result<Request, Win16Error> {
    Ok(Request::Control {
        direction,
        handle: word_argument(arguments, 0)?,
        command,
    })
}
