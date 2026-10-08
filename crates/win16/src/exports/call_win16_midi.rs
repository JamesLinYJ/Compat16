//! Width-checked MIDI request decoding for the Windows 3.1 MMSYSTEM exports.

use super::call::call_helpers::{dword_argument, word_argument};
use super::request::{Win16MidiDirection as Direction, Win16MidiRequest as Request,
    Win16MidiStreamArgument as StreamArgument};
use super::Win16ExportDescriptor;
use crate::{Win16Argument, Win16Error};

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[Win16Argument],
) -> Result<Request, Win16Error> {
    if !descriptor.module().eq_ignore_ascii_case("MMSYSTEM") {
        return Err(Win16Error::InvalidRange);
    }
    let ordinal = descriptor.ordinal();
    let direction = || if (301..=313).contains(&ordinal) { Direction::Input } else { Direction::Output };
    Ok(match ordinal {
        201 | 301 => Request::DeviceCount { direction: direction() },
        202 | 302 => Request::GetDeviceCaps { direction: direction(),
            device_id: word_argument(arguments, 0)?, output_far: dword_argument(arguments, 1)?,
            size: word_argument(arguments, 2)? },
        203 | 303 => Request::GetErrorText { direction: direction(),
            error: word_argument(arguments, 0)?, output_far: dword_argument(arguments, 1)?,
            size: word_argument(arguments, 2)? },
        204 | 304 => Request::Open { direction: direction(),
            output_far: dword_argument(arguments, 0)?, device_id: word_argument(arguments, 1)?,
            callback: dword_argument(arguments, 2)?, instance: dword_argument(arguments, 3)?,
            flags: dword_argument(arguments, 4)? },
        205 | 305 => Request::Close { direction: direction(), device: word_argument(arguments, 0)? },
        206 | 306 => Request::PrepareHeader { direction: direction(), device: word_argument(arguments, 0)?,
            header_far: dword_argument(arguments, 1)?, size: word_argument(arguments, 2)? },
        207 | 307 => Request::UnprepareHeader { direction: direction(), device: word_argument(arguments, 0)?,
            header_far: dword_argument(arguments, 1)?, size: word_argument(arguments, 2)? },
        208 => Request::OutputShortMessage { device: word_argument(arguments, 0)?, message: dword_argument(arguments, 1)? },
        209 => Request::OutputLongMessage { device: word_argument(arguments, 0)?,
            header_far: dword_argument(arguments, 1)?, size: word_argument(arguments, 2)? },
        210 => Request::OutputReset { device: word_argument(arguments, 0)? },
        211 => Request::OutputGetVolume { device: word_argument(arguments, 0)?, output_far: dword_argument(arguments, 1)? },
        212 => Request::OutputSetVolume { device: word_argument(arguments, 0)?, volume: dword_argument(arguments, 1)? },
        213 => Request::OutputCachePatches { device: word_argument(arguments, 0)?, bank: word_argument(arguments, 1)?,
            patches_far: dword_argument(arguments, 2)?, flags: word_argument(arguments, 3)? },
        214 => Request::OutputCacheDrumPatches { device: word_argument(arguments, 0)?, patch: word_argument(arguments, 1)?,
            keys_far: dword_argument(arguments, 2)?, flags: word_argument(arguments, 3)? },
        215 | 312 => Request::GetId { direction: direction(), device: word_argument(arguments, 0)?, output_far: dword_argument(arguments, 1)? },
        216 | 313 => Request::DriverMessage { direction: direction(), device: word_argument(arguments, 0)?,
            message: word_argument(arguments, 1)?, parameter1: dword_argument(arguments, 2)?,
            parameter2: dword_argument(arguments, 3)? },
        250..=257 => Request::StreamUnsupported { ordinal, arguments: raw_arguments(arguments)? },
        308 => Request::InputAddBuffer { device: word_argument(arguments, 0)?,
            header_far: dword_argument(arguments, 1)?, size: word_argument(arguments, 2)? },
        309 => Request::InputStart { device: word_argument(arguments, 0)? },
        310 => Request::InputStop { device: word_argument(arguments, 0)? },
        311 => Request::InputReset { device: word_argument(arguments, 0)? },
        _ => return Err(Win16Error::InvalidRange),
    })
}

fn raw_arguments(arguments: &[Win16Argument]) -> Result<Vec<StreamArgument>, Win16Error> {
    let mut raw = Vec::new();
    raw.try_reserve_exact(arguments.len()).map_err(|_| Win16Error::OutOfMemory)?;
    for argument in arguments {
        raw.push(match *argument {
            Win16Argument::Word(value) => StreamArgument::Word(value),
            Win16Argument::Dword(value) => StreamArgument::Dword(value),
            Win16Argument::Byte(_) => return Err(Win16Error::InvalidRange),
        });
    }
    Ok(raw)
}
