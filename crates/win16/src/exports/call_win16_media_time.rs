//! Decoding for synchronous MMSYSTEM timer calls.

use super::call::call_helpers::{dword_argument, word_argument};
use super::request::Win16MediaTimeRequest;
use super::Win16ExportDescriptor;
use crate::{Win16Argument, Win16Error};

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[Win16Argument],
) -> Result<Win16MediaTimeRequest, Win16Error> {
    if !descriptor.module().eq_ignore_ascii_case("MMSYSTEM") {
        return Err(Win16Error::InvalidRange);
    }
    match descriptor.ordinal() {
        601 => Ok(Win16MediaTimeRequest::GetSystemTime {
            time: dword_argument(arguments, 0)?,
            size: word_argument(arguments, 1)?,
        }),
        604 => Ok(Win16MediaTimeRequest::GetDevCaps {
            caps: dword_argument(arguments, 0)?,
            size: word_argument(arguments, 1)?,
        }),
        605 => Ok(Win16MediaTimeRequest::BeginPeriod {
            period: word_argument(arguments, 0)?,
        }),
        606 => Ok(Win16MediaTimeRequest::EndPeriod {
            period: word_argument(arguments, 0)?,
        }),
        607 if arguments.is_empty() => Ok(Win16MediaTimeRequest::GetTime),
        _ => Err(Win16Error::InvalidRange),
    }
}
