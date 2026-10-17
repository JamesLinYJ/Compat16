//! Decoder adapter for the WINMEM32 export family.

use crate::{Win16Argument, Win16Error};

use super::request::{Win16Winmem32Request, decode_winmem32};

pub(super) fn decode(
    ordinal: u16,
    arguments: &[Win16Argument],
) -> Result<Option<Win16Winmem32Request>, Win16Error> {
    decode_winmem32(ordinal, arguments)
}
