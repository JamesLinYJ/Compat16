//! Win16 profile-string result projection for the Windows host adapter.

use super::super::guest_text::GuestTextCodec;
use super::*;

pub(super) fn private_string(
    codec: GuestTextCodec,
    section: Option<&[u8]>,
    key: Option<&[u8]>,
    default: Option<&[u8]>,
    filename: Option<&[u8]>,
    capacity: u16,
) -> Result<(Vec<u8>, u16), RuntimeError> {
    let output = super::super::win16_common::get_private_profile_string(
        codec,
        section,
        key,
        default,
        filename,
        u32::from(capacity),
    )?;
    Ok((output.buffer, output.copied as u16))
}

pub(super) fn system_string(
    codec: GuestTextCodec,
    section: Option<&[u8]>,
    key: Option<&[u8]>,
    default: Option<&[u8]>,
    capacity: u16,
) -> Result<(Vec<u8>, u16), RuntimeError> {
    let output = super::super::win16_common::get_profile_string(
        codec,
        section,
        key,
        default,
        u32::from(capacity),
    )?;
    Ok((output.buffer, output.copied as u16))
}
