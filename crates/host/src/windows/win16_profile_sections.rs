//! Native Win32 adapters for Win16 profile-section queries.

use std::ptr;

use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::System::WindowsProgramming::{
    GetPrivateProfileSectionW, GetProfileSectionW, WritePrivateProfileSectionW,
    WriteProfileSectionW,
};

use super::guest_text::GuestTextCodec;

const MAX_WIN16_STRING_BYTES: usize = 1 << 16;

pub(super) struct ProfileSectionOutput {
    pub(super) buffer: Vec<u8>,
    pub(super) copied: u16,
}

pub(super) fn get_profile_section(
    codec: GuestTextCodec,
    section: Option<&[u8]>,
    requested_size: u16,
) -> Result<ProfileSectionOutput, RuntimeError> {
    read_section(codec, section, None, false, requested_size, None)
}

pub(super) fn get_private_profile_section(
    codec: GuestTextCodec,
    section: Option<&[u8]>,
    filename: Option<&[u8]>,
    requested_size: u16,
) -> Result<ProfileSectionOutput, RuntimeError> {
    read_section(codec, section, filename, true, requested_size, None)
}

pub(super) fn write_profile_section(
    codec: GuestTextCodec,
    section: Option<&[u8]>,
    entries: Option<&[u8]>,
) -> Result<bool, RuntimeError> {
    write_section(codec, section, entries, None, false, None)
}

pub(super) fn write_private_profile_section(
    codec: GuestTextCodec,
    section: Option<&[u8]>,
    entries: Option<&[u8]>,
    filename: Option<&[u8]>,
) -> Result<bool, RuntimeError> {
    write_section(codec, section, entries, filename, true, None)
}

pub(super) fn private_section_wide(
    codec: GuestTextCodec,
    section: Option<&[u8]>,
    filename: &[u16],
    capacity: u16,
) -> Result<ProfileSectionOutput, RuntimeError> {
    read_section(codec, section, None, true, capacity, Some(filename))
}

pub(super) fn private_write_wide(
    codec: GuestTextCodec,
    section: Option<&[u8]>,
    entries: Option<&[u8]>,
    filename: &[u16],
) -> Result<bool, RuntimeError> {
    write_section(codec, section, entries, None, true, Some(filename))
}

fn read_section(
    codec: GuestTextCodec,
    section: Option<&[u8]>,
    filename: Option<&[u8]>,
    private_profile: bool,
    requested_size: u16,
    native_filename: Option<&[u16]>,
) -> Result<ProfileSectionOutput, RuntimeError> {
    let capacity = usize::from(requested_size);
    let buffer = zeroed_buffer(capacity)?;
    if !valid_optional_string(section) || !valid_optional_string(filename) {
        return Ok(ProfileSectionOutput { buffer, copied: 0 });
    }

    let section = match optional_wide_z(codec, section) {
        Ok(value) => value,
        Err(error) if guest_text_failure(&error) => {
            return Ok(ProfileSectionOutput { buffer, copied: 0 });
        }
        Err(error) => return Err(error),
    };
    let filename = match native_filename
        .map(|path| Ok(Some(path.to_vec())))
        .unwrap_or_else(|| optional_wide_z(codec, filename))
    {
        Ok(value) => value,
        Err(error) if guest_text_failure(&error) => {
            return Ok(ProfileSectionOutput { buffer, copied: 0 });
        }
        Err(error) => return Err(error),
    };
    let section_ptr = section.as_ref().map_or(ptr::null(), |value| value.as_ptr());
    let filename_ptr = filename
        .as_ref()
        .map_or(ptr::null(), |value| value.as_ptr());
    // Guest output can expand when UTF-16 is encoded in a multibyte page. Two
    // UTF-16 units per guest byte cover surrogate pairs and default replacement
    // characters; the extra units keep the native MULTI_SZ terminators intact.
    let wide_capacity = capacity
        .checked_mul(2)
        .and_then(|size| size.checked_add(2))
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "size Win16 profile-section UTF-16 output",
            )
        })?;
    let native_capacity = u32::try_from(wide_capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "size native profile-section output",
            error,
        )
    })?;
    let mut wide_buffer = zeroed_wide(wide_capacity)?;
    // SAFETY: inputs are owned NUL-terminated UTF-16 copies, absent inputs stay
    // NULL, and the output is writable for `wide_capacity` UTF-16 units.
    let copied = unsafe {
        if private_profile {
            GetPrivateProfileSectionW(
                section_ptr,
                wide_buffer.as_mut_ptr(),
                native_capacity,
                filename_ptr,
            )
        } else {
            GetProfileSectionW(section_ptr, wide_buffer.as_mut_ptr(), native_capacity)
        }
    };

    let native_copied = usize::try_from(copied).map_err(|error| {
        RuntimeError::with_source(
            Kind::InternalInvariant,
            "native profile-section count is outside the host range",
            error,
        )
    })?;
    let native_truncation_sentinel = wide_capacity.saturating_sub(2);
    if native_copied > native_truncation_sentinel {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "native profile-section count exceeds its output buffer",
        ));
    }
    let native_truncated = native_copied == native_truncation_sentinel;
    // The count excludes only the final MULTI_SZ NUL and includes the last
    // entry's NUL. Do not inspect zero-filled storage beyond this exact prefix.
    let source = &wide_buffer[..native_copied];
    match encode_profile_output(codec, source, native_truncated, buffer) {
        Ok(output) => Ok(output),
        Err(error) if guest_text_failure(&error) => Ok(ProfileSectionOutput {
            buffer: zeroed_buffer(capacity)?,
            copied: 0,
        }),
        Err(error) => Err(error),
    }
}

fn encode_profile_output(
    codec: GuestTextCodec,
    source: &[u16],
    native_truncated: bool,
    mut buffer: Vec<u8>,
) -> Result<ProfileSectionOutput, RuntimeError> {
    let capacity = buffer.len();
    // A zero- or one-byte destination cannot hold a MULTI_SZ terminator. Return
    // the largest representable empty prefix; capacity two can hold only the
    // actual double-NUL empty list and reports zero for either API outcome.
    if capacity < 2 {
        return Ok(ProfileSectionOutput { buffer, copied: 0 });
    }

    let data_capacity = capacity.saturating_sub(2);
    let mut source_length = source.len();
    if native_truncated
        && source_length > 0
        && (0xD800..=0xDBFF).contains(&source[source_length - 1])
    {
        // GetProfileSectionW may stop between the two UTF-16 units of a
        // supplementary scalar. Never pass that dangling high surrogate to the
        // guest encoder; the native truncation flag still records the loss.
        source_length -= 1;
    }
    let source = &source[..source_length];
    let mut position = 0_usize;
    let mut truncated = native_truncated;
    let mut start = 0_usize;

    while start < source.len() {
        if source[start] == 0 {
            break;
        }
        if position > data_capacity {
            truncated = true;
            break;
        }
        let relative_end = source[start..].iter().position(|unit| *unit == 0);
        let (end, has_entry_nul) =
            relative_end.map_or((source.len(), false), |offset| (start + offset, true));
        let remaining = data_capacity.saturating_sub(position);
        let encoded = codec.from_wide_bounded(&source[start..end], remaining)?;
        buffer[position..position + encoded.bytes.len()].copy_from_slice(&encoded.bytes);
        position += encoded.bytes.len();
        if encoded.truncated {
            truncated = true;
        }

        // Each completed or partial item gets one NUL, then the final NUL is
        // written below. This keeps a real double-NUL terminator even when the
        // returned count is the nSize-2 truncation sentinel.
        if position >= capacity {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "guest profile item leaves no room for its MULTI_SZ terminator",
            ));
        }
        buffer[position] = 0;
        position += 1;

        if encoded.truncated || !has_entry_nul {
            truncated = true;
            break;
        }
        if end + 1 >= source.len() {
            break;
        }
        start = end + 1;
    }

    if position >= capacity {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "guest profile MULTI_SZ leaves no room for its final NUL",
        ));
    }
    buffer[position] = 0;

    let copied = if truncated {
        // Profile-section APIs reserve two bytes for the MULTI_SZ terminator
        // and return nSize-2 when either native or guest conversion truncates.
        data_capacity
    } else {
        position
    };
    if copied > usize::from(u16::MAX) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "guest profile MULTI_SZ count exceeds Win16 WORD",
        ));
    }
    Ok(ProfileSectionOutput {
        buffer,
        copied: copied as u16,
    })
}

fn write_section(
    codec: GuestTextCodec,
    section: Option<&[u8]>,
    entries: Option<&[u8]>,
    filename: Option<&[u8]>,
    private_profile: bool,
    native_filename: Option<&[u16]>,
) -> Result<bool, RuntimeError> {
    if !valid_optional_string(section)
        || !valid_optional_string(filename)
        || entries.is_some_and(|value| !valid_multistring(value))
    {
        return Ok(false);
    }

    let section = match optional_wide_z(codec, section) {
        Ok(value) => value,
        Err(error) if guest_text_failure(&error) => return Ok(false),
        Err(error) => return Err(error),
    };
    let entries = match entries.map(|value| codec.to_wide(value)).transpose() {
        Ok(value) => value,
        Err(error) if guest_text_failure(&error) => return Ok(false),
        Err(error) => return Err(error),
    };
    let filename = match native_filename
        .map(|path| Ok(Some(path.to_vec())))
        .unwrap_or_else(|| optional_wide_z(codec, filename))
    {
        Ok(value) => value,
        Err(error) if guest_text_failure(&error) => return Ok(false),
        Err(error) => return Err(error),
    };
    let section_ptr = section.as_ref().map_or(ptr::null(), |value| value.as_ptr());
    let entries_ptr = entries.as_ref().map_or(ptr::null(), |value| value.as_ptr());

    // SAFETY: present inputs are owned UTF-16 strings or the exact validated
    // UTF-16 MULTI_SZ; NULL remains distinct for documented profile semantics.
    let result = unsafe {
        if private_profile {
            WritePrivateProfileSectionW(
                section_ptr,
                entries_ptr,
                filename
                    .as_ref()
                    .map_or(ptr::null(), |value| value.as_ptr()),
            )
        } else {
            WriteProfileSectionW(section_ptr, entries_ptr)
        }
    };
    Ok(result != 0)
}

fn optional_wide_z(
    codec: GuestTextCodec,
    value: Option<&[u8]>,
) -> Result<Option<Vec<u16>>, RuntimeError> {
    value.map(|bytes| codec.to_wide_z(bytes)).transpose()
}

fn guest_text_failure(error: &RuntimeError) -> bool {
    matches!(error.kind(), Kind::HostFailure | Kind::InvalidInput)
}

fn valid_optional_string(value: Option<&[u8]>) -> bool {
    value.map_or(true, valid_string)
}

fn valid_string(value: &[u8]) -> bool {
    !value.contains(&0) && value.len() < MAX_WIN16_STRING_BYTES
}

fn valid_multistring(value: &[u8]) -> bool {
    // No shared profile MULTI_SZ validator exists; keep the native pointer
    // bounded to one complete, final-double-NUL Win16 section list.
    if !(2..=u16::MAX as usize).contains(&value.len()) || !value.ends_with(&[0, 0]) {
        return false;
    }
    !value[..value.len() - 2]
        .windows(2)
        .any(|pair| pair == [0, 0])
}

fn zeroed_buffer(length: usize) -> Result<Vec<u8>, RuntimeError> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate Win16 profile-section output",
            error,
        )
    })?;
    buffer.resize(length, 0);
    Ok(buffer)
}

fn zeroed_wide(length: usize) -> Result<Vec<u16>, RuntimeError> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate native profile-section output",
            error,
        )
    })?;
    buffer.resize(length, 0);
    Ok(buffer)
}

#[cfg(test)]
#[path = "win16_profile_sections_tests.rs"]
mod tests;
