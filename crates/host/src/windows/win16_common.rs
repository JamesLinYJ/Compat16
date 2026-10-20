//! Native Windows adapters for simple Win16 USER and profile queries.
//!
//! Callers pass copied guest strings as byte slices and receive copied output
//! buffers. This module never accepts a guest pointer or applies an
//! application-name allowlist.

use super::guest_text::GuestTextCodec;
use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::System::Diagnostics::Debug::MessageBeep;
use windows_sys::Win32::System::SystemInformation::GetTickCount;
use windows_sys::Win32::System::WindowsProgramming::{
    GetPrivateProfileIntW, GetPrivateProfileStringW, GetProfileIntW, GetProfileStringW,
    WritePrivateProfileStringW,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::GetAsyncKeyState;
use windows_sys::Win32::UI::WindowsAndMessaging::SM_CYCAPTION;

/// A Win16 addressable string must fit in at most one 64-KiB segment.
const MAX_WIN16_STRING_BYTES: usize = 1 << 16;
/// Profile output is capped at one Win16 segment in guest bytes.
pub(super) const MAX_PROFILE_OUTPUT_BYTES: usize = u16::MAX as usize;

/// Return the native wrapping millisecond tick count.
pub(super) fn get_tick_count() -> u32 {
    // SAFETY: GetTickCount has no pointer arguments or ownership requirements.
    unsafe { GetTickCount() }
}

/// Play the requested native Windows beep and preserve its BOOL result.
pub(super) fn message_beep(kind: u32) -> i32 {
    // SAFETY: MessageBeep has no pointer arguments or ownership requirements.
    unsafe { MessageBeep(kind) }
}

/// Return the native asynchronous key-state value, including its transition
/// and down bits.
pub(super) fn get_async_key_state(virtual_key: i32) -> i16 {
    // SAFETY: GetAsyncKeyState has no pointer arguments or ownership requirements.
    unsafe { GetAsyncKeyState(virtual_key) }
}

/// Expose caption space consistent with the Win16 frame geometry.
///
/// Windows 3.1 indexes run from `SM_CXSCREEN` through `SM_CMOUSEBUTTONS`.
/// Learn returns 0 when `GetSystemMetrics` fails, so a later host metric is
/// not queried.
pub(super) fn get_system_metrics(index: i32) -> i32 {
    if !runtime::win31_system_metric(index) {
        return 0;
    }
    // SAFETY: GetSystemMetrics has no pointer arguments or ownership requirements.
    let native = crate::windows::win32_safe::system_metrics(index);
    if index == SM_CYCAPTION {
        super::win16_windows::caption_height(native)
    } else {
        native
    }
}

/// Call the Windows Unicode profile integer reader using guest-code-page input.
/// Embedded NUL bytes or strings larger than one Win16 segment return the
/// caller-supplied default, matching this API's ordinary missing-value path.
pub(super) fn get_private_profile_int(
    codec: GuestTextCodec,
    app_name: Option<&[u8]>,
    key_name: Option<&[u8]>,
    default: i32,
    file_name: Option<&[u8]>,
) -> Result<u32, RuntimeError> {
    profile_int(
        codec,
        app_name,
        key_name,
        default,
        ProfileIntSource::File(file_name),
    )
}

pub(super) fn private_int_wide(
    codec: GuestTextCodec,
    section: Option<&[u8]>,
    key: Option<&[u8]>,
    default: i32,
    filename: &[u16],
) -> Result<u32, RuntimeError> {
    profile_int(
        codec,
        section,
        key,
        default,
        ProfileIntSource::WideFile(filename),
    )
}

pub(super) fn private_string_wide(
    codec: GuestTextCodec,
    section: Option<&[u8]>,
    key: Option<&[u8]>,
    default: Option<&[u8]>,
    filename: &[u16],
    capacity: u32,
) -> Result<ProfileStringOutput, RuntimeError> {
    profile_string(
        codec,
        section,
        key,
        default,
        ProfileStringSource::WideFile(filename),
        capacity,
    )
}

pub(super) fn private_write_wide(
    codec: GuestTextCodec,
    section: Option<&[u8]>,
    key: Option<&[u8]>,
    value: Option<&[u8]>,
    filename: &[u16],
) -> Result<bool, RuntimeError> {
    if !inputs_are_valid(&[section, key, value]) {
        return Ok(false);
    }
    let section = copy_optional_wide_z(codec, section)?;
    let key = copy_optional_wide_z(codec, key)?;
    let value = copy_optional_wide_z(codec, value)?;
    // The path belongs to a private host temporary file, never guest text.
    // SAFETY: `WritePrivateProfileStringW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    Ok(unsafe {
        WritePrivateProfileStringW(
            wide_ptr(section.as_ref()),
            wide_ptr(key.as_ref()),
            wide_ptr(value.as_ref()),
            filename.as_ptr(),
        )
    } != 0)
}

/// Read the system profile using Windows' WIN.INI compatibility mapping.
pub(super) fn get_profile_int(
    codec: GuestTextCodec,
    app_name: Option<&[u8]>,
    key_name: Option<&[u8]>,
    default: i32,
) -> Result<u32, RuntimeError> {
    profile_int(codec, app_name, key_name, default, ProfileIntSource::System)
}

#[derive(Clone, Copy)]
enum ProfileIntSource<'a> {
    System,
    File(Option<&'a [u8]>),
    WideFile(&'a [u16]),
}

fn profile_int(
    codec: GuestTextCodec,
    app_name: Option<&[u8]>,
    key_name: Option<&[u8]>,
    default: i32,
    source: ProfileIntSource<'_>,
) -> Result<u32, RuntimeError> {
    let file_name = match source {
        ProfileIntSource::System => None,
        ProfileIntSource::File(file_name) => file_name,
        ProfileIntSource::WideFile(_) => None,
    };
    if !inputs_are_valid(&[app_name, key_name, file_name]) {
        return Ok(default as u32);
    }

    let app_name = copy_optional_wide_z(codec, app_name)?;
    let key_name = copy_optional_wide_z(codec, key_name)?;
    let file_name = match source {
        ProfileIntSource::WideFile(path) => Some(path.to_vec()),
        _ => copy_optional_wide_z(codec, file_name)?,
    };

    // SAFETY: Every non-null pointer references an owned, NUL-terminated UTF-16
    // copy which remains alive for the synchronous call; null options preserve
    // the native API's null-parameter semantics.
    Ok(unsafe {
        match source {
            ProfileIntSource::System => GetProfileIntW(
                wide_ptr(app_name.as_ref()),
                wide_ptr(key_name.as_ref()),
                default,
            ),
            ProfileIntSource::File(_) | ProfileIntSource::WideFile(_) => GetPrivateProfileIntW(
                wide_ptr(app_name.as_ref()),
                wide_ptr(key_name.as_ref()),
                default,
                wide_ptr(file_name.as_ref()),
            ) as u32,
        }
    })
}

/// A guest-code-page output buffer and its Win16 return count. The buffer has
/// the requested guest-byte length and is NUL-filled after the copied data.
pub(super) struct ProfileStringOutput {
    pub(super) buffer: Vec<u8>,
    pub(super) copied: u32,
}

#[derive(Clone, Copy)]
enum ProfileStringSource<'a> {
    System,
    File(Option<&'a [u8]>),
    WideFile(&'a [u16]),
}

/// Query a private profile through the W API, translating text through the
/// fixed guest code page. Enumerations preserve the guest MULTI_SZ byte/count
/// contract, including the two trailing NUL bytes.
pub(super) fn get_private_profile_string(
    codec: GuestTextCodec,
    app_name: Option<&[u8]>,
    key_name: Option<&[u8]>,
    default: Option<&[u8]>,
    file_name: Option<&[u8]>,
    requested_size: u32,
) -> Result<ProfileStringOutput, RuntimeError> {
    profile_string(
        codec,
        app_name,
        key_name,
        default,
        ProfileStringSource::File(file_name),
        requested_size,
    )
}

/// Query the system profile through Windows' own WIN.INI compatibility API.
pub(super) fn get_profile_string(
    codec: GuestTextCodec,
    app_name: Option<&[u8]>,
    key_name: Option<&[u8]>,
    default: Option<&[u8]>,
    requested_size: u32,
) -> Result<ProfileStringOutput, RuntimeError> {
    profile_string(
        codec,
        app_name,
        key_name,
        default,
        ProfileStringSource::System,
        requested_size,
    )
}

fn profile_string(
    codec: GuestTextCodec,
    app_name: Option<&[u8]>,
    key_name: Option<&[u8]>,
    default: Option<&[u8]>,
    source: ProfileStringSource<'_>,
    requested_size: u32,
) -> Result<ProfileStringOutput, RuntimeError> {
    let capacity = requested_size.min(MAX_PROFILE_OUTPUT_BYTES as u32) as usize;
    let buffer = zeroed_buffer(capacity)?;
    let file_name = match source {
        ProfileStringSource::System => None,
        ProfileStringSource::File(file_name) => file_name,
        ProfileStringSource::WideFile(_) => None,
    };
    if capacity == 0 || !inputs_are_valid(&[app_name, key_name, default, file_name]) {
        return Ok(ProfileStringOutput { buffer, copied: 0 });
    }

    let app_name = copy_optional_wide_z(codec, app_name)?;
    let key_name = copy_optional_wide_z(codec, key_name)?;
    let default = copy_optional_wide_z(codec, default)?;
    let file_name = match source {
        ProfileStringSource::WideFile(path) => Some(path.to_vec()),
        _ => copy_optional_wide_z(codec, file_name)?,
    };
    let enumerate = app_name.is_none() || key_name.is_none();

    // A supplementary scalar can occupy two UTF-16 units and map to one
    // guest replacement byte. Two W units per guest byte therefore leave
    // enough room to convert the complete guest-visible prefix, plus NULs.
    let wide_capacity = capacity
        .checked_mul(2)
        .and_then(|size| size.checked_add(2))
        .ok_or_else(|| resource_error("size Win16 profile UTF-16 output"))?;
    let mut wide = zeroed_wide(wide_capacity, "allocate Win16 profile UTF-16 output")?;
    let wide_capacity_u32 = u32::try_from(wide_capacity)
        .map_err(|_| resource_error("size Win16 profile UTF-16 output"))?;

    // SAFETY: Input pointers refer to owned, NUL-terminated UTF-16 copies (or
    // null when requested). The output pointer addresses an initialized UTF-16
    // buffer of `wide_capacity` units. The native call is synchronous.
    let read_profile = |output: &mut [u16], default: *const u16| unsafe {
        match source {
            ProfileStringSource::System => GetProfileStringW(
                wide_ptr(app_name.as_ref()),
                wide_ptr(key_name.as_ref()),
                default,
                output.as_mut_ptr(),
                wide_capacity_u32,
            ),
            ProfileStringSource::File(_) | ProfileStringSource::WideFile(_) => {
                GetPrivateProfileStringW(
                    wide_ptr(app_name.as_ref()),
                    wide_ptr(key_name.as_ref()),
                    default,
                    output.as_mut_ptr(),
                    wide_capacity_u32,
                    wide_ptr(file_name.as_ref()),
                )
            }
        }
    };
    let native_copied = read_profile(&mut wide, wide_ptr(default.as_ref()));
    if native_copied >= wide_capacity_u32 {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "native profile string count exceeds its UTF-16 output buffer",
        ));
    }

    if enumerate {
        let native_copied = native_copied as usize;
        let native_multisz_truncated = native_copied == wide_capacity.saturating_sub(2);
        // A default string can have exactly the same count as the MULTI_SZ
        // truncation sentinel. Query names without that default only for this
        // ambiguity, while keeping the original API's default text and trim.
        let ambiguous_default = native_multisz_truncated
            && app_name.is_some()
            && key_name.is_none()
            && default.as_ref().is_some_and(|value| value.len() > 1);
        let missing_names = if ambiguous_default {
            let mut names =
                zeroed_wide(wide_capacity, "query profile enumeration without default")?;
            read_profile(&mut names, std::ptr::null()) == 0
        } else {
            false
        };
        let ordinary_default = missing_names
            || native_copied == wide_capacity.saturating_sub(1)
            || (!native_multisz_truncated
                && native_copied > 0
                && wide.get(native_copied.saturating_sub(1)) != Some(&0));
        if ordinary_default {
            encode_profile_string(codec, &wide, native_copied, wide_capacity, buffer)
        } else {
            encode_profile_multisz(codec, &wide, native_copied, buffer)
        }
    } else {
        encode_profile_string(codec, &wide, native_copied as usize, wide_capacity, buffer)
    }
}

/// Call `WritePrivateProfileStringW` with guest-code-page inputs.
/// Its native BOOL failure result is returned unchanged. `None` preserves the
/// API's null-pointer behavior, including deleting keys/sections or flushing
/// a profile file where supported by Windows.
pub(super) fn write_private_profile_string(
    codec: GuestTextCodec,
    app_name: Option<&[u8]>,
    key_name: Option<&[u8]>,
    value: Option<&[u8]>,
    file_name: Option<&[u8]>,
) -> Result<i32, RuntimeError> {
    if !inputs_are_valid(&[app_name, key_name, value, file_name]) {
        return Ok(0);
    }

    let app_name = copy_optional_wide_z(codec, app_name)?;
    let key_name = copy_optional_wide_z(codec, key_name)?;
    let value = copy_optional_wide_z(codec, value)?;
    let file_name = copy_optional_wide_z(codec, file_name)?;

    // SAFETY: Every non-null pointer references an owned, NUL-terminated UTF-16
    // copy which remains alive for the synchronous call; null options preserve
    // the native API's deletion and flush semantics.
    Ok(unsafe {
        WritePrivateProfileStringW(
            wide_ptr(app_name.as_ref()),
            wide_ptr(key_name.as_ref()),
            wide_ptr(value.as_ref()),
            wide_ptr(file_name.as_ref()),
        )
    })
}

fn inputs_are_valid(values: &[Option<&[u8]>]) -> bool {
    values.iter().flatten().all(|value| {
        !value.contains(&0)
            && value.len() < MAX_WIN16_STRING_BYTES
            && value.len().checked_add(1).is_some()
    })
}

fn copy_optional_wide_z(
    codec: GuestTextCodec,
    value: Option<&[u8]>,
) -> Result<Option<Vec<u16>>, RuntimeError> {
    value.map(|bytes| codec.to_wide_z(bytes)).transpose()
}

fn wide_ptr(value: Option<&Vec<u16>>) -> *const u16 {
    value.map_or(std::ptr::null(), Vec::as_ptr)
}

fn zeroed_buffer(length: usize) -> Result<Vec<u8>, RuntimeError> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate Win16 profile output",
            error,
        )
    })?;
    buffer.resize(length, 0);
    Ok(buffer)
}

fn zeroed_wide(length: usize, operation: &'static str) -> Result<Vec<u16>, RuntimeError> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(length)
        .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted, operation, error))?;
    buffer.resize(length, 0);
    Ok(buffer)
}

fn resource_error(operation: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::ResourceExhausted, operation)
}

fn encode_profile_string(
    codec: GuestTextCodec,
    wide: &[u16],
    native_copied: usize,
    wide_capacity: usize,
    mut buffer: Vec<u8>,
) -> Result<ProfileStringOutput, RuntimeError> {
    let capacity = buffer.len();
    let native_truncated = native_copied >= wide_capacity.saturating_sub(1);
    let mut source_length = native_copied.min(wide.len());
    if native_truncated
        && wide
            .get(source_length.saturating_sub(1))
            .is_some_and(|unit| (0xD800..=0xDBFF).contains(unit))
    {
        source_length = source_length.saturating_sub(1);
    }
    let encoded = codec.from_wide_bounded(&wide[..source_length], capacity.saturating_sub(1))?;
    let byte_count = encoded.bytes.len();
    buffer[..byte_count].copy_from_slice(&encoded.bytes);
    let truncated = native_truncated || encoded.truncated;
    let copied = if truncated {
        capacity.saturating_sub(1)
    } else {
        byte_count
    };
    Ok(ProfileStringOutput {
        buffer,
        copied: copied as u32,
    })
}

fn encode_profile_multisz(
    codec: GuestTextCodec,
    wide: &[u16],
    native_copied: usize,
    mut buffer: Vec<u8>,
) -> Result<ProfileStringOutput, RuntimeError> {
    let capacity = buffer.len();
    let data_capacity = capacity.saturating_sub(2);
    let mut position = 0_usize;
    let mut truncated = native_copied >= wide.len().saturating_sub(2);
    let mut start = 0_usize;

    while start < wide.len() {
        if wide[start] == 0 {
            if wide.get(start + 1) == Some(&0) {
                break;
            }
            // An empty item also denotes the MULTI_SZ terminator if the next
            // unit is outside the native output buffer.
            break;
        }
        let Some(relative_end) = wide[start..].iter().position(|unit| *unit == 0) else {
            truncated = true;
            break;
        };
        let end = start + relative_end;
        let last_entry = wide.get(end + 1) == Some(&0) || end + 1 >= wide.len();
        let remaining = data_capacity.saturating_sub(position);
        if !last_entry && remaining == 0 {
            truncated = true;
            break;
        }
        let scalar_capacity = if last_entry {
            remaining
        } else {
            remaining.saturating_sub(1)
        };
        let mut source_end = end;
        if truncated
            && last_entry
            && source_end > start
            && (0xD800..=0xDBFF).contains(&wide[source_end - 1])
        {
            // The native W buffer can end between a UTF-16 surrogate pair.
            // Preserve a complete guest encoding and keep the truncation flag.
            source_end -= 1;
        }
        let encoded = codec.from_wide_bounded(&wide[start..source_end], scalar_capacity)?;
        buffer[position..position + encoded.bytes.len()].copy_from_slice(&encoded.bytes);
        position += encoded.bytes.len();
        if encoded.truncated {
            truncated = true;
            break;
        }
        if last_entry {
            break;
        }
        // Preserve the separator between completed entries. The final two
        // bytes remain zero in the caller's initialized guest buffer.
        buffer[position] = 0;
        position += 1;
        start = end + 1;
    }

    let copied = if truncated {
        data_capacity
    } else if position == 0 {
        0
    } else {
        // Windows' complete MULTI_SZ count includes the final entry's NUL,
        // while its truncation count is the guest byte capacity minus two.
        position + 1
    };
    Ok(ProfileStringOutput {
        buffer,
        copied: copied as u32,
    })
}
