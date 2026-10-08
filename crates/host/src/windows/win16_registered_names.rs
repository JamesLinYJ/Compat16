//! Windows-managed names for registered messages and clipboard formats.

use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::System::DataExchange::{GetClipboardFormatNameW, RegisterClipboardFormatW};
use windows_sys::Win32::UI::WindowsAndMessaging::RegisterWindowMessageW;

use super::guest_text::GuestTextCodec;

pub(super) fn register_message(
    codec: GuestTextCodec,
    name: Option<&[u8]>,
) -> Result<u16, RuntimeError> {
    let Some(name) = native_name(codec, name)? else {
        return Ok(0);
    };
    // SAFETY: The owned UTF-16 name remains valid throughout the synchronous
    // call. Windows owns registration, name matching and the returned ID.
    Ok(unsafe { RegisterWindowMessageW(name.as_ptr()) } as u16)
}

pub(super) fn register_clipboard_format(
    codec: GuestTextCodec,
    name: Option<&[u8]>,
) -> Result<u16, RuntimeError> {
    let Some(name) = native_name(codec, name)? else {
        return Ok(0);
    };
    // SAFETY: The converted name is an owned NUL-terminated UTF-16 string.
    Ok(unsafe { RegisterClipboardFormatW(name.as_ptr()) } as u16)
}

/// Return a guest-encoded, NUL-terminated prefix for the worker clipboard API.
pub(super) fn clipboard_format_name_prefix(
    codec: GuestTextCodec,
    format: u16,
    capacity: usize,
) -> Result<(Vec<u8>, u16), RuntimeError> {
    if capacity == 0 {
        return Ok((Vec::new(), 0));
    }
    let native_capacity = wide_capacity_for_guest_bytes(capacity)?;
    let native_capacity = i32::try_from(native_capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::InvalidInput,
            "Win16 clipboard format-name capacity exceeds native range",
            error,
        )
    })?;
    let mut wide = Vec::new();
    wide.try_reserve_exact(native_capacity as usize)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate native clipboard format-name output",
                error,
            )
        })?;
    wide.resize(native_capacity as usize, 0xffff);

    // SAFETY: `wide` is writable for exactly the UTF-16 capacity passed to
    // Windows, and its storage lives until the synchronous call returns.
    let copied =
        unsafe { GetClipboardFormatNameW(u32::from(format), wide.as_mut_ptr(), native_capacity) };
    if copied <= 0 {
        return Ok((Vec::new(), 0));
    }
    let copied = usize::try_from(copied).map_err(|error| {
        RuntimeError::with_source(
            Kind::HostFailure,
            "native clipboard format-name count is invalid",
            error,
        )
    })?;
    if copied >= wide.len() {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "native GetClipboardFormatNameW count exceeds its UTF-16 output capacity",
        ));
    }
    if wide[copied] != 0 || wide[..copied].contains(&0) {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "native GetClipboardFormatNameW output is not a terminated prefix",
        ));
    }

    let encoded = codec.from_wide_bounded(&wide[..copied], capacity - 1)?;
    let copied = u16::try_from(encoded.bytes.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::InternalInvariant,
            "guest clipboard format-name count exceeds WORD",
            error,
        )
    })?;
    let mut bytes = encoded.bytes;
    bytes.push(0);
    Ok((bytes, copied))
}

/// The runtime host keeps a fixed-size guest buffer and copies back only its
/// prefix; preserve its tail exactly as GetClipboardFormatName does.
pub(super) fn clipboard_format_name(
    codec: GuestTextCodec,
    format: u16,
    mut buffer: Vec<u8>,
) -> Result<(Vec<u8>, u16), RuntimeError> {
    let (prefix, copied) = clipboard_format_name_prefix(codec, format, buffer.len())?;
    if copied != 0 {
        buffer[..prefix.len()].copy_from_slice(&prefix);
    }
    Ok((buffer, copied))
}

fn native_name(
    codec: GuestTextCodec,
    name: Option<&[u8]>,
) -> Result<Option<Vec<u16>>, RuntimeError> {
    let Some(name) = name else {
        return Ok(None);
    };
    if name.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 registered name contains an embedded NUL",
        ));
    }
    codec.to_wide_z(name).map(Some)
}

/// Win16 capacities count encoded bytes; W APIs count UTF-16 units. Two units
/// per guest byte is sufficient even when a supplementary scalar is replaced
/// by a one-byte default character in a single-byte guest page.
fn wide_capacity_for_guest_bytes(capacity: usize) -> Result<usize, RuntimeError> {
    if capacity == 0 {
        return Ok(0);
    }
    capacity
        .checked_sub(1)
        .and_then(|bytes| bytes.checked_mul(2))
        .and_then(|units| units.checked_add(1))
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "size UTF-16 output for guest byte capacity",
            )
        })
}
