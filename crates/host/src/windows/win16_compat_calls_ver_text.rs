use super::MAX_VER_PATH_UNITS;
use crate::windows::guest_text::GuestTextCodec;
use runtime::{DiagnosticKind as Kind, RuntimeError};

pub(super) fn guest_wide_z(
    codec: GuestTextCodec,
    bytes: &[u8],
    operation: &'static str,
) -> Result<Option<Vec<u16>>, RuntimeError> {
    if bytes.contains(&0) {
        return Ok(None);
    }
    guest_wide_z_required(codec, bytes, operation).map(Some)
}

pub(super) fn guest_wide_z_required(
    codec: GuestTextCodec,
    bytes: &[u8],
    operation: &'static str,
) -> Result<Vec<u16>, RuntimeError> {
    if bytes.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            format!("{operation} contains an embedded NUL"),
        ));
    }
    let mut wide = codec.to_wide(bytes)?;
    let length = wide.len().checked_add(1).ok_or_else(|| {
        RuntimeError::new(Kind::ResourceExhausted, format!("{operation} is too long"))
    })?;
    if length > MAX_VER_PATH_UNITS {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            format!("{operation} exceeds the bounded UTF-16 path capacity"),
        ));
    }
    wide.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            format!("terminate {operation}"),
            error,
        )
    })?;
    wide.push(0);
    Ok(wide)
}

pub(super) fn zeroed_wide_buffer(length: usize) -> Result<Vec<u16>, RuntimeError> {
    if length > MAX_VER_PATH_UNITS {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "VER wide buffer exceeds the bounded UTF-16 path capacity",
        ));
    }
    let mut output = Vec::new();
    output.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "allocate VER UTF-16 buffer", error)
    })?;
    output.resize(length, 0);
    Ok(output)
}

pub(super) fn grow_wide_capacity(
    current: usize,
    required: usize,
    force_growth: bool,
    operation: &'static str,
) -> Result<usize, RuntimeError> {
    let doubled = if force_growth && current < MAX_VER_PATH_UNITS {
        current.checked_mul(2).unwrap_or(MAX_VER_PATH_UNITS)
    } else {
        current
    };
    let next = required.max(doubled);
    if next > MAX_VER_PATH_UNITS || (next <= current && force_growth) {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            format!("{operation} exceeds the bounded UTF-16 path capacity"),
        ));
    }
    Ok(next)
}

pub(super) fn wide_output_text<'a>(
    buffer: &'a [u16],
    reported_units_including_nul: u32,
    operation: &'static str,
) -> Result<&'a [u16], RuntimeError> {
    let reported = usize::try_from(reported_units_including_nul).map_err(|error| {
        RuntimeError::with_source(
            Kind::InternalInvariant,
            format!("{operation} length does not fit host memory"),
            error,
        )
    })?;
    if reported > buffer.len() {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            format!("{operation} length exceeds its native output buffer"),
        ));
    }
    if reported == 0 {
        if buffer.first() == Some(&0) {
            return Ok(&buffer[..0]);
        }
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            format!("{operation} returned no length and no terminator"),
        ));
    }
    let visible = &buffer[..reported];
    let Some(end) = visible.iter().position(|unit| *unit == 0) else {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            format!("{operation} output is not NUL terminated"),
        ));
    };
    Ok(&visible[..end])
}

/// Convert an output string using the fixed guest page, reserve one byte for
/// its NUL terminator, and preserve the caller's untouched buffer tail.
pub(super) fn write_guest_string(
    codec: GuestTextCodec,
    wide: &[u16],
    output: &mut [u8],
    operation: &'static str,
) -> Result<(usize, bool), RuntimeError> {
    let full = codec.from_wide(wide)?;
    let required = full.bytes.len().checked_add(1).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            format!("{operation} byte length overflow"),
        )
    })?;
    if output.is_empty() {
        return Ok((required, true));
    }
    let encoded = codec.from_wide_bounded(wide, output.len() - 1)?;
    output[..encoded.bytes.len()].copy_from_slice(&encoded.bytes);
    output[encoded.bytes.len()] = 0;
    Ok((required, required > output.len() || encoded.truncated))
}

pub(super) fn checked_u32(value: usize, operation: &'static str) -> Result<u32, RuntimeError> {
    u32::try_from(value).map_err(|error| {
        RuntimeError::with_source(
            Kind::InvalidInput,
            format!("{operation} exceeds DWORD"),
            error,
        )
    })
}

pub(super) fn checked_u16(value: usize, operation: &'static str) -> Result<u16, RuntimeError> {
    u16::try_from(value).map_err(|error| {
        RuntimeError::with_source(
            Kind::InvalidInput,
            format!("{operation} exceeds the Win16 WORD"),
            error,
        )
    })
}
