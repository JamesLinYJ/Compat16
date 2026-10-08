use crate::windows::guest_text::GuestTextCodec;
use runtime::{DiagnosticKind as Kind, RuntimeError};

pub(in crate::windows) fn wide_terminated(
    codec: GuestTextCodec,
    value: &[u8],
) -> Result<Vec<u16>, RuntimeError> {
    if value.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "MCI guest string contains an embedded terminator",
        ));
    }
    codec.to_wide_z(value)
}
pub(in crate::windows) fn zeroed_buffer(capacity: Option<u32>) -> Result<Vec<u8>, RuntimeError> {
    let size = usize::try_from(capacity.unwrap_or(0)).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "MCI output buffer size does not fit host address space",
            error,
        )
    })?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate owned MCI output buffer",
            error,
        )
    })?;
    bytes.resize(size, 0);
    Ok(bytes)
}

pub(in crate::windows) fn wide_capacity(capacity: Option<u32>) -> Result<usize, RuntimeError> {
    usize::try_from(capacity.unwrap_or(0)).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "MCI guest text capacity does not fit host address space",
            error,
        )
    })
}

pub(in crate::windows) fn zeroed_wide_buffer(size: usize) -> Result<Vec<u16>, RuntimeError> {
    let mut units = Vec::new();
    units.try_reserve_exact(size).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate owned MCI UTF-16 output buffer",
            error,
        )
    })?;
    units.resize(size, 0);
    Ok(units)
}

/// The Win16 capacity is bytes and includes the terminator. That same numeric
/// capacity is enough UTF-16 units for at most `capacity - 1` guest text bytes
/// plus NUL. Encode only complete characters and reserve the guest NUL byte.
pub(in crate::windows) fn guest_output_from_wide(
    codec: GuestTextCodec,
    wide: &[u16],
    capacity: Option<u32>,
) -> Result<Vec<u8>, RuntimeError> {
    guest_output_projection(codec, wide, capacity).map(|(bytes, _)| bytes)
}

pub(in crate::windows) fn guest_output_projection(
    codec: GuestTextCodec,
    wide: &[u16],
    capacity: Option<u32>,
) -> Result<(Vec<u8>, bool), RuntimeError> {
    let mut output = zeroed_buffer(capacity)?;
    if output.is_empty() {
        return Ok((output, false));
    }
    let text = &wide[..wide
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(wide.len())];
    let encoded = codec.from_wide_bounded(text, output.len() - 1)?;
    output[..encoded.bytes.len()].copy_from_slice(&encoded.bytes);
    Ok((output, encoded.truncated))
}
