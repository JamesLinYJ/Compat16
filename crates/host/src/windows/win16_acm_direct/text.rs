//! Convert text fields at the Win16 ACM boundary.

use runtime::{DiagnosticKind as Kind, RuntimeError};

use super::super::guest_text::GuestTextCodec;

/// Decode a fixed guest ANSI field into a same-sized, owned UTF-16 field.
/// A terminator ends the guest string; a full field without one is decoded in
/// full. Win16 byte fields cannot expand beyond their capacity for supported
/// Windows SBCS/DBCS and UTF-8 mappings; report a compatibility gap otherwise.
pub(super) fn guest_fixed_to_wide<const N: usize>(
    codec: GuestTextCodec,
    source: &[u8; N],
) -> Result<[u16; N], RuntimeError> {
    let source_len = source.iter().position(|byte| *byte == 0).unwrap_or(N);
    let wide = codec.to_wide(&source[..source_len])?;
    if wide.len() > N {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "guest text does not fit its native UTF-16 field",
        ));
    }
    let mut output = [0; N];
    output[..wide.len()].copy_from_slice(&wide);
    Ok(output)
}

/// Encode a native fixed UTF-16 field into a fixed guest-byte field. The byte
/// capacity, not the UTF-16 array length, controls truncation; the result is
/// always NUL-terminated when the destination has at least one byte.
pub(super) fn wide_fixed_to_guest<const N: usize>(
    codec: GuestTextCodec,
    source: &[u16; N],
) -> Result<[u8; N], RuntimeError> {
    let source_len = source.iter().position(|unit| *unit == 0).unwrap_or(N);
    let encoded = codec.from_wide_bounded(&source[..source_len], N.saturating_sub(1))?;
    let mut output = [0; N];
    output[..encoded.bytes.len()].copy_from_slice(&encoded.bytes);
    Ok(output)
}

/// Encode a native UTF-16 string into an owned guest output buffer. The
/// destination retains its exact guest byte capacity and a terminating NUL.
pub(super) fn wide_to_guest_buffer(
    codec: GuestTextCodec,
    source: &[u16],
    byte_capacity: usize,
) -> Result<Vec<u8>, RuntimeError> {
    let mut output = Vec::new();
    output.try_reserve_exact(byte_capacity).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "reserve guest text buffer", error)
    })?;
    output.resize(byte_capacity, 0);
    if byte_capacity == 0 {
        return Ok(output);
    }
    let source_len = source.iter().position(|unit| *unit == 0).unwrap_or(source.len());
    let encoded = codec.from_wide_bounded(&source[..source_len], byte_capacity - 1)?;
    output[..encoded.bytes.len()].copy_from_slice(&encoded.bytes);
    Ok(output)
}

/// Convert an optional guest C string while preserving the distinction
/// between an absent pointer and a present empty string.
pub(super) fn optional_guest_string_to_wide_z(
    codec: GuestTextCodec,
    source: Option<&[u8]>,
) -> Result<Option<Vec<u16>>, RuntimeError> {
    source.map(|bytes| codec.to_wide_z(bytes)).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf8() -> GuestTextCodec {
        GuestTextCodec::new(65_001).expect("Windows UTF-8 code page is available")
    }

    #[test]
    fn fixed_guest_field_decodes_full_unterminated_bytes() {
        let codec = utf8();
        let wide = guest_fixed_to_wide(codec, &[0xe4, 0xb8, 0xad]).unwrap();
        assert_eq!(wide, [0x4e2d, 0, 0]);
    }

    #[test]
    fn fixed_wide_field_reserves_guest_byte_for_terminator() {
        let codec = utf8();
        let bytes = wide_fixed_to_guest(codec, &[b'A' as u16, 0x4e2d, 0, 0]).unwrap();
        assert_eq!(bytes, [b'A', 0, 0, 0]);
    }

    #[test]
    fn variable_guest_buffer_keeps_capacity_and_does_not_split_utf8_scalar() {
        let codec = utf8();
        let bytes = wide_to_guest_buffer(codec, &[0xd83d, 0xde00, 0], 4).unwrap();
        assert_eq!(bytes, [0, 0, 0, 0]);
        assert_eq!(wide_to_guest_buffer(codec, &[b'A' as u16, 0], 3).unwrap(), [b'A', 0, 0]);
    }
}
