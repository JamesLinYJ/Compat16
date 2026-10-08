//! Fixed-code-page conversion at the PE32 Win32 import boundary.

use runtime::{DiagnosticKind as Kind, RuntimeError, Win32ImportString as S};

use super::super::guest_text::GuestTextCodec;

/// Guest A entrypoints carry bytes in the configured guest code page. Decode
/// those bytes before calling the host W API; never rely on the process ACP.
pub(super) fn to_wide(codec: GuestTextCodec, value: S) -> Result<Vec<u16>, RuntimeError> {
    match value {
        S::Ansi(bytes) => codec.to_wide(&bytes),
        S::Wide(units) => copy_wide(&units, "copy guest UTF-16 text"),
    }
}

pub(super) fn to_wide_z(codec: GuestTextCodec, value: S, context: &'static str)
    -> Result<Vec<u16>, RuntimeError> {
    let mut units = to_wide(codec, value)?;
    if units.contains(&0) {
        return Err(RuntimeError::new(Kind::InvalidInput, context));
    }
    units.try_reserve(1).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "terminate guest UTF-16 text", error))?;
    units.push(0);
    Ok(units)
}

pub(super) fn optional_to_wide_z(codec: GuestTextCodec, value: Option<S>, context: &'static str)
    -> Result<Option<Vec<u16>>, RuntimeError> {
    value.map(|value| to_wide_z(codec, value, context)).transpose()
}

pub(super) fn from_wide(codec: GuestTextCodec, units: &[u16]) -> Result<Vec<u8>, RuntimeError> {
    Ok(codec.from_wide(units)?.bytes)
}

pub(super) fn from_wide_z(codec: GuestTextCodec, units: &[u16], context: &'static str)
    -> Result<Vec<u8>, RuntimeError> {
    let end = units.iter().position(|unit| *unit == 0)
        .ok_or_else(|| RuntimeError::new(Kind::HostFailure, context))?;
    from_wide(codec, &units[..end])
}

/// Convert a native fixed-width W filename to the guest A record. The guest
/// arrays have a byte-sized code-page contract, so leave room for NUL and clip
/// only at complete Unicode scalar boundaries using the shared codec.
pub(super) fn fixed_ansi<const N: usize>(codec: GuestTextCodec, units: &[u16], context: &'static str)
    -> Result<[u8; N], RuntimeError> {
    let end = units.iter().position(|unit| *unit == 0)
        .ok_or_else(|| RuntimeError::new(Kind::HostFailure, context))?;
    let mut output = [0_u8; N];
    if N > 1 {
        let encoded = codec.from_wide_bounded(&units[..end], N - 1)?;
        output[..encoded.bytes.len()].copy_from_slice(&encoded.bytes);
    }
    Ok(output)
}

fn copy_wide(units: &[u16], context: &'static str) -> Result<Vec<u16>, RuntimeError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(units.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, context, error))?;
    copy.extend_from_slice(units);
    Ok(copy)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp936() -> GuestTextCodec {
        GuestTextCodec::new(936).expect("Windows should provide code page 936")
    }

    #[test]
    fn ansi_text_uses_the_configured_guest_code_page() {
        let codec = cp936();
        assert_eq!(codec.code_page(), 936);
        assert_eq!(to_wide(codec, S::Ansi(vec![0xd6, 0xd0])).unwrap(), [0x4e2d]);
        assert_eq!(from_wide(codec, &[0x4e2d]).unwrap(), [0xd6, 0xd0]);
    }

    #[test]
    fn terminated_inputs_reject_embedded_nuls_and_keep_absence_distinct() {
        let codec = cp936();
        assert_eq!(to_wide_z(codec, S::Ansi(Vec::new()), "test").unwrap(), [0]);
        assert!(optional_to_wide_z(codec, None, "test").unwrap().is_none());
        assert!(to_wide_z(codec, S::Ansi(vec![b'A', 0, b'B']), "test").is_err());
    }

    #[test]
    fn fixed_ansi_arrays_keep_terminators_and_never_split_dbcs_characters() {
        let codec = cp936();
        assert_eq!(fixed_ansi::<4>(codec, &[0x4e2d, b'A' as u16, 0], "test").unwrap(),
            [0xd6, 0xd0, b'A', 0]);
        assert_eq!(fixed_ansi::<2>(codec, &[0x4e2d, 0], "test").unwrap(), [0, 0]);
    }
}
