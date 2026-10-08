//! Guest-byte and native UTF-16 buffers retained by modeless FINDREPLACEW.

use std::cell::{RefCell, UnsafeCell};
use std::ptr;
use std::rc::Rc;

use runtime::{DiagnosticKind as Kind, RuntimeError};

use super::super::super::win16_window_worker::WorkerState;

pub(super) fn native_text(
    state: &Rc<RefCell<WorkerState>>,
    bytes: Vec<u8>,
    name: &'static str,
) -> Result<Box<[UnsafeCell<u16>]>, RuntimeError> {
    if bytes.is_empty() || !bytes.contains(&0) {
        return Err(RuntimeError::new(Kind::CompatibilityGap,
            format!("Win16 {name} buffer is empty or not NUL terminated")));
    }
    let native_capacity = native_backing_units(bytes.len())?;
    let declared_units = usize::from(native_field_capacity(bytes.len())?) / 2;
    let end = bytes.iter().position(|byte| *byte == 0).ok_or_else(|| {
        RuntimeError::new(Kind::CompatibilityGap,
            format!("Win16 {name} buffer is not NUL terminated"))
    })?;
    let initial_wide = state.borrow().text_codec.to_wide(&bytes[..end])?;
    if initial_wide.len() >= declared_units {
        return Err(RuntimeError::new(Kind::CompatibilityGap,
            format!("Win16 {name} text exceeds the native FINDREPLACEW WORD capacity")));
    }
    let mut wide = super::super::text::zeroed_wide(native_capacity,
        "allocate modeless FINDREPLACEW UTF-16 buffer")?;
    super::super::text::guest_buffer_to_wide(state, &bytes, &mut wide,
        "Win16 FINDREPLACE text cannot fit its native UTF-16 backing")?;
    let mut cells = Vec::new();
    cells.try_reserve_exact(wide.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "allocate modeless Find/Replace native text", error))?;
    cells.extend(wide.into_iter().map(UnsafeCell::new));
    Ok(cells.into_boxed_slice())
}

pub(super) fn native_buffer_length(
    length: usize,
    name: &'static str,
) -> Result<u16, RuntimeError> {
    u16::try_from(length).map_err(|_| RuntimeError::new(Kind::CompatibilityGap,
        format!("Win16 FINDREPLACE {name} capacity exceeds the native WORD field")))
}

/// FINDREPLACEW specifies each buffer size in bytes in a WORD. Keep the
/// original guest byte capacity separately and cap the host declaration at
/// that native field's representable maximum.
pub(super) fn native_field_capacity(
    guest_byte_capacity: usize,
) -> Result<u16, RuntimeError> {
    let byte_capacity = guest_byte_capacity.saturating_mul(2)
        .min(usize::from(u16::MAX));
    u16::try_from(byte_capacity).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted,
        "convert FINDREPLACEW UTF-16 byte capacity",
        error,
    ))
}

/// Allocate for documented byte-count behavior and implementations that may
/// use the WORD value as a UTF-16-unit limit. Native writers stay in bounds.
pub(super) fn native_backing_units(
    guest_byte_capacity: usize,
) -> Result<usize, RuntimeError> {
    let declared = usize::from(native_field_capacity(guest_byte_capacity)?);
    Ok(guest_byte_capacity.max(declared))
}

pub(super) fn guest_text_for_native(
    state: &Rc<RefCell<WorkerState>>,
    guest_buffer: &[u8],
    native_storage_units: usize,
    declared_capacity_units: usize,
    description: &'static str,
) -> Result<Vec<u16>, RuntimeError> {
    let end = guest_buffer.iter().position(|byte| *byte == 0).ok_or_else(|| {
        RuntimeError::new(Kind::CompatibilityGap, description)
    })?;
    let wide = state.borrow().text_codec.to_wide(&guest_buffer[..end]).map_err(|error| {
        let kind = if error.kind() == Kind::ResourceExhausted {
            Kind::ResourceExhausted
        } else {
            Kind::CompatibilityGap
        };
        RuntimeError::with_source(kind, description, error)
    })?;
    if wide.len() >= declared_capacity_units {
        return Err(RuntimeError::new(Kind::CompatibilityGap, description));
    }
    let mut output = super::super::text::zeroed_wide(native_storage_units,
        "allocate FINDREPLACEW update scratch")?;
    output[..wide.len()].copy_from_slice(&wide);
    Ok(output)
}

pub(super) fn copy_native_text(
    state: &Rc<RefCell<WorkerState>>,
    source: *const UnsafeCell<u16>,
    native_units: usize,
    guest_byte_capacity: usize,
    context: &'static str,
) -> Result<Vec<u8>, RuntimeError> {
    if guest_byte_capacity == 0 {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "FINDREPLACEW backing lost its guest byte capacity"));
    }
    let mut wide = super::super::text::zeroed_wide(native_units,
        "copy native FINDREPLACEW text")?;
    // SAFETY: Source is an owned stable array of UnsafeCell<u16>; the native
    // callback is suspended and the destination has the exact checked unit
    // count.
    unsafe { ptr::copy_nonoverlapping(source.cast::<u16>(), wide.as_mut_ptr(), native_units); }
    let end = wide.iter().position(|unit| *unit == 0).ok_or_else(|| {
        RuntimeError::new(Kind::HostFailure, context)
    })?;
    let encoded = state.borrow().text_codec.from_wide_bounded(
        &wide[..end], guest_byte_capacity - 1,
    )?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(guest_byte_capacity).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, context, error))?;
    bytes.resize(guest_byte_capacity, 0);
    bytes[..encoded.bytes.len()].copy_from_slice(&encoded.bytes);
    if encoded.truncated {
        super::super::super::win16_window_position::report_diagnostic(state,
            Kind::CompatibilityGap,
            "Find/Replace native W text was truncated to the original guest byte capacity");
    }
    if encoded.used_default_char == Some(true) {
        super::super::super::win16_window_position::report_diagnostic(state,
            Kind::CompatibilityGap,
            "Find/Replace native W text used guest-code-page replacement characters");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_capacity_and_wide_backing_stay_bounded() {
        assert_eq!(native_field_capacity(1).unwrap(), 2);
        assert_eq!(native_backing_units(1).unwrap(), 2);
        assert_eq!(native_field_capacity(32_767).unwrap(), u16::MAX - 1);
        assert_eq!(native_backing_units(32_767).unwrap(), usize::from(u16::MAX - 1));
        assert_eq!(native_field_capacity(32_768).unwrap(), u16::MAX);
        assert_eq!(native_backing_units(32_768).unwrap(), usize::from(u16::MAX));
        assert_eq!(native_backing_units(65_535).unwrap(), usize::from(u16::MAX));
    }
}
