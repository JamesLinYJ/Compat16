//! Explicit guest-code-page conversion for common-dialog text and wire blocks.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::Globalization::{CPINFO, GetCPInfo};

use super::super::win16_window_worker::WorkerState;
use crate::windows::guest_text::GuestTextCodec;

const DEVNAMES_HEADER_BYTES: usize = 8;
const MAX_GUEST_DEVNAMES_BYTES: usize = 64 * 1024;
const MAX_NATIVE_DEVNAMES_BYTES: usize = 128 * 1024;

#[derive(Debug)]
pub(super) struct TextProjection {
    /// Converted bytes, including any terminators preserved by the caller's
    /// C-string or MULTI_SZ contract.
    pub bytes: Vec<u8>,
    pub truncated: bool,
    pub used_default_char: bool,
}

pub(super) fn zeroed_wide(
    units: usize,
    description: &'static str,
) -> Result<Vec<u16>, RuntimeError> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(units)
        .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted, description, error))?;
    buffer.resize(units, 0);
    Ok(buffer)
}

/// Convert a non-NUL-terminated guest string into an owned UTF-16 C string.
pub(in crate::windows::win16_windows) fn guest_z_to_wide(
    state: &Rc<RefCell<WorkerState>>,
    bytes: &[u8],
    description: &'static str,
) -> Result<Vec<u16>, RuntimeError> {
    if bytes.contains(&0) {
        return Err(RuntimeError::new(Kind::CompatibilityGap, description));
    }
    state.borrow().text_codec.to_wide_z(bytes)
}

pub(super) fn optional_guest_z_to_wide(
    state: &Rc<RefCell<WorkerState>>,
    bytes: Option<&[u8]>,
    description: &'static str,
) -> Result<Option<Vec<u16>>, RuntimeError> {
    bytes
        .map(|bytes| guest_z_to_wide(state, bytes, description))
        .transpose()
}

/// Convert one NUL-terminated guest buffer while preserving its requested
/// native WCHAR capacity. Only the text prefix is read; the guest tail remains
/// host-owned and is never used as native string data.
pub(super) fn guest_buffer_to_wide(
    state: &Rc<RefCell<WorkerState>>,
    bytes: &[u8],
    wide_buffer: &mut [u16],
    description: &'static str,
) -> Result<(), RuntimeError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| RuntimeError::new(Kind::CompatibilityGap, description))?;
    let converted = state.borrow().text_codec.to_wide(&bytes[..end])?;
    if converted.len() >= wide_buffer.len() {
        return Err(RuntimeError::new(Kind::CompatibilityGap, description));
    }
    wide_buffer.fill(0);
    wide_buffer[..converted.len()].copy_from_slice(&converted);
    Ok(())
}

/// Convert a guest MULTI_SZ while retaining every NUL separator.
pub(super) fn guest_multisz_to_wide(
    state: &Rc<RefCell<WorkerState>>,
    bytes: &[u8],
    description: &'static str,
) -> Result<Vec<u16>, RuntimeError> {
    guest_multisz_to_wide_with_codec(state.borrow().text_codec, bytes, description)
}

fn guest_multisz_to_wide_with_codec(
    codec: GuestTextCodec,
    bytes: &[u8],
    description: &'static str,
) -> Result<Vec<u16>, RuntimeError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.ends_with(&[0, 0]) {
        return Err(RuntimeError::new(Kind::CompatibilityGap, description));
    }
    let mut wide = Vec::new();
    wide.try_reserve_exact(bytes.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate converted common-dialog MULTI_SZ",
            error,
        )
    })?;
    let mut start = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == 0 {
            wide.extend(codec.to_wide(&bytes[start..index])?);
            wide.push(0);
            start = index + 1;
        }
    }
    if start != bytes.len() {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "converted common-dialog MULTI_SZ lost its final terminator",
        ));
    }
    Ok(wide)
}

/// Convert the two OPENFILENAME custom-filter strings from their double-NUL
/// terminated guest prefix, ignoring unused bytes after that prefix.
pub(super) fn guest_custom_filter_to_wide(
    state: &Rc<RefCell<WorkerState>>,
    bytes: &[u8],
    wide_buffer: &mut [u16],
    description: &'static str,
) -> Result<(), RuntimeError> {
    if bytes.is_empty() {
        wide_buffer.fill(0);
        return Ok(());
    }
    let converted = guest_custom_filter_to_wide_with_codec(
        state.borrow().text_codec,
        bytes,
        description,
    )?;
    if converted.len() > wide_buffer.len() {
        return Err(RuntimeError::new(Kind::CompatibilityGap, description));
    }
    wide_buffer.fill(0);
    wide_buffer[..converted.len()].copy_from_slice(&converted);
    Ok(())
}

fn guest_custom_filter_to_wide_with_codec(
    codec: GuestTextCodec,
    bytes: &[u8],
    description: &'static str,
) -> Result<Vec<u16>, RuntimeError> {
    let mut converted = Vec::new();
    converted.try_reserve_exact(bytes.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate converted OPENFILENAME custom-filter pair",
            error,
        )
    })?;
    let mut cursor = 0;
    let mut second_length = 0;
    for index in 0..2 {
        let remaining = bytes
            .get(cursor..)
            .ok_or_else(|| RuntimeError::new(Kind::CompatibilityGap, description))?;
        let length = remaining
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| RuntimeError::new(Kind::CompatibilityGap, description))?;
        if index == 1 {
            second_length = length;
        }
        converted.extend(codec.to_wide(&remaining[..length])?);
        converted.push(0);
        cursor = cursor.checked_add(length + 1).ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted, description)
        })?;
    }
    let has_extra_terminator = bytes.get(cursor) == Some(&0);
    let empty_second_ends_double_nul = second_length == 0
        && cursor >= 2
        && bytes.get(cursor - 2..cursor) == Some(&[0, 0]);
    if !has_extra_terminator && !empty_second_ends_double_nul {
        return Err(RuntimeError::new(Kind::CompatibilityGap, description));
    }
    if has_extra_terminator {
        converted.push(0);
    }
    Ok(converted)
}

pub(super) fn native_wide_z_to_guest(
    state: &Rc<RefCell<WorkerState>>,
    wide_buffer: &[u16],
    guest_byte_capacity: usize,
    description: &'static str,
) -> Result<TextProjection, RuntimeError> {
    let end = wide_buffer
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| RuntimeError::new(Kind::HostFailure, description))?;
    let converted = state
        .borrow()
        .text_codec
        .from_wide_bounded(&wide_buffer[..end], guest_byte_capacity)?;
    Ok(TextProjection {
        bytes: converted.bytes,
        truncated: converted.truncated,
        used_default_char: converted.used_default_char == Some(true),
    })
}

/// Project a native MULTI_SZ into a byte capacity without splitting an
/// encoded character or dropping the terminating empty string.
pub(super) fn native_wide_multisz_to_guest_bounded(
    state: &Rc<RefCell<WorkerState>>,
    wide_buffer: &[u16],
    guest_byte_capacity: usize,
    description: &'static str,
) -> Result<TextProjection, RuntimeError> {
    native_wide_multisz_to_guest_with_codec(
        state.borrow().text_codec,
        wide_buffer,
        guest_byte_capacity,
        description,
    )
}

fn native_wide_multisz_to_guest_with_codec(
    codec: GuestTextCodec,
    wide_buffer: &[u16],
    guest_byte_capacity: usize,
    description: &'static str,
) -> Result<TextProjection, RuntimeError> {
    if guest_byte_capacity < 2 {
        return Ok(TextProjection {
            bytes: Vec::new(),
            truncated: !wide_buffer.starts_with(&[0, 0]),
            used_default_char: false,
        });
    }
    if wide_buffer.len() < 2 {
        return Err(RuntimeError::new(Kind::HostFailure, description));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(guest_byte_capacity)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve a bounded common-dialog MULTI_SZ",
                error,
            )
        })?;
    let mut truncated = false;
    let mut used_default_char = false;
    let mut cursor = 0;
    loop {
        if wide_buffer.get(cursor) == Some(&0) {
            // Every preceding entry already supplied its own NUL. Only an
            // empty list needs both terminators appended here.
            if bytes.is_empty() {
                if wide_buffer.get(cursor + 1) != Some(&0) {
                    return Err(RuntimeError::new(Kind::HostFailure, description));
                }
                bytes.push(0);
            }
            bytes.push(0);
            break;
        }
        if cursor >= wide_buffer.len() {
            return Err(RuntimeError::new(Kind::HostFailure, description));
        }
        let remaining = &wide_buffer[cursor..];
        let Some(length) = remaining.iter().position(|unit| *unit == 0) else {
            return Err(RuntimeError::new(Kind::HostFailure, description));
        };
        if guest_byte_capacity - bytes.len() < 2 {
            bytes.push(0);
            truncated = true;
            break;
        }
        let room_for_text = guest_byte_capacity.saturating_sub(bytes.len().saturating_add(2));
        let encoded = codec.from_wide_bounded(&remaining[..length], room_for_text)?;
        used_default_char |= encoded.used_default_char == Some(true);
        truncated |= encoded.truncated;
        if encoded.truncated && encoded.bytes.is_empty() && !bytes.is_empty() {
            bytes.push(0);
            break;
        }
        bytes.extend_from_slice(&encoded.bytes);
        bytes.push(0);
        cursor += length + 1;
        if truncated {
            bytes.push(0);
            break;
        }
    }
    Ok(TextProjection {
        bytes,
        truncated,
        used_default_char,
    })
}

/// Write a converted C string over the front of an existing guest buffer.
/// Bytes after the written terminator remain unchanged for partial native
/// output writes.
pub(super) fn write_native_z_to_guest(
    state: &Rc<RefCell<WorkerState>>,
    wide_buffer: &[u16],
    guest_buffer: &mut [u8],
    description: &'static str,
) -> Result<TextProjection, RuntimeError> {
    if guest_buffer.is_empty() {
        let projection = native_wide_z_to_guest(state, wide_buffer, 0, description)?;
        return Ok(projection);
    }
    let projection =
        native_wide_z_to_guest(state, wide_buffer, guest_buffer.len() - 1, description)?;
    let copied = projection.bytes.len();
    guest_buffer[..copied].copy_from_slice(&projection.bytes);
    guest_buffer[copied] = 0;
    Ok(projection)
}

pub(super) fn write_native_multisz_to_guest(
    state: &Rc<RefCell<WorkerState>>,
    wide_buffer: &[u16],
    guest_buffer: &mut [u8],
    description: &'static str,
) -> Result<TextProjection, RuntimeError> {
    let projection =
        native_wide_multisz_to_guest_bounded(state, wide_buffer, guest_buffer.len(), description)?;
    if projection.bytes.len() > guest_buffer.len() {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "bounded common-dialog MULTI_SZ exceeds its guest buffer",
        ));
    }
    guest_buffer[..projection.bytes.len()].copy_from_slice(&projection.bytes);
    Ok(projection)
}

/// Write the two native custom-filter strings into the guest buffer. Win16
/// requires a double-NUL suffix; the UTF-16 buffer may contain only the two
/// individual string terminators, so add the list terminator when needed.
pub(super) fn write_native_custom_filter_to_guest(
    state: &Rc<RefCell<WorkerState>>,
    wide_buffer: &[u16],
    guest_buffer: &mut [u8],
    description: &'static str,
) -> Result<TextProjection, RuntimeError> {
    let projection = native_custom_filter_to_guest_with_codec(
        state.borrow().text_codec,
        wide_buffer,
        guest_buffer.len(),
        description,
    )?;
    if projection.bytes.len() > guest_buffer.len() {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "bounded OPENFILENAME custom-filter pair exceeds its guest buffer",
        ));
    }
    guest_buffer[..projection.bytes.len()].copy_from_slice(&projection.bytes);
    Ok(projection)
}

fn native_custom_filter_to_guest_with_codec(
    codec: GuestTextCodec,
    wide_buffer: &[u16],
    guest_byte_capacity: usize,
    description: &'static str,
) -> Result<TextProjection, RuntimeError> {
    if wide_buffer.is_empty() {
        return Err(RuntimeError::new(Kind::HostFailure, description));
    }
    let mut strings = [(0_usize, 0_usize); 2];
    let mut cursor = 0;
    for string in &mut strings {
        let remaining = wide_buffer
            .get(cursor..)
            .ok_or_else(|| RuntimeError::new(Kind::HostFailure, description))?;
        let length = remaining
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| RuntimeError::new(Kind::HostFailure, description))?;
        *string = (cursor, length);
        cursor = cursor.checked_add(length + 1).ok_or_else(|| {
            RuntimeError::new(Kind::HostFailure, description)
        })?;
    }
    if guest_byte_capacity < 2 {
        return Ok(TextProjection {
            bytes: Vec::new(),
            truncated: true,
            used_default_char: false,
        });
    }
    let reserve_final_nul = usize::from(strings[1].1 != 0);
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(guest_byte_capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve bounded OPENFILENAME custom-filter pair",
            error,
        )
    })?;
    let mut truncated = false;
    let mut used_default_char = false;
    for (index, (start, length)) in strings.into_iter().enumerate() {
        let terminators_left = 2 - index + reserve_final_nul;
        let text_capacity = guest_byte_capacity
            .saturating_sub(bytes.len().saturating_add(terminators_left));
        let encoded = codec.from_wide_bounded(
            &wide_buffer[start..start + length],
            text_capacity,
        )?;
        truncated |= encoded.truncated;
        used_default_char |= encoded.used_default_char == Some(true);
        bytes.extend_from_slice(&encoded.bytes);
        bytes.push(0);
    }
    if !bytes.ends_with(&[0, 0]) {
        if bytes.len() < guest_byte_capacity {
            bytes.push(0);
        } else {
            truncated = true;
        }
    }
    Ok(TextProjection {
        bytes,
        truncated,
        used_default_char,
    })
}

pub(super) fn fixed_guest_text_to_wide<const N: usize>(
    state: &Rc<RefCell<WorkerState>>,
    source: &[u8; N],
    description: &'static str,
) -> Result<[u16; N], RuntimeError> {
    let end = source.iter().position(|byte| *byte == 0).unwrap_or(N);
    let converted = state.borrow().text_codec.to_wide(&source[..end])?;
    if converted.len() > N {
        return Err(RuntimeError::new(Kind::CompatibilityGap, description));
    }
    let mut output = [0_u16; N];
    output[..converted.len()].copy_from_slice(&converted);
    Ok(output)
}

pub(super) fn native_wide_prefix_guest_bytes(
    state: &Rc<RefCell<WorkerState>>,
    wide_prefix: &[u16],
    description: &'static str,
) -> Result<usize, RuntimeError> {
    native_wide_prefix_guest_bytes_with_codec(state.borrow().text_codec, wide_prefix, description)
}

fn native_wide_prefix_guest_bytes_with_codec(
    codec: GuestTextCodec,
    wide_prefix: &[u16],
    description: &'static str,
) -> Result<usize, RuntimeError> {
    let converted = codec
        .from_wide(wide_prefix)
        .map_err(|error| RuntimeError::with_source(Kind::CompatibilityGap, description, error))?;
    Ok(converted.bytes.len())
}

pub(super) fn guest_max_character_bytes(
    state: &Rc<RefCell<WorkerState>>,
) -> Result<usize, RuntimeError> {
    let code_page = state.borrow().text_codec.code_page();
    let mut info = CPINFO::default();
    // SAFETY: GetCPInfo receives an explicit numeric guest code page and a
    // writable fixed-size record that remains live for this call.
    if unsafe { GetCPInfo(code_page, &mut info) } == 0 || info.MaxCharSize == 0 {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "Windows could not report the guest code-page maximum character width",
        ));
    }
    usize::try_from(info.MaxCharSize).map_err(|error| {
        RuntimeError::with_source(
            Kind::InternalInvariant,
            "convert the guest code-page maximum character width",
            error,
        )
    })
}

pub(super) fn wide_units_to_guest_upper_bound(
    state: &Rc<RefCell<WorkerState>>,
    wide_units: usize,
) -> Result<u16, RuntimeError> {
    let required = wide_units
        .checked_mul(guest_max_character_bytes(state)?)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 common-dialog required byte capacity overflow",
            )
        })?;
    u16::try_from(required).map_err(|error| {
        RuntimeError::with_source(
            Kind::CompatibilityGap,
            "native UTF-16 required size has no representable Win16 WORD upper bound",
            error,
        )
    })
}

pub(in crate::windows::win16_windows) fn guest_devnames_to_wide(
    state: &Rc<RefCell<WorkerState>>,
    bytes: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    guest_devnames_to_wide_with_codec(state.borrow().text_codec, bytes)
}

fn guest_devnames_to_wide_with_codec(
    codec: GuestTextCodec,
    bytes: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    validate_guest_devnames(bytes)?;
    let offsets = [
        read_u16(bytes, 0)?,
        read_u16(bytes, 2)?,
        read_u16(bytes, 4)?,
    ];
    let default = read_u16(bytes, 6)?;
    let mut wide = vec![0_u16; 4];
    let mut converted_offsets = [0_u16; 3];
    for index in 0..3 {
        if let Some(previous) = (0..index).find(|previous| offsets[*previous] == offsets[index]) {
            converted_offsets[index] = converted_offsets[previous];
            continue;
        }
        let start = usize::from(offsets[index]);
        let end = bytes[start..]
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| {
                RuntimeError::new(Kind::GuestFault, "Win16 DEVNAMES string is unterminated")
            })?
            + start;
        let string = codec.to_wide(&bytes[start..end])?;
        converted_offsets[index] = u16::try_from(wide.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "native DEVNAMES character offset exceeds WORD",
                error,
            )
        })?;
        wide.try_reserve(string.len().saturating_add(1))
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "allocate native DEVNAMES strings",
                    error,
                )
            })?;
        wide.extend_from_slice(&string);
        wide.push(0);
    }
    let mut output = Vec::new();
    let output_size = wide.len().checked_mul(2).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "native DEVNAMES byte size overflow",
        )
    })?;
    output.try_reserve_exact(output_size).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate native wide DEVNAMES block",
            error,
        )
    })?;
    for word in [
        converted_offsets[0],
        converted_offsets[1],
        converted_offsets[2],
        default,
    ] {
        output.extend_from_slice(&word.to_le_bytes());
    }
    for unit in wide.into_iter().skip(4) {
        output.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(output)
}

pub(in crate::windows::win16_windows) fn native_wide_devnames_to_guest(
    state: &Rc<RefCell<WorkerState>>,
    bytes: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    let (guest, used_default_char) =
        native_wide_devnames_to_guest_with_codec(state.borrow().text_codec, bytes)?;
    if used_default_char {
        super::super::win16_window_position::report_diagnostic(
            state,
            Kind::CompatibilityGap,
            "native wide DEVNAMES contains a printer name outside the guest code page",
        );
    }
    Ok(guest)
}

fn native_wide_devnames_to_guest_with_codec(
    codec: GuestTextCodec,
    bytes: &[u8],
) -> Result<(Vec<u8>, bool), RuntimeError> {
    if bytes.len() < DEVNAMES_HEADER_BYTES
        || bytes.len() > MAX_NATIVE_DEVNAMES_BYTES
        || bytes.len() % 2 != 0
    {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "native wide DEVNAMES block has an invalid size",
        ));
    }
    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    let offsets = [
        read_u16(bytes, 0)?,
        read_u16(bytes, 2)?,
        read_u16(bytes, 4)?,
    ];
    let default = read_u16(bytes, 6)?;
    let mut guest = vec![0_u8; DEVNAMES_HEADER_BYTES];
    let mut converted_offsets = [0_u16; 3];
    let mut used_default_char = false;
    for index in 0..3 {
        if let Some(previous) = (0..index).find(|previous| offsets[*previous] == offsets[index]) {
            converted_offsets[index] = converted_offsets[previous];
            continue;
        }
        let start = usize::from(offsets[index]);
        if start < 4 || start >= units.len() {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "native wide DEVNAMES offset is outside its string block",
            ));
        }
        let end = units[start..]
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::HostFailure,
                    "native wide DEVNAMES string is unterminated",
                )
            })?
            + start;
        let encoded = codec.from_wide(&units[start..end])?;
        converted_offsets[index] = u16::try_from(guest.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "Win16 DEVNAMES byte offset exceeds WORD",
                error,
            )
        })?;
        let needed = guest
            .len()
            .checked_add(encoded.bytes.len())
            .and_then(|size| size.checked_add(1))
            .filter(|size| *size <= MAX_GUEST_DEVNAMES_BYTES)
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "converted Win16 DEVNAMES exceeds its 64 KiB global block",
                )
            })?;
        guest
            .try_reserve(needed.saturating_sub(guest.len()))
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "allocate converted Win16 DEVNAMES",
                    error,
                )
            })?;
        guest.extend_from_slice(&encoded.bytes);
        guest.push(0);
        used_default_char |= encoded.used_default_char == Some(true);
    }
    guest[0..2].copy_from_slice(&converted_offsets[0].to_le_bytes());
    guest[2..4].copy_from_slice(&converted_offsets[1].to_le_bytes());
    guest[4..6].copy_from_slice(&converted_offsets[2].to_le_bytes());
    guest[6..8].copy_from_slice(&default.to_le_bytes());
    Ok((guest, used_default_char))
}

fn validate_guest_devnames(bytes: &[u8]) -> Result<(), RuntimeError> {
    if bytes.len() < DEVNAMES_HEADER_BYTES || bytes.len() > MAX_GUEST_DEVNAMES_BYTES {
        return Err(RuntimeError::new(
            Kind::GuestFault,
            "Win16 DEVNAMES block has an invalid size",
        ));
    }
    for offset in [0, 2, 4] {
        let start = usize::from(read_u16(bytes, offset)?);
        if start < DEVNAMES_HEADER_BYTES || start >= bytes.len() || !bytes[start..].contains(&0) {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "Win16 DEVNAMES offset is outside its string block",
            ));
        }
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, RuntimeError> {
    let end = offset.checked_add(2).ok_or_else(|| {
        RuntimeError::new(Kind::InternalInvariant, "DEVNAMES word offset overflow")
    })?;
    let pair = bytes.get(offset..end).ok_or_else(|| {
        RuntimeError::new(
            Kind::HostFailure,
            "DEVNAMES block is shorter than its header",
        )
    })?;
    Ok(u16::from_le_bytes([pair[0], pair[1]]))
}

#[cfg(test)]
#[path = "win16_common_dialog_text_tests.rs"]
mod tests;
