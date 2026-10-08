//! Windows printer-name resolution shared by the spool-job and queue adapters.

use std::mem::size_of;
use std::ptr;

use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PRINTER_NAME};
use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
use windows_sys::Win32::Graphics::Printing::{
    EnumPrintersW, PRINTER_ENUM_CONNECTIONS, PRINTER_ENUM_LOCAL, PRINTER_INFO_2W,
};

use super::last_error;

pub(super) fn resolve_printer_name(
    target_z: &[u16],
) -> Result<Result<Vec<u16>, u32>, RuntimeError> {
    if target_z.is_empty() {
        return Ok(Err(ERROR_INVALID_PRINTER_NAME));
    }
    let target = target_z.strip_suffix(&[0]).unwrap_or(target_z);
    if target.is_empty() {
        return Ok(Err(ERROR_INVALID_PRINTER_NAME));
    }

    let mut needed = 0u32;
    let mut returned = 0u32;
    // SAFETY: this first call requests the byte count only; the output buffer
    // is null and the returned byte count is writable.
    unsafe {
        EnumPrintersW(
            PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS,
            ptr::null(),
            2,
            ptr::null_mut(),
            0,
            &mut needed,
            &mut returned,
        );
    }
    if needed == 0 {
        let error = last_error();
        if error != ERROR_INSUFFICIENT_BUFFER {
            // There may be no local queues. A direct OpenPrinterW name or
            // remote queue can still be valid, so let that API decide.
            return Ok(Ok(target_z.to_vec()));
        }
    }

    let words = usize::try_from(needed)
        .ok()
        .and_then(|bytes| bytes.checked_add(size_of::<usize>() - 1))
        .map(|bytes| bytes / size_of::<usize>())
        .ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted, "printer enumeration size overflow")
        })?;
    let mut storage = Vec::<usize>::new();
    storage.try_reserve_exact(words).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate printer enumeration buffer",
            error,
        )
    })?;
    storage.resize(words, 0);
    let capacity_bytes = words
        .checked_mul(size_of::<usize>())
        .and_then(|bytes| u32::try_from(bytes).ok())
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "printer enumeration buffer exceeds Windows ABI",
            )
        })?;
    let mut actual_bytes = 0u32;
    let mut returned = 0u32;
    // SAFETY: storage is aligned for SDK structures and writable for the
    // supplied byte count. Windows fills only the documented level-2 array
    // and strings within this owned buffer.
    if unsafe {
        EnumPrintersW(
            PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS,
            ptr::null(),
            2,
            storage.as_mut_ptr().cast(),
            capacity_bytes,
            &mut actual_bytes,
            &mut returned,
        )
    } == 0
    {
        return Ok(Ok(target_z.to_vec()));
    }
    let available_bytes = usize::try_from(actual_bytes)
        .unwrap_or(0)
        .min(capacity_bytes as usize);
    let record_count = usize::try_from(returned).map_err(|error| {
        RuntimeError::with_source(Kind::InternalInvariant, "invalid printer count", error)
    })?;
    let records_bytes = record_count
        .checked_mul(size_of::<PRINTER_INFO_2W>())
        .ok_or_else(|| {
            RuntimeError::new(Kind::InternalInvariant, "printer record count overflow")
        })?;
    if records_bytes > available_bytes {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "EnumPrintersW returned records outside its output buffer",
        ));
    }
    // SAFETY: the records span is validated against the SDK byte count above;
    // storage has pointer alignment and EnumPrintersW produced initialized
    // PRINTER_INFO_2W records.
    let records = unsafe {
        std::slice::from_raw_parts(storage.as_ptr().cast::<PRINTER_INFO_2W>(), record_count)
    };
    let mut exact_name: Option<Vec<u16>> = None;
    let mut port_name_match: Option<Vec<u16>> = None;
    for record in records {
        let printer_name = wide_string_in_buffer(record.pPrinterName, &storage, available_bytes)?;
        let port_name = wide_string_in_buffer(record.pPortName, &storage, available_bytes)?;
        let (Some(printer_name), Some(port_name)) = (printer_name, port_name) else {
            continue;
        };
        let name_matches = ordinal_equal_ignore_case(target, printer_name);
        let port_matches = port_name
            .split(|unit| *unit == u16::from(b','))
            .any(|port| ordinal_equal_ignore_case(target, trim_wide(port)));
        if !name_matches && !port_matches {
            continue;
        }
        if name_matches && !record_unique_name(&mut exact_name, printer_name) {
            return Ok(Err(ERROR_INVALID_PRINTER_NAME));
        }
        if port_matches && !record_unique_name(&mut port_name_match, printer_name) {
            return Ok(Err(ERROR_INVALID_PRINTER_NAME));
        }
    }
    let mut name = exact_name
        .or(port_name_match)
        .unwrap_or_else(|| target_z.to_vec());
    if name.last() != Some(&0) {
        name.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "terminate Windows printer name",
                error,
            )
        })?;
        name.push(0);
    }
    Ok(Ok(name))
}

fn record_unique_name(slot: &mut Option<Vec<u16>>, name: &[u16]) -> bool {
    match slot {
        Some(previous) => ordinal_equal_ignore_case(previous, name),
        None => {
            *slot = Some(name.to_vec());
            true
        }
    }
}

fn wide_string_in_buffer<'a>(
    pointer: *const u16,
    storage: &'a [usize],
    used_bytes: usize,
) -> Result<Option<&'a [u16]>, RuntimeError> {
    if pointer.is_null() {
        return Ok(None);
    }
    let start = pointer as usize;
    let base = storage.as_ptr() as usize;
    let end = base.checked_add(used_bytes).ok_or_else(|| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "EnumPrintersW output range overflow",
        )
    })?;
    if start < base || start >= end || start % size_of::<u16>() != 0 {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "EnumPrintersW returned a string outside its output buffer",
        ));
    }
    let capacity = (end - start) / size_of::<u16>();
    // SAFETY: the pointer range is checked against the live enumeration
    // buffer; the terminator search is bounded by its remaining byte count.
    let units = unsafe { std::slice::from_raw_parts(pointer, capacity) };
    let Some(length) = units.iter().position(|unit| *unit == 0) else {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "EnumPrintersW returned an unterminated string",
        ));
    };
    Ok(Some(&units[..length]))
}

pub(super) fn ordinal_equal_ignore_case(left: &[u16], right: &[u16]) -> bool {
    let Ok(left_len) = i32::try_from(left.len()) else {
        return false;
    };
    let Ok(right_len) = i32::try_from(right.len()) else {
        return false;
    };
    // SAFETY: both slices are live and the explicit lengths bound the reads.
    unsafe {
        CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) == CSTR_EQUAL
    }
}

fn trim_wide(value: &[u16]) -> &[u16] {
    let mut start = 0;
    let mut end = value.len();
    while start < end && value[start] == u16::from(b' ') {
        start += 1;
    }
    while start < end && value[end - 1] == u16::from(b' ') {
        end -= 1;
    }
    &value[start..end]
}
