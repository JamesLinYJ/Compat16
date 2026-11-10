//! KERNEL32 path calls use native UTF-16 and translate guest A byte units.

use std::ptr;

use super::super::guest_text::GuestTextCodec;
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win32HostImportResult, Win32HostImportValue as V,
    Win32HostPathCall as C, Win32ImportString as S, Win32ImportTextEncoding as E,
    Win32PathQuery as Q, Win32PathTransform as T,
};
use windows_sys::Win32::{
    Storage::FileSystem::{GetFullPathNameW, GetLongPathNameW, GetShortPathNameW, GetTempPathW},
    System::{
        Environment::{GetCurrentDirectoryW, SetCurrentDirectoryW},
        SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW},
    },
};

use super::{api_error, result, text};

pub(super) fn execute(
    call: C,
    codec: GuestTextCodec,
) -> Result<Win32HostImportResult, RuntimeError> {
    match call {
        C::Query {
            kind,
            encoding,
            capacity,
            output_present,
        } => query(kind, encoding, capacity, output_present, codec),
        C::SetCurrentDirectory { path } => set_current_directory(path, codec),
        C::Transform {
            kind,
            path,
            capacity,
            output_present,
            request_file_part,
        } => transform(
            kind,
            path,
            capacity,
            output_present,
            request_file_part,
            codec,
        ),
    }
}

fn query(
    kind: Q,
    encoding: E,
    capacity: u32,
    output_present: bool,
    codec: GuestTextCodec,
) -> Result<Win32HostImportResult, RuntimeError> {
    if let E::Wide = encoding {
        let mut buffer = wide_buffer(capacity, output_present)?;
        let pointer = if output_present {
            buffer.as_mut_ptr()
        } else {
            ptr::null_mut()
        };
        crate::windows::win32_safe::set_last_error(0);
        // SAFETY: `pointer` is null only for the guest's valid NULL and
        // zero-capacity pair. Otherwise it addresses the caller-owned buffer of
        // `capacity` UTF-16 units, which stays live for this call. A zero return
        // is the failure result. The pointer is a host address, not a guest
        // address.
        let returned = unsafe { call_query_w(kind, capacity, pointer) };
        let error = (returned == 0).then(api_error);
        let valid = output_is_complete(returned, capacity, output_present);
        let value = if valid {
            terminated_prefix_wide(&buffer, returned)?
        } else {
            Vec::new()
        };
        return Ok(result(
            V::Text {
                result: returned,
                output_valid: valid,
                text: S::Wide(value),
                file_part_offset: None,
            },
            error,
        ));
    }

    let (value, error) = complete_query_w(kind)?;
    let Some(value) = value else {
        return Ok(result(
            V::Text {
                result: 0,
                output_valid: false,
                text: S::Ansi(Vec::new()),
                file_part_offset: None,
            },
            error,
        ));
    };
    let bytes = text::from_wide(codec, &value)?;
    let (returned, valid) =
        ansi_output_count(bytes.len(), capacity, output_present, "ANSI path result")?;
    Ok(result(
        V::Text {
            result: returned,
            output_valid: valid,
            text: S::Ansi(if valid { bytes } else { Vec::new() }),
            file_part_offset: None,
        },
        None,
    ))
}

fn set_current_directory(
    path: S,
    codec: GuestTextCodec,
) -> Result<Win32HostImportResult, RuntimeError> {
    let path = text::to_wide_z(
        codec,
        path,
        "Win32 current-directory path contains embedded NUL",
    )?;
    // SAFETY: `path` is an owned NUL-terminated UTF-16 path that stays live for
    // this call. A zero BOOL is the only failure result. The pointer is a host
    // address, not a guest address.
    let success = unsafe { SetCurrentDirectoryW(path.as_ptr()) } != 0;
    Ok(result(V::Bool(success), (!success).then(api_error)))
}

fn transform(
    kind: T,
    path: S,
    capacity: u32,
    output_present: bool,
    request_file_part: bool,
    codec: GuestTextCodec,
) -> Result<Win32HostImportResult, RuntimeError> {
    if !matches!(kind, T::Full) && request_file_part {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "file-part output was requested for a path transform without that parameter",
        ));
    }
    let ansi = matches!(path, S::Ansi(_));
    let path = text::to_wide_z(
        codec,
        path,
        "Win32 path transform input contains embedded NUL",
    )?;
    if ansi {
        let (wide, file_part, error) = complete_transform_w(kind, &path, request_file_part)?;
        let Some(wide) = wide else {
            return Ok(result(
                V::Text {
                    result: 0,
                    output_valid: false,
                    text: S::Ansi(Vec::new()),
                    file_part_offset: None,
                },
                error,
            ));
        };
        let bytes = text::from_wide(codec, &wide)?;
        let (returned, valid) = ansi_output_count(
            bytes.len(),
            capacity,
            output_present,
            "ANSI path transform result",
        )?;
        let file_part_offset = if valid {
            file_part
                .map(|offset| {
                    let prefix = wide.get(..offset).ok_or_else(|| {
                        contract("GetFullPathNameW file-part offset exceeds its UTF-16 result")
                    })?;
                    let encoded = text::from_wide(codec, prefix)?;
                    u32::try_from(encoded.len()).map_err(|_| exhausted("ANSI file-part offset"))
                })
                .transpose()?
        } else {
            None
        };
        Ok(result(
            V::Text {
                result: returned,
                output_valid: valid,
                text: S::Ansi(if valid { bytes } else { Vec::new() }),
                file_part_offset,
            },
            None,
        ))
    } else {
        transform_wide_guest(kind, path, capacity, output_present, request_file_part)
    }
}

fn transform_wide_guest(
    kind: T,
    path: Vec<u16>,
    capacity: u32,
    output_present: bool,
    request_file_part: bool,
) -> Result<Win32HostImportResult, RuntimeError> {
    let mut buffer = wide_buffer(capacity, output_present)?;
    let output = if output_present {
        buffer.as_mut_ptr()
    } else {
        ptr::null_mut()
    };
    let mut file_part = ptr::null_mut();
    let file_part_ptr = if request_file_part {
        &mut file_part
    } else {
        ptr::null_mut()
    };
    crate::windows::win32_safe::set_last_error(0);
    // SAFETY: `path` is an owned NUL-terminated UTF-16 path that stays live for
    // this call. `output` is null or the caller-owned buffer of `capacity`
    // UTF-16 units, which stays live. `file_part_ptr` is null or the local
    // file-part slot, which stays live and does not escape. All three are host
    // addresses, not guest addresses.
    let returned =
        unsafe { call_transform_w(kind, path.as_ptr(), capacity, output, file_part_ptr) };
    let valid = returned != 0 && returned < capacity && output_present;
    let error = (returned == 0).then(api_error);
    let value = if valid {
        terminated_prefix_wide(&buffer, returned)?
    } else {
        Vec::new()
    };
    let offset = if valid && request_file_part && !file_part.is_null() {
        Some(checked_wide_offset(
            buffer.as_ptr(),
            buffer.len(),
            file_part,
        )?)
    } else {
        None
    };
    Ok(result(
        V::Text {
            result: returned,
            output_valid: valid,
            text: S::Wide(value),
            file_part_offset: offset,
        },
        error,
    ))
}

fn complete_transform_w(
    kind: T,
    path: &[u16],
    request_file_part: bool,
) -> Result<(Option<Vec<u16>>, Option<usize>, Option<u32>), RuntimeError> {
    let mut capacity = 260_usize;
    loop {
        let native_capacity = u32::try_from(capacity).map_err(|_| exhausted("wide path buffer"))?;
        let mut buffer = wide_buffer(native_capacity, true)?;
        let mut file_part = ptr::null_mut();
        let file_part_ptr = if request_file_part {
            &mut file_part
        } else {
            ptr::null_mut()
        };
        crate::windows::win32_safe::set_last_error(0);
        // SAFETY: `path` is a NUL-terminated UTF-16 input that stays live for
        // this call. `buffer` has `native_capacity` writable UTF-16 units and
        // stays live. `file_part_ptr` is null or the local file-part slot, which
        // stays live and does not escape. All three are host addresses, not
        // guest addresses.
        let returned = unsafe {
            call_transform_w(
                kind,
                path.as_ptr(),
                native_capacity,
                buffer.as_mut_ptr(),
                file_part_ptr,
            )
        };
        if returned == 0 {
            return Ok((None, None, Some(api_error())));
        }
        if returned < native_capacity {
            let value = terminated_prefix_wide(&buffer, returned)?;
            let offset = if request_file_part && !file_part.is_null() {
                let offset = usize::try_from(checked_wide_offset(
                    buffer.as_ptr(),
                    buffer.len(),
                    file_part,
                )?)
                .map_err(|_| exhausted("wide file-part offset"))?;
                if offset > value.len() {
                    return Err(contract(
                        "GetFullPathNameW file-part pointer follows the path",
                    ));
                }
                Some(offset)
            } else {
                None
            };
            return Ok((Some(value), offset, None));
        }
        capacity = next_capacity(capacity, returned, "wide path transform")?;
    }
}

// SAFETY: `path` is a NUL-terminated UTF-16 path that stays live for the call.
// `output` is null or addresses at least `capacity` writable UTF-16 units that
// stay live. `file_part` is null or addresses a caller-owned pointer slot that
// stays live for the call and does not escape. Every pointer is a host address,
// not a guest address. `file_part` is used only for `T::Full`.
unsafe fn call_transform_w(
    kind: T,
    path: *const u16,
    capacity: u32,
    output: *mut u16,
    file_part: *mut *mut u16,
) -> u32 {
    match kind {
        T::Full => {
            // SAFETY: `path` is a NUL-terminated UTF-16 path that stays live for
            // this call. `output` is null or addresses at least `capacity`
            // writable UTF-16 units that stay live. `file_part` is null or a
            // caller-owned pointer slot that stays live and does not escape.
            // GetFullPathNameW returns 0 on failure and retains no pointer.
            // Every pointer is a host address, not a guest address.
            unsafe { GetFullPathNameW(path, capacity, output, file_part) }
        }
        T::Long => {
            // SAFETY: `path` is a NUL-terminated UTF-16 path that stays live for
            // this call. `output` is null or addresses at least `capacity`
            // writable UTF-16 units that stay live. GetLongPathNameW returns 0
            // on failure and retains no pointer. `file_part` is not passed.
            // Both pointers are host addresses, not guest addresses.
            unsafe { GetLongPathNameW(path, output, capacity) }
        }
        T::Short => {
            // SAFETY: `path` is a NUL-terminated UTF-16 path that stays live for
            // this call. `output` is null or addresses at least `capacity`
            // writable UTF-16 units that stay live. GetShortPathNameW returns 0
            // on failure and retains no pointer. `file_part` is not passed.
            // Both pointers are host addresses, not guest addresses.
            unsafe { GetShortPathNameW(path, output, capacity) }
        }
    }
}

fn complete_query_w(kind: Q) -> Result<(Option<Vec<u16>>, Option<u32>), RuntimeError> {
    let mut capacity = 260_usize;
    loop {
        let native_capacity = u32::try_from(capacity).map_err(|_| exhausted("wide path buffer"))?;
        let mut buffer = wide_buffer(native_capacity, true)?;
        crate::windows::win32_safe::set_last_error(0);
        // SAFETY: `buffer` is caller-owned and has `native_capacity` writable
        // UTF-16 units that stay live for this call. A zero return is the
        // failure result. The pointer is a host address, not a guest address.
        let returned = unsafe { call_query_w(kind, native_capacity, buffer.as_mut_ptr()) };
        if returned == 0 {
            return Ok((None, Some(api_error())));
        }
        if returned < native_capacity {
            return Ok((Some(terminated_prefix_wide(&buffer, returned)?), None));
        }
        capacity = next_capacity(capacity, returned, "wide path query")?;
    }
}

// SAFETY: `output` is null or addresses at least `capacity` writable UTF-16
// units that stay live for the call. The pointer is a host address, not a guest
// address. A null output is valid only with a zero capacity.
unsafe fn call_query_w(kind: Q, capacity: u32, output: *mut u16) -> u32 {
    match kind {
        Q::CurrentDirectory => {
            // SAFETY: `output` is null or addresses at least `capacity` writable
            // UTF-16 units that stay live for this call. GetCurrentDirectoryW
            // returns 0 on failure and retains no pointer. The pointer is a host
            // address, not a guest address.
            unsafe { GetCurrentDirectoryW(capacity, output) }
        }
        Q::SystemDirectory => {
            // SAFETY: `output` is null or addresses at least `capacity` writable
            // UTF-16 units that stay live for this call. GetSystemDirectoryW
            // returns 0 on failure and retains no pointer. The pointer is a host
            // address, not a guest address.
            unsafe { GetSystemDirectoryW(output, capacity) }
        }
        Q::WindowsDirectory => {
            // SAFETY: `output` is null or addresses at least `capacity` writable
            // UTF-16 units that stay live for this call. GetWindowsDirectoryW
            // returns 0 on failure and retains no pointer. The pointer is a host
            // address, not a guest address.
            unsafe { GetWindowsDirectoryW(output, capacity) }
        }
        Q::TempPath => {
            // SAFETY: `output` is null or addresses at least `capacity` writable
            // UTF-16 units that stay live for this call. GetTempPathW returns 0
            // on failure and retains no pointer. The pointer is a host address,
            // not a guest address.
            unsafe { GetTempPathW(capacity, output) }
        }
    }
}

fn next_capacity(
    current: usize,
    reported: u32,
    resource: &'static str,
) -> Result<usize, RuntimeError> {
    const MAX_WIDE_PATH: usize = 32_768;
    let reported = usize::try_from(reported).map_err(|_| exhausted(resource))?;
    let doubled = current.checked_mul(2).ok_or_else(|| exhausted(resource))?;
    let next = reported.max(doubled);
    if next <= current || next > MAX_WIDE_PATH {
        return Err(exhausted(resource));
    }
    Ok(next)
}

fn with_nul_count(length: usize, resource: &'static str) -> Result<usize, RuntimeError> {
    length.checked_add(1).ok_or_else(|| exhausted(resource))
}

/// ANSI path APIs count guest bytes without the terminator on success, and
/// include its byte when reporting the required capacity.
fn ansi_output_count(
    byte_length: usize,
    capacity: u32,
    output_present: bool,
    resource: &'static str,
) -> Result<(u32, bool), RuntimeError> {
    let required = with_nul_count(byte_length, resource)?;
    let capacity = usize::try_from(capacity).map_err(|_| exhausted(resource))?;
    let valid = output_present && capacity >= required;
    let count = if valid { byte_length } else { required };
    Ok((
        u32::try_from(count).map_err(|_| exhausted(resource))?,
        valid,
    ))
}

fn wide_buffer(capacity: u32, present: bool) -> Result<Vec<u16>, RuntimeError> {
    if !present && capacity != 0 {
        return Err(RuntimeError::new(
            Kind::GuestFault,
            "Win32 wide path output is NULL with nonzero capacity",
        ));
    }
    let size = usize::try_from(capacity).map_err(|_| exhausted("Win32 wide path output"))?;
    let allocation = size.max(usize::from(present && size == 0));
    let mut output = Vec::new();
    output.try_reserve_exact(allocation).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve Win32 wide path output",
            error,
        )
    })?;
    output.resize(allocation, 0);
    Ok(output)
}

fn output_is_complete(returned: u32, capacity: u32, present: bool) -> bool {
    returned != 0 && returned < capacity && present
}

fn terminated_prefix_wide(buffer: &[u16], returned: u32) -> Result<Vec<u16>, RuntimeError> {
    let length = usize::try_from(returned).map_err(|_| exhausted("Win32 wide path result"))?;
    if length >= buffer.len() || buffer[length] != 0 {
        return Err(contract(
            "native wide path API returned success without a bounded terminator",
        ));
    }
    let mut text = Vec::new();
    text.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "copy Win32 wide path result",
            error,
        )
    })?;
    text.extend_from_slice(&buffer[..length]);
    Ok(text)
}

fn checked_wide_offset(
    base: *const u16,
    capacity: usize,
    part: *const u16,
) -> Result<u32, RuntimeError> {
    let base = base as usize;
    let part = part as usize;
    let bytes = part
        .checked_sub(base)
        .filter(|offset| *offset % 2 == 0)
        .ok_or_else(|| contract("GetFullPathNameW returned an unaligned local pointer"))?;
    let offset = bytes / 2;
    if offset >= capacity {
        return Err(contract(
            "GetFullPathNameW returned a pointer outside its local buffer",
        ));
    }
    u32::try_from(offset).map_err(|_| contract("GetFullPathNameW file-part offset overflowed"))
}

fn exhausted(resource: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::ResourceExhausted, format!("{resource} exhausted"))
}

fn contract(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::HostFailure, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ansi_path_counts_guest_bytes_and_only_counts_nul_when_required() {
        assert_eq!(ansi_output_count(2, 3, true, "test").unwrap(), (2, true));
        assert_eq!(ansi_output_count(2, 2, true, "test").unwrap(), (3, false));
        assert_eq!(ansi_output_count(2, 0, false, "test").unwrap(), (3, false));
    }

    #[test]
    fn wide_path_success_requires_a_terminated_complete_buffer() {
        assert!(output_is_complete(2, 3, true));
        assert!(!output_is_complete(3, 3, true));
        assert!(!output_is_complete(2, 3, false));
    }
}
