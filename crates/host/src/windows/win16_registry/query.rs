//! Native registry reads and the Win3.1 string-only projection.
use super::{GuestTextCodec, guest_output_conversion_failure};
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostRegistryResult, Win16RegistryQueryOutput,
    Win16RegistryQueryView,
};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    ERROR_INVALID_DATA, ERROR_MORE_DATA, ERROR_NO_UNICODE_TRANSLATION, ERROR_SUCCESS,
    ERROR_UNSUPPORTED_TYPE,
};
use windows_sys::Win32::System::Registry::{
    HKEY, REG_EXPAND_SZ, REG_SZ, RRF_NOEXPAND, RRF_RT_REG_EXPAND_SZ, RegGetValueW, RegQueryValueW,
};
pub(super) fn query_value(
    codec: GuestTextCodec,
    key: HKEY,
    subkey: &[u16],
    output: Win16RegistryQueryOutput,
    view: Win16RegistryQueryView,
) -> Result<Win16HostRegistryResult, RuntimeError> {
    if let Win16RegistryQueryOutput::WithoutLength { data_present } = output {
        // Preserve native ordering: a missing subkey is reported before a
        // non-NULL data buffer with no length is rejected. Native data never
        // points into guest memory. The one-unit buffer also accommodates the
        // legacy empty-default case; a nonempty transfer requires lpcbData.
        let mut unused = 0_u16;
        let data = if data_present {
            &mut unused as *mut u16
        } else {
            null_mut()
        };
        // SAFETY: key/subkey remain live. With NULL lpcbData the native API
        // rejects nonempty data transfer; the owned unit covers an empty NUL.
        let status = unsafe { RegQueryValueW(key, subkey.as_ptr(), data, null_mut()) };
        return Ok(query_result(status, 0, Vec::new()));
    }
    let mut native_size = 0_i32;
    // RegQueryValueW's null-output query reports the native UTF-16 data size in
    // bytes. A complete value is needed to compute the guest code-page byte
    // count; the legacy Win16 capacity remains in guest bytes below.
    // SAFETY: the key and UTF-16 subkey are live, and `native_size` is writable.
    let mut sizing_status =
        unsafe { RegQueryValueW(key, subkey.as_ptr(), null_mut(), &mut native_size) };
    let raw_expandable =
        sizing_status == ERROR_INVALID_DATA && view == Win16RegistryQueryView::Win31Strings;
    if raw_expandable {
        // Win3.1 has no expandable-string type. Read the actual text without
        // interpreting environment references; never retype the native value.
        // SAFETY: this is a sizing query with no output buffer.
        sizing_status = unsafe { read_expandable(key, subkey, null_mut(), &mut native_size) };
    }
    if sizing_status != ERROR_SUCCESS {
        return Ok(query_result(sizing_status, 0, Vec::new()));
    }
    if native_size < 0 || native_size % 2 != 0 {
        return Ok(query_result(ERROR_INVALID_DATA, 0, Vec::new()));
    }

    let mut required_native = usize::try_from(native_size).map_err(|error| {
        RuntimeError::with_source(
            Kind::InternalInvariant,
            "RegQueryValue returned an invalid UTF-16 byte count",
            error,
        )
    })?;
    if raw_expandable {
        // RegGetValue guarantees termination on an actual data transfer. Its
        // sizing call can report zero for an empty, zero-byte stored value.
        required_native = required_native.checked_add(2).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "reserve registry string terminator",
            )
        })?;
    }
    for attempt in 0..3 {
        if required_native % 2 != 0 {
            return Ok(query_result(ERROR_INVALID_DATA, 0, Vec::new()));
        }
        let wide_units = required_native / 2;
        let mut wide = Vec::new();
        wide.try_reserve_exact(wide_units).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate Win16 registry query buffer",
                error,
            )
        })?;
        wide.resize(wide_units, 0);
        let mut returned_native = i32::try_from(required_native).map_err(|error| {
            RuntimeError::with_source(
                Kind::InvalidInput,
                "registry value exceeds the native byte-count range",
                error,
            )
        })?;
        let native_output = if wide.is_empty() {
            null_mut()
        } else {
            wide.as_mut_ptr()
        };
        // SAFETY: the optional output is writable for exactly the byte count
        // passed through `returned_native`, and all pointers remain live.
        let status = unsafe {
            if raw_expandable {
                read_expandable(key, subkey, native_output, &mut returned_native)
            } else {
                RegQueryValueW(key, subkey.as_ptr(), native_output, &mut returned_native)
            }
        };
        if status == ERROR_MORE_DATA
            && attempt < 2
            && returned_native >= 0
            && usize::try_from(returned_native).is_ok_and(|length| length > required_native)
        {
            required_native = returned_native as usize;
            continue;
        }
        if status != ERROR_SUCCESS {
            return Ok(query_result(status, 0, Vec::new()));
        }
        if returned_native < 0
            || returned_native % 2 != 0
            || usize::try_from(returned_native)
                .ok()
                .is_none_or(|length| length > required_native)
        {
            return Ok(query_result(ERROR_INVALID_DATA, 0, Vec::new()));
        }
        wide.truncate(returned_native as usize / 2);
        let mut bytes = match codec.from_wide(&wide) {
            Ok(encoded) => encoded.bytes,
            Err(error) if guest_output_conversion_failure(&error) => {
                return Ok(query_result(ERROR_NO_UNICODE_TRANSLATION, 0, Vec::new()));
            }
            Err(error) => return Err(error),
        };
        let required_bytes = u32::try_from(bytes.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::InvalidInput,
                "Win16 registry value exceeds DWORD byte count",
                error,
            )
        })?;
        if matches!(output, Win16RegistryQueryOutput::Bounded(capacity) if bytes.len() > capacity as usize)
        {
            return Ok(query_result(ERROR_MORE_DATA, required_bytes, Vec::new()));
        }
        // The size-only query still converts the complete native value so a
        // DBCS byte count cannot be mistaken for its UTF-16 storage size.
        if output == Win16RegistryQueryOutput::SizeOnly {
            bytes.clear();
        }
        return Ok(Win16HostRegistryResult::QueryValue {
            status: ERROR_SUCCESS,
            value_type: if raw_expandable {
                REG_EXPAND_SZ
            } else {
                REG_SZ
            },
            required_bytes,
            bytes,
        });
    }
    Ok(query_result(ERROR_MORE_DATA, 0, Vec::new()))
}

/// The optional buffer is owned by query_value and writable for *byte_count
/// bytes. No guest pointer reaches this function.
unsafe fn read_expandable(
    key: HKEY,
    subkey: &[u16],
    buffer: *mut u16,
    byte_count: &mut i32,
) -> u32 {
    let Ok(mut count) = u32::try_from(*byte_count) else {
        return ERROR_INVALID_DATA;
    };
    // RegGetValueW checks the native type and ensures string termination.
    // NOEXPAND preserves the original text even for defined environment names.
    // https://learn.microsoft.com/windows/win32/api/winreg/nf-winreg-reggetvaluew
    // SAFETY: the caller owns the optional buffer and the terminated subkey;
    // count exactly describes that buffer, and unused value/type fields are NULL.
    let status = unsafe {
        RegGetValueW(
            key,
            subkey.as_ptr(),
            null(),
            RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
            null_mut(),
            buffer.cast(),
            &mut count,
        )
    };
    let Ok(count) = i32::try_from(count) else {
        return ERROR_INVALID_DATA;
    };
    *byte_count = count;
    // Other native types retain the original RegQueryValue failure. This
    // includes a value changed concurrently to a non-expandable type.
    if status == ERROR_UNSUPPORTED_TYPE {
        ERROR_INVALID_DATA
    } else {
        status
    }
}

fn query_result(status: u32, required_bytes: u32, bytes: Vec<u8>) -> Win16HostRegistryResult {
    Win16HostRegistryResult::QueryValue {
        status,
        value_type: REG_SZ,
        required_bytes,
        bytes,
    }
}
