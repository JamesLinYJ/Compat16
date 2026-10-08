//! Shared, host-only identity and value conversion for the OLE operation
//! dispatchers. Guest values are already checked/owned before they arrive.

use std::ffi::c_void;
use std::ptr;

use compat_services::com::{ComObjectId, Guid, ReferenceDisposition};
use runtime::{
    DiagnosticKind, RuntimeError, Win16ComHostInterface,
    Win16OleHostReply as Win16OleNativeReply, Win16OleHostValue as Win16OleNativeValue,
};
use windows_sys::Win32::Foundation::FILETIME;
use windows_sys::core::{GUID as NativeGuid, HRESULT, PWSTR};

use super::super::win16_com_objects::{NativeComError, Win16ComObjects};

const MAX_NATIVE_WIDE_STRING: usize = 32 * 1024;

pub(super) fn with_optional_unknown<R>(
    objects: &Win16ComObjects,
    object: Option<ComObjectId>,
    operation: impl FnOnce(*mut c_void) -> R,
) -> Result<Option<R>, RuntimeError> {
    with_optional_interface(objects, object, compat_services::com::IID_IUNKNOWN, operation)
}

pub(super) fn with_optional_interface<R>(
    objects: &Win16ComObjects,
    object: Option<ComObjectId>,
    iid: Guid,
    operation: impl FnOnce(*mut c_void) -> R,
) -> Result<Option<R>, RuntimeError> {
    match object {
        Some(object) => objects
            .with_interface(object, iid, operation)
            .map_err(com_error),
        None => Ok(Some(operation(ptr::null_mut()))),
    }
}

pub(super) fn with_required_interface<R>(
    objects: &Win16ComObjects,
    object: ComObjectId,
    iid: Guid,
    _name: &'static str,
    operation: impl FnOnce(*mut c_void) -> R,
) -> Result<Option<R>, RuntimeError> {
    objects
        .with_interface(object, iid, operation)
        .map_err(com_error)
}

pub(super) fn with_two_required_interfaces<R>(
    objects: &Win16ComObjects,
    first_object: ComObjectId,
    first_iid: Guid,
    second_object: ComObjectId,
    second_iid: Guid,
    operation: impl FnOnce(*mut c_void, *mut c_void) -> R,
) -> Result<Option<R>, RuntimeError> {
    let nested = objects
        .with_interface(first_object, first_iid, |first| {
            objects.with_interface(second_object, second_iid, |second| operation(first, second))
        })
        .map_err(com_error)?;
    match nested {
        Some(result) => result.map_err(com_error),
        None => Ok(None),
    }
}

pub(super) fn adopt_interface(
    objects: &Win16ComObjects,
    result: HRESULT,
    output: *mut c_void,
    iid: Guid,
) -> Result<(HRESULT, Win16OleNativeValue), RuntimeError> {
    if result >= 0 {
        if output.is_null() {
            return Err(RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "native COM activation succeeded with a null interface",
            ));
        }
        let object = objects.insert_owned(output).map_err(com_error)?;
        Ok((
            result,
            Win16OleNativeValue::Object(Win16ComHostInterface {
                object,
                owner: objects.owner_identity(),
                iid,
                disposition: ReferenceDisposition::Owned,
            }),
        ))
    } else {
        if !output.is_null() {
            objects.discard_owned(output).map_err(com_error)?;
        }
        Ok((result, Win16OleNativeValue::None))
    }
}

pub(super) fn status(status: HRESULT, value: Win16OleNativeValue) -> Win16OleNativeReply {
    Win16OleNativeReply {
        status: status as u32,
        value,
    }
}

pub(super) fn native_guid(value: Guid) -> NativeGuid {
    NativeGuid {
        data1: value.data1,
        data2: value.data2,
        data3: value.data3,
        data4: value.data4,
    }
}

pub(super) fn logical_guid(value: NativeGuid) -> Guid {
    Guid::new(value.data1, value.data2, value.data3, value.data4)
}

pub(super) fn file_time_from_bytes(bytes: [u8; 8]) -> FILETIME {
    FILETIME {
        dwLowDateTime: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        dwHighDateTime: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
    }
}

pub(super) fn file_time_bytes(value: FILETIME) -> [u8; 8] {
    let mut result = [0; 8];
    result[..4].copy_from_slice(&value.dwLowDateTime.to_le_bytes());
    result[4..].copy_from_slice(&value.dwHighDateTime.to_le_bytes());
    result
}

pub(super) fn ascii_wide_z(input: &[u8]) -> Option<Vec<u16>> {
    if input.contains(&0) || !input.is_ascii() {
        return None;
    }
    Some(
        input
            .iter()
            .map(|byte| u16::from(*byte))
            .chain(std::iter::once(0))
            .collect(),
    )
}

pub(super) fn wide_z(input: &[u16]) -> Option<Vec<u16>> {
    if input.contains(&0) {
        return None;
    }
    Some(input.iter().copied().chain(std::iter::once(0)).collect())
}

pub(super) fn decode_guest_text(input: &[u8], code_page: u32) -> Result<String, RuntimeError> {
    text_codec::CodePage::try_from(code_page)
        .and_then(|page| page.decode(input))
        .map_err(|error| {
            RuntimeError::with_source(
                DiagnosticKind::InvalidInput,
                "decode Win16 COM program identifier",
                error,
            )
        })
}

pub(super) fn copy_native_wide(pointer: PWSTR) -> Option<Vec<u16>> {
    if pointer.is_null() {
        return None;
    }
    let mut text = Vec::new();
    text.try_reserve_exact(64).ok()?;
    for index in 0..MAX_NATIVE_WIDE_STRING {
        // SAFETY: this native NUL-terminated string is API-owned; the bound
        // prevents an unterminated result from causing an unbounded scan.
        let unit = unsafe { pointer.add(index).read() };
        if unit == 0 {
            text.push(0);
            return Some(text);
        }
        text.try_reserve(1).ok()?;
        text.push(unit);
    }
    None
}

pub(super) fn com_error(error: NativeComError) -> RuntimeError {
    RuntimeError::with_source(
        DiagnosticKind::HostFailure,
        "Win16 native COM object",
        error,
    )
}
