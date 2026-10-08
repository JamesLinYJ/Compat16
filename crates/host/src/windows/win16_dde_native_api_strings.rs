//! Native DDEML string-handle operations.

use super::*;
use crate::windows::guest_text::GuestTextCodec;
use windows_sys::Win32::Foundation::{ERROR_NO_UNICODE_TRANSLATION, GetLastError};

pub(super) fn create_string(
    context: &WorkerContext,
    instance: Win16HostDdeInstance,
    value: Vec<u8>,
    code_page: i16,
) -> Result<Win16HostDdeResult, RuntimeError> {
    let native_instance = context.state.borrow().native_instance(instance)?;
    let value = match guest_dde_string_to_wide(context, &value, code_page) {
        Ok(value) => value,
        Err(error) if is_guest_parameter_error(&error) => {
            return Ok(result(
                Win16HostDdeValue::String(None),
                compat_services::win16_dde::error::INVALIDPARAMETER,
            ));
        }
        Err(error) => return Err(error),
    };
    let native = unsafe { DdeCreateStringHandleW(native_instance, value.as_ptr(), CP_WINUNICODE) };
    if native.is_null() {
        return Ok(result(
            Win16HostDdeValue::String(None),
            native_error(native_instance),
        ));
    }
    let interned = context.state.borrow_mut().intern_string(instance, native);
    match interned {
        Ok(Some(token)) => {
            if let Err(error) = context.state.borrow_mut().retain_string(token) {
                unsafe {
                    DdeFreeStringHandle(native_instance, native);
                }
                context
                    .state
                    .borrow_mut()
                    .discard_unreferenced_string(token);
                return Err(error);
            }
            Ok(result(Win16HostDdeValue::String(Some(token)), 0))
        }
        Ok(None) => Ok(result(
            Win16HostDdeValue::String(None),
            native_error(native_instance),
        )),
        Err(error) => {
            unsafe {
                DdeFreeStringHandle(native_instance, native);
            }
            Err(error)
        }
    }
}

pub(super) fn free_string(
    context: &WorkerContext,
    instance: Win16HostDdeInstance,
    string: Win16HostDdeString,
) -> Result<Win16HostDdeResult, RuntimeError> {
    let (native_instance, native_string, references) = {
        let state = context.state.borrow();
        let references = state
            .strings
            .get(&string)
            .filter(|record| record.instance == instance)
            .ok_or_else(|| protocol_error("DDE string handle belongs to another instance"))?
            .references;
        (
            state.native_instance(instance)?,
            state.native_string(instance, string)?,
            references,
        )
    };
    if references == 0 {
        return Ok(result(
            Win16HostDdeValue::Boolean(false),
            compat_services::win16_dde::error::INVALIDPARAMETER,
        ));
    }
    let succeeded = unsafe { DdeFreeStringHandle(native_instance, native_string) } != 0;
    let error = if succeeded {
        0
    } else {
        native_error(native_instance)
    };
    if succeeded {
        context.state.borrow_mut().release_string(string);
    }
    Ok(result(Win16HostDdeValue::Boolean(succeeded), error))
}

pub(super) fn query_string(
    context: &WorkerContext,
    instance: Win16HostDdeInstance,
    string: Win16HostDdeString,
    capacity: Option<u32>,
    code_page: i16,
) -> Result<Win16HostDdeResult, RuntimeError> {
    let (native_instance, native_string) = {
        let state = context.state.borrow();
        (
            state.native_instance(instance)?,
            state.native_string(instance, string)?,
        )
    };
    if let Err(error) = validate_guest_code_page(code_page) {
        if is_guest_parameter_error(&error) {
            return Ok(invalid_query_result(capacity)?);
        }
        return Err(error);
    }
    let capacity_usize = match capacity {
        Some(value) => Some(usize::try_from(value).map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "DDE QueryString capacity does not fit the host",
            )
        })?),
        None => None,
    };
    let _ = native_error(native_instance);
    let required = unsafe {
        DdeQueryStringW(
            native_instance,
            native_string,
            ptr::null_mut(),
            0,
            CP_WINUNICODE,
        )
    };
    if required == 0 {
        let error = native_error(native_instance);
        return Ok(result(
            Win16HostDdeValue::Text {
                bytes: empty_query_bytes(capacity)?,
                characters: 0,
            },
            error,
        ));
    }
    let wide_capacity = usize::try_from(required)
        .ok()
        .and_then(|length| length.checked_add(1))
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "DDE QueryString UTF-16 length exceeds the host range",
            )
        })?;
    let mut wide = Vec::new();
    wide.try_reserve_exact(wide_capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate DDE QueryString UTF-16 output",
            error,
        )
    })?;
    wide.resize(wide_capacity, 0);
    let _ = native_error(native_instance);
    let native_capacity = u32::try_from(wide_capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "DDE QueryString UTF-16 capacity exceeds the Windows API width",
            error,
        )
    })?;
    let copied = unsafe {
        DdeQueryStringW(
            native_instance,
            native_string,
            wide.as_mut_ptr(),
            native_capacity,
            CP_WINUNICODE,
        )
    };
    if copied == 0 {
        let error = native_error(native_instance);
        return Ok(result(
            Win16HostDdeValue::Text {
                bytes: empty_query_bytes(capacity)?,
                characters: 0,
            },
            error,
        ));
    }
    let copied_units = (copied as usize).min(wide.len());
    let copied_units = wide[..copied_units]
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(copied_units);
    let text = &wide[..copied_units];
    let Some(byte_capacity) = capacity_usize else {
        let characters = match guest_dde_text_length(context, text, code_page) {
            Ok(characters) => characters,
            Err(error) if is_guest_parameter_error(&error) => {
                return Ok(invalid_query_result(capacity)?);
            }
            Err(error) => return Err(error),
        };
        return Ok(result(
            Win16HostDdeValue::Text {
                bytes: Vec::new(),
                characters,
            },
            0,
        ));
    };
    let (bytes, characters) =
        match guest_dde_text_from_wide(context, text, code_page, byte_capacity) {
            Ok(converted) => converted,
            Err(error) if is_guest_parameter_error(&error) => {
                return Ok(invalid_query_result(capacity)?);
            }
            Err(error) => return Err(error),
        };
    Ok(result(Win16HostDdeValue::Text { bytes, characters }, 0))
}

fn guest_dde_string_to_wide(
    context: &WorkerContext,
    bytes: &[u8],
    code_page: i16,
) -> Result<Vec<u16>, RuntimeError> {
    if bytes.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "DDE string contains an embedded NUL byte",
        ));
    }
    let mut wide = if i32::from(code_page) == CP_WINANSI {
        context.guest_ansi_codec.to_wide(bytes)?
    } else if i32::from(code_page) == CP_WINUNICODE {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "CP_WINUNICODE is not a Win16 DDEML guest code page",
        ));
    } else {
        guest_codec(code_page)?.to_wide(bytes)?
    };
    if wide.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "DDE UTF-16 string contains an embedded NUL unit",
        ));
    }
    wide.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "terminate DDE UTF-16 string",
            error,
        )
    })?;
    wide.push(0);
    Ok(wide)
}

fn guest_dde_text_from_wide(
    context: &WorkerContext,
    text: &[u16],
    code_page: i16,
    byte_capacity: usize,
) -> Result<(Vec<u8>, u32), RuntimeError> {
    if i32::from(code_page) == CP_WINUNICODE {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "CP_WINUNICODE is not a Win16 DDEML guest code page",
        ));
    }

    let codec = if i32::from(code_page) == CP_WINANSI {
        context.guest_ansi_codec
    } else {
        guest_codec(code_page)?
    };
    if byte_capacity == 0 {
        return Ok((Vec::new(), 0));
    }
    let converted = codec.from_wide_bounded(text, byte_capacity.saturating_sub(1))?;
    let characters = u32::try_from(converted.bytes.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "DDE guest-byte result length exceeds the return value width",
            error,
        )
    })?;
    let mut bytes = converted.bytes;
    bytes.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "terminate guest DDE string", error)
    })?;
    bytes.push(0);
    Ok((bytes, characters))
}

fn guest_dde_text_length(
    context: &WorkerContext,
    text: &[u16],
    code_page: i16,
) -> Result<u32, RuntimeError> {
    if i32::from(code_page) == CP_WINUNICODE {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "CP_WINUNICODE is not a Win16 DDEML guest code page",
        ));
    }
    let codec = if i32::from(code_page) == CP_WINANSI {
        context.guest_ansi_codec
    } else {
        guest_codec(code_page)?
    };
    u32::try_from(codec.from_wide(text)?.bytes.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "DDE guest-byte result length exceeds the return value width",
            error,
        )
    })
}

fn guest_codec(code_page: i16) -> Result<GuestTextCodec, RuntimeError> {
    let code_page = u32::try_from(code_page)
        .map_err(|_| RuntimeError::new(Kind::InvalidInput, "DDE code page is negative"))?;
    GuestTextCodec::new(code_page)
}

fn validate_guest_code_page(code_page: i16) -> Result<(), RuntimeError> {
    if i32::from(code_page) == CP_WINANSI {
        return Ok(());
    }
    guest_codec(code_page).map(|_| ())
}

fn is_guest_parameter_error(error: &RuntimeError) -> bool {
    error.kind() == Kind::InvalidInput
        || (error.kind() == Kind::HostFailure
            && unsafe { GetLastError() } == ERROR_NO_UNICODE_TRANSLATION)
}

fn empty_query_bytes(capacity: Option<u32>) -> Result<Vec<u8>, RuntimeError> {
    if capacity.unwrap_or(0) == 0 {
        return Ok(Vec::new());
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(1).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate terminated empty DDE QueryString output",
            error,
        )
    })?;
    bytes.push(0);
    Ok(bytes)
}

fn invalid_query_result(capacity: Option<u32>) -> Result<Win16HostDdeResult, RuntimeError> {
    Ok(result(
        Win16HostDdeValue::Text {
            bytes: empty_query_bytes(capacity)?,
            characters: 0,
        },
        compat_services::win16_dde::error::INVALIDPARAMETER,
    ))
}

pub(super) fn keep_string(
    context: &WorkerContext,
    instance: Win16HostDdeInstance,
    string: Win16HostDdeString,
) -> Result<Win16HostDdeResult, RuntimeError> {
    let (native_instance, native_string) = {
        let state = context.state.borrow();
        (
            state.native_instance(instance)?,
            state.native_string(instance, string)?,
        )
    };
    let succeeded = unsafe { DdeKeepStringHandle(native_instance, native_string) } != 0;
    let error = if succeeded {
        0
    } else {
        native_error(native_instance)
    };
    if succeeded {
        if let Err(error) = context.state.borrow_mut().retain_string(string) {
            unsafe {
                DdeFreeStringHandle(native_instance, native_string);
            }
            return Err(error);
        }
    }
    Ok(result(Win16HostDdeValue::Boolean(succeeded), error))
}
