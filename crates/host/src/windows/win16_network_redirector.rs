//! WFW network redirector calls backed by the installed Windows MPR provider.
//!
//! The Win16 side supplies owned guest bytes. This adapter uses W APIs and the
//! configured guest codec so host ANSI settings never define guest strings.

use super::guest_text::GuestTextCodec;
use runtime::{
    RuntimeError, Win16HostNetworkRedirectorCall as Call,
    Win16HostNetworkRedirectorResult as ResultValue, Win16HostNetworkRedirectorValue as Value,
};
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, NO_ERROR};
use windows_sys::Win32::NetworkManagement::WNet::{
    WNetAddConnectionW, WNetCancelConnectionW, WNetGetConnectionW, WNetGetLastErrorW, WNetGetUserW,
};

const INITIAL_TEXT_CAPACITY: usize = 256;
const MAX_NATIVE_TEXT_UNITS: usize = 1_048_576;
const MAX_LAST_ERROR_TEXT_UNITS: usize = 65_536;

pub(super) fn execute(call: Call, codec: &GuestTextCodec) -> Result<ResultValue, RuntimeError> {
    match call {
        Call::AddConnection {
            remote_name,
            password,
            local_name,
        } => {
            let (status, value) = add_connection(
                codec,
                &remote_name,
                password.as_deref(),
                local_name.as_deref(),
            )?;
            Ok(ResultValue { status, value })
        }
        Call::CancelConnection { local_name, force } => {
            let status = cancel_connection(codec, &local_name, force)?;
            Ok(ResultValue {
                status,
                value: Value::None,
            })
        }
        Call::GetConnection { local_name } => match get_connection(codec, &local_name) {
            Ok((status, text)) => Ok(ResultValue {
                status,
                value: text.map_or(Value::None, Value::Text),
            }),
            Err(error) => Err(error),
        },
        Call::GetUser => match get_user(codec) {
            Ok((status, text)) => Ok(ResultValue {
                status,
                value: text.map_or(Value::None, Value::Text),
            }),
            Err(error) => Err(error),
        },
        Call::GetLastError => match get_last_error(codec) {
            Ok((status, last_error)) => Ok(ResultValue {
                status,
                value: last_error.map_or(Value::None, |(code, message)| Value::LastError {
                    code,
                    message,
                }),
            }),
            Err(error) => Err(error),
        },
    }
}

fn add_connection(
    codec: &GuestTextCodec,
    remote_name: &[u8],
    password: Option<&[u8]>,
    local_name: Option<&[u8]>,
) -> Result<(u32, Value), RuntimeError> {
    let remote_name = match to_wide_input(codec, remote_name)? {
        Ok(value) => value,
        Err(status) => return Ok((status, Value::None)),
    };
    let password = match password.filter(|password| !password.is_empty()) {
        Some(password) => match to_wide_input(codec, password)? {
            Ok(value) => Some(value),
            Err(status) => return Ok((status, Value::None)),
        },
        None => None,
    };
    let local_name = match local_name {
        Some(name) => match to_wide_input(codec, name)? {
            Ok(value) => Some(value),
            Err(status) => return Ok((status, Value::None)),
        },
        None => None,
    };
    let password_pointer = password
        .as_ref()
        .map_or(std::ptr::null(), |value| value.as_ptr());
    let local_pointer = local_name
        .as_ref()
        .map_or(std::ptr::null(), |value| value.as_ptr());

    // Every pointer refers to a terminated Vec<u16> retained for this call.
    let status =
        // SAFETY: `WNetAddConnectionW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        unsafe { WNetAddConnectionW(remote_name.as_ptr(), password_pointer, local_pointer) };
    Ok((status, Value::None))
}

fn cancel_connection(
    codec: &GuestTextCodec,
    local_name: &[u8],
    force: bool,
) -> Result<u32, RuntimeError> {
    let local_name = match to_wide_input(codec, local_name)? {
        Ok(value) => value,
        Err(status) => return Ok(status),
    };
    // `local_name` is terminated and remains live for the synchronous API call.
    // SAFETY: `WNetCancelConnectionW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    Ok(unsafe { WNetCancelConnectionW(local_name.as_ptr(), i32::from(force)) })
}

fn get_connection(
    codec: &GuestTextCodec,
    local_name: &[u8],
) -> Result<(u32, Option<Vec<u8>>), RuntimeError> {
    let local_name = match to_wide_input(codec, local_name)? {
        Ok(value) => value,
        Err(status) => return Ok((status, None)),
    };
    query_text(codec, |buffer, length| {
        // The local name and writable buffer remain owned for the call.
        // SAFETY: `WNetGetConnectionW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        unsafe { WNetGetConnectionW(local_name.as_ptr(), buffer, length) }
    })
}

fn get_user(codec: &GuestTextCodec) -> Result<(u32, Option<Vec<u8>>), RuntimeError> {
    query_text(codec, |buffer, length| {
        // A null name requests the current user; output storage is owned here.
        // SAFETY: `WNetGetUserW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        unsafe { WNetGetUserW(std::ptr::null(), buffer, length) }
    })
}

fn query_text(
    codec: &GuestTextCodec,
    mut query: impl FnMut(*mut u16, *mut u32) -> u32,
) -> Result<(u32, Option<Vec<u8>>), RuntimeError> {
    let mut buffer = allocated_wide(INITIAL_TEXT_CAPACITY, "allocate WNet output buffer")?;
    loop {
        let mut length = u32::try_from(buffer.len()).map_err(|error| {
            RuntimeError::with_source(
                runtime::DiagnosticKind::ResourceExhausted,
                "WNet output buffer exceeds API length width",
                error,
            )
        })?;
        let status = query(buffer.as_mut_ptr(), &mut length);
        if status == NO_ERROR {
            let Some(end) = buffer.iter().position(|unit| *unit == 0) else {
                return Err(RuntimeError::new(
                    runtime::DiagnosticKind::HostFailure,
                    "Windows WNet returned unterminated text",
                ));
            };
            return Ok((status, Some(codec.from_wide(&buffer[..end])?.bytes)));
        }
        if status != ERROR_MORE_DATA {
            return Ok((status, None));
        }

        let requested = usize::try_from(length).unwrap_or(usize::MAX);
        let doubled = buffer.len().checked_mul(2).unwrap_or(usize::MAX);
        let next_length = requested
            .saturating_add(1)
            .max(doubled)
            .min(MAX_NATIVE_TEXT_UNITS);
        if next_length <= buffer.len() {
            return Ok((ERROR_MORE_DATA, None));
        }
        resize_wide(&mut buffer, next_length, "grow WNet output buffer")?;
    }
}

fn get_last_error(codec: &GuestTextCodec) -> Result<(u32, Option<(u32, Vec<u8>)>), RuntimeError> {
    let mut message = allocated_wide(INITIAL_TEXT_CAPACITY, "allocate WNet error text")?;
    let mut provider = allocated_wide(INITIAL_TEXT_CAPACITY, "allocate WNet provider name")?;
    loop {
        let mut code = 0_u32;
        // SAFETY: `WNetGetLastErrorW` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        let status = unsafe {
            WNetGetLastErrorW(
                &mut code,
                message.as_mut_ptr(),
                u32::try_from(message.len()).unwrap_or(u32::MAX),
                provider.as_mut_ptr(),
                u32::try_from(provider.len()).unwrap_or(u32::MAX),
            )
        };
        if status != ERROR_MORE_DATA {
            if status != NO_ERROR {
                return Ok((status, None));
            }
            let Some(end) = message.iter().position(|unit| *unit == 0) else {
                return Err(RuntimeError::new(
                    runtime::DiagnosticKind::HostFailure,
                    "Windows WNet returned unterminated error text",
                ));
            };
            // Unlike the ordinary WNet string queries, this API succeeds
            // with a NUL-terminated truncated string. Re-query if the NUL
            // occupies the last slot; a larger buffer disambiguates an exact
            // fit from truncation before guest byte lengths are reported.
            if end + 1 < message.len() {
                return Ok((
                    NO_ERROR,
                    Some((code, codec.from_wide(&message[..end])?.bytes)),
                ));
            }
        }

        let next_length = message
            .len()
            .checked_mul(2)
            .unwrap_or(usize::MAX)
            .min(MAX_LAST_ERROR_TEXT_UNITS);
        if next_length <= message.len() {
            return Ok((ERROR_MORE_DATA, None));
        }
        resize_wide(&mut message, next_length, "grow WNet error text")?;
        resize_wide(&mut provider, next_length, "grow WNet provider name")?;
    }
}

fn to_wide_input(
    codec: &GuestTextCodec,
    bytes: &[u8],
) -> Result<Result<Vec<u16>, u32>, RuntimeError> {
    match codec.to_wide_z(bytes) {
        Ok(value) => Ok(Ok(value)),
        Err(error) if error.kind() == runtime::DiagnosticKind::InvalidInput => {
            Ok(Err(windows_status::INVALID_PARAMETER))
        }
        Err(error) => Err(error),
    }
}

fn allocated_wide(length: usize, context: &'static str) -> Result<Vec<u16>, RuntimeError> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(runtime::DiagnosticKind::ResourceExhausted, context, error)
    })?;
    buffer.resize(length, 0);
    Ok(buffer)
}

fn resize_wide(
    buffer: &mut Vec<u16>,
    length: usize,
    context: &'static str,
) -> Result<(), RuntimeError> {
    if length > buffer.len() {
        buffer
            .try_reserve_exact(length - buffer.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    runtime::DiagnosticKind::ResourceExhausted,
                    context,
                    error,
                )
            })?;
        buffer.resize(length, 0);
    }
    Ok(())
}

mod windows_status {
    pub const INVALID_PARAMETER: u32 = 87;
}
