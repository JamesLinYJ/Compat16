//! PE32 directory-search calls and their separate guest search-handle table.

use guest_core::memory::Memory;

use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    Win32HostFileCall as C, Win32HostImportCall as HC,
    Win32HostImportValue as V, Win32HostSearchHandle, Win32HostServiceOperation as O};
use crate::win32_import_catalog::Win32ImportService as A;
use crate::win32_import_state::{Win32ImportState, Win32ServiceGate};

use super::super::{Win32GuestReturn, invariant};
use super::super::memory::{self, GuestOutput};

const INVALID_HANDLE_VALUE: u32 = u32::MAX;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_INVALID_PARAMETER: u32 = 87;

pub(super) fn first(
    state: &mut Win32ImportState, gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, arguments: &[u32],
) -> Result<Win32GuestReturn, RuntimeError> {
    let wide = matches!(gate.service, A::FindFirstFileW | A::FindFirstFileExW);
    let extended = matches!(gate.service, A::FindFirstFileExA | A::FindFirstFileExW);
    if extended && arguments[4] != 0 {
        // FindFirstFileEx's currently supported search operations require a
        // null filter. A PE32 pointer is never passed to the native adapter.
        state.set_last_error(ERROR_INVALID_PARAMETER);
        return Ok(ret(INVALID_HANDLE_VALUE));
    }
    let path = memory::read_string(memory, arguments[0], wide)?;
    let output_address = if extended { arguments[2] } else { arguments[1] };
    let output_capacity = if wide { 592 } else { 320 };
    let mut output = GuestOutput::new(memory, output_address, output_capacity)?;
    let reservation = state.reserve_guest_search_handle()?;
    let call = if extended {
        C::FindFirstEx { path, information_level: arguments[1],
            search_operation: arguments[3], additional_flags: arguments[5] }
    } else {
        C::FindFirst { path }
    };
    let response = match super::super::invoke(state, gate, host, O::File(call)) {
        Ok(value) => value,
        Err(primary) => {
            let cleanup = state.cancel_guest_search_handle(reservation).err();
            return Err(match cleanup { Some(cleanup) => combine(primary, cleanup), None => primary });
        }
    };
    let (native, data) = match response {
        V::FindStart { handle, data } => (handle, data),
        _ => {
            let primary = invariant("FindFirst service returned an incompatible host value");
            let cleanup = state.cancel_guest_search_handle(reservation).err();
            return Err(match cleanup { Some(cleanup) => combine(primary, cleanup), None => primary });
        }
    };
    match (native, data) {
        (None, None) => {
            state.cancel_guest_search_handle(reservation)?;
            Ok(ret(INVALID_HANDLE_VALUE))
        }
        (None, Some(_)) => {
            let primary = invariant("FindFirst returned data without a search handle");
            let cleanup = state.cancel_guest_search_handle(reservation).err();
            Err(match cleanup { Some(cleanup) => combine(primary, cleanup), None => primary })
        }
        (Some(native), maybe_data) => {
            let guest = match state.publish_guest_search_handle(&reservation, native) {
                Ok(value) => value,
                Err(primary) => {
                    let primary = match state.cancel_guest_search_handle(reservation) {
                        Ok(()) => primary,
                        Err(cleanup) => combine(primary, cleanup),
                    };
                    return Err(close_unpublished(host, native, primary));
                }
            };
            let Some(data) = maybe_data else {
                return Err(close_published(state, guest, host,
                    invariant("FindFirst returned a search handle without data")));
            };
            let staged = if wide {
                super::super::find_data::encode_wide(&data).and_then(|bytes| output.set(&bytes))
            } else {
                super::super::find_data::encode_ansi(&data).and_then(|bytes| output.set(&bytes))
            };
            if let Err(primary) = staged {
                return Err(close_published(state, guest, host, primary));
            }
            if let Err(primary) = memory::commit(memory, std::slice::from_mut(&mut output)) {
                return Err(close_published(state, guest, host, primary));
            }
            Ok(ret(guest))
        }
    }
}

pub(super) fn next(
    state: &mut Win32ImportState, gate: Win32ServiceGate, memory: &mut Memory,
    host: &mut impl RuntimeHost, arguments: &[u32],
) -> Result<Win32GuestReturn, RuntimeError> {
    let wide = gate.service == A::FindNextFileW;
    let mut output = GuestOutput::new(memory, arguments[1], if wide { 592 } else { 320 })?;
    let Some(handle) = state.native_search_handle(arguments[0]) else {
        state.set_last_error(ERROR_INVALID_HANDLE);
        return Ok(ret(0));
    };
    let encoding = if wide { crate::Win32ImportTextEncoding::Wide }
        else { crate::Win32ImportTextEncoding::Ansi };
    match super::super::invoke(state, gate, host, O::File(C::FindNext { handle, encoding }))? {
        V::FindData(Some(data)) => {
            let staged = if wide {
                super::super::find_data::encode_wide(&data).and_then(|bytes| output.set(&bytes))
            } else {
                super::super::find_data::encode_ansi(&data).and_then(|bytes| output.set(&bytes))
            };
            staged?;
            memory::commit(memory, std::slice::from_mut(&mut output))?;
            Ok(ret(1))
        }
        V::FindData(None) => Ok(ret(0)),
        _ => Err(invariant("FindNext service returned an incompatible host value")),
    }
}

pub(super) fn close(
    state: &mut Win32ImportState, gate: Win32ServiceGate,
    host: &mut impl RuntimeHost, value: u32,
) -> Result<Win32GuestReturn, RuntimeError> {
    let native = match state.begin_close_search_handle(value) {
        Ok(handle) => handle,
        Err(error) if error.kind() == Kind::GuestFault => {
            state.set_last_error(ERROR_INVALID_HANDLE);
            return Ok(ret(0));
        }
        Err(error) => return Err(error),
    };
    match super::super::invoke(state, gate, host, O::File(C::FindClose { handle: native })) {
        Ok(V::Bool(closed)) => {
            state.finish_close_search_handle(value, closed)?;
            Ok(ret(u32::from(closed)))
        }
        Ok(_) => {
            state.finish_close_search_handle(value, false)?;
            Err(invariant("FindClose service returned a non-BOOL host value"))
        }
        Err(primary) => {
            let cleanup = state.finish_close_search_handle(value, false).err();
            Err(match cleanup { Some(cleanup) => combine(primary, cleanup), None => primary })
        }
    }
}

fn close_unpublished(
    host: &mut impl RuntimeHost, native: Win32HostSearchHandle, primary: RuntimeError,
) -> RuntimeError {
    match host.win32_import(HC::CloseOwnedSearchHandle { handle: native }) {
        Ok(response) if matches!(&response.value, V::Bool(true)) => primary,
        Ok(response) => combine(primary, close_failure(response.value, response.last_error)),
        Err(cleanup) => combine(primary, cleanup),
    }
}

fn close_published(
    state: &mut Win32ImportState, guest: u32, host: &mut impl RuntimeHost,
    primary: RuntimeError,
) -> RuntimeError {
    let native = match state.begin_close_search_handle(guest) {
        Ok(handle) => handle,
        Err(cleanup) => return combine(primary, cleanup),
    };
    match host.win32_import(HC::CloseOwnedSearchHandle { handle: native }) {
        Ok(response) if matches!(&response.value, V::Bool(true)) => {
            match state.finish_close_search_handle(guest, true) {
                Ok(()) => primary,
                Err(cleanup) => combine(primary, cleanup),
            }
        }
        Ok(response) => {
            let failure = close_failure(response.value, response.last_error);
            match state.finish_close_search_handle(guest, false) {
                Ok(()) => combine(primary, failure),
                Err(cleanup) => combine(combine(primary, failure), cleanup),
            }
        }
        Err(failure) => match state.finish_close_search_handle(guest, false) {
            Ok(()) => combine(primary, failure),
            Err(cleanup) => combine(combine(primary, failure), cleanup),
        },
    }
}

fn close_failure(value: V, last_error: Option<u32>) -> RuntimeError {
    let kind = if matches!(&value, V::Bool(false)) {
        Kind::HostFailure
    } else {
        Kind::InternalInvariant
    };
    RuntimeError::with_source(
        kind,
        "FindClose cleanup failed",
        NativeSearchCloseOutcome { value, last_error },
    )
}

struct NativeSearchCloseOutcome {
    value: V,
    last_error: Option<u32>,
}

impl std::fmt::Debug for NativeSearchCloseOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeSearchCloseOutcome")
            .field("response_shape", &search_close_response_shape(&self.value))
            .field("last_error", &self.last_error)
            .finish()
    }
}

impl std::fmt::Display for NativeSearchCloseOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.value {
            V::Bool(false) => formatter.write_str("Windows returned FALSE")?,
            V::Bool(true) => formatter.write_str("an unexpected successful BOOL reached failure handling")?,
            _ => formatter.write_str("the host returned an unexpected result shape instead of BOOL")?,
        }
        match self.last_error {
            Some(code) => write!(formatter, " with Windows error {code}"),
            None => formatter.write_str("; Windows last-error was unavailable"),
        }
    }
}

impl std::error::Error for NativeSearchCloseOutcome {}

fn search_close_response_shape(value: &V) -> &'static str {
    match value {
        V::Bool(_) => "BOOL",
        _ => "non-BOOL DTO",
    }
}

fn ret(eax: u32) -> Win32GuestReturn { Win32GuestReturn { eax: Some(eax), edx: None } }

fn combine(primary: RuntimeError, cleanup: RuntimeError) -> RuntimeError {
    primary.with_cleanup("PE32 search owner cleanup failed", cleanup)
}
