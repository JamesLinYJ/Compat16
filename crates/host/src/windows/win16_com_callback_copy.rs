//! Bounded, owned copies of native COM callback arguments.
//!
//! COM structures and interface vtables come from the finite generated
//! `com_bindings::generated` module. This adapter copies callback-scoped data before
//! returning to the native caller and never exposes an interface pointer to the
//! runtime.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::os::windows::ffi::OsStringExt;
use std::ptr;

use runtime::Win16ComHostFormatEtc;
use runtime::{Win16ComHostCallbackFailure, Win16ComHostCallbackFailureKind};
use windows_core::{IUnknown, Interface, PWSTR};
use windows_sys::Win32::Foundation::{GetLastError, SetLastError};
use windows_sys::Win32::System::Com::CreateBindCtx;

use super::com_bindings::generated::{
    CoTaskMemFree, GlobalLock, GlobalSize, GlobalUnlock, HGLOBAL, IMoniker, FORMATETC, STGMEDIUM,
};
use super::win16_com_interface_calls::valid_target_device;

const MAX_TARGET_DEVICE_BYTES: usize = 64 * 1024;
const MAX_MONIKER_NAME_UNITS: usize = 32 * 1024;
const MAX_CALLBACK_MEDIUM_BYTES: usize = 64 * 1024 * 1024;
const MAX_CALLBACK_FILE_UNITS: usize = 32 * 1024;
const TYMED_HGLOBAL_VALUE: u32 = 1;
const TYMED_FILE_VALUE: u32 = 2;

/// Balance a successful GlobalLock. Zero is also the successful final unlock;
/// only a nonzero last-error value distinguishes a failure (Win32 GlobalUnlock).
pub(super) unsafe fn unlock_medium(handle: HGLOBAL) -> io::Result<()> {
    unsafe { SetLastError(0) };
    if !unsafe { GlobalUnlock(handle) }.as_bool() {
        let error = unsafe { GetLastError() };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
    }
    Ok(())
}

pub(super) unsafe fn copy_callback_medium(
    medium: &STGMEDIUM,
) -> Result<Option<runtime::Win16ComHostStorageMedium>, String> {
    match medium.tymed {
        TYMED_HGLOBAL_VALUE => {
            // SAFETY: the STGMEDIUM discriminant selects its HGLOBAL member;
            // the callback source retains ownership until OnDataChange returns.
            let handle = unsafe { medium.Anonymous.hGlobal };
            let size = unsafe { GlobalSize(handle) };
            if handle.0.is_null() || size > MAX_CALLBACK_MEDIUM_BYTES {
                return Err("IAdviseSink HGLOBAL payload is invalid or exceeds the host limit".into());
            }
            if size == 0 {
                return Ok(Some(runtime::Win16ComHostStorageMedium::HGlobal(Vec::new())));
            }
            // SAFETY: lock only long enough to make a bounded owned copy.
            let locked = unsafe { GlobalLock(handle) };
            if locked.is_null() {
                return Err("GlobalLock failed for IAdviseSink HGLOBAL payload".into());
            }
            let payload = unsafe { std::slice::from_raw_parts(locked.cast::<u8>(), size) }.to_vec();
            unsafe { unlock_medium(handle) }
                .map_err(|error| format!("unlock IAdviseSink HGLOBAL payload: {error}"))?;
            Ok(Some(runtime::Win16ComHostStorageMedium::HGlobal(payload)))
        }
        TYMED_FILE_VALUE => {
            // SAFETY: the tag selects a callback-scoped NUL-terminated path.
            let path = unsafe { medium.Anonymous.lpszFileName }.0;
            if path.is_null() {
                return Err("IAdviseSink TYMED_FILE path is null".into());
            }
            unsafe { read_file_medium_contents(path) }
                .map(runtime::Win16ComHostStorageMedium::FileContents)
                .map(Some)
                .map_err(|error| format!("copy IAdviseSink TYMED_FILE contents: {error}"))
        }
        _ => Ok(None),
    }
}

/// Read a TYMED_FILE while its containing STGMEDIUM still owns the file.
/// The caller releases the complete medium only after this bounded copy ends.
pub(super) unsafe fn read_file_medium_contents(path: *const u16) -> io::Result<Vec<u8>> {
    if path.is_null() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "TYMED_FILE path is null"));
    }
    let mut path_units = Vec::new();
    for index in 0..MAX_CALLBACK_FILE_UNITS {
        let unit = unsafe { *path.add(index) };
        if unit == 0 {
            let mut file = File::open(OsString::from_wide(&path_units))?;
            let mut contents = Vec::new();
            file.by_ref()
                .take((MAX_CALLBACK_MEDIUM_BYTES + 1) as u64)
                .read_to_end(&mut contents)?;
            if contents.len() > MAX_CALLBACK_MEDIUM_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TYMED_FILE contents exceed the host bridge limit",
                ));
            }
            return Ok(contents);
        }
        path_units.push(unit);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "TYMED_FILE path exceeds the host bridge limit",
    ))
}

pub(super) unsafe fn project_format(
    format: FORMATETC,
) -> Result<Win16ComHostFormatEtc, &'static str> {
    let target_device = if format.ptd.is_null() {
        None
    } else {
        // SAFETY: tdSize is read from the callback's SDK record, then checked
        // before any complete DVTARGETDEVICE bytes are copied.
        let size = unsafe { (*format.ptd).tdSize as usize };
        if !(12..=MAX_TARGET_DEVICE_BYTES).contains(&size) {
            return Err("FORMATETC target device size is outside the accepted bound");
        }
        let bytes = unsafe { std::slice::from_raw_parts(format.ptd.cast::<u8>(), size) }.to_vec();
        if !valid_target_device(&bytes) {
            return Err("IAdviseSink::OnDataChange received a malformed target device");
        }
        Some(bytes)
    };
    Ok(Win16ComHostFormatEtc {
        format: format.cfFormat.0,
        target_device,
        aspect: format.dwAspect,
        index: format.lindex,
        tymed: format.tymed,
    })
}

pub(super) unsafe fn copy_moniker_display_name(
    moniker: &IMoniker,
) -> Result<Vec<u16>, Win16ComHostCallbackFailure> {
    let mut bind_context = ptr::null_mut();
    // SAFETY: output is writable and reserved is zero as required by
    // CreateBindCtx. The owned result is wrapped in windows-core below.
    let bind_result = unsafe { CreateBindCtx(0, &mut bind_context) };
    if bind_result < 0 {
        if !bind_context.is_null() {
            // SAFETY: a nonnull failed output, if present, is one transferred
            // IBindCtx reference from this system API.
            drop(unsafe { IUnknown::from_raw(bind_context) });
        }
        return Err(callback_failure(
            Win16ComHostCallbackFailureKind::CallbackTransport,
            format!("CreateBindCtx failed with HRESULT 0x{:08X}", bind_result as u32),
        ));
    }
    if bind_context.is_null() {
        return Err(callback_failure(
            Win16ComHostCallbackFailureKind::CallbackImplementation,
            "CreateBindCtx succeeded with a null IBindCtx",
        ));
    }
    // SAFETY: CreateBindCtx returned one owned IBindCtx reference, which also
    // has the standard IUnknown ABI and is released by this wrapper.
    let bind_context = unsafe { IUnknown::from_raw(bind_context) };
    let mut output = PWSTR::null();
    // Use the generated IMoniker vtable for exact SDK dispatch. The left
    // moniker is null; GetDisplayName still receives a valid IBindCtx.
    let result = unsafe {
        (moniker.vtable().GetDisplayName)(
            moniker.as_raw(),
            bind_context.as_raw(),
            ptr::null_mut(),
            &mut output,
        )
    };
    drop(bind_context);
    if result.0 < 0 {
        if !output.0.is_null() {
            unsafe { CoTaskMemFree(output.0.cast()) };
        }
        return Err(callback_failure(
            Win16ComHostCallbackFailureKind::CallbackImplementation,
            format!("IMoniker::GetDisplayName failed with HRESULT 0x{:08X}", result.0 as u32),
        ));
    }
    if output.0.is_null() {
        return Err(callback_failure(
            Win16ComHostCallbackFailureKind::CallbackImplementation,
            "IMoniker returned a null display name on success",
        ));
    }
    let mut name = Vec::new();
    for index in 0..MAX_MONIKER_NAME_UNITS {
        let unit = unsafe { *output.0.add(index) };
        if unit == 0 {
            unsafe { CoTaskMemFree(output.0.cast()) };
            return Ok(name);
        }
        name.push(unit);
    }
    unsafe { CoTaskMemFree(output.0.cast()) };
    Err(callback_failure(
        Win16ComHostCallbackFailureKind::InvalidNativeCallbackArguments,
        "IMoniker display name exceeds the host bridge limit",
    ))
}

fn callback_failure(
    kind: Win16ComHostCallbackFailureKind,
    context: impl Into<String>,
) -> Win16ComHostCallbackFailure {
    Win16ComHostCallbackFailure { kind, context: context.into() }
}
