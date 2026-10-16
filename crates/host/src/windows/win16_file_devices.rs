//! Classic console/null endpoints with fixed native names, separate from files.
//!
//! Capability paths reject Windows device names. These two documented DOS
//! endpoints require an explicit route; no guest path can select a raw device,
//! serial port, physical disk or arbitrary Windows device namespace here.

use runtime::Win16GuestPath;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING};

pub(super) fn name(path: &Win16GuestPath) -> Option<&'static str> {
    let leaf = &path.components.last()?.text;
    let stem = leaf.split('.').next()?.trim_end_matches([' ', ':']);
    if stem.eq_ignore_ascii_case("NUL") {
        Some("NUL")
    } else if stem.eq_ignore_ascii_case("CON") {
        Some("CON")
    } else {
        None
    }
}

pub(super) fn open(name: &str, access: u32, share: u32) -> Result<OwnedHandle, u32> {
    let path = match name {
        "NUL" => windows_sys::core::w!("NUL"),
        "CON" => windows_sys::core::w!("CON"),
        _ => return Err(windows_sys::Win32::Foundation::ERROR_INVALID_NAME),
    };
    // SAFETY: Fixed whitelisted UTF-16 names, no caller-owned pointers; the
    // resulting HANDLE is uniquely owned and follows ordinary file IO rules.
    let handle = unsafe {
        CreateFileW(
            path,
            access,
            share,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        Err(unsafe { GetLastError() })
    } else {
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }
}
