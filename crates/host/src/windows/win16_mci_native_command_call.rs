use std::ffi::c_void;

use windows_sys::Win32::Media::Multimedia::mciSendCommandW;

// SAFETY: callers pass an MCI device id and a parameter record whose interior
// pointers stay valid for the synchronous call. A bad id returns an MCI error.
pub(super) unsafe fn call_native<T>(
    native: u32,
    message: u16,
    flags: u32,
    parameters: &mut T,
) -> u32 {
    // SAFETY: the caller keeps this MCI parameter record and every buffer it
    // points at alive for the synchronous mciSendCommandW call.
    unsafe {
        mciSendCommandW(
            native,
            u32::from(message),
            flags as usize,
            (parameters as *mut T).cast::<c_void>() as usize,
        )
    }
}

pub(super) fn call_native_null(native: u32, message: u16, flags: u32) -> u32 {
    // SAFETY: the parameter pointer is null and the device id is an integer.
    // mciSendCommandW returns an MCI error for an unknown device.
    unsafe { mciSendCommandW(native, u32::from(message), flags as usize, 0) }
}
