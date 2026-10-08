use std::ffi::c_void;

use windows_sys::Win32::Media::Multimedia::mciSendCommandW;

pub(super) unsafe fn call_native<T>(
    native: u32,
    message: u16,
    flags: u32,
    parameters: &mut T,
) -> u32 {
    // Each caller keeps the official MCI parameter record and its pointed-to
    // buffers alive for the duration of this synchronous native call.
    unsafe {
        mciSendCommandW(
            native,
            u32::from(message),
            flags as usize,
            (parameters as *mut T).cast::<c_void>() as usize,
        )
    }
}

pub(super) unsafe fn call_native_null(native: u32, message: u16, flags: u32) -> u32 {
    unsafe { mciSendCommandW(native, u32::from(message), flags as usize, 0) }
}
