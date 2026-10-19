//! Native standard-stream inspection; DOS owns the returned bit layout.

use dos_kernel::{DosErrorCode, DosHostError, DosIoctlObjectInfo, DosIoctlStream};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_TYPE_CHAR, FILE_TYPE_DISK, FILE_TYPE_PIPE, FILE_TYPE_UNKNOWN, GetFileType,
};
use windows_sys::Win32::System::Console::{GetConsoleMode, GetStdHandle};

/// Validate types supported by the byte-read fallback. Non-console character
/// devices (including NUL) can support ReadFile too. The read itself still
/// decides access and completion; a device type is not proof of readability.
/// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
pub(crate) fn validate_redirected_input(input: HANDLE) -> Result<(), DosHostError> {
    if input.is_null() || input as isize == -1 {
        return Err(DosHostError::new(DosErrorCode::InvalidHandle));
    }
    // SAFETY: These calls only inspect the OS-owned handle and thread-local
    // error state. Clearing the error distinguishes unknown types from errors.
    let (file_type, error) = unsafe {
        crate::windows::win32_safe::set_last_error(0);
        let file_type = GetFileType(input);
        (file_type, crate::windows::win32_safe::last_error())
    };
    match file_type {
        FILE_TYPE_DISK | FILE_TYPE_PIPE | FILE_TYPE_CHAR => Ok(()),
        FILE_TYPE_UNKNOWN if error != 0 => Err(crate::windows::os_error(
            std::io::Error::from_raw_os_error(error as i32),
        )),
        _ => Err(DosHostError::new(DosErrorCode::InvalidFunction)),
    }
}

pub(crate) fn standard_info(
    input: HANDLE,
    stream: DosIoctlStream,
) -> Result<DosIoctlObjectInfo, DosHostError> {
    let handle = match stream {
        DosIoctlStream::Input => input,
        // SAFETY: This retrieves an OS-owned standard handle without borrowing memory.
        DosIoctlStream::Output => unsafe { GetStdHandle((-11i32) as u32) },
        // SAFETY: The same standard-handle contract applies to stderr.
        DosIoctlStream::Error => unsafe { GetStdHandle((-12i32) as u32) },
    };
    if handle.is_null() || handle as isize == -1 {
        return Err(DosHostError::new(DosErrorCode::InvalidHandle));
    }
    let mut mode = 0;
    // SAFETY: The handle is OS-owned and mode points to a writable u32.
    if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
        // Redirected native files/pipes have no known guest drive/device
        // mapping yet. Do not misreport them as a console or invent a drive.
        return Err(DosHostError::new(DosErrorCode::InvalidFunction));
    }
    Ok(DosIoctlObjectInfo::CharacterDevice {
        input_eof: false,
        // Current handle I/O transfers characters without DOS cooked-mode
        // control-character processing. This describes guest I/O behavior,
        // independently of the native console mode saved by WindowsHost.
        raw_mode: true,
        standard_input: matches!(stream, DosIoctlStream::Input),
        standard_output: matches!(stream, DosIoctlStream::Output | DosIoctlStream::Error),
    })
}
