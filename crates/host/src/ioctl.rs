//! Native standard-stream inspection; DOS owns the returned bit layout.

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Console::{GetConsoleMode, GetStdHandle};
use dos_kernel::{DosErrorCode, DosHostError, DosIoctlObjectInfo, DosIoctlStream};

pub(crate) fn standard_info(input: HANDLE, stream: DosIoctlStream) -> Result<DosIoctlObjectInfo, DosHostError> {
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
