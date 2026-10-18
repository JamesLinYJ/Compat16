//! Windows error translation for DOS, console input and VGA host operations.

use super::vga_window::VgaWindowError;
use dos_kernel::{DosErrorCode, DosHostError};
use runtime::{DiagnosticKind as Kind, RuntimeError};
use std::io;
use windows_sys::Win32::Foundation::{ERROR_DIRECTORY, ERROR_INVALID_NAME};

pub(crate) fn os_error(error: io::Error) -> DosHostError {
    let code = match error.raw_os_error() {
        // A syntactically invalid host path is invalid input, not a device
        // failure. Optional environment path mapping can preserve such values
        // as data (for example a list of paths) instead of aborting startup.
        Some(code) if code == ERROR_INVALID_NAME as i32 => DosErrorCode::InvalidData,
        // A file in a directory position is a path failure. DOS callers
        // (including command pathname probing) distinguish it from device I/O.
        Some(code) if code == ERROR_DIRECTORY as i32 => DosErrorCode::PathNotFound,
        Some(2) => DosErrorCode::FileNotFound,
        Some(3) => DosErrorCode::PathNotFound,
        Some(4) => DosErrorCode::TooManyOpenFiles,
        Some(5 | 80 | 145 | 183) => DosErrorCode::AccessDenied,
        Some(16) => DosErrorCode::CannotRemoveCurrentDirectory,
        Some(17) => DosErrorCode::NotSameDevice,
        Some(6) => DosErrorCode::InvalidHandle,
        Some(19) => DosErrorCode::WriteProtected,
        Some(21) => DosErrorCode::DriveNotReady,
        Some(32) => DosErrorCode::SharingViolation,
        Some(33) => DosErrorCode::LockViolation,
        Some(39 | 112) => DosErrorCode::DiskFull,
        _ => match error.kind() {
            io::ErrorKind::PermissionDenied => DosErrorCode::AccessDenied,
            io::ErrorKind::NotFound => DosErrorCode::FileNotFound,
            io::ErrorKind::NotADirectory => DosErrorCode::PathNotFound,
            io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => DosErrorCode::InvalidData,
            _ => DosErrorCode::GeneralFailure,
        },
    };
    DosHostError::with_source(code, error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_windows_path_is_invalid_data() {
        let error = os_error(io::Error::from_raw_os_error(ERROR_INVALID_NAME as i32));
        assert_eq!(error.code, DosErrorCode::InvalidData);
    }

    #[test]
    fn not_a_directory_retains_its_source_as_a_dos_path_error() {
        for native in [
            io::Error::from_raw_os_error(ERROR_DIRECTORY as i32),
            io::Error::from(io::ErrorKind::NotADirectory),
        ] {
            let error = os_error(native);
            assert_eq!(error.code, DosErrorCode::PathNotFound);
            assert!(std::error::Error::source(&error).is_some());
        }
    }

    #[test]
    fn path_error_mapping_keeps_access_and_device_errors_distinct() {
        for (native, expected) in [
            (5, DosErrorCode::AccessDenied),
            (31, DosErrorCode::GeneralFailure),
            (32, DosErrorCode::SharingViolation),
        ] {
            assert_eq!(
                os_error(io::Error::from_raw_os_error(native)).code,
                expected
            );
        }
    }
}
pub(super) fn last_error() -> DosHostError {
    os_error(io::Error::last_os_error())
}
pub(crate) fn invalid(code: DosErrorCode) -> DosHostError {
    DosHostError::new(code)
}

pub(super) fn console_input_runtime_error(
    context: &'static str,
    error: DosHostError,
) -> RuntimeError {
    let kind = if error.code == DosErrorCode::InsufficientMemory {
        Kind::ResourceExhausted
    } else {
        Kind::HostFailure
    };
    RuntimeError::with_source(kind, context, error)
}

pub(super) fn vga_runtime_error(error: VgaWindowError) -> RuntimeError {
    let kind = match &error {
        VgaWindowError::AllocationFailed
        | VgaWindowError::Graphics(graphics::GraphicsError::AllocationFailed)
        | VgaWindowError::Windowing(crate::windowing::WindowingError::AllocationFailed)
        | VgaWindowError::Windowing(crate::windowing::WindowingError::IdentifierExhausted) => {
            Kind::ResourceExhausted
        }
        VgaWindowError::InvalidDimensions
        | VgaWindowError::PixelCount { .. }
        | VgaWindowError::InvalidRgbPixel { .. }
        | VgaWindowError::Graphics(_) => Kind::InternalInvariant,
        _ => Kind::HostFailure,
    };
    RuntimeError::with_source(kind, "VGA display", error)
}
