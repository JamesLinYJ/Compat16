//! Scalar DOS metadata on the exact retained Win16 open description.
//! No pathname reopening, access escalation, or cursor movement is allowed.

use super::{Win16Files, Win16NativeFile};
use crate::windows::{invalid, os_error};
use dos_kernel::{DosErrorCode, DosHostError};
use runtime::Win16HostFile;
use std::io;
use windows_sys::Win32::Foundation::{
    ERROR_INVALID_FUNCTION, FILETIME, GENERIC_WRITE, GetLastError, HANDLE,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_TYPE_CHAR, FILE_TYPE_DISK, FILE_TYPE_PIPE, FlushFileBuffers,
    GetFileInformationByHandle, GetFileType, SetFileTime,
};
use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;

impl Win16Files {
    fn metadata_handle(&self, file: Win16HostFile) -> Result<(HANDLE, Option<u32>), DosHostError> {
        let entry = self
            .files
            .get(&file)
            .ok_or_else(|| invalid(DosErrorCode::InvalidHandle))?;
        let handle = match entry.native {
            Win16NativeFile::NativeHandle(handle) => handle,
            Win16NativeFile::Ordinary(hfile) => {
                // Only the typed native legacy HFILE can use this conversion.
                // Neither a guest HFILE nor a decoded LZ token is a HANDLE.
                super::super::win16_compat_calls_lzexpand::hfile_as_kernel_handle(hfile)
            }
            Win16NativeFile::LzHandle(_) => return Err(invalid(DosErrorCode::InvalidFunction)),
        };
        Ok((handle, entry.access))
    }

    pub(in crate::windows) fn commit(&self, file: Win16HostFile) -> Result<(), DosHostError> {
        let (handle, access) = self.metadata_handle(file)?;
        // SAFETY: The table retains this HANDLE throughout the synchronous
        // type query and flush. Exclusive host dispatch serializes its close.
        match unsafe { GetFileType(handle) } {
            // DOS commit skips character devices. Console output cannot be
            // sent to FlushFileBuffers, where it reports invalid handle.
            FILE_TYPE_CHAR => return Ok(()),
            FILE_TYPE_DISK => {}
            _ => return Err(invalid(DosErrorCode::InvalidFunction)),
        }
        if access.is_some_and(|rights| rights & GENERIC_WRITE == 0) {
            // This open description provably cannot have written. As in the
            // DOS file backend, a clean read-only commit is a successful no-op.
            return Ok(());
        }
        // FlushFileBuffers requires GENERIC_WRITE. Preserve a native failure
        // for unknown legacy access rather than treating AccessDenied as clean.
        // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers
        if unsafe { FlushFileBuffers(handle) } == 0 {
            return Err(metadata_error(unsafe { GetLastError() }));
        }
        Ok(())
    }

    pub(in crate::windows) fn write_time(
        &self,
        file: Win16HostFile,
    ) -> Result<(u16, u16), DosHostError> {
        let (handle, _) = self.metadata_handle(file)?;
        let ticks = last_write_ticks(handle).map_err(metadata_error)?;
        crate::filesystem::dos_write_time_from_ticks(ticks)
    }

    pub(in crate::windows) fn set_write_time(
        &self,
        file: Win16HostFile,
        time: u16,
        date: u16,
    ) -> Result<(), DosHostError> {
        let (handle, _) = self.metadata_handle(file)?;
        // DOS File_Times returns immediately for device objects on AL=1;
        // no calendar validation or host timestamp update takes place there.
        // LZ streams were rejected by their explicit type above.
        // SAFETY: The native HANDLE is borrowed from this live table entry.
        match unsafe { GetFileType(handle) } {
            FILE_TYPE_CHAR => return Ok(()),
            FILE_TYPE_DISK => {}
            _ => return Err(invalid(DosErrorCode::InvalidFunction)),
        }
        let last_write = crate::filesystem::dos_to_native_write_time(time, date)?;
        // SetFileTime checks FILE_WRITE_ATTRIBUTES on this same open object.
        // Keep creation/access times unchanged and preserve native errors.
        // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfiletime
        // SAFETY: The retained HANDLE and initialized FILETIME remain live.
        if unsafe { SetFileTime(handle, std::ptr::null(), std::ptr::null(), &last_write) } == 0 {
            return Err(metadata_error(unsafe { GetLastError() }));
        }
        Ok(())
    }
}

fn metadata_error(code: u32) -> DosHostError {
    if code == ERROR_INVALID_FUNCTION {
        invalid(DosErrorCode::InvalidFunction)
    } else {
        os_error(io::Error::from_raw_os_error(code as i32))
    }
}

/// Raw Win32 errors keep OpenFile's OFSTRUCT error reporting intact; DOS
/// callers map them separately. Both services then share DOS local conversion.
pub(in crate::windows) fn last_write_ticks(handle: HANDLE) -> Result<u64, u32> {
    // SAFETY: Callers borrow this HANDLE from an owned, live file entry.
    let stamp = match unsafe { GetFileType(handle) } {
        FILE_TYPE_CHAR => {
            let mut now = FILETIME::default();
            // DOS character-device queries use the current local clock.
            unsafe { GetSystemTimeAsFileTime(&mut now) };
            now
        }
        FILE_TYPE_PIPE => return Err(ERROR_INVALID_FUNCTION),
        _ => {
            let mut info = BY_HANDLE_FILE_INFORMATION::default();
            // This query supports write-only opens without adding read rights.
            if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
                return Err(unsafe { GetLastError() });
            }
            info.ftLastWriteTime
        }
    };
    Ok((u64::from(stamp.dwHighDateTime) << 32) | u64::from(stamp.dwLowDateTime))
}
