//! DOS I/O on retained ordinary Win16 files. Access checks precede even a
//! zero-count operation; no guest pointer or path reopening reaches Windows.

use super::{Win16Files, file_error};
use crate::windows::invalid;
use dos_kernel::{DosErrorCode, DosFileAccess, DosHostError, DosSeekOrigin};
use runtime::Win16HostFile;
use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, GetLastError};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_BEGIN, FILE_CURRENT, FILE_TYPE_CHAR, FILE_TYPE_DISK,
    GetFileInformationByHandle, GetFileType, ReadFile, SetEndOfFile, SetFilePointerEx, WriteFile,
};

impl Win16Files {
    pub(in crate::windows) fn dos_access(
        &self,
        file: Win16HostFile,
    ) -> Result<DosFileAccess, DosHostError> {
        let (_, rights) = self.ordinary_handle(file)?;
        let rights = rights.ok_or_else(|| invalid(DosErrorCode::InvalidFunction))?;
        match (rights & GENERIC_READ != 0, rights & GENERIC_WRITE != 0) {
            (true, false) => Ok(DosFileAccess::ReadOnly),
            (false, true) => Ok(DosFileAccess::WriteOnly),
            (true, true) => Ok(DosFileAccess::ReadWrite),
            _ => Err(invalid(DosErrorCode::InvalidAccess)),
        }
    }

    pub(in crate::windows) fn dos_read(
        &self,
        file: Win16HostFile,
        output: &mut [u8],
    ) -> Result<usize, DosHostError> {
        if self.dos_access(file)? == DosFileAccess::WriteOnly {
            return Err(invalid(DosErrorCode::AccessDenied));
        }
        // DOS checks the open mode, then skips I/O entirely for CX=0.
        if output.is_empty() {
            return Ok(0);
        }
        let (handle, _) = self.ordinary_handle(file)?;
        let count = u32::try_from(output.len()).map_err(|_| invalid(DosErrorCode::InvalidData))?;
        let mut read = 0;
        // SAFETY: The table retains this synchronous HANDLE; output is
        // exclusively borrowed host storage with at least count bytes.
        if unsafe {
            ReadFile(
                handle,
                output.as_mut_ptr(),
                count,
                &mut read,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(file_error(unsafe { GetLastError() }));
        }
        Ok(read as usize)
    }

    pub(in crate::windows) fn dos_write(
        &mut self,
        file: Win16HostFile,
        input: &[u8],
    ) -> Result<usize, DosHostError> {
        if self.dos_access(file)? == DosFileAccess::ReadOnly {
            return Err(invalid(DosErrorCode::AccessDenied));
        }
        let (handle, _) = self.ordinary_handle(file)?;
        if input.is_empty() {
            // DOS zero-byte disk writes set EOF at the existing cursor. A
            // character device instead receives an ordinary empty write.
            // SAFETY: This is the table's retained file HANDLE.
            if unsafe { GetFileType(handle) } == FILE_TYPE_DISK {
                // A Win16 seek may have left this shared object beyond the
                // DOS DWORD range. Match DOS's checked current-position
                // query before changing EOF, without reopening the file.
                self.dos_seek(file, 0, DosSeekOrigin::Current)?;
                if unsafe { SetEndOfFile(handle) } == 0 {
                    return Err(file_error(unsafe { GetLastError() }));
                }
                self.mark_written(file);
                return Ok(0);
            }
        }
        let count = u32::try_from(input.len()).map_err(|_| invalid(DosErrorCode::InvalidData))?;
        let mut written = 0;
        let empty = 0u8;
        let pointer = if input.is_empty() {
            &empty as *const u8
        } else {
            input.as_ptr()
        };
        // SAFETY: The table retains this synchronous HANDLE; input is an
        // immutable host copy, including a live local byte for an empty write.
        if unsafe { WriteFile(handle, pointer, count, &mut written, std::ptr::null_mut()) } == 0 {
            return Err(file_error(unsafe { GetLastError() }));
        }
        if written != 0 { self.mark_written(file); }
        Ok(written as usize)
    }

    pub(in crate::windows) fn dos_seek(
        &self,
        file: Win16HostFile,
        offset: i32,
        origin: DosSeekOrigin,
    ) -> Result<u32, DosHostError> {
        // This DOS route requires a retained ordinary KERNEL open mode.
        // Legacy/LZ objects without that contract keep their own API route.
        self.dos_access(file)?;
        let (handle, _) = self.ordinary_handle(file)?;
        // DOS device seeks succeed at position zero. Pipes and other
        // non-seeking objects must not receive a disk-pointer operation.
        // SAFETY: The table retains this HANDLE throughout the sequence.
        match unsafe { GetFileType(handle) } {
            FILE_TYPE_CHAR => return Ok(0),
            FILE_TYPE_DISK => {}
            _ => return Err(invalid(DosErrorCode::InvalidFunction)),
        }
        let base = match origin {
            DosSeekOrigin::Start => 0i128,
            DosSeekOrigin::Current => {
                let mut position = 0i64;
                // Querying FILE_CURRENT with zero displacement preserves it.
                if unsafe { SetFilePointerEx(handle, 0, &mut position, FILE_CURRENT) } == 0 {
                    return Err(file_error(unsafe { GetLastError() }));
                }
                i128::from(position)
            }
            DosSeekOrigin::End => {
                let mut info = BY_HANDLE_FILE_INFORMATION::default();
                // Query the open object without temporarily seeking to EOF.
                if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
                    return Err(file_error(unsafe { GetLastError() }));
                }
                i128::from((u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow))
            }
        };
        let displacement = match origin {
            DosSeekOrigin::Start => i128::from(offset as u32),
            DosSeekOrigin::Current | DosSeekOrigin::End => i128::from(offset),
        };
        let target = base + displacement;
        if !(0..=i128::from(u32::MAX)).contains(&target) {
            return Err(invalid(DosErrorCode::InvalidData));
        }
        let mut position = 0i64;
        // All DOS range checks precede the only cursor-changing operation.
        // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfilepointerex
        if unsafe { SetFilePointerEx(handle, target as i64, &mut position, FILE_BEGIN) } == 0 {
            return Err(file_error(unsafe { GetLastError() }));
        }
        u32::try_from(position).map_err(|_| invalid(DosErrorCode::InvalidData))
    }
}
