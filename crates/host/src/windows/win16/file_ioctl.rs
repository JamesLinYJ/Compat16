//! IOCTL facts for the same retained KERNEL open object, without reopening it.

use super::{Win16Files, file_error};
use crate::windows::invalid;
use dos_kernel::{DosErrorCode, DosHostError, DosIoctlObjectInfo};
use runtime::Win16HostFile;
use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_DISK, FILE_TYPE_UNKNOWN, GetFileType};

impl Win16Files {
    pub(in crate::windows) fn ioctl_info(
        &self,
        file: Win16HostFile,
    ) -> Result<DosIoctlObjectInfo, DosHostError> {
        let (handle, _) = self.ordinary_handle(file)?;
        // SAFETY: This table retains the HANDLE for the whole synchronous query.
        // UNKNOWN with no native error denotes an unsupported type, not success.
        let kind = unsafe {
            crate::windows::win32_safe::set_last_error(0);
            GetFileType(handle)
        };
        if kind == FILE_TYPE_UNKNOWN {
            let error = crate::windows::win32_safe::last_error();
            if error != 0 {
                return Err(file_error(error));
            }
        }
        if kind != FILE_TYPE_DISK {
            return Err(invalid(DosErrorCode::InvalidFunction));
        }
        let entry = self.files.get(&file).expect("validated retained file");
        let drive = entry
            .dos_drive
            .ok_or_else(|| invalid(DosErrorCode::InvalidFunction))?;
        Ok(DosIoctlObjectInfo::File {
            drive,
            written: entry.written,
        })
    }
}
