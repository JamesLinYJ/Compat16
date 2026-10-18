//! DOS deletion honors readonly attributes without temporary attribute changes.
use super::Filesystem;
use crate::windows::{invalid, os_error};
use cap_std::fs::{OpenOptions, OpenOptionsExt};
use dos_kernel::{DosErrorCode, DosHostError};
use std::{io, mem::size_of, os::windows::io::AsRawHandle};
use windows_sys::Win32::{
    Foundation::HANDLE,
    Storage::FileSystem::{
        DELETE, FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
        FILE_DISPOSITION_INFO_EX, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FileDispositionInfoEx, SetFileInformationByHandle,
    },
};

impl Filesystem {
    pub(crate) fn file_delete(&mut self, path: &[u8]) -> Result<(), DosHostError> {
        self.delete_entry(path, false)
    }

    pub(crate) fn file_delete_fcb(
        &mut self,
        path: &[u8],
        ignore_read_only: bool,
    ) -> Result<(), DosHostError> {
        self.delete_entry(path, ignore_read_only)
    }

    fn delete_entry(&mut self, path: &[u8], ignore_read_only: bool) -> Result<(), DosHostError> {
        let path = self.resolve_path(path, false)?;
        let path = self.confined_path(&path, false, false)?;
        // Open the entry through the capability and never follow its final
        // reparse point. Existing DOS opens deny delete sharing, so this open
        // also preserves their native exclusive-access failure.
        let source = self
            .root
            .open_with(
                &path,
                OpenOptions::new()
                    .access_mode(DELETE | FILE_READ_ATTRIBUTES)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS),
            )
            .map_err(os_error)?;
        if source.metadata().map_err(os_error)?.is_dir() {
            return Err(invalid(DosErrorCode::AccessDenied));
        }
        let mut disposition = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_FLAG_DELETE
                | if ignore_read_only {
                    FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE
                } else {
                    0
                },
        };
        // SAFETY: source is a capability-owned live file; disposition is one
        // initialized fixed-layout native record. No guest address is used.
        if unsafe {
            SetFileInformationByHandle(
                source.as_raw_handle() as HANDLE,
                FileDispositionInfoEx,
                std::ptr::from_mut(&mut disposition).cast(),
                size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
            )
        } == 0
        {
            return Err(os_error(io::Error::last_os_error()));
        }
        // Normal (non-POSIX) deletion takes effect when this owned handle
        // closes. Failed marking/opening leaves all attributes untouched.
        drop(source);
        Ok(())
    }
}
