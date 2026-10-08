use std::os::windows::ffi::OsStrExt;

use dos_kernel::{DosDiskSpace, DosErrorCode, DosHostError};
use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

use super::Filesystem;
use crate::windows::{invalid, os_error};

impl Filesystem {
    /// Query byte counts for the mounted host volume.
    ///
    /// The API reports volume capacity and bytes available to this process's
    /// user, including quota effects. Other host volumes are not guest drives.
    pub(crate) fn disk_space(&self, drive: u8) -> Result<DosDiskSpace, DosHostError> {
        if drive != self.drive {
            return Err(invalid(DosErrorCode::UnknownUnit));
        }

        let mut path: Vec<u16> = self.canonical_root.as_os_str().encode_wide().collect();
        path.push(0);
        let mut available_bytes = 0_u64;
        let mut total_bytes = 0_u64;
        let mut total_free_bytes = 0_u64;
        // SAFETY: `path` is NUL-terminated UTF-16 from the retained canonical
        // mapping root. Each output points to an initialized writable u64.
        let succeeded = unsafe {
            GetDiskFreeSpaceExW(
                path.as_ptr(),
                &mut available_bytes,
                &mut total_bytes,
                &mut total_free_bytes,
            )
        };
        if succeeded == 0 {
            return Err(os_error(std::io::Error::last_os_error()));
        }

        Ok(DosDiskSpace {
            total_bytes,
            available_bytes,
        })
    }
}
