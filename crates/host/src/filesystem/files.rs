use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::windows::io::AsRawHandle;
use std::sync::{Arc, Mutex};

use cap_std::fs::{MetadataExt, OpenOptions, OpenOptionsExt};
use dos_kernel::{
    DosErrorCode, DosFileAccess, DosFileSharing, DosFileStatus, DosHostError, DosHostFile,
    DosIoctlObjectInfo, DosSeekOrigin,
};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_SYSTEM, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FileBasicInfo, SetFileInformationByHandle, SetFileTime,
};

use crate::windows::{encode, invalid, os_error};

use super::metadata;
use super::{Filesystem, OpenFile, SharedFile};

/// DOS SFT size and position fields expose only the low DWORD.
pub(super) const fn dos_dword(value: u64) -> u32 {
    value as u32
}

/// Native readiness must not use the DOS SFT's low-DWORD size/cursor fields.
pub(super) const fn file_has_unread_bytes(position: u64, length: u64) -> bool {
    position < length
}

impl Filesystem {
    pub(super) fn file_short_name(&mut self, path: &std::path::Path) -> Result<[u8; 11], DosHostError> {
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new(""));
        let name = path
            .file_name()
            .ok_or_else(|| invalid(DosErrorCode::InvalidData))?;
        let alias = self
            .aliases_for(parent)?
            .by_real_name
            .get(name)
            .cloned()
            .ok_or_else(|| invalid(DosErrorCode::FileNotFound))?;
        let encoded = encode(&alias, self.code_page)?;
        let mut parts = encoded.split(|&byte| byte == b'.');
        let stem = parts.next().unwrap_or_default();
        let extension = parts.next().unwrap_or_default();
        if stem.is_empty() || stem.len() > 8 || extension.len() > 3 || parts.next().is_some() {
            return Err(invalid(DosErrorCode::InvalidData));
        }
        let mut result = [b' '; 11];
        result[..stem.len()].copy_from_slice(stem);
        result[8..8 + extension.len()].copy_from_slice(extension);
        Ok(result)
    }

    pub(super) fn insert_file(&mut self, file: SharedFile) -> Result<DosHostFile, DosHostError> {
        let id = DosHostFile(self.next_file);
        self.next_file = self
            .next_file
            .checked_add(1)
            .ok_or_else(|| invalid(DosErrorCode::TooManyOpenFiles))?;
        self.files.insert(id, file);
        Ok(id)
    }

    fn file(&self, id: DosHostFile) -> Result<SharedFile, DosHostError> {
        self.files
            .get(&id)
            .cloned()
            .ok_or_else(|| invalid(DosErrorCode::InvalidHandle))
    }

    fn lock_file(file: &SharedFile) -> Result<std::sync::MutexGuard<'_, OpenFile>, DosHostError> {
        file.lock()
            .map_err(|_| invalid(DosErrorCode::GeneralFailure))
    }

    fn set_attributes(&self, path: &std::path::Path, attributes: u8) -> Result<(), DosHostError> {
        metadata::validate_attributes(attributes)?;
        let path = self.confined_path(path, true, false)?;
        let metadata = self.root.metadata(&path).map_err(os_error)?;
        const MUTABLE_DOS_ATTRIBUTES: u32 = FILE_ATTRIBUTE_READONLY
            | FILE_ATTRIBUTE_HIDDEN
            | FILE_ATTRIBUTE_SYSTEM
            | FILE_ATTRIBUTE_ARCHIVE;
        let requested = u32::from(attributes & 0x27);
        // Preserve native flags which have no DOS representation.
        let mut native = (metadata.file_attributes() & !MUTABLE_DOS_ATTRIBUTES) | requested;
        native &= !FILE_ATTRIBUTE_NORMAL;
        if native == 0 {
            native = FILE_ATTRIBUTE_NORMAL;
        }

        // Request only FILE_WRITE_ATTRIBUTES. Opening with write-data would
        // prevent clearing READONLY on a read-only file.
        let file = self
            .root
            .open_with(
                &path,
                OpenOptions::new()
                    .access_mode(FILE_WRITE_ATTRIBUTES)
                    .custom_flags(if metadata.is_dir() {
                        FILE_FLAG_BACKUP_SEMANTICS
                    } else {
                        0
                    }),
            )
            .map_err(os_error)?;
        let basic = FILE_BASIC_INFO {
            CreationTime: 0,
            LastAccessTime: 0,
            LastWriteTime: 0,
            ChangeTime: 0,
            FileAttributes: native,
        };
        let length = u32::try_from(std::mem::size_of::<FILE_BASIC_INFO>())
            .map_err(|_| invalid(DosErrorCode::InvalidData))?;
        // SAFETY: The handle came from cap-std for this confined file and the
        // buffer has the documented FILE_BASIC_INFO layout and exact size.
        if unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle() as HANDLE,
                FileBasicInfo,
                (&basic as *const FILE_BASIC_INFO).cast(),
                length,
            )
        } == 0
        {
            return Err(os_error(io::Error::last_os_error()));
        }
        Ok(())
    }

    pub(crate) fn file_create(
        &mut self,
        path: &[u8],
        attributes: u8,
    ) -> Result<DosHostFile, DosHostError> {
        self.create_file(path, attributes, false)
    }

    pub(crate) fn file_create_new(
        &mut self,
        path: &[u8],
        attributes: u8,
    ) -> Result<DosHostFile, DosHostError> {
        self.create_file(path, attributes, true)
    }

    fn create_file(
        &mut self,
        path: &[u8],
        attributes: u8,
        exclusive: bool,
    ) -> Result<DosHostFile, DosHostError> {
        metadata::validate_attributes(attributes)?;
        self.next_file
            .checked_add(1)
            .ok_or_else(|| invalid(DosErrorCode::TooManyOpenFiles))?;
        let path = self.resolve_path(path, false).map_err(|error| {
            if exclusive { create_new_path_error(error) } else { error }
        })?;
        // Exclusive creation operates on the directory entry itself, so even
        // a dangling final symlink counts as existing. Confine its parent and
        // let the capability-rooted atomic create decide whether it exists.
        let path = self.confined_path(&path, !exclusive, true).map_err(|error| {
            if exclusive { create_new_path_error(error) } else { error }
        })?;
        let native = if attributes == 0 {
            FILE_ATTRIBUTE_NORMAL
        } else {
            u32::from(attributes)
        };
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(!exclusive)
            .truncate(!exclusive)
            .create_new(exclusive)
            .attributes(native);
        if exclusive {
            // Match file_open's documented local compatibility-mode policy.
            options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
        }
        let file = self
            .root
            .open_with(&path, &options)
            .map_err(|error| if exclusive { create_new_error(error) } else { os_error(error) })?;
        let short_name = self.file_short_name(&path)?;
        self.insert_file(Arc::new(Mutex::new(OpenFile::new(
            file,
            DosFileAccess::ReadWrite,
            short_name,
        ))))
    }

    pub(crate) fn file_open(
        &mut self,
        path: &[u8],
        access: DosFileAccess,
        sharing: DosFileSharing,
    ) -> Result<DosHostFile, DosHostError> {
        let path = self.resolve_path(path, false)?;
        let path = self.confined_path(&path, true, false)?;
        let file = self
            .root
            .open_with(&path, &open_options(access, sharing))
            .map_err(os_error)?;
        let short_name = self.file_short_name(&path)?;
        self.insert_file(Arc::new(Mutex::new(OpenFile::new(file, access, short_name))))
    }

    pub(crate) fn file_duplicate(
        &mut self,
        file: DosHostFile,
    ) -> Result<DosHostFile, DosHostError> {
        // Sharing the same File object guarantees shared cursor semantics for
        // duplicates rather than relying on platform-specific clone behavior.
        let shared = self.file(file)?;
        self.insert_file(shared)
    }

    pub(crate) fn file_close(&mut self, file: DosHostFile) -> Result<(), DosHostError> {
        self.files
            .remove(&file)
            .map(drop)
            .ok_or_else(|| invalid(DosErrorCode::InvalidHandle))
    }

    pub(crate) fn file_commit(&mut self, file: DosHostFile) -> Result<(), DosHostError> {
        let shared = self.file(file)?;
        let handle = Self::lock_file(&shared)?;
        // Read-only descriptions cannot have local changes. DOS accepts a
        // clean commit, while Windows FlushFileBuffers requires write access:
        // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers
        if handle.access == DosFileAccess::ReadOnly {
            return Ok(());
        }
        // Sync data and metadata on the same owned object, including creation
        // or truncation before a write. The IOCTL written bit is historical,
        // not pending-dirty state, and must not gate or be cleared by commit.
        handle.file.sync_all().map_err(os_error)
    }

    pub(crate) fn file_read(
        &mut self,
        file: DosHostFile,
        output: &mut [u8],
    ) -> Result<usize, DosHostError> {
        let shared = self.file(file)?;
        let mut handle = Self::lock_file(&shared)?;
        handle.file.read(output).map_err(os_error)
    }

    pub(crate) fn file_input_status(&mut self, file: DosHostFile) -> Result<bool, DosHostError> {
        let shared = self.file(file)?;
        let mut handle = Self::lock_file(&shared)?;
        // Query the same open object and cursor used by reads and duplicates,
        // under their shared lock. No speculative read or cursor restoration.
        let length = handle.file.metadata().map_err(os_error)?.len();
        let position = handle.file.stream_position().map_err(os_error)?;
        Ok(file_has_unread_bytes(position, length))
    }

    pub(crate) fn file_write(
        &mut self,
        file: DosHostFile,
        input: &[u8],
    ) -> Result<usize, DosHostError> {
        let shared = self.file(file)?;
        let mut handle = Self::lock_file(&shared)?;
        let written = handle.file.write(input).map_err(os_error)?;
        if written != 0 {
            handle.written = true;
        }
        Ok(written)
    }

    pub(crate) fn file_seek(
        &mut self,
        file: DosHostFile,
        offset: i32,
        origin: DosSeekOrigin,
    ) -> Result<u32, DosHostError> {
        let shared = self.file(file)?;
        let mut handle = Self::lock_file(&shared)?;
        let base = match origin {
            DosSeekOrigin::Start => 0i128,
            DosSeekOrigin::Current => i128::from(handle.file.stream_position().map_err(os_error)?),
            DosSeekOrigin::End => i128::from(handle.file.metadata().map_err(os_error)?.len()),
        };
        // AH=42h treats CX:DX as unsigned for Start, signed for Current/End.
        let displacement = match origin {
            DosSeekOrigin::Start => i128::from(offset as u32),
            DosSeekOrigin::Current | DosSeekOrigin::End => i128::from(offset),
        };
        let target = base + displacement;
        if !(0..=i128::from(u32::MAX)).contains(&target) {
            return Err(invalid(DosErrorCode::InvalidData));
        }
        let position = handle
            .file
            .seek(SeekFrom::Start(target as u64))
            .map_err(os_error)?;
        u32::try_from(position).map_err(|_| invalid(DosErrorCode::InvalidData))
    }

    pub(crate) fn file_set_len(
        &mut self,
        file: DosHostFile,
        length: u32,
    ) -> Result<(), DosHostError> {
        let shared = self.file(file)?;
        let mut handle = Self::lock_file(&shared)?;
        handle.file.set_len(u64::from(length)).map_err(os_error)?;
        handle.written = true;
        Ok(())
    }

    pub(crate) fn file_ioctl_info(
        &self,
        file: DosHostFile,
    ) -> Result<DosIoctlObjectInfo, DosHostError> {
        let shared = self.file(file)?;
        let handle = Self::lock_file(&shared)?;
        // File handles retain the actual drive backing this mounted volume.
        Ok(DosIoctlObjectInfo::File {
            drive: self.drive,
            written: handle.written,
        })
    }

    pub(crate) fn file_set_write_time(
        &mut self,
        file: DosHostFile,
        time: u16,
        date: u16,
    ) -> Result<(), DosHostError> {
        let shared = self.file(file)?;
        let mut handle = Self::lock_file(&shared)?;
        let write_time = metadata::dos_to_native_write_time(time, date)?;
        // DOS permits timestamp updates even on read-only DOS opens. Windows
        // requires FILE_WRITE_ATTRIBUTES on this existing native handle; our
        // read-only opens lack that right. Preserve the real native failure as
        // a compatibility gap instead of reopening or widening every open.
        // Only last-write time changes; null creation/access pointers preserve
        // those fields. The shared lock retains the exact open-description
        // identity and serializes this metadata change with writes and aliases.
        // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfiletime
        // SAFETY: The owned handle remains live under its lock. The timestamp
        // is an initialized FILETIME, and the two optional pointers are null.
        if unsafe {
            SetFileTime(
                handle.file.as_raw_handle() as HANDLE,
                std::ptr::null(),
                std::ptr::null(),
                &write_time,
            )
        } == 0 {
            return Err(os_error(io::Error::last_os_error()));
        }
        // Like DOS4's cleared SFT clean bit, this includes successful metadata
        // writes. Native mutation is immediate, not DOS's deferred close-time
        // update; later SFT refresh failure does not roll it back.
        // https://github.com/microsoft/MS-DOS/blob/main/v4.0/src/DOS/HANDLE.ASM#L664-L695
        handle.written = true;
        Ok(())
    }

    pub(crate) fn file_status(&mut self, file: DosHostFile) -> Result<DosFileStatus, DosHostError> {
        let shared = self.file(file)?;
        let mut handle = Self::lock_file(&shared)?;
        let facts = handle.file.metadata().map_err(os_error)?;
        let position = handle.file.stream_position().map_err(os_error)?;
        let (write_time, write_date) = metadata::dos_write_time(&facts)?;
        Ok(DosFileStatus {
            short_name: handle.short_name,
            // DOS SFT fields are DWORDs. Keep the low 32 bits, matching the
            // classic DOS-visible size/cursor width (and Win32 DTA nFileSizeLow).
            size: dos_dword(facts.len()),
            position: dos_dword(position),
            attributes: metadata::dos_attributes(&facts),
            write_time,
            write_date,
        })
    }

    pub(crate) fn file_delete(&mut self, path: &[u8]) -> Result<(), DosHostError> {
        let path = self.resolve_path(path, false)?;
        let path = self.confined_path(&path, false, false)?;
        self.root.remove_file(&path).map_err(os_error)
    }

    pub(crate) fn file_get_attributes(&mut self, path: &[u8]) -> Result<u8, DosHostError> {
        let path = self.resolve_path(path, false)?;
        let path = self.confined_path(&path, true, false)?;
        let metadata = self.root.metadata(&path).map_err(os_error)?;
        Ok(metadata::dos_attributes(&metadata))
    }

    pub(crate) fn file_set_attributes(
        &mut self,
        path: &[u8],
        attributes: u8,
    ) -> Result<(), DosHostError> {
        let path = self.resolve_path(path, false)?;
        self.set_attributes(&path, attributes)
    }
}

pub(super) fn open_options(access: DosFileAccess, sharing: DosFileSharing) -> OpenOptions {
    let share_mode = match sharing {
        // DOS compatibility mode permits repeated opens by local processes.
        // Win32 has no compatibility-mode flag; read/write sharing is the
        // permissive local mapping. Exact DOS process-aware conflict rules
        // would need DOS-level open tracking.
        DosFileSharing::Compatibility | DosFileSharing::DenyNone => {
            FILE_SHARE_READ | FILE_SHARE_WRITE
        }
        DosFileSharing::DenyAll => 0,
        DosFileSharing::DenyWrite => FILE_SHARE_READ,
        DosFileSharing::DenyRead => FILE_SHARE_WRITE,
    };
    let mut options = OpenOptions::new();
    options
        .read(access != DosFileAccess::WriteOnly)
        .write(access != DosFileAccess::ReadOnly)
        .share_mode(share_mode);
    options
}

pub(super) fn create_new_path_error(mut error: DosHostError) -> DosHostError {
    // Resolving an exclusive-create path enumerates each parent for its DOS
    // aliases. A missing parent may therefore surface as ERROR_FILE_NOT_FOUND
    // from a metadata/open operation, before CREATE_NEW sees the full path.
    // A missing final leaf is valid for creation; failures in these phases
    // are path-not-found (DOS 5Ah/5Bh), not an existing-file lookup failure.
    // Apply this only before/during creation, never to post-create metadata.
    // Preserve the original native cause for diagnostics.
    // https://www.pcjs.org/documents/books/mspl13/msdos/encyclopedia/section5/
    if error.code == DosErrorCode::FileNotFound {
        error.code = DosErrorCode::PathNotFound;
    }
    error
}

pub(super) fn create_new_error(error: io::Error) -> DosHostError {
    // CREATE_NEW reports ERROR_FILE_EXISTS (80). Preserve DOS 5Bh's distinct
    // error without changing 3Ch, mkdir, or rename's existing error policies.
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
    if matches!(error.raw_os_error(), Some(80 | 183))
        || error.kind() == io::ErrorKind::AlreadyExists
    {
        DosHostError::with_source(DosErrorCode::FileExists, error)
    } else {
        create_new_path_error(os_error(error))
    }
}

#[cfg(test)]
mod create_new_error_tests {
    use super::*;

    #[test]
    fn create_new_error_preserves_exists_and_other_native_failures() {
        for code in [80, 183] {
            assert_eq!(
                create_new_error(io::Error::from_raw_os_error(code)).code,
                DosErrorCode::FileExists,
            );
        }
        for (code, expected) in [
            (2, DosErrorCode::PathNotFound),
            (3, DosErrorCode::PathNotFound),
            (5, DosErrorCode::AccessDenied),
            (32, DosErrorCode::SharingViolation),
            (112, DosErrorCode::DiskFull),
        ] {
            assert_eq!(create_new_error(io::Error::from_raw_os_error(code)).code, expected);
        }
        assert_eq!(os_error(io::Error::from_raw_os_error(80)).code, DosErrorCode::AccessDenied);
        assert_eq!(os_error(io::Error::from_raw_os_error(2)).code, DosErrorCode::FileNotFound);
        assert_eq!(create_new_error(io::Error::from(io::ErrorKind::NotFound)).code, DosErrorCode::PathNotFound);
    }

    #[test]
    fn create_new_path_error_retains_native_cause_and_other_dos_codes() {
        let error = create_new_path_error(os_error(io::Error::from_raw_os_error(2)));
        assert_eq!(error.code, DosErrorCode::PathNotFound);
        let cause = std::error::Error::source(&error).unwrap().downcast_ref::<io::Error>().unwrap();
        assert_eq!(cause.raw_os_error(), Some(2));
        for code in [DosErrorCode::PathNotFound, DosErrorCode::FileExists,
            DosErrorCode::AccessDenied, DosErrorCode::SharingViolation,
            DosErrorCode::InvalidData, DosErrorCode::UnknownUnit, DosErrorCode::DiskFull] {
            assert_eq!(create_new_path_error(DosHostError::new(code)).code, code);
        }
    }
}
