use std::io;
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use cap_std::fs::{OpenOptions, OpenOptionsExt};
use dos_kernel::{DosDirectoryEntry, DosErrorCode, DosHostError, DosHostSearch};
use runtime::Win16CanonicalPath;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_RENAME_INFORMATION, FileRenameInformation, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{HANDLE, RtlNtStatusToDosError};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use crate::windows::{encode, invalid, os_error};

use super::Filesystem;
use super::files::dos_dword;
use super::metadata;

pub(super) struct SearchState {
    pub(super) entries: Vec<DosDirectoryEntry>,
    pub(super) next: usize,
}

impl Filesystem {
    pub(crate) fn directory_create(&mut self, path: &[u8]) -> Result<(), DosHostError> {
        let path = self.resolve_path(path, false)?;
        let path = self.confined_path(&path, true, true)?;
        self.root.create_dir(&path).map_err(os_error)
    }

    pub(crate) fn directory_remove(&mut self, path: &[u8]) -> Result<(), DosHostError> {
        let path = self.resolve_path(path, false)?;
        let path = self.confined_path(&path, false, false)?;
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        let parent = self
            .root
            .canonicalize(Self::cap_path(parent))
            .map_err(os_error)?;
        let Some(name) = path.file_name() else {
            return Err(invalid(DosErrorCode::AccessDenied));
        };
        let removed_entry = parent.join(name);
        let current = self
            .root
            .canonicalize(Self::cap_path(&self.current_directory))
            .map_err(os_error)?;
        if current.starts_with(&removed_entry) {
            return Err(invalid(DosErrorCode::CannotRemoveCurrentDirectory));
        }
        self.root.remove_dir(&path).map_err(os_error)
    }

    pub(crate) fn directory_set_current(
        &mut self,
        path: &[u8],
        synchronize_native: bool,
    ) -> Result<(), DosHostError> {
        let path = self.resolve_path(path, true)?;
        self.commit_current_directory(path, synchronize_native)
    }

    /// Activate a retained owner path directly. Canonical components must not
    /// be translated through DOS aliases a second time.
    pub(crate) fn directory_set_current_canonical(
        &mut self,
        path: &Win16CanonicalPath,
        synchronize_native: bool,
    ) -> Result<(), DosHostError> {
        let path = self.resolve_win16_canonical_path(path)?;
        self.commit_current_directory(path, synchronize_native)
    }

    fn commit_current_directory(
        &mut self,
        path: PathBuf,
        synchronize_native: bool,
    ) -> Result<(), DosHostError> {
        let path = self.confined_path(&path, true, false)?;
        let directory = self
            .root
            .open_dir(Self::cap_path(&path))
            .map_err(os_error)?;
        drop(directory);
        if synchronize_native {
            // Commit the DOS directory only after Windows accepted the same
            // directory, so failure does not split relative-path resolution.
            std::env::set_current_dir(self.canonical_root.join(&path)).map_err(os_error)?;
        }
        self.current_directory = path;
        Ok(())
    }

    pub(crate) fn directory_get_current(
        &mut self,
        drive: u8,
        output: &mut [u8],
    ) -> Result<usize, DosHostError> {
        if drive != self.drive {
            return Err(invalid(DosErrorCode::UnknownUnit));
        }
        let current_directory = self.current_directory.clone();
        self.encode_dos_directory_path(&current_directory, output)
    }

    /// Project a retained canonical owner path into AH=47's virtual DOS 8.3
    /// namespace without reparsing its component strings.
    pub(crate) fn directory_get_current_canonical(
        &mut self,
        path: &Win16CanonicalPath,
        output: &mut [u8],
    ) -> Result<usize, DosHostError> {
        let relative = self.resolve_win16_canonical_path(path)?;
        let canonical = self.confined_path(&relative, true, false)?;
        self.encode_dos_directory_path(&canonical, output)
    }

    pub(crate) fn file_rename(
        &mut self,
        old_path: &[u8],
        new_path: &[u8],
    ) -> Result<(), DosHostError> {
        let old_path = self.resolve_path(old_path, false)?;
        let new_path = self.resolve_path(new_path, false)?;
        // Do not follow the final entry: renaming a symlink or junction moves
        // the entry itself and must not open or rename its target.
        let old_path = self.confined_path(&old_path, false, false)?;
        let new_path = self.confined_path(&new_path, false, true)?;
        let old_name = old_path
            .file_name()
            .ok_or_else(|| invalid(DosErrorCode::FileNotFound))?;
        let new_name = new_path
            .file_name()
            .ok_or_else(|| invalid(DosErrorCode::InvalidData))?;

        match self.root.symlink_metadata(&new_path) {
            Ok(_) => return Err(invalid(DosErrorCode::AccessDenied)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(os_error(error)),
        }

        let old_parent = old_path.parent().unwrap_or_else(|| Path::new(""));
        let old_parent = self
            .root
            .canonicalize(Self::cap_path(old_parent))
            .map_err(os_error)?;
        let old_entry = old_parent.join(old_name);
        let new_parent = new_path.parent().unwrap_or_else(|| Path::new(""));
        let new_parent = self
            .root
            .canonicalize(Self::cap_path(new_parent))
            .map_err(os_error)?;
        let new_entry = new_parent.join(new_name);
        let current = self
            .root
            .canonicalize(Self::cap_path(&self.current_directory))
            .map_err(os_error)?;
        let current_suffix = current.strip_prefix(&old_entry).ok().map(Path::to_path_buf);

        // Open the source entry through the capability. OPEN_REPARSE_POINT
        // means a final symlink/junction itself is renamed instead of opening
        // whatever target it names; DELETE is the access needed for rename.
        let source = self
            .root
            .open_with(
                &old_path,
                OpenOptions::new()
                    .access_mode(DELETE | FILE_READ_ATTRIBUTES)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS),
            )
            .map_err(os_error)?;
        let destination_directory = self
            .root
            .open_dir(Self::cap_path(&new_parent))
            .map_err(os_error)?
            .into_std_file();

        let wide_name: Vec<u16> = new_name.encode_wide().collect();
        let file_name_bytes = wide_name
            .len()
            .checked_mul(size_of::<u16>())
            .ok_or_else(|| invalid(DosErrorCode::InvalidData))?;
        let name_offset = offset_of!(FILE_RENAME_INFORMATION, FileName);
        let buffer_len = name_offset
            .checked_add(file_name_bytes)
            .ok_or_else(|| invalid(DosErrorCode::InvalidData))?
            .max(size_of::<FILE_RENAME_INFORMATION>());
        let word_size = size_of::<usize>();
        let word_count = buffer_len
            .checked_add(word_size - 1)
            .ok_or_else(|| invalid(DosErrorCode::InvalidData))?
            / word_size;
        let mut buffer = vec![0usize; word_count];
        let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        let buffer_len_u32 =
            u32::try_from(buffer_len).map_err(|_| invalid(DosErrorCode::InvalidData))?;
        let file_name_bytes_u32 =
            u32::try_from(file_name_bytes).map_err(|_| invalid(DosErrorCode::InvalidData))?;
        // SAFETY: The aligned buffer is large enough for the fixed structure
        // and UTF-16 tail. The source/destination handles are capability-opened.
        unsafe {
            (*info).Anonymous.ReplaceIfExists = false;
            (*info).RootDirectory = destination_directory.as_raw_handle() as HANDLE;
            (*info).FileNameLength = file_name_bytes_u32;
            let file_name = std::ptr::addr_of_mut!((*info).FileName).cast::<u16>();
            std::ptr::copy_nonoverlapping(wide_name.as_ptr(), file_name, wide_name.len());
        }
        // Win32's FileRenameInfo wrapper rejects RootDirectory plus a relative
        // name on supported hosts (ERROR_INVALID_PARAMETER).
        // Use the documented NT service so the destination remains relative
        // to our capability-opened directory, without an ambient-path retry.
        let mut status_block = IO_STATUS_BLOCK::default();
        // SAFETY: Both native handles are live; the source was opened for
        // synchronous I/O. The initialized buffer and status block remain
        // owned and valid until this synchronous operation returns.
        let status = unsafe {
            NtSetInformationFile(
                source.as_raw_handle() as HANDLE,
                &mut status_block,
                info.cast(),
                buffer_len_u32,
                FileRenameInformation,
            )
        };
        if status < 0 {
            // SAFETY: This is the returned NT status, not a guest value.
            let code = unsafe { RtlNtStatusToDosError(status) };
            return Err(os_error(io::Error::from_raw_os_error(code as i32)));
        }

        if let Some(suffix) = current_suffix {
            self.current_directory = new_entry.join(suffix);
        }
        // Move cached aliases for directories below a renamed directory. The
        // parent tables refresh lazily while retaining assignments for entries
        // that are still present.
        let previous = std::mem::take(&mut self.aliases);
        for (directory, table) in previous {
            if let Ok(suffix) = directory.strip_prefix(&old_entry) {
                self.aliases.entry(new_entry.join(suffix)).or_insert(table);
            } else {
                self.aliases.insert(directory, table);
            }
        }
        Ok(())
    }

    pub(crate) fn directory_search_open(
        &mut self,
        directory: &[u8],
    ) -> Result<DosHostSearch, DosHostError> {
        let path = self.resolve_path(directory, true)?;
        let path = self.confined_path(&path, true, false)?;
        let (directory_entries, case_sensitivity) = self.read_directory_entries(&path)?;
        let names = directory_entries
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        self.refresh_aliases_for_names(&path, names, case_sensitivity)?;
        let aliases = self.aliases.get(&path).expect("alias table was inserted");
        let code_page = self.code_page;
        let mut entries = Vec::with_capacity(aliases.by_real_name.len() + 2);
        // DOS subdirectories expose their current and parent directory entries.
        // Rust's read_dir omits these names. They describe the mapped hierarchy;
        // the guest drive root has no parent entry and never exposes the host
        // parent outside the capability root.
        if !path.as_os_str().is_empty() && path != Path::new(".") {
            let parent = path.parent().unwrap_or_else(|| Path::new(""));
            for (name, target) in [
                (b".".as_slice(), path.as_path()),
                (b"..".as_slice(), parent),
            ] {
                let facts = self
                    .root
                    .metadata(Self::cap_path(target))
                    .map_err(os_error)?;
                let (write_time, write_date) = metadata::dos_write_time(&facts)?;
                entries.push(DosDirectoryEntry {
                    short_name: name.to_vec(),
                    attributes: metadata::DOS_ATTRIBUTE_DIRECTORY,
                    write_time,
                    write_date,
                    size: 0,
                });
            }
        }
        for directory_entry in directory_entries {
            let name = directory_entry.name;
            let Some(short_name) = aliases.by_real_name.get(&name) else {
                return Err(invalid(DosErrorCode::GeneralFailure));
            };
            let encoded_name = encode(short_name, code_page)?;
            // Windows directory enumeration already supplies entry metadata.
            // Listing a link or protected child does not require opening its
            // target; access checks still apply when the guest opens it.
            let metadata = directory_entry.entry.metadata().map_err(os_error)?;
            let (write_time, write_date) = metadata::dos_write_time(&metadata)?;
            let attributes = metadata::dos_attributes(&metadata);
            let size = if attributes & metadata::DOS_ATTRIBUTE_DIRECTORY != 0 {
                0
            } else {
                // DOS directory entries carry only the low DWORD of size,
                // matching the existing guest file-status representation.
                dos_dword(metadata.len())
            };
            entries.push(DosDirectoryEntry {
                short_name: encoded_name,
                attributes,
                write_time,
                write_date,
                size,
            });
        }
        entries.sort_by(|left, right| left.short_name.cmp(&right.short_name));

        let id = DosHostSearch(self.next_search);
        self.next_search = self
            .next_search
            .checked_add(1)
            .ok_or_else(|| invalid(DosErrorCode::TooManyOpenFiles))?;
        self.searches.insert(id, SearchState { entries, next: 0 });
        Ok(id)
    }

    pub(crate) fn directory_search_next(
        &mut self,
        search: DosHostSearch,
    ) -> Result<Option<DosDirectoryEntry>, DosHostError> {
        let state = self
            .searches
            .get_mut(&search)
            .ok_or_else(|| invalid(DosErrorCode::InvalidHandle))?;
        let Some(entry) = state.entries.get(state.next).cloned() else {
            return Ok(None);
        };
        state.next += 1;
        Ok(Some(entry))
    }

    pub(crate) fn directory_search_close(
        &mut self,
        search: DosHostSearch,
    ) -> Result<(), DosHostError> {
        self.searches
            .remove(&search)
            .map(drop)
            .ok_or_else(|| invalid(DosErrorCode::InvalidHandle))
    }
}
