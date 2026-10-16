//! DOS extended-open dispositions and native outcome reporting.
//!
//! OPEN_EXISTING and CREATE_NEW determine the action from the successful
//! operation itself. Reading GetLastError after cap-std's wrapper returns
//! would not reliably recover OPEN_ALWAYS's created-versus-opened result.
//! https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew

use std::sync::{Arc, Mutex};

use cap_std::fs::OpenOptionsExt;
use dos_kernel::{
    DosErrorCode, DosFileAccess, DosFileDisposition, DosFileOpenOutcome, DosFileOpenRequest,
    DosFileOpenResult, DosHostError,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;

use crate::windows::{invalid, os_error};

use super::files::{create_new_error, create_new_path_error, open_options};
use super::{Filesystem, OpenFile, metadata};

#[path = "extended_open/replacement.rs"]
mod replacement;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenAttempt {
    Existing,
    CreateNew,
    ReplaceExisting,
}

impl Filesystem {
    pub(crate) fn file_extended_open(
        &mut self,
        path: &[u8],
        request: DosFileOpenRequest,
    ) -> Result<DosFileOpenResult, DosHostError> {
        metadata::validate_attributes(request.attributes)?;
        // Reserve token capacity before any operation that could create a
        // native file. No other insertion can interleave with this &mut self.
        self.next_file
            .checked_add(1)
            .ok_or_else(|| invalid(DosErrorCode::TooManyOpenFiles))?;
        let ((file, path), outcome) = open_with_disposition(
            request.disposition,
            request.access,
            |attempt| {
                let create = attempt == OpenAttempt::CreateNew;
                let replace = attempt == OpenAttempt::ReplaceExisting;
                let path = self.resolve_path(path, false).map_err(|error| {
                    if create { create_new_path_error(error) } else { error }
                })?;
                // Follow an existing file's final entry, but CREATE_NEW must
                // retain that entry: even a dangling symlink already exists.
                let path = self.confined_path(&path, !create, create).map_err(|error| {
                    if create { create_new_path_error(error) } else { error }
                })?;
                // Creation/replacement requests a mutation even when the
                // returned DOS handle is read-only. Acquire the mutation right
                // only for this operation, then reduce the same owned object
                // through DuplicateHandle, without reopening its path.
                let mutation_only_access = (replace || create)
                    && request.access == DosFileAccess::ReadOnly;
                let access = if mutation_only_access { DosFileAccess::ReadWrite } else { request.access };
                let mut options = open_options(access, request.sharing);
                if create {
                    let attributes = if request.attributes == 0 {
                        FILE_ATTRIBUTE_NORMAL
                    } else {
                        u32::from(request.attributes)
                    };
                    options.create_new(true).attributes(attributes);
                }
                if replace { options.truncate(true); }
                let file = self.root.open_with(&path, &options).map_err(|error| {
                    if create { create_new_error(error) } else { os_error(error) }
                })?;
                if replace { replacement::set_attributes(&file, request.attributes)?; }
                let file = if mutation_only_access {
                    replacement::read_only_handle(file)?
                } else { file };
                Ok((file, path))
            },
        )?;
        // Like the existing create services, a later alias/metadata failure
        // closes this native handle but may leave the newly created entry.
        // Do not unlink by path as rollback: another actor may now own it.
        let short_name = self.file_short_name(&path)?;
        let file = self.insert_file(Arc::new(Mutex::new(OpenFile::new(
            file,
            request.access,
            short_name,
        ))))?;
        Ok(DosFileOpenResult { file, outcome })
    }
}

fn open_with_disposition<T>(
    disposition: DosFileDisposition,
    access: DosFileAccess,
    mut attempt: impl FnMut(OpenAttempt) -> Result<T, DosHostError>,
) -> Result<(T, DosFileOpenOutcome), DosHostError> {
    use DosFileDisposition::{ReplaceExisting, ReplaceOrCreate};
    if !matches!(disposition, ReplaceExisting | ReplaceOrCreate) {
        return nontruncating_open(disposition, access, attempt);
    }
    match attempt(OpenAttempt::ReplaceExisting) {
        Ok(file) => return Ok((file, DosFileOpenOutcome::Replaced)),
        Err(error) if disposition == ReplaceOrCreate && error.code == DosErrorCode::FileNotFound => {}
        Err(error) => return Err(error),
    }
    match attempt(OpenAttempt::CreateNew) {
        Ok(file) => Ok((file, DosFileOpenOutcome::Created)),
        Err(error) if error.code == DosErrorCode::FileExists => {
            // A concurrent creator won. Retry only the existing-only
            // truncation: another disappearance never becomes implicit create.
            attempt(OpenAttempt::ReplaceExisting)
                .map(|file| (file, DosFileOpenOutcome::Replaced))
        }
        Err(error) => Err(error),
    }
}

fn nontruncating_open<T>(
    disposition: DosFileDisposition,
    _access: DosFileAccess,
    mut attempt: impl FnMut(OpenAttempt) -> Result<T, DosHostError>,
) -> Result<(T, DosFileOpenOutcome), DosHostError> {
    use DosFileDisposition::{CreateNew, OpenExisting, OpenOrCreate};
    use DosFileOpenOutcome::{Created, Opened};

    if disposition != CreateNew {
        match attempt(OpenAttempt::Existing) {
            Ok(file) => return Ok((file, Opened)),
            Err(error) if disposition == OpenOrCreate && error.code == DosErrorCode::FileNotFound => {}
            Err(error) => return Err(error),
        }
    }
    // Creation is itself a mutation, even for a read-only returned DOS handle.
    // The native owner reduces that same open object before publication.
    debug_assert!(disposition != OpenExisting);
    match attempt(OpenAttempt::CreateNew) {
        Ok(file) => Ok((file, Created)),
        Err(error) if disposition == OpenOrCreate && error.code == DosErrorCode::FileExists => {
            // Another creator won after the failed open. Retry OPEN_EXISTING
            // once; repeated removal/recreation cannot make this loop forever.
            attempt(OpenAttempt::Existing).map(|file| (file, Opened))
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests;
