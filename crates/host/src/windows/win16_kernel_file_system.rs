//! Native Windows adapter for owner-scoped Win16 KERNEL file services.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};

use guest_core::OwnerId;
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16CanonicalPath, Win16GuestPath, Win16HostDiskSpace,
    Win16HostFileSystemCall as Call, Win16HostFileSystemOperation as Operation,
    Win16HostFileSystemPath, Win16HostFileSystemResult as ResultValue, Win16HostFindData,
    Win16HostFindFirst, Win16HostSearchId, Win16PathNamespace,
};
use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateDirectoryW, DeleteFileW, FILE_ATTRIBUTE_DIRECTORY, FindFirstFileW, FindNextFileW,
        GetDiskFreeSpaceW, GetFileAttributesW, INVALID_FILE_ATTRIBUTES, RemoveDirectoryW,
        SetFileAttributesW, WIN32_FIND_DATAW,
    },
};

use crate::filesystem::Filesystem;

struct OwnedSearch {
    owner: OwnerId,
    handle: HANDLE,
}

/// Host-owned native handles. The OwnerId check is repeated here even though
/// runtime also scopes each guest WORD handle to the same task incarnation.
#[derive(Default)]
pub(crate) struct Win16HostFileSystemState {
    searches: BTreeMap<Win16HostSearchId, OwnedSearch>,
    next_search_id: u64,
}

impl Drop for Win16HostFileSystemState {
    fn drop(&mut self) {
        for search in self.searches.values() {
            // SAFETY: every retained handle was returned by FindFirstFileW
            // and remains privately owned by this registry.
            crate::windows::win32_safe::find_close(search.handle);
        }
    }
}

pub(crate) fn execute(
    filesystem: &mut Filesystem,
    state: &mut Win16HostFileSystemState,
    call: Call,
) -> Result<ResultValue, RuntimeError> {
    let Call {
        owner,
        ansi_code_page,
        operation,
    } = call;
    match operation {
        Operation::NormalizePath {
            path,
            follow_final,
            allow_missing_final,
        } => Ok(ResultValue::NormalizedPath(normalize_path(
            filesystem,
            &path,
            follow_final,
            allow_missing_final,
        )?)),
        Operation::CreateDirectory { path } => {
            Ok(ResultValue::Completed(create_directory(filesystem, &path)?))
        }
        Operation::RemoveDirectory { path } => {
            Ok(ResultValue::Completed(remove_directory(filesystem, &path)?))
        }
        Operation::DeleteFile { path } => {
            Ok(ResultValue::Completed(delete_file(filesystem, &path)?))
        }
        Operation::QueryDirectory { path } => {
            Ok(ResultValue::Completed(query_directory(filesystem, &path)?))
        }
        Operation::GetFileAttributes { path } => {
            Ok(ResultValue::Attributes(get_attributes(filesystem, &path)?))
        }
        Operation::SetFileAttributes { path, attributes } => Ok(ResultValue::Completed(
            set_attributes(filesystem, &path, attributes)?,
        )),
        Operation::GetDiskFreeSpace { path } => {
            Ok(ResultValue::DiskSpace(disk_space(filesystem, &path)?))
        }
        Operation::FindFirst { search_file } => {
            find_first(filesystem, state, owner, ansi_code_page, &search_file)
        }
        Operation::FindNext { search } => find_next(state, owner, search, ansi_code_page),
        Operation::FindClose { search } => {
            Ok(ResultValue::FindClose(close_search(state, owner, search)))
        }
        Operation::ShortPath { path } => short_path(filesystem, &path, ansi_code_page),
        Operation::RetireTask => {
            retire_task(state, owner)?;
            Ok(ResultValue::TaskRetired)
        }
    }
}

fn create_directory(
    filesystem: &mut Filesystem,
    guest_path: &Win16HostFileSystemPath,
) -> Result<bool, RuntimeError> {
    let Some(path) = native_path(filesystem, guest_path, false, true)? else {
        return Ok(false);
    };
    // SAFETY: the mapped path is a host-owned NUL-terminated UTF-16 string.
    Ok(unsafe { CreateDirectoryW(path.as_ptr(), std::ptr::null()) != 0 })
}

fn remove_directory(
    filesystem: &mut Filesystem,
    guest_path: &Win16HostFileSystemPath,
) -> Result<bool, RuntimeError> {
    let Some(path) = native_path(filesystem, guest_path, false, false)? else {
        return Ok(false);
    };
    // SAFETY: the path is owned and terminated; it was confined to the
    // mounted volume root without following the final directory entry.
    Ok(unsafe { RemoveDirectoryW(path.as_ptr()) != 0 })
}

fn delete_file(
    filesystem: &mut Filesystem,
    guest_path: &Win16HostFileSystemPath,
) -> Result<bool, RuntimeError> {
    let Some(path) = native_path(filesystem, guest_path, false, false)? else {
        return Ok(false);
    };
    // SAFETY: the path is owned and terminated; its parent was resolved
    // through the capability root and the final entry is not followed.
    Ok(unsafe { DeleteFileW(path.as_ptr()) != 0 })
}

fn query_directory(
    filesystem: &mut Filesystem,
    guest_path: &Win16HostFileSystemPath,
) -> Result<bool, RuntimeError> {
    let Some(path) = native_path(filesystem, guest_path, true, false)? else {
        return Ok(false);
    };
    // SAFETY: the path is an owned, terminated name whose resolved target was
    // confirmed to remain beneath the configured volume root.
    let attributes = unsafe { GetFileAttributesW(path.as_ptr()) };
    Ok(attributes != INVALID_FILE_ATTRIBUTES && attributes & FILE_ATTRIBUTE_DIRECTORY != 0)
}

fn get_attributes(
    filesystem: &mut Filesystem,
    guest_path: &Win16HostFileSystemPath,
) -> Result<Option<u32>, RuntimeError> {
    let Some(path) = native_path(filesystem, guest_path, true, false)? else {
        return Ok(None);
    };
    // SAFETY: the path is an owned, terminated name inside the mapped volume.
    let attributes = unsafe { GetFileAttributesW(path.as_ptr()) };
    Ok((attributes != INVALID_FILE_ATTRIBUTES).then_some(attributes))
}

fn set_attributes(
    filesystem: &mut Filesystem,
    guest_path: &Win16HostFileSystemPath,
    attributes: u32,
) -> Result<bool, RuntimeError> {
    let Some(path) = native_path(filesystem, guest_path, true, false)? else {
        return Ok(false);
    };
    // SAFETY: the path is an owned, terminated name inside the mapped volume.
    Ok(unsafe { SetFileAttributesW(path.as_ptr(), attributes) != 0 })
}

fn disk_space(
    filesystem: &mut Filesystem,
    guest_path: &Win16HostFileSystemPath,
) -> Result<Option<Win16HostDiskSpace>, RuntimeError> {
    let Some(_) = native_path(filesystem, guest_path, true, false)? else {
        return Ok(None);
    };
    let mut root = wide_z(filesystem.canonical_root.as_os_str());
    let mut sectors_per_cluster = 0;
    let mut bytes_per_sector = 0;
    let mut free_clusters = 0;
    let mut total_clusters = 0;
    // Use the mounted volume root even when KERNEL received a path to a
    // directory. The requested path is still resolved and validated first.
    // SAFETY: root and all four local output DWORDs are valid for this call.
    let success = unsafe {
        GetDiskFreeSpaceW(
            root.as_mut_ptr(),
            &mut sectors_per_cluster,
            &mut bytes_per_sector,
            &mut free_clusters,
            &mut total_clusters,
        )
    } != 0;
    Ok(success.then_some(Win16HostDiskSpace {
        sectors_per_cluster,
        bytes_per_sector,
        free_clusters,
        total_clusters,
    }))
}

fn find_first(
    filesystem: &mut Filesystem,
    state: &mut Win16HostFileSystemState,
    owner: OwnerId,
    ansi_code_page: u32,
    guest_search_file: &Win16GuestPath,
) -> Result<ResultValue, RuntimeError> {
    let Some(path) = native_search_path(filesystem, guest_search_file)? else {
        return Ok(ResultValue::FindFirst(None));
    };
    let mut native = WIN32_FIND_DATAW::default();
    // SAFETY: path and output record are owned by this synchronous adapter.
    let handle = unsafe { FindFirstFileW(path.as_ptr(), &mut native) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Ok(ResultValue::FindFirst(None));
    }
    let Some(entry) = find_data(&native, ansi_code_page)? else {
        // An entry that cannot be represented in the task's current ANSI code
        // page is not truncated into a different guest filename.
        // SAFETY: this is the fresh FindFirst handle from the call above.
        if (crate::windows::win32_safe::find_close(handle)) == 0 {
            return Err(last_error(
                "FindClose after unrepresentable Win16 FindFirst result",
            ));
        }
        return Ok(ResultValue::FindFirst(None));
    };
    let search = match state.register_search(owner, handle) {
        Ok(search) => search,
        Err(primary) => {
            // SAFETY: no token was published; this is still the new native
            // search handle returned above.
            if (crate::windows::win32_safe::find_close(handle)) == 0 {
                return Err(primary.with_cleanup(
                    "close native search after registry failure",
                    last_error("FindClose after Win16 FindFirst registry failure"),
                ));
            }
            return Err(primary);
        }
    };
    Ok(ResultValue::FindFirst(Some(Win16HostFindFirst {
        search,
        entry,
    })))
}

fn find_next(
    state: &Win16HostFileSystemState,
    owner: OwnerId,
    search: Win16HostSearchId,
    ansi_code_page: u32,
) -> Result<ResultValue, RuntimeError> {
    let Some(handle) = state.search_handle(owner, search) else {
        return Ok(ResultValue::FindNext(None));
    };
    let mut native = WIN32_FIND_DATAW::default();
    // SAFETY: the search handle was found in the owner-checked host registry;
    // output is a local native record.
    if unsafe { FindNextFileW(handle, &mut native) } == 0 {
        return Ok(ResultValue::FindNext(None));
    }
    Ok(ResultValue::FindNext(find_data(&native, ansi_code_page)?))
}

fn close_search(
    state: &mut Win16HostFileSystemState,
    owner: OwnerId,
    search: Win16HostSearchId,
) -> bool {
    let Some(handle) = state.search_handle(owner, search) else {
        return false;
    };
    // SAFETY: the native handle is owned by this exact owner/token registry
    // entry. Remove it only after the native close succeeds.
    if (crate::windows::win32_safe::find_close(handle)) == 0 {
        return false;
    }
    state.searches.remove(&search);
    true
}

fn retire_task(state: &mut Win16HostFileSystemState, owner: OwnerId) -> Result<(), RuntimeError> {
    let ids: Vec<_> = state
        .searches
        .iter()
        .filter_map(|(id, search)| (search.owner == owner).then_some(*id))
        .collect();
    for id in ids {
        let Some(search) = state.searches.get(&id) else {
            continue;
        };
        // SAFETY: this handle is retained for the matching owner and ID.
        if (crate::windows::win32_safe::find_close(search.handle)) == 0 {
            return Err(last_error("FindClose while retiring Win16 file searches"));
        }
        state.searches.remove(&id);
    }
    Ok(())
}

impl Win16HostFileSystemState {
    fn register_search(
        &mut self,
        owner: OwnerId,
        handle: HANDLE,
    ) -> Result<Win16HostSearchId, RuntimeError> {
        self.next_search_id = self.next_search_id.checked_add(1).ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted, "Win16 host search IDs exhausted")
        })?;
        let id = Win16HostSearchId::from_host_id(self.next_search_id);
        self.searches.insert(id, OwnedSearch { owner, handle });
        Ok(id)
    }

    fn search_handle(&self, owner: OwnerId, id: Win16HostSearchId) -> Option<HANDLE> {
        self.searches
            .get(&id)
            .filter(|search| search.owner == owner)
            .map(|search| search.handle)
    }
}

fn short_path(
    filesystem: &mut Filesystem,
    path: &Win16CanonicalPath,
    ansi_code_page: u32,
) -> Result<ResultValue, RuntimeError> {
    let Some(text) = filesystem.short_path_text(path) else {
        return Ok(ResultValue::ShortPath(None));
    };
    if text.is_empty() || text.contains('\0') {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "short Win16 path text is empty or contains NUL",
        ));
    }
    let codec = super::guest_text::GuestTextCodec::new(ansi_code_page)?;
    let wide: Vec<u16> = text.encode_utf16().collect();
    let encoded = codec.from_wide(&wide)?;
    // Reject a substitution that would make the guest 8.3 name a different path.
    if encoded.used_default_char == Some(true)
        || encoded.bytes.is_empty()
        || encoded.bytes.contains(&0)
        || codec.to_wide(&encoded.bytes)? != wide
    {
        return Ok(ResultValue::ShortPath(None));
    }
    Ok(ResultValue::ShortPath(Some(encoded.bytes)))
}

fn native_path(
    filesystem: &mut Filesystem,
    guest_path: &Win16HostFileSystemPath,
    follow_final: bool,
    allow_missing_final: bool,
) -> Result<Option<Vec<u16>>, RuntimeError> {
    let Ok(resolved) = filesystem.resolve_win16_host_path(guest_path) else {
        return Ok(None);
    };
    let Ok(confined) = filesystem.confined_path(&resolved, follow_final, allow_missing_final)
    else {
        return Ok(None);
    };
    if !follow_final && !allow_missing_final && filesystem.root.symlink_metadata(&resolved).is_err()
    {
        return Ok(None);
    }
    let path = filesystem.canonical_root.join(confined);
    Ok(Some(wide_z(path.as_os_str())))
}

fn normalize_path(
    filesystem: &mut Filesystem,
    guest_path: &Win16GuestPath,
    follow_final: bool,
    allow_missing_final: bool,
) -> Result<Option<Win16CanonicalPath>, RuntimeError> {
    let Ok(resolved) = filesystem.resolve_win16_guest_path(guest_path) else {
        return Ok(None);
    };
    let Ok(confined) = filesystem.confined_path(&resolved, follow_final, allow_missing_final)
    else {
        return Ok(None);
    };
    if !follow_final && !allow_missing_final && filesystem.root.symlink_metadata(&resolved).is_err()
    {
        return Ok(None);
    }
    filesystem
        .canonical_win16_path(guest_path.drive, &confined)
        .map_err(|error| RuntimeError::from(dos_kernel::DosError::HostOperation(error)))
}

fn native_search_path(
    filesystem: &mut Filesystem,
    guest_path: &Win16GuestPath,
) -> Result<Option<Vec<u16>>, RuntimeError> {
    if guest_path.namespace != Win16PathNamespace::NativeWindows {
        return Ok(None);
    }
    let Some(pattern) = guest_path.components.last() else {
        return Ok(None);
    };
    if pattern.source != runtime::Win16PathComponentSource::GuestInput
        || pattern.text.is_empty()
        || pattern
            .text
            .chars()
            .any(|character| matches!(character, '\\' | '/' | '\0'))
    {
        return Ok(None);
    }
    let mut directory = guest_path.clone();
    directory.components.pop();
    let Ok(resolved) = filesystem.resolve_win16_guest_path(&directory) else {
        return Ok(None);
    };
    let Ok(confined) = filesystem.confined_path(&resolved, true, false) else {
        return Ok(None);
    };
    let mut path = filesystem.canonical_root.join(confined);
    let pattern: Vec<u16> = pattern.text.encode_utf16().collect();
    if pattern.is_empty() {
        return Ok(None);
    }
    path.push(OsString::from_wide(&pattern));
    Ok(Some(wide_z(path.as_os_str())))
}

fn find_data(
    data: &WIN32_FIND_DATAW,
    code_page: u32,
) -> Result<Option<Win16HostFindData>, RuntimeError> {
    let Some(file_name) = fixed_ansi(&data.cFileName, code_page, 260)? else {
        return Ok(None);
    };
    let Some(alternate_file_name) = fixed_ansi(&data.cAlternateFileName, code_page, 14)? else {
        return Ok(None);
    };
    Ok(Some(Win16HostFindData {
        attributes: data.dwFileAttributes,
        creation_time: filetime(
            data.ftCreationTime.dwLowDateTime,
            data.ftCreationTime.dwHighDateTime,
        ),
        last_access_time: filetime(
            data.ftLastAccessTime.dwLowDateTime,
            data.ftLastAccessTime.dwHighDateTime,
        ),
        last_write_time: filetime(
            data.ftLastWriteTime.dwLowDateTime,
            data.ftLastWriteTime.dwHighDateTime,
        ),
        file_size_high: data.nFileSizeHigh,
        file_size_low: data.nFileSizeLow,
        reserved: [data.dwReserved0, data.dwReserved1],
        file_name,
        alternate_file_name,
    }))
}

fn fixed_ansi(
    source: &[u16],
    code_page: u32,
    capacity: usize,
) -> Result<Option<Vec<u8>>, RuntimeError> {
    let Some(end) = source.iter().position(|unit| *unit == 0) else {
        return Ok(None);
    };
    let codec = super::guest_text::GuestTextCodec::new(code_page)?;
    let encoded = codec.from_wide(&source[..end])?;
    if encoded.used_default_char == Some(true)
        || encoded.bytes.len() >= capacity
        || encoded.bytes.contains(&0)
    {
        return Ok(None);
    }
    Ok(Some(encoded.bytes))
}

fn filetime(low: u32, high: u32) -> u64 {
    u64::from(low) | (u64::from(high) << 32)
}

fn wide_z(path: &std::ffi::OsStr) -> Vec<u16> {
    path.encode_wide().chain(std::iter::once(0)).collect()
}

fn last_error(operation: &'static str) -> RuntimeError {
    let error =
        std::io::Error::from_raw_os_error((crate::windows::win32_safe::last_error()) as i32);
    RuntimeError::with_source(Kind::HostFailure, operation, error)
}
