//! Guest-code-page path search and bounded file reads for guest Win16 DLLs.
//!
//! This module only returns copied file bytes. It never asks the native
//! loader to map or execute a guest module; parsing remains in the runtime.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use super::guest_text::GuestTextCodec;
use runtime::{DiagnosticKind as Kind, RuntimeError, Win16ModuleImage};
use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GetLastError, HANDLE, INVALID_HANDLE_VALUE, SetLastError,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_SEQUENTIAL_SCAN,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, FILE_TYPE_UNKNOWN,
    GetFileAttributesW, GetFileSizeEx, GetFileType, GetFullPathNameW, INVALID_FILE_ATTRIBUTES,
    OPEN_EXISTING, ReadFile,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};
#[path = "win16_module_files_path.rs"]
mod path;
mod task;
pub(crate) use task::read_module as read_task_module;

/// Resource bound for one guest module image. Exceeding it reports the
/// Win16 LoadLibrary memory error instead of allocating an unbounded buffer.
const MAX_MODULE_IMAGE_BYTES: usize = 64 * 1024 * 1024;
/// Win32 wide path APIs use UTF-16 unit capacities and do not require MAX_PATH,
/// but this loader caps paths to avoid runaway environment/path allocation.
const MAX_WIDE_PATH_UNITS: usize = 32 * 1024;
const READ_CHUNK_BYTES: usize = 64 * 1024;

enum CandidateError {
    Missing(u16),
    Load(u16),
    Host(RuntimeError),
}

struct NativeFile(HANDLE);

impl Drop for NativeFile {
    fn drop(&mut self) {
        // SAFETY: This RAII wrapper owns a successful native file-open handle
        // until this drop.
        unsafe { CloseHandle(self.0) };
    }
}

impl super::WindowsHost {
    /// Convert the canonical host module path to this executable's fixed guest
    /// code page for the Win16 startup ABI.
    pub fn win16_main_module_path(&self, path: &Path) -> Result<Vec<u8>, RuntimeError> {
        path::win16_main_module_path(path, self.win16_dcs.text_codec())
    }
}

/// Resolve and copy a Win16 DLL after decoding both guest paths with the
/// executable's fixed code page. Host search directories remain UTF-16.
///
/// A path-bearing name is resolved exactly once. A simple name receives the
/// default `.DLL` extension when it has none, then searches application,
/// current, configured guest system, host system, Windows, and PATH locations.
pub(crate) fn read_module(
    codec: GuestTextCodec,
    name: &[u8],
    application_path: &[u8],
) -> Result<Result<Win16ModuleImage, u16>, RuntimeError> {
    if name.is_empty() {
        return Ok(Err(2));
    }
    if name.contains(&0) {
        return Ok(Err(3));
    }

    let name = match codec.to_wide(name) {
        Ok(name) => name,
        Err(error) if error.kind() == Kind::InvalidInput => return Ok(Err(3)),
        Err(error) => return Err(error),
    };
    if name.len() > MAX_WIDE_PATH_UNITS {
        return Ok(Err(3));
    }

    if has_directory_component(&name) {
        return match read_candidate(codec, &name) {
            Ok(image) => Ok(Ok(image)),
            Err(CandidateError::Missing(code) | CandidateError::Load(code)) => Ok(Err(code)),
            Err(CandidateError::Host(error)) => Err(error),
        };
    }

    let file_name = match name_with_default_extension(&name) {
        Ok(file_name) => file_name,
        Err(code) => return Ok(Err(code)),
    };
    let application_path = match codec.to_wide(application_path) {
        Ok(path) => path,
        Err(error) if error.kind() == Kind::InvalidInput => Vec::new(),
        Err(error) => return Err(error),
    };
    if let Some(directory) = application_directory(&application_path)? {
        if let Some(result) = try_search_directory(codec, &directory, &file_name)? {
            return Ok(result);
        }
    }
    if let Some(current) = current_directory_wide()? {
        if let Some(result) = try_search_directory(codec, &current, &file_name)? {
            return Ok(result);
        }
    }
    if let Some(configured) = optional_env_wide("VDM_SYSTEM_DIR")? {
        if let Some(result) =
            try_search_directory(codec, trim_path_quotes(&configured), &file_name)?
        {
            return Ok(result);
        }
    }
    for (api, operation) in [
        (
            GetSystemDirectoryW as DirectoryApi,
            "read Windows system directory",
        ),
        (GetWindowsDirectoryW, "read Windows directory"),
    ] {
        match wide_directory(api, operation) {
            Ok(directory) => {
                if let Some(result) = try_search_directory(codec, &directory, &file_name)? {
                    return Ok(result);
                }
            }
            Err(error) if error.kind() == Kind::InvalidInput => {}
            Err(error) => return Err(error),
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        if let Some(result) = search_path_components(codec, &path, &file_name)? {
            return Ok(result);
        }
    }
    Ok(Err(2))
}

fn try_search_directory(
    codec: GuestTextCodec,
    directory: &[u16],
    file_name: &[u16],
) -> Result<Option<Result<Win16ModuleImage, u16>>, RuntimeError> {
    if directory.is_empty() {
        return Ok(None);
    }
    let candidate = match join_wide_path(directory, file_name) {
        Ok(path) => path,
        Err(3) => return Ok(None),
        Err(code) => return Ok(Some(Err(code))),
    };
    match read_candidate(codec, &candidate) {
        Ok(image) => Ok(Some(Ok(image))),
        Err(CandidateError::Missing(_)) => Ok(None),
        Err(CandidateError::Load(code)) => Ok(Some(Err(code))),
        Err(CandidateError::Host(error)) => Err(error),
    }
}

fn has_directory_component(name: &[u16]) -> bool {
    find_last_ascii_unit(name, |unit| matches!(unit, 0x5c | 0x2f | 0x3a)).is_some()
}

fn has_extension(name: &[u16]) -> bool {
    let file_start = find_last_ascii_unit(name, |unit| matches!(unit, 0x5c | 0x2f | 0x3a))
        .map_or(0, |separator| separator + 1);
    find_last_ascii_unit(&name[file_start..], |unit| unit == 0x2e).is_some()
}

fn name_with_default_extension(name: &[u16]) -> Result<Vec<u16>, u16> {
    if has_extension(name) {
        return copy_wide_bounded(name);
    }
    let length = name.len().checked_add(4).ok_or(3_u16)?;
    if length > MAX_WIDE_PATH_UNITS {
        return Err(3);
    }
    let mut result = Vec::new();
    result.try_reserve_exact(length).map_err(|_| 8_u16)?;
    result.extend_from_slice(name);
    result.extend_from_slice(&[b'.' as u16, b'D' as u16, b'L' as u16, b'L' as u16]);
    Ok(result)
}

fn copy_wide_bounded(units: &[u16]) -> Result<Vec<u16>, u16> {
    if units.len() > MAX_WIDE_PATH_UNITS {
        return Err(3);
    }
    let mut result = Vec::new();
    result.try_reserve_exact(units.len()).map_err(|_| 8_u16)?;
    result.extend_from_slice(units);
    Ok(result)
}

fn join_wide_path(directory: &[u16], name: &[u16]) -> Result<Vec<u16>, u16> {
    let separator = !directory
        .last()
        .is_some_and(|unit| matches!(*unit, 0x5c | 0x2f));
    let length = directory
        .len()
        .checked_add(usize::from(separator))
        .and_then(|length| length.checked_add(name.len()))
        .ok_or(3_u16)?;
    if length > MAX_WIDE_PATH_UNITS {
        return Err(3);
    }
    let mut result = Vec::new();
    result.try_reserve_exact(length).map_err(|_| 8_u16)?;
    result.extend_from_slice(directory);
    if separator {
        result.push(b'\\' as u16);
    }
    result.extend_from_slice(name);
    Ok(result)
}

fn application_directory(application_path: &[u16]) -> Result<Option<Vec<u16>>, RuntimeError> {
    let Some(separator) =
        find_last_ascii_unit(application_path, |unit| matches!(unit, 0x5c | 0x2f))
    else {
        return Ok(None);
    };
    let end = if separator == 0 {
        1
    } else if separator == 2 && application_path.get(1) == Some(&(b':' as u16)) {
        separator + 1
    } else {
        separator
    };
    let mut directory = Vec::new();
    directory.try_reserve_exact(end).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate Win16 application directory",
            error,
        )
    })?;
    directory.extend_from_slice(&application_path[..end]);
    Ok(Some(directory))
}

fn trim_path_quotes(path: &[u16]) -> &[u16] {
    if path.len() >= 2
        && path.first() == Some(&(b'"' as u16))
        && path.last() == Some(&(b'"' as u16))
    {
        &path[1..path.len() - 1]
    } else {
        path
    }
}

fn find_last_ascii_unit(units: &[u16], matches: impl Fn(u16) -> bool) -> Option<usize> {
    units.iter().rposition(|unit| matches(*unit))
}

fn search_path_components(
    codec: GuestTextCodec,
    path: &OsStr,
    file_name: &[u16],
) -> Result<Option<Result<Win16ModuleImage, u16>>, RuntimeError> {
    search_path_with(path, |directory| try_search_directory(codec, directory, file_name))
}

fn search_path_with(path: &OsStr, mut search: impl FnMut(&[u16])
    -> Result<Option<Result<Win16ModuleImage, u16>>, RuntimeError>)
    -> Result<Option<Result<Win16ModuleImage, u16>>, RuntimeError> {
    let mut component = Vec::new();
    let mut component_too_long = false;
    for unit in path.encode_wide().chain(std::iter::once(b';' as u16)) {
        if unit == b';' as u16 {
            if !component_too_long {
                if let Some(result) =
                    search(trim_path_quotes(&component))?
                {
                    return Ok(Some(result));
                }
            }
            component.clear();
            component_too_long = false;
        } else if !component_too_long {
            if component.len() == MAX_WIDE_PATH_UNITS {
                component.clear();
                component_too_long = true;
            } else {
                if component.len() == component.capacity() {
                    component.try_reserve(1).map_err(|error| {
                        RuntimeError::with_source(
                            Kind::ResourceExhausted,
                            "allocate PATH search component",
                            error,
                        )
                    })?;
                }
                component.push(unit);
            }
        }
    }
    Ok(None)
}

fn optional_env_wide(name: &str) -> Result<Option<Vec<u16>>, RuntimeError> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    match wide_os_units(&value) {
        Ok(path) => Ok(Some(path)),
        Err(error) if error.kind() == Kind::InvalidInput => Ok(None),
        Err(error) => Err(error),
    }
}

fn current_directory_wide() -> Result<Option<Vec<u16>>, RuntimeError> {
    let path = std::env::current_dir().map_err(|error| {
        RuntimeError::with_source(
            Kind::HostFailure,
            "read process current directory for Win16 DLL search",
            error,
        )
    })?;
    match wide_os_units(path.as_os_str()) {
        Ok(path) => Ok(Some(path)),
        Err(error) if error.kind() == Kind::InvalidInput => Ok(None),
        Err(error) => Err(error),
    }
}

fn wide_os_units(value: &OsStr) -> Result<Vec<u16>, RuntimeError> {
    let mut wide = Vec::new();
    for unit in value.encode_wide() {
        if unit == 0 {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 DLL host path contains a null character",
            ));
        }
        if wide.len() == MAX_WIDE_PATH_UNITS {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 DLL host path exceeds the UTF-16 path resource limit",
            ));
        }
        if wide.len() == wide.capacity() {
            wide.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "allocate UTF-16 Win16 DLL path",
                    error,
                )
            })?;
        }
        wide.push(unit);
    }
    Ok(wide)
}

type DirectoryApi = unsafe extern "system" fn(*mut u16, u32) -> u32;

fn wide_directory(api: DirectoryApi, operation: &'static str) -> Result<Vec<u16>, RuntimeError> {
    let mut capacity = 260_usize;
    loop {
        if capacity > MAX_WIDE_PATH_UNITS {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Windows directory exceeds the Win16 path resource limit",
            ));
        }
        let mut buffer = zeroed_wide_buffer(capacity, operation)?;
        let capacity_u32 = u32::try_from(capacity).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "Windows directory capacity exceeds DWORD",
                error,
            )
        })?;
        let length = unsafe { api(buffer.as_mut_ptr(), capacity_u32) } as usize;
        if length == 0 {
            return Err(last_os_error(operation));
        }
        if length < capacity {
            buffer.truncate(length);
            return Ok(buffer);
        }
        capacity = length.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Windows directory buffer size overflow",
            )
        })?;
    }
}

fn zeroed_wide_buffer(capacity: usize, operation: &'static str) -> Result<Vec<u16>, RuntimeError> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(capacity)
        .map_err(|error| RuntimeError::with_source(Kind::ResourceExhausted, operation, error))?;
    buffer.resize(capacity, 0);
    Ok(buffer)
}

fn resolve_wide_path(path: &[u16]) -> Result<Vec<u16>, CandidateError> {
    if path.is_empty() || path.contains(&0) || path.len() > MAX_WIDE_PATH_UNITS {
        return Err(CandidateError::Missing(3));
    }
    let terminated = nul_terminated_wide(path).map_err(|_| CandidateError::Load(8))?;
    let mut capacity = 260_usize;
    loop {
        if capacity > MAX_WIDE_PATH_UNITS {
            return Err(CandidateError::Missing(3));
        }
        let mut buffer = zeroed_wide_buffer(capacity, "allocate resolved Win16 DLL path")
            .map_err(|_| CandidateError::Load(8))?;
        let capacity_u32 = u32::try_from(capacity).map_err(|_| CandidateError::Load(3))?;
        let length = unsafe {
            GetFullPathNameW(
                terminated.as_ptr(),
                capacity_u32,
                buffer.as_mut_ptr(),
                std::ptr::null_mut(),
            )
        } as usize;
        if length == 0 {
            return Err(classify_candidate_path_error(
                unsafe { GetLastError() },
                "resolve Win16 DLL path",
            ));
        }
        if length < capacity {
            buffer.truncate(length);
            return Ok(buffer);
        }
        capacity = length
            .checked_add(1)
            .ok_or_else(|| CandidateError::Load(3))?;
    }
}

fn read_candidate(codec: GuestTextCodec, path: &[u16]) -> Result<Win16ModuleImage, CandidateError> {
    let resolved = resolve_wide_path(path)?;
    let terminated = nul_terminated_wide(&resolved).map_err(|_| CandidateError::Load(8))?;
    let attributes = unsafe { GetFileAttributesW(terminated.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        return Err(classify_candidate_path_error(
            unsafe { GetLastError() },
            "inspect Win16 DLL file",
        ));
    }
    if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(CandidateError::Missing(2));
    }

    // SAFETY: The path is an owned NUL-terminated UTF-16 string;
    // the null security/template arguments request ordinary read-only access.
    let handle = unsafe {
        CreateFileW(
            terminated.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(classify_candidate_path_error(
            unsafe { GetLastError() },
            "open Win16 DLL file",
        ));
    }
    read_owned_candidate(codec, &resolved, NativeFile(handle))
}

// Native search and capability-rooted task search share the same ordinary
// disk-file checks, bounded copy and exact guest path projection.
fn read_owned_candidate(codec: GuestTextCodec, resolved: &[u16], file: NativeFile)
    -> Result<Win16ModuleImage, CandidateError> {
    unsafe { SetLastError(0) };
    let file_type = unsafe { GetFileType(file.0) };
    if file_type != FILE_TYPE_DISK {
        let error = unsafe { GetLastError() };
        if file_type == FILE_TYPE_UNKNOWN && error != 0 {
            return Err(classify_candidate_error(
                error,
                "inspect Win16 DLL file type",
            ));
        }
        return Err(CandidateError::Host(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 DLL candidate is not an ordinary disk file",
        )));
    }

    let mut file_size = 0_i64;
    if unsafe { GetFileSizeEx(file.0, &mut file_size) } == 0 {
        return Err(classify_candidate_error(
            unsafe { GetLastError() },
            "get Win16 DLL file size",
        ));
    }
    if file_size < 0 {
        return Err(CandidateError::Host(RuntimeError::new(
            Kind::InternalInvariant,
            "Windows returned a negative Win16 DLL file size",
        )));
    }
    let file_size = file_size as u64;
    if file_size > MAX_MODULE_IMAGE_BYTES as u64 {
        return Err(CandidateError::Load(8));
    }
    let capacity = file_size as usize;
    let mut image = Vec::new();
    image
        .try_reserve_exact(capacity)
        .map_err(|_| CandidateError::Load(8))?;
    image.resize(capacity, 0);

    let mut total_read = 0_usize;
    while total_read < capacity {
        let requested = (capacity - total_read).min(READ_CHUNK_BYTES) as u32;
        let mut bytes_read = 0_u32;
        let succeeded = unsafe {
            ReadFile(
                file.0,
                image[total_read..].as_mut_ptr(),
                requested,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };
        if succeeded == 0 {
            let error = unsafe { GetLastError() };
            if error == windows_sys::Win32::Foundation::ERROR_HANDLE_EOF {
                break;
            }
            return Err(classify_candidate_error(error, "read Win16 DLL file"));
        }
        if bytes_read == 0 {
            break;
        }
        if bytes_read > requested {
            return Err(CandidateError::Host(RuntimeError::new(
                Kind::InternalInvariant,
                "Windows read more Win16 DLL bytes than requested",
            )));
        }
        total_read += bytes_read as usize;
    }
    image.truncate(total_read);
    // Every module identity uses the same checked guest path projection as
    // the main executable. Lossy substitutions cannot identify a DLL.
    let guest_path = path::win16_module_path(resolved, codec).map_err(|error| {
        if error.kind() == Kind::InvalidInput {
            CandidateError::Missing(3)
        } else {
            CandidateError::Host(error)
        }
    })?;
    Ok(Win16ModuleImage {
        path: guest_path,
        image,
    })
}

fn classify_candidate_error(code: u32, operation: &'static str) -> CandidateError {
    match code {
        2 => CandidateError::Missing(2),
        3 | 15 | 111 | 123 | 161 | 206 | 267 => CandidateError::Missing(3),
        5 | 32 | 33 | 65 => CandidateError::Load(5),
        8 | 14 => CandidateError::Load(8),
        11 => CandidateError::Host(last_os_error_with_code(operation, code)),
        code if code <= 32 => CandidateError::Load(code as u16),
        _ => CandidateError::Host(last_os_error_with_code(operation, code)),
    }
}

fn classify_candidate_path_error(code: u32, operation: &'static str) -> CandidateError {
    match code {
        windows_sys::Win32::Foundation::ERROR_BAD_NETPATH
        | windows_sys::Win32::Foundation::ERROR_NETNAME_DELETED
        | windows_sys::Win32::Foundation::ERROR_BAD_NET_NAME
        | windows_sys::Win32::Foundation::ERROR_NETWORK_UNREACHABLE
        | windows_sys::Win32::Foundation::ERROR_HOST_UNREACHABLE => CandidateError::Missing(3),
        _ => classify_candidate_error(code, operation),
    }
}

fn nul_terminated_wide(units: &[u16]) -> Result<Vec<u16>, RuntimeError> {
    if units.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 DLL path contains an embedded NUL",
        ));
    }
    if units.len() > MAX_WIDE_PATH_UNITS {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 DLL path exceeds the UTF-16 path resource limit",
        ));
    }
    let length = units.len().checked_add(1).ok_or_else(|| {
        RuntimeError::new(Kind::ResourceExhausted, "Win16 DLL path length overflow")
    })?;
    let mut result = Vec::new();
    result.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate NUL-terminated Win16 DLL path",
            error,
        )
    })?;
    result.extend_from_slice(units);
    result.push(0);
    Ok(result)
}

fn last_os_error(operation: &'static str) -> RuntimeError {
    let code = unsafe { GetLastError() };
    last_os_error_with_code(operation, code)
}

fn last_os_error_with_code(operation: &'static str, code: u32) -> RuntimeError {
    RuntimeError::with_source(
        Kind::HostFailure,
        operation,
        io::Error::from_raw_os_error(code as i32),
    )
}

#[cfg(test)]
#[path = "win16_module_files_tests.rs"]
mod tests;
