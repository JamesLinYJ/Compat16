//! KERNEL DLL lookup using the calling task's checked DOS filename namespace.

use super::*;
use crate::filesystem::Filesystem;
use cap_std::fs::{OpenOptions, OpenOptionsExt};
use runtime::Win16GuestPath;
use std::os::windows::io::IntoRawHandle;

pub(crate) fn read_module(
    codec: GuestTextCodec,
    filesystem: &mut Filesystem,
    name: &[u8],
    application_path: &[u8],
    task_path: &Win16GuestPath,
) -> Result<Result<Win16ModuleImage, u16>, RuntimeError> {
    let name = match codec.to_wide(name) {
        Ok(name) => name,
        Err(error) if error.kind() == Kind::InvalidInput => return Ok(Err(3)),
        Err(error) => return Err(error),
    };
    if name.is_empty() {
        return Ok(Err(2));
    }
    if name.contains(&0) || name.len() > MAX_WIDE_PATH_UNITS {
        return Ok(Err(3));
    }
    let search = !has_directory_component(&name);
    match read_task_candidate(codec, filesystem, task_path) {
        Ok(image) => return Ok(Ok(image)),
        Err(CandidateError::Missing(code)) if !search => return Ok(Err(code)),
        Err(CandidateError::Missing(_)) => {}
        Err(CandidateError::Load(code)) => return Ok(Err(code)),
        Err(CandidateError::Host(error)) => return Err(error),
    }

    let file_name = match name_with_default_extension(&name) {
        Ok(name) => name,
        Err(code) => return Ok(Err(code)),
    };
    // Win3.1 KERNEL31/LDOPEN.ASM DefaultOrder: current, Windows, 16-bit
    // system, system, application, PATH. Current was the exact task candidate
    // above. Never insert std::env::current_dir() as another current directory.
    if let Some(result) = search_directory(
        codec,
        GetWindowsDirectoryW,
        "read Windows directory",
        &file_name,
    )? {
        return Ok(result);
    }
    if let Some(configured) = optional_env_wide("VDM_SYSTEM_DIR")? {
        if let Some(result) = search_task_directory(
            codec,
            filesystem,
            task_path,
            trim_path_quotes(&configured),
            &file_name,
        )? {
            return Ok(result);
        }
    }
    if let Some(result) = search_directory(
        codec,
        GetSystemDirectoryW,
        "read Windows system directory",
        &file_name,
    )? {
        return Ok(result);
    }
    let application_path = match codec.to_wide(application_path) {
        Ok(path) => path,
        Err(error) if error.kind() == Kind::InvalidInput => Vec::new(),
        Err(error) => return Err(error),
    };
    if let Some(directory) = application_directory(&application_path)? {
        if let Some(result) =
            search_task_directory(codec, filesystem, task_path, &directory, &file_name)?
        {
            return Ok(result);
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        if let Some(result) = search_path_with(&path, |directory| {
            search_task_directory(codec, filesystem, task_path, directory, &file_name)
        })? {
            return Ok(result);
        }
    }
    Ok(Err(2))
}

/// Relative configured/PATH directories belong to the task as well. Win32
/// GetFullPathNameW must never supply its process-wide per-drive cwd here.
fn search_task_directory(
    codec: GuestTextCodec,
    filesystem: &mut Filesystem,
    task_path: &Win16GuestPath,
    directory: &[u16],
    file_name: &[u16],
) -> Result<Option<Result<Win16ModuleImage, u16>>, RuntimeError> {
    if directory.is_empty() {
        return Ok(None);
    }
    let slash = |unit: u16| matches!(unit, 0x5c | 0x2f);
    let drive_qualified = directory.get(1) == Some(&0x3a);
    if directory.len() >= 2 && slash(directory[0]) && slash(directory[1])
        || drive_qualified && directory.get(2).copied().is_some_and(slash)
    {
        return try_search_directory(codec, directory, file_name);
    }
    let relative = if drive_qualified {
        let drive = u8::try_from(directory[0])
            .ok()
            .map(|unit| unit.to_ascii_uppercase());
        if drive != Some(b'A' + task_path.drive) {
            return Ok(None);
        }
        &directory[2..]
    } else {
        directory
    };
    let base = if relative.first().copied().is_some_and(slash) {
        filesystem.canonical_root.clone()
    } else {
        let mut parent = task_path.clone();
        parent.components.pop();
        let parent = filesystem
            .resolve_win16_guest_path(&parent)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::HostFailure,
                    "resolve task directory for Win16 DLL search",
                    error,
                )
            })?;
        filesystem.canonical_root.join(parent)
    };
    let base = wide_os_units(base.as_os_str())?;
    let relative = relative
        .strip_prefix(&[0x5c])
        .or_else(|| relative.strip_prefix(&[0x2f]))
        .unwrap_or(relative);
    let directory = match join_wide_path(&base, relative) {
        Ok(path) => path,
        Err(3) => return Ok(None),
        Err(code) => return Ok(Some(Err(code))),
    };
    try_search_directory(codec, &directory, file_name)
}

fn search_directory(
    codec: GuestTextCodec,
    api: DirectoryApi,
    operation: &'static str,
    file_name: &[u16],
) -> Result<Option<Result<Win16ModuleImage, u16>>, RuntimeError> {
    match wide_directory(api, operation) {
        Ok(directory) => try_search_directory(codec, &directory, file_name),
        Err(error) if error.kind() == Kind::InvalidInput => Ok(None),
        Err(error) => Err(error),
    }
}

fn read_task_candidate(
    codec: GuestTextCodec,
    filesystem: &mut Filesystem,
    path: &Win16GuestPath,
) -> Result<Win16ModuleImage, CandidateError> {
    let relative = super::super::win16_file_paths::resolve(filesystem, path, true, false).map_err(
        |error| match error.code {
            dos_kernel::DosErrorCode::InvalidData | dos_kernel::DosErrorCode::UnknownUnit => {
                CandidateError::Missing(3)
            }
            _ => classify_candidate_error(error.code as u32, "resolve Win16 task DLL file"),
        },
    )?;
    let resolved = wide_os_units(filesystem.canonical_root.join(&relative).as_os_str())
        .map_err(CandidateError::Host)?;
    let metadata = filesystem
        .root
        .metadata(&relative)
        .map_err(|error| task_file_error(error, "inspect Win16 task DLL file"))?;
    if metadata.is_dir() {
        return Err(CandidateError::Missing(2));
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    // Keep the final open beneath the mount even if a reparse point changed
    // after path normalization. Only this owned handle supplies image bytes.
    let file = filesystem
        .root
        .open_with(relative, &options)
        .map_err(|error| task_file_error(error, "open Win16 task DLL file"))?;
    read_owned_candidate(
        codec,
        &resolved,
        NativeFile(file.into_std().into_raw_handle()),
    )
}

/// Existing file in the Win3.1 LoadLibrary order, without a `.DLL` suffix.
///
/// The Windows 3.1 Programmer's Reference passes a font filename through
/// LoadLibrary. The order is the calling task, then Windows, the
/// 16-bit system directory, the system directory, the application directory,
/// and PATH. A name that already contains a directory is only the task
/// candidate. The process current directory is not a second current directory.
pub(crate) fn locate_library_file(
    codec: GuestTextCodec,
    filesystem: &mut Filesystem,
    name: &[u8],
    application_path: &[u8],
    task_path: &Win16GuestPath,
) -> Result<Option<Vec<u16>>, RuntimeError> {
    let wide = match codec.to_wide(name) {
        Ok(name) => name,
        Err(error) if error.kind() == Kind::InvalidInput => return Ok(None),
        Err(error) => return Err(error),
    };
    if wide.is_empty() || wide.contains(&0) || wide.len() > MAX_WIDE_PATH_UNITS {
        return Ok(None);
    }
    let search = !has_directory_component(&wide);
    match existing_task_file(filesystem, task_path)? {
        Some(path) => return Ok(Some(path)),
        None if !search => return Ok(None),
        None => {}
    }

    if let Some(path) =
        search_existing_directory(GetWindowsDirectoryW, "read Windows directory", &wide)?
    {
        return Ok(Some(path));
    }
    if let Some(configured) = optional_env_wide("VDM_SYSTEM_DIR")? {
        if let Some(path) = search_existing_task_directory(
            filesystem,
            task_path,
            trim_path_quotes(&configured),
            &wide,
        )? {
            return Ok(Some(path));
        }
    }
    if let Some(path) =
        search_existing_directory(GetSystemDirectoryW, "read Windows system directory", &wide)?
    {
        return Ok(Some(path));
    }
    let application_path = match codec.to_wide(application_path) {
        Ok(path) => path,
        Err(error) if error.kind() == Kind::InvalidInput => Vec::new(),
        Err(error) => return Err(error),
    };
    if let Some(directory) = application_directory(&application_path)? {
        if let Some(path) =
            search_existing_task_directory(filesystem, task_path, &directory, &wide)?
        {
            return Ok(Some(path));
        }
    }
    if let Some(path_env) = std::env::var_os("PATH") {
        if let Some(path) = search_path_with(&path_env, |directory| {
            search_existing_task_directory(filesystem, task_path, directory, &wide)
        })? {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn existing_task_file(
    filesystem: &mut Filesystem,
    path: &Win16GuestPath,
) -> Result<Option<Vec<u16>>, RuntimeError> {
    let relative = match super::super::win16_file_paths::resolve(filesystem, path, true, false) {
        Ok(path) => path,
        Err(error) => {
            return match error.code {
                dos_kernel::DosErrorCode::FileNotFound
                | dos_kernel::DosErrorCode::PathNotFound
                | dos_kernel::DosErrorCode::InvalidData
                | dos_kernel::DosErrorCode::UnknownUnit
                | dos_kernel::DosErrorCode::NoMoreFiles => Ok(None),
                _ => Err(RuntimeError::with_source(
                    Kind::HostFailure,
                    "resolve Win16 font library file",
                    error,
                )),
            };
        }
    };
    let metadata = match filesystem.root.metadata(&relative) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(RuntimeError::with_source(
                Kind::HostFailure,
                "inspect Win16 font library file",
                error,
            ));
        }
    };
    if metadata.is_dir() {
        return Ok(None);
    }
    let wide = wide_os_units(filesystem.canonical_root.join(&relative).as_os_str())?;
    nul_terminated_wide(&wide).map(Some)
}

fn search_existing_directory(
    api: DirectoryApi,
    operation: &'static str,
    file_name: &[u16],
) -> Result<Option<Vec<u16>>, RuntimeError> {
    match wide_directory(api, operation) {
        Ok(directory) => probe_joined(&directory, file_name),
        Err(error) if error.kind() == Kind::InvalidInput => Ok(None),
        Err(error) => Err(error),
    }
}

fn search_existing_task_directory(
    filesystem: &mut Filesystem,
    task_path: &Win16GuestPath,
    directory: &[u16],
    file_name: &[u16],
) -> Result<Option<Vec<u16>>, RuntimeError> {
    if directory.is_empty() {
        return Ok(None);
    }
    let slash = |unit: u16| matches!(unit, 0x5c | 0x2f);
    let drive_qualified = directory.get(1) == Some(&0x3a);
    if directory.len() >= 2 && slash(directory[0]) && slash(directory[1])
        || drive_qualified && directory.get(2).copied().is_some_and(slash)
    {
        return probe_joined(directory, file_name);
    }
    let relative = if drive_qualified {
        let drive = u8::try_from(directory[0])
            .ok()
            .map(|unit| unit.to_ascii_uppercase());
        if drive != Some(b'A' + task_path.drive) {
            return Ok(None);
        }
        &directory[2..]
    } else {
        directory
    };
    let base = if relative.first().copied().is_some_and(slash) {
        filesystem.canonical_root.clone()
    } else {
        let mut parent = task_path.clone();
        parent.components.pop();
        let parent = filesystem
            .resolve_win16_guest_path(&parent)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::HostFailure,
                    "resolve task directory for Win16 font search",
                    error,
                )
            })?;
        filesystem.canonical_root.join(parent)
    };
    let base = wide_os_units(base.as_os_str())?;
    let relative = relative
        .strip_prefix(&[0x5c])
        .or_else(|| relative.strip_prefix(&[0x2f]))
        .unwrap_or(relative);
    let directory = match join_wide_path(&base, relative) {
        Ok(path) => path,
        Err(_) => return Ok(None),
    };
    probe_joined(&directory, file_name)
}

fn probe_joined(directory: &[u16], file_name: &[u16]) -> Result<Option<Vec<u16>>, RuntimeError> {
    if directory.is_empty() {
        return Ok(None);
    }
    let candidate = match join_wide_path(directory, file_name) {
        Ok(path) => path,
        Err(_) => return Ok(None),
    };
    probe_wide_file(&candidate)
}

fn probe_wide_file(path: &[u16]) -> Result<Option<Vec<u16>>, RuntimeError> {
    if path.is_empty() || path.contains(&0) {
        return Ok(None);
    }
    let terminated = nul_terminated_wide(path)?;
    // SAFETY: `terminated` is a caller-owned NUL-terminated UTF-16 path and
    // stays live for this synchronous attribute query. No guest address is passed.
    let attributes = unsafe { GetFileAttributesW(terminated.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Ok(None);
    }
    Ok(Some(terminated))
}

fn task_file_error(error: io::Error, operation: &'static str) -> CandidateError {
    match error.raw_os_error() {
        Some(code) => classify_candidate_path_error(code as u32, operation),
        None => CandidateError::Host(RuntimeError::with_source(
            Kind::HostFailure,
            operation,
            error,
        )),
    }
}
