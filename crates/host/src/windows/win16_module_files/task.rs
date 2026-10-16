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
