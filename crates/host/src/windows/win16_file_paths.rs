//! Capability-rooted opens for task-resolved classic KERNEL filenames.

use std::os::windows::io::IntoRawHandle;
use std::path::PathBuf;
use cap_std::fs::{OpenOptions, OpenOptionsExt};
use runtime::{RuntimeError, Win16GuestPath, Win16HostFile, Win16HostFileSystemPath};
use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
use crate::filesystem::Filesystem;
use super::win16::{Win16Files, Win16NativeFile, create_attributes, open_access_and_share};

pub(super) fn resolve(
    filesystem: &mut Filesystem, path: &Win16GuestPath, follow: bool, missing: bool,
) -> Result<PathBuf, dos_kernel::DosHostError> {
    let path = filesystem.resolve_win16_host_path(&Win16HostFileSystemPath::Guest(path.clone()))?;
    filesystem.confined_path(&path, follow, missing)
}

pub(super) fn open(
    filesystem: &mut Filesystem, files: &mut Win16Files,
    path: &Win16GuestPath, mode: u16, create: bool,
) -> Result<Option<Win16HostFile>, RuntimeError> {
    let (access, share, attributes) = if create {
        let Some(attributes) = create_attributes(mode) else { return Ok(None); };
        (GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, attributes)
    } else {
        let Some((access, share)) = open_access_and_share(mode) else { return Ok(None); };
        (access, share, 0)
    };
    if let Some(name) = super::win16_file_devices::name(path) {
        let Ok(handle) = super::win16_file_devices::open(name, access, share) else { return Ok(None); };
        return files.retain_native(Win16NativeFile::NativeHandle(handle.into_raw_handle()));
    }
    let Ok(path) = resolve(filesystem, path, true, create) else { return Ok(None); };
    let mut options = OpenOptions::new();
    options.read(access & GENERIC_READ != 0).write(access & GENERIC_WRITE != 0)
        .share_mode(share).create(create).truncate(create);
    if create { options.attributes(attributes); }
    // The open itself stays beneath the capability root, including any
    // reparse-point changes between resolution and the native open.
    let Ok(file) = filesystem.root.open_with(path, &options) else { return Ok(None); };
    files.retain_native(Win16NativeFile::NativeHandle(file.into_std().into_raw_handle()))
}
