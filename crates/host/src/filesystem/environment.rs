use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf, Prefix};

use dos_kernel::DosHostError;
use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};

use crate::windows::{encode, os_error};

use super::Filesystem;

impl Filesystem {
    /// Map an existing host file or directory to its DOS 8.3 path, only when
    /// the path resolves inside this filesystem's capability root.
    pub(crate) fn guest_path_for_host_path(
        &mut self,
        host_path: &Path,
    ) -> Result<Option<Vec<u8>>, DosHostError> {
        self.guest_path_for_host_path_kind(host_path, false)
    }

    /// Map an existing host directory to its DOS 8.3 path.
    pub(crate) fn guest_directory_for_host_path(
        &mut self,
        host_path: &Path,
    ) -> Result<Option<Vec<u8>>, DosHostError> {
        self.guest_path_for_host_path_kind(host_path, true)
    }

    fn guest_path_for_host_path_kind(
        &mut self,
        host_path: &Path,
        require_directory: bool,
    ) -> Result<Option<Vec<u8>>, DosHostError> {
        if !host_path.is_absolute() {
            return Ok(None);
        }
        let Some(relative) = windows_root_relative(host_path, &self.canonical_root) else {
            return Ok(None);
        };
        self.guest_path_for_relative(&relative, require_directory)
    }

    fn guest_path_for_relative(
        &mut self,
        relative: &Path,
        require_directory: bool,
    ) -> Result<Option<Vec<u8>>, DosHostError> {
        let Some(canonical) = self.canonical_relative_path(relative)? else {
            return Ok(None);
        };
        let metadata = match self.root.metadata(Filesystem::cap_path(&canonical)) {
            Ok(metadata) => metadata,
            Err(error) if is_unavailable_path(&error) => return Ok(None),
            Err(error) => return Err(os_error(error)),
        };
        if require_directory && !metadata.is_dir() {
            return Ok(None);
        }

        let mut parent = PathBuf::new();
        let mut aliases = Vec::new();
        for component in canonical.components() {
            let name = match component {
                std::path::Component::CurDir => continue,
                std::path::Component::Normal(name) => name,
                _ => return Ok(None),
            };
            let alias = self.aliases_for(&parent)?.by_real_name.get(name).cloned();
            let Some(alias) = alias else {
                return Ok(None);
            };
            aliases.push(alias);
            parent.push(name);
        }

        let mut dos_path = format!("{}:\\", char::from(b'A' + self.drive));
        dos_path.push_str(&aliases.join("\\"));
        encode(&dos_path, self.code_page).map(Some)
    }

    fn canonical_relative_path(&self, relative: &Path) -> Result<Option<PathBuf>, DosHostError> {
        let canonical = match self.root.canonicalize(Filesystem::cap_path(relative)) {
            Ok(path) => path,
            Err(error) if is_unavailable_path(&error) => return Ok(None),
            Err(error) => return Err(os_error(error)),
        };
        if Filesystem::verify_relative_canonical_path(&canonical).is_err() {
            return Ok(None);
        }
        Ok(Some(canonical))
    }
}

fn is_unavailable_path(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    )
}

/// Strip a Windows root by path components, allowing the ordinary drive
/// spelling and its `\\?\` verbatim-drive equivalent. Prefix and directory
/// comparisons follow Windows' ordinal, case-insensitive path comparison.
fn windows_root_relative(path: &Path, root: &Path) -> Option<PathBuf> {
    let mut path_components = path.components();
    let mut root_components = root.components();

    let path_prefix = match path_components.next()? {
        Component::Prefix(prefix) => prefix.kind(),
        _ => return None,
    };
    let root_prefix = match root_components.next()? {
        Component::Prefix(prefix) => prefix.kind(),
        _ => return None,
    };
    if !equivalent_prefix(path_prefix, root_prefix) {
        return None;
    }
    if !matches!(path_components.next(), Some(Component::RootDir))
        || !matches!(root_components.next(), Some(Component::RootDir))
    {
        return None;
    }

    for root_component in root_components {
        let path_component = path_components.next()?;
        if !equivalent_component(path_component, root_component) {
            return None;
        }
    }

    let mut relative = PathBuf::new();
    for component in path_components {
        relative.push(component.as_os_str());
    }
    Some(relative)
}

fn equivalent_prefix(path: Prefix<'_>, root: Prefix<'_>) -> bool {
    match (path, root) {
        (Prefix::Disk(left), Prefix::Disk(right))
        | (Prefix::Disk(left), Prefix::VerbatimDisk(right))
        | (Prefix::VerbatimDisk(left), Prefix::Disk(right))
        | (Prefix::VerbatimDisk(left), Prefix::VerbatimDisk(right)) => {
            left.eq_ignore_ascii_case(&right)
        }
        (Prefix::UNC(left_server, left_share), Prefix::UNC(right_server, right_share))
        | (Prefix::UNC(left_server, left_share), Prefix::VerbatimUNC(right_server, right_share))
        | (Prefix::VerbatimUNC(left_server, left_share), Prefix::UNC(right_server, right_share))
        | (
            Prefix::VerbatimUNC(left_server, left_share),
            Prefix::VerbatimUNC(right_server, right_share),
        ) => {
            windows_component_eq(left_server, right_server)
                && windows_component_eq(left_share, right_share)
        }
        _ => false,
    }
}

fn equivalent_component(path: Component<'_>, root: Component<'_>) -> bool {
    match (path, root) {
        (Component::Normal(left), Component::Normal(right)) => windows_component_eq(left, right),
        (Component::CurDir, Component::CurDir) | (Component::ParentDir, Component::ParentDir) => {
            true
        }
        _ => false,
    }
}

pub(super) fn windows_component_eq(left: &OsStr, right: &OsStr) -> bool {
    let left: Vec<u16> = left.encode_wide().collect();
    let right: Vec<u16> = right.encode_wide().collect();
    let (Ok(left_len), Ok(right_len)) = (i32::try_from(left.len()), i32::try_from(right.len()))
    else {
        return false;
    };
    // SAFETY: The buffers remain alive for the call and explicit lengths are
    // bounded i32 values; CompareStringOrdinal reads no terminator.
    unsafe {
        CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) == CSTR_EQUAL
    }
}
