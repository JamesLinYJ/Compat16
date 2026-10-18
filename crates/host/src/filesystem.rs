//! DOS filesystem paths within a mounted Windows volume.
//!
//! DOS paths are decoded, normalized, and resolved through per-directory
//! virtual 8.3 names before they reach the capability-rooted `Dir`.

mod aliases;
mod canonical_name;
mod directory;
mod environment;
mod extended_open;
mod files;
mod metadata;
mod volume;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use cap_std::fs::{Dir, File};
use dos_kernel::{DosErrorCode, DosFileAccess, DosHostError, DosHostFile, DosHostSearch};
use runtime::{
    Win16CanonicalPath, Win16GuestPath, Win16HostFileSystemPath, Win16PathComponentSource,
    Win16PathNamespace,
};

use crate::windows::{decode, invalid, os_error};

/// Share the DOS local timestamp policy with handle-based Win16 file services.
pub(crate) fn dos_write_time_from_ticks(ticks: u64) -> Result<(u16, u16), DosHostError> {
    metadata::dos_write_time_from_ticks(ticks)
}

pub(crate) fn dos_to_native_write_time(
    time: u16,
    date: u16,
) -> Result<windows_sys::Win32::Foundation::FILETIME, DosHostError> {
    metadata::dos_to_native_write_time(time, date)
}

/// Open-description state is shared by duplicated DOS file tokens.
pub(super) struct OpenFile {
    file: File,
    // Rights selected for this native open, independent of file attributes.
    access: DosFileAccess,
    written: bool,
    short_name: [u8; 11],
}

impl OpenFile {
    fn new(file: File, access: DosFileAccess, short_name: [u8; 11]) -> Self {
        Self {
            file,
            access,
            written: false,
            short_name,
        }
    }
}

pub(super) type SharedFile = Arc<Mutex<OpenFile>>;

pub(crate) struct Filesystem {
    pub(super) root: Dir,
    pub(super) canonical_root: PathBuf,
    pub(super) current_directory: PathBuf,
    pub(super) drive: u8,
    code_page: u32,
    guest_code_page: text_codec::CodePage,
    pub(super) files: BTreeMap<DosHostFile, SharedFile>,
    next_file: u64,
    searches: BTreeMap<DosHostSearch, directory::SearchState>,
    next_search: u64,
    aliases: BTreeMap<PathBuf, aliases::AliasTable>,
}

impl Filesystem {
    /// Mount the actual Windows volume and keep the program directory as its
    /// working directory. Native module paths and DOS paths then identify the
    /// same files; opening an absolute name does not prepend the program directory.
    pub(crate) fn new_native_directory(
        directory: &Path,
        code_page: u32,
    ) -> Result<Self, DosHostError> {
        use std::path::{Component, Prefix};
        let canonical = std::fs::canonicalize(directory).map_err(os_error)?;
        let drive = match canonical.components().next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter.to_ascii_uppercase(),
                _ => return Err(invalid(DosErrorCode::UnknownUnit)),
            },
            _ => return Err(invalid(DosErrorCode::PathNotFound)),
        };
        let volume_root: PathBuf = canonical.components().take(2).collect();
        let relative = canonical
            .strip_prefix(&volume_root)
            .map_err(|_| invalid(DosErrorCode::PathNotFound))?;
        let guest_code_page = text_codec::CodePage::try_from(code_page)
            .map_err(|error| DosHostError::with_source(DosErrorCode::InvalidData, error))?;
        let root =
            Dir::open_ambient_dir(&volume_root, cap_std::ambient_authority()).map_err(os_error)?;
        Ok(Self {
            root,
            canonical_root: volume_root.clone(),
            current_directory: relative.to_path_buf(),
            drive: drive - b'A',
            code_page,
            guest_code_page,
            files: BTreeMap::new(),
            next_file: 1,
            searches: BTreeMap::new(),
            next_search: 1,
            aliases: BTreeMap::new(),
        })
    }

    pub(crate) fn drive(&self) -> u8 {
        self.drive
    }

    pub(crate) fn guest_code_page(&self) -> text_codec::CodePage {
        self.guest_code_page
    }

    pub(super) fn cap_path(path: &Path) -> &Path {
        if path.as_os_str().is_empty() {
            Path::new(".")
        } else {
            path
        }
    }

    /// Convert a DOS path to a normalized root-relative path and expand any
    /// 8.3 aliases in each existing parent directory.
    pub(super) fn resolve_path(
        &mut self,
        raw: &[u8],
        allow_empty: bool,
    ) -> Result<PathBuf, DosHostError> {
        let decoded = decode(raw, self.code_page)?;
        self.resolve_text_path(&decoded, allow_empty)
    }

    /// Resolve an already-decoded DOS path while preserving Unicode names.
    /// Existing components, including the final entry, resolve to their actual
    /// directory-entry spelling using Windows ordinal case rules. DOS byte
    /// callers decode with the mounted OEM code page above; Win16 ANSI APIs
    /// pass task-codec text without an OEM round-trip.
    pub(super) fn resolve_text_path(
        &mut self,
        decoded: &str,
        allow_empty: bool,
    ) -> Result<PathBuf, DosHostError> {
        if decoded.contains('\0') {
            return Err(invalid(DosErrorCode::InvalidData));
        }

        let mut text = decoded;
        if text.as_bytes().get(1) == Some(&b':') {
            if !text.as_bytes()[0].eq_ignore_ascii_case(&(b'A' + self.drive)) {
                return Err(invalid(DosErrorCode::UnknownUnit));
            }
            text = &text[2..];
        }

        let normalized = text.replace('\\', "/");
        // UNC, Win32 device, and extended-length namespaces are not DOS drive
        // paths. Reject them instead of letting Win32 reinterpret a prefix.
        if normalized.starts_with("//") {
            return Err(invalid(DosErrorCode::InvalidData));
        }
        let rooted = normalized.starts_with('/');
        if normalized.is_empty() && !allow_empty {
            return Err(invalid(DosErrorCode::PathNotFound));
        }
        let mut result = if rooted {
            PathBuf::new()
        } else {
            self.current_directory.clone()
        };

        for component in normalized.split('/') {
            if component.is_empty() || component == "." {
                continue;
            }
            if component == ".." {
                // DOS paths remain on the selected drive; `..` at its root is
                // clamped at the root rather than escaping the capability.
                result.pop();
                continue;
            }
            if component
                .chars()
                .any(|character| matches!(character, ':' | '*' | '?' | '<' | '>' | '"' | '|'))
            {
                return Err(invalid(DosErrorCode::InvalidData));
            }
            if is_reserved_device_name(component) {
                return Err(invalid(DosErrorCode::AccessDenied));
            }

            let actual = self.resolve_dos_path_component(&result, component)?;
            result.push(actual);
        }

        if result.as_os_str().is_empty() && !allow_empty {
            return Err(invalid(DosErrorCode::PathNotFound));
        }
        Ok(result)
    }

    /// Resolve a typed KERNEL or DOS path without flattening canonical cwd
    /// components back into guest text. NativeWindows deliberately bypasses
    /// virtual aliases; DosVirtual translates only GuestInput components.
    pub(crate) fn resolve_win16_guest_path(
        &mut self,
        guest_path: &Win16GuestPath,
    ) -> Result<PathBuf, DosHostError> {
        if guest_path.drive != self.drive {
            return Err(invalid(DosErrorCode::UnknownUnit));
        }
        let mut result = PathBuf::new();
        for component in &guest_path.components {
            let text = component.text.as_str();
            let invalid_structure = text.is_empty()
                || matches!(text, "." | "..")
                || text
                    .chars()
                    .any(|character| matches!(character, '\\' | '/' | '\0'));
            let invalid_dos_input = guest_path.namespace == Win16PathNamespace::DosVirtual
                && component.source == Win16PathComponentSource::GuestInput
                && (text
                    .chars()
                    .any(|character| matches!(character, ':' | '<' | '>' | '"' | '|' | '*' | '?'))
                    || text.ends_with(' ')
                    || text.ends_with('.')
                    || is_reserved_device_name(text));
            if invalid_structure || invalid_dos_input {
                return Err(invalid(DosErrorCode::InvalidData));
            }
            let requested = OsStr::new(text);
            let actual = match (guest_path.namespace, component.source) {
                (_, Win16PathComponentSource::CanonicalCwd) => requested.to_os_string(),
                (Win16PathNamespace::DosVirtual, Win16PathComponentSource::GuestInput) => {
                    self.resolve_dos_path_component(&result, text)?
                }
                (Win16PathNamespace::NativeWindows, Win16PathComponentSource::GuestInput) => self
                    .resolve_native_path_component(&result, requested)?
                    .unwrap_or_else(|| requested.to_os_string()),
            };
            result.push(actual);
        }
        Ok(result)
    }

    /// Convert a canonical Win16 path directly into a root-relative path.
    /// This route intentionally does not consult aliases or case folding.
    pub(crate) fn resolve_win16_canonical_path(
        &self,
        path: &Win16CanonicalPath,
    ) -> Result<PathBuf, DosHostError> {
        if path.drive != self.drive {
            return Err(invalid(DosErrorCode::UnknownUnit));
        }
        let mut result = PathBuf::new();
        for component in &path.components {
            if component.is_empty()
                || matches!(component.as_str(), "." | "..")
                || component
                    .chars()
                    .any(|character| matches!(character, '\\' | '/' | '\0'))
            {
                return Err(invalid(DosErrorCode::InvalidData));
            }
            result.push(component);
        }
        Ok(result)
    }

    pub(crate) fn resolve_win16_host_path(
        &mut self,
        path: &Win16HostFileSystemPath,
    ) -> Result<PathBuf, DosHostError> {
        match path {
            Win16HostFileSystemPath::Guest(path) => self.resolve_win16_guest_path(path),
            Win16HostFileSystemPath::Canonical(path) => self.resolve_win16_canonical_path(path),
        }
    }

    pub(crate) fn canonical_win16_path(
        &self,
        drive: u8,
        relative: &Path,
    ) -> Result<Option<Win16CanonicalPath>, DosHostError> {
        if drive != self.drive {
            return Err(invalid(DosErrorCode::UnknownUnit));
        }
        let mut components = Vec::new();
        for component in relative.components() {
            let std::path::Component::Normal(component) = component else {
                if matches!(component, std::path::Component::CurDir) {
                    continue;
                }
                return Err(invalid(DosErrorCode::AccessDenied));
            };
            let Some(component) = component.to_str() else {
                return Ok(None);
            };
            components.push(component.to_owned());
        }
        Ok(Some(Win16CanonicalPath { drive, components }))
    }

    fn resolve_dos_path_component(
        &mut self,
        parent: &Path,
        component: &str,
    ) -> Result<OsString, DosHostError> {
        let alias = aliases::canonical_83(OsStr::new(component), self.guest_code_page)
            .unwrap_or_else(|| component.to_ascii_uppercase());
        let requested = OsStr::new(component);
        let lookup = {
            let table = self.aliases_for(parent)?;
            match table.by_alias.get(&alias) {
                // Keep an already-issued guest short alias bound to its entry
                // even if a later external entry takes the same spelling.
                Some(actual) => aliases::RealNameLookup::Resolved(Some(actual.clone())),
                None => match table.by_real_name.get_key_value(requested) {
                    Some((actual, _)) => aliases::RealNameLookup::Resolved(Some(actual.clone())),
                    None => table.lookup_real_name(requested)?,
                },
            }
        };
        match lookup {
            aliases::RealNameLookup::Resolved(Some(actual)) => Ok(actual),
            aliases::RealNameLookup::Resolved(None) => Ok(OsString::from(component)),
            aliases::RealNameLookup::Native {
                ordinal_candidate_exists,
            } => Ok(self
                .lookup_unknown_case_real_name(parent, requested, ordinal_candidate_exists)?
                .unwrap_or_else(|| OsString::from(component))),
        }
    }

    /// Project an owner-retained canonical path through the stable DOS virtual
    /// alias table. This path has already been resolved and must not be parsed
    /// as guest text again.
    pub(crate) fn dos_path_bytes_for_canonical(
        &mut self,
        path: &Win16CanonicalPath,
    ) -> Option<Vec<u8>> {
        let relative = self.resolve_win16_canonical_path(path).ok()?;
        let relative = self.confined_path(&relative, false, true).ok()?;
        let components: Vec<_> = relative
            .components()
            .filter(|component| !matches!(component, std::path::Component::CurDir))
            .map(|component| component.as_os_str().to_os_string())
            .collect();
        let mut parent = PathBuf::new();
        let mut aliases = Vec::with_capacity(components.len());
        let last = components.len().checked_sub(1);
        for (index, component) in components.into_iter().enumerate() {
            let alias = match self
                .aliases_for(&parent)
                .ok()?
                .by_real_name
                .get(&component)
                .cloned()
            {
                Some(alias) => alias,
                None if Some(index) == last => component.to_str()?.to_owned(),
                None => return None,
            };
            aliases.push(alias);
            parent.push(component);
        }
        let absolute = format!("{}:\\{}", char::from(b'A' + path.drive), aliases.join("\\"));
        crate::windows::encode(&absolute, self.code_page).ok()
    }

    /// Absolute 8.3 spelling of an existing canonical path. The final entry
    /// must exist, and every component must already have an alias. This does
    /// not invent a short name when the volume has none.
    pub(crate) fn short_path_text(&mut self, path: &Win16CanonicalPath) -> Option<String> {
        if path.drive != self.drive {
            return None;
        }
        let relative = self.resolve_win16_canonical_path(path).ok()?;
        let relative = self.confined_path(&relative, true, false).ok()?;
        let components: Vec<_> = relative
            .components()
            .filter(|component| !matches!(component, std::path::Component::CurDir))
            .map(|component| component.as_os_str().to_os_string())
            .collect();
        let mut parent = PathBuf::new();
        let mut aliases = Vec::with_capacity(components.len());
        for component in &components {
            let alias = self.aliases_for(parent.as_path()).ok()?
                .by_real_name.get(component).cloned()?;
            aliases.push(alias);
            parent.push(component);
        }
        let drive = char::from(b'A' + path.drive);
        Some(if aliases.is_empty() {
            format!("{drive}:\\")
        } else {
            format!("{drive}:\\{}", aliases.join("\\"))
        })
    }

    pub(super) fn encode_dos_directory_path(
        &mut self,
        path: &Path,
        output: &mut [u8],
    ) -> Result<usize, DosHostError> {
        let components: Vec<_> = path
            .components()
            .filter(|component| !matches!(component, std::path::Component::CurDir))
            .map(|component| component.as_os_str().to_os_string())
            .collect();
        let mut parent = PathBuf::new();
        let mut short_components = Vec::with_capacity(components.len());
        for component in &components {
            let alias = self
                .aliases_for(&parent)?
                .by_real_name
                .get(component)
                .cloned()
                .ok_or_else(|| invalid(DosErrorCode::PathNotFound))?;
            short_components.push(alias);
            parent.push(component);
        }
        let text = short_components.join("\\");
        let encoded = crate::windows::encode(&text, self.code_page)?;
        if encoded.len() > output.len() {
            return Err(invalid(DosErrorCode::InvalidData));
        }
        output[..encoded.len()].copy_from_slice(&encoded);
        Ok(encoded.len())
    }

    /// Resolve through the capability and reject a canonical target which
    /// escapes the selected root. For entry operations such as unlink/rename,
    /// only the parent is followed because the final entry isn't dereferenced.
    pub(super) fn confined_path(
        &self,
        path: &Path,
        follow_final: bool,
        allow_missing_final: bool,
    ) -> Result<PathBuf, DosHostError> {
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        let canonical_parent = self
            .root
            .canonicalize(Self::cap_path(parent))
            .map_err(os_error)?;
        Self::verify_relative_canonical_path(&canonical_parent)?;
        let Some(file_name) = path.file_name() else {
            return Ok(canonical_parent);
        };
        if !follow_final {
            return Ok(canonical_parent.join(file_name));
        }

        match self.root.symlink_metadata(path) {
            Err(error) if allow_missing_final && error.kind() == io::ErrorKind::NotFound => {
                Ok(canonical_parent.join(file_name))
            }
            Err(error) => Err(os_error(error)),
            Ok(_) => {
                let canonical = self
                    .root
                    .canonicalize(Self::cap_path(path))
                    .map_err(os_error)?;
                Self::verify_relative_canonical_path(&canonical)?;
                Ok(canonical)
            }
        }
    }

    fn verify_relative_canonical_path(path: &Path) -> Result<(), DosHostError> {
        for component in path.components() {
            match component {
                std::path::Component::Normal(_) | std::path::Component::CurDir => {}
                _ => return Err(invalid(DosErrorCode::AccessDenied)),
            }
        }
        Ok(())
    }
}

/// Device names are special in Win32 even when a suffix or trailing dot is
/// present. Reject these path components before they reach a filesystem API.
pub(crate) fn is_reserved_device_name(component: &str) -> bool {
    let trimmed = component.trim_end_matches([' ', '.']);
    let base = trimmed.split('.').next().unwrap_or("").to_ascii_uppercase();
    matches!(
        base.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        base.strip_prefix(prefix).is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    })
}
