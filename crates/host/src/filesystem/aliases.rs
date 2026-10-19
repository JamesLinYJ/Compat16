use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use cap_std::fs::DirEntry;
use dos_kernel::{DosErrorCode, DosHostError};
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED,
    ERROR_PATH_NOT_FOUND, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_CASE_SENSITIVE_INFO, FILE_ID_BOTH_DIR_INFO, FileCaseSensitiveInfo,
    FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo, FindClose, FindFirstFileW,
    GetFileInformationByHandleEx, WIN32_FIND_DATAW,
};

use crate::windows::{invalid, os_error};

use super::Filesystem;

mod short_name;
pub(super) use short_name::canonical_83;

#[cfg(test)]
mod tests;

#[derive(Clone, Default)]
pub(super) struct AliasTable {
    /// Uppercase DOS alias to its actual on-disk component.
    pub(super) by_alias: BTreeMap<String, OsString>,
    /// Exact on-disk component to the stable uppercase DOS alias.
    pub(super) by_real_name: BTreeMap<OsString, String>,
    case_sensitivity: DirectoryCaseSensitivity,
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub(super) enum DirectoryCaseSensitivity {
    Insensitive,
    Sensitive,
    #[default]
    Unknown,
}

impl AliasTable {
    /// Resolve a long filename according to Windows ordinal equality.
    /// Exact spelling and DOS aliases are checked by the caller first. In an
    /// unknown directory, multiple ordinal candidates remain ambiguous.
    pub(super) fn lookup_real_name(
        &self,
        requested: &OsStr,
    ) -> Result<RealNameLookup, DosHostError> {
        if matches!(self.case_sensitivity, DirectoryCaseSensitivity::Sensitive) {
            return Ok(RealNameLookup::Resolved(None));
        }

        let mut matched = None;
        for actual in self.by_real_name.keys() {
            if super::environment::windows_component_eq(actual, requested) {
                if matched.is_some() {
                    return Err(invalid(DosErrorCode::InvalidData));
                }
                matched = Some(actual.clone());
            }
        }
        match self.case_sensitivity {
            DirectoryCaseSensitivity::Insensitive => Ok(RealNameLookup::Resolved(matched)),
            DirectoryCaseSensitivity::Sensitive => unreachable!("handled above"),
            DirectoryCaseSensitivity::Unknown => Ok(RealNameLookup::Native {
                ordinal_candidate_exists: matched.is_some(),
            }),
        }
    }
}

pub(super) enum RealNameLookup {
    Resolved(Option<OsString>),
    Native { ordinal_candidate_exists: bool },
}

pub(super) struct DirectoryEntry {
    pub(super) name: OsString,
    pub(super) entry: DirEntry,
}

impl Filesystem {
    /// Resolve a native Win32 path component to its on-disk long spelling
    /// without consulting the DOS virtual alias table. DOS short aliases are
    /// considered only through the OS-provided alternate name.
    pub(super) fn resolve_native_path_component(
        &mut self,
        directory: &Path,
        requested: &OsStr,
    ) -> Result<Option<OsString>, DosHostError> {
        let lookup = {
            let table = self.aliases_for(directory)?;
            match table.by_real_name.get_key_value(requested) {
                Some((actual, _)) => RealNameLookup::Resolved(Some(actual.clone())),
                None => table.lookup_real_name(requested)?,
            }
        };
        match lookup {
            RealNameLookup::Resolved(Some(actual)) => Ok(Some(actual)),
            RealNameLookup::Native {
                ordinal_candidate_exists: true,
            } => self.lookup_unknown_case_real_name(directory, requested, true),
            RealNameLookup::Resolved(None)
            | RealNameLookup::Native {
                ordinal_candidate_exists: false,
            } => self.lookup_native_short_name(directory, requested),
        }
    }

    fn lookup_native_short_name(
        &self,
        directory: &Path,
        requested: &OsStr,
    ) -> Result<Option<OsString>, DosHostError> {
        let directory = self.confined_path(directory, true, false)?;
        let native_path = self
            .canonical_root
            .join(Self::cap_path(&directory))
            .join(requested);
        let wide_path: Vec<u16> = native_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut data = WIN32_FIND_DATAW::default();
        // SAFETY: the path names one literal child of a confined directory and
        // the output record is writable for this synchronous lookup.
        let handle = unsafe { FindFirstFileW(wide_path.as_ptr(), &mut data) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            let error = io::Error::last_os_error();
            let code = error
                .raw_os_error()
                .and_then(|code| u32::try_from(code).ok());
            if code == Some(ERROR_FILE_NOT_FOUND) || code == Some(ERROR_PATH_NOT_FOUND) {
                return Ok(None);
            }
            return Err(os_error(error));
        }

        let result = (|| {
            let Some(file_name_end) = data.cFileName.iter().position(|unit| *unit == 0) else {
                return Err(invalid(DosErrorCode::InvalidData));
            };
            let Some(alternate_end) = data.cAlternateFileName.iter().position(|unit| *unit == 0)
            else {
                return Err(invalid(DosErrorCode::InvalidData));
            };
            if alternate_end == 0 {
                return Err(invalid(DosErrorCode::InvalidData));
            }
            let alternate = OsString::from_wide(&data.cAlternateFileName[..alternate_end]);
            if !super::environment::windows_component_eq(&alternate, requested) {
                return Err(invalid(DosErrorCode::InvalidData));
            }
            Ok(Some(OsString::from_wide(&data.cFileName[..file_name_end])))
        })();
        // SAFETY: this is the fresh FindFirst handle returned above.
        if unsafe { FindClose(handle) } == 0 {
            return Err(os_error(io::Error::last_os_error()));
        }
        result
    }

    /// Resolve a name in a directory whose case-sensitivity query is
    /// unsupported. The native lookup returns the entry spelling selected by
    /// Win32 without opening or following the final reparse point.
    pub(super) fn lookup_unknown_case_real_name(
        &self,
        directory: &Path,
        requested: &OsStr,
        ordinal_candidate_exists: bool,
    ) -> Result<Option<OsString>, DosHostError> {
        let directory = self.confined_path(directory, true, false)?;
        let native_path = self
            .canonical_root
            .join(Self::cap_path(&directory))
            .join(requested);
        let wide_path: Vec<u16> = native_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut data = WIN32_FIND_DATAW::default();
        // SAFETY: the path and result structure remain live for the call. The
        // path names one literal child of a canonical, confined parent; it has
        // no wildcard characters because the caller validated the component.
        let handle = unsafe { FindFirstFileW(wide_path.as_ptr(), &mut data) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            let error = io::Error::last_os_error();
            let code = error
                .raw_os_error()
                .and_then(|code| u32::try_from(code).ok());
            if code == Some(ERROR_FILE_NOT_FOUND) || code == Some(ERROR_PATH_NOT_FOUND) {
                if ordinal_candidate_exists {
                    return Err(invalid(DosErrorCode::InvalidData));
                }
                return Ok(None);
            }
            return Err(os_error(error));
        }

        let Some(end) = data.cFileName.iter().position(|unit| *unit == 0) else {
            // SAFETY: this is the fresh search handle returned above.
            let closed = unsafe { FindClose(handle) } != 0;
            if !closed {
                return Err(os_error(io::Error::last_os_error()));
            }
            return Err(invalid(DosErrorCode::InvalidData));
        };
        let actual = OsString::from_wide(&data.cFileName[..end]);
        // SAFETY: this is the fresh search handle returned above.
        if unsafe { FindClose(handle) } == 0 {
            return Err(os_error(io::Error::last_os_error()));
        }
        if !super::environment::windows_component_eq(&actual, requested) {
            return Err(invalid(DosErrorCode::InvalidData));
        }
        Ok(Some(actual))
    }

    pub(super) fn read_names(
        &self,
        directory: &Path,
    ) -> Result<(Vec<OsString>, DirectoryCaseSensitivity), DosHostError> {
        let directory = self.confined_path(directory, true, false)?;
        let case_sensitivity = self.directory_case_sensitivity(&directory)?;
        let mut names = Vec::new();
        for item in self
            .root
            .read_dir(Self::cap_path(&directory))
            .map_err(os_error)?
        {
            let name = item.map_err(os_error)?.file_name();
            // Never expose a host entry through an alias that would later be
            // interpreted by Win32 as a device rather than a directory child.
            if !name.to_str().is_some_and(super::is_reserved_device_name) {
                names.push(name);
            }
        }
        Ok((
            sort_directory_names(names, OsString::as_os_str),
            case_sensitivity,
        ))
    }

    /// Read one confined directory snapshot while retaining each native entry
    /// for metadata retrieval after aliases have been refreshed from its names.
    pub(super) fn read_directory_entries(
        &self,
        directory: &Path,
    ) -> Result<(Vec<DirectoryEntry>, DirectoryCaseSensitivity), DosHostError> {
        let directory = self.confined_path(directory, true, false)?;
        let case_sensitivity = self.directory_case_sensitivity(&directory)?;
        let mut entries = Vec::new();
        for item in self
            .root
            .read_dir(Self::cap_path(&directory))
            .map_err(os_error)?
        {
            let entry = item.map_err(os_error)?;
            let name = entry.file_name();
            // Keep the search snapshot in the same DOS-visible namespace as
            // the aliases built from it.
            if !name.to_str().is_some_and(super::is_reserved_device_name) {
                entries.push(DirectoryEntry { name, entry });
            }
        }
        Ok((
            sort_directory_names(entries, |entry| entry.name.as_os_str()),
            case_sensitivity,
        ))
    }

    fn directory_case_sensitivity(
        &self,
        directory: &Path,
    ) -> Result<DirectoryCaseSensitivity, DosHostError> {
        let native_directory = self
            .root
            .open_dir(Self::cap_path(directory))
            .map_err(os_error)?
            .into_std_file();
        let mut case_sensitive_info = FILE_CASE_SENSITIVE_INFO::default();
        // SAFETY: the handle names this already-confined open directory, and
        // the output points to the complete fixed-size information structure.
        let case_sensitivity = if unsafe {
            GetFileInformationByHandleEx(
                native_directory.as_raw_handle() as HANDLE,
                FileCaseSensitiveInfo,
                (&mut case_sensitive_info as *mut FILE_CASE_SENSITIVE_INFO).cast(),
                size_of::<FILE_CASE_SENSITIVE_INFO>() as u32,
            )
        } != 0
        {
            if case_sensitive_info.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0 {
                DirectoryCaseSensitivity::Sensitive
            } else {
                DirectoryCaseSensitivity::Insensitive
            }
        } else {
            let error = io::Error::last_os_error();
            match error
                .raw_os_error()
                .and_then(|code| u32::try_from(code).ok())
            {
                // Older Windows versions and some filesystems do not expose
                // this property. Do not infer case-insensitivity: the resolver
                // uses native lookup and rejects multiple ordinal candidates.
                Some(ERROR_INVALID_FUNCTION)
                | Some(ERROR_INVALID_PARAMETER)
                | Some(ERROR_NOT_SUPPORTED) => DirectoryCaseSensitivity::Unknown,
                _ => return Err(os_error(error)),
            }
        };
        drop(native_directory);
        Ok(case_sensitivity)
    }

    pub(super) fn aliases_for(&mut self, directory: &Path) -> Result<&AliasTable, DosHostError> {
        // Refresh contents while carrying forward assignments for entries
        // that remain. This makes external additions visible without changing
        // active aliases already returned to the guest.
        let (names, case_sensitivity) = self.read_names(directory)?;
        self.refresh_aliases_for_names(directory, names, case_sensitivity)?;
        Ok(self
            .aliases
            .get(directory)
            .expect("alias table was inserted"))
    }

    pub(super) fn refresh_aliases_for_names(
        &mut self,
        directory: &Path,
        names: Vec<OsString>,
        case_sensitivity: DirectoryCaseSensitivity,
    ) -> Result<(), DosHostError> {
        let native_short_names = self.native_short_names(directory);
        let previous = self.aliases.remove(directory).unwrap_or_default();
        let table = make_alias_table(names, previous, native_short_names, case_sensitivity, self.guest_code_page)?;
        self.aliases.insert(directory.to_path_buf(), table);
        Ok(())
    }

    /// Ask the already capability-opened directory for its native 8.3 aliases.
    /// If a filesystem doesn't expose them, the virtual deterministic aliases
    /// below remain the fallback.
    fn native_short_names(&self, directory: &Path) -> BTreeMap<OsString, String> {
        let Ok(directory) = self.confined_path(directory, true, false) else {
            return BTreeMap::new();
        };
        let Ok(directory) = self.root.open_dir(Self::cap_path(&directory)) else {
            return BTreeMap::new();
        };
        let directory = directory.into_std_file();
        let raw = directory.as_raw_handle() as HANDLE;
        // 32 KiB is ample for many records and always enough for at least one
        // maximum-length Windows filename record.
        let mut buffer = vec![0usize; 4096];
        let buffer_len = buffer.len() * size_of::<usize>();
        let Ok(buffer_len_u32) = u32::try_from(buffer_len) else {
            return BTreeMap::new();
        };
        let mut class = FileIdBothDirectoryRestartInfo;
        let mut result = BTreeMap::new();
        loop {
            // SAFETY: `raw` is an open directory handle obtained from cap-std;
            // the aligned buffer is writable and its exact byte length is given.
            if unsafe {
                GetFileInformationByHandleEx(raw, class, buffer.as_mut_ptr().cast(), buffer_len_u32)
            } == 0
            {
                // ERROR_NO_MORE_FILES means normal exhaustion. Other failures
                // make this optional source unavailable, so use virtual names.
                break;
            }
            class = FileIdBothDirectoryInfo;
            let mut offset = 0usize;
            loop {
                let header_size = size_of::<FILE_ID_BOTH_DIR_INFO>();
                if buffer_len.saturating_sub(offset) < header_size {
                    return result;
                }
                // SAFETY: The previous check ensures that a complete fixed
                // record lies within the initialized OS result buffer.
                let entry = unsafe {
                    &*buffer
                        .as_ptr()
                        .cast::<u8>()
                        .add(offset)
                        .cast::<FILE_ID_BOTH_DIR_INFO>()
                };
                let short_len = usize::try_from(entry.ShortNameLength).unwrap_or(usize::MAX);
                let file_len = entry.FileNameLength as usize;
                let name_offset = offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
                let next = entry.NextEntryOffset as usize;
                if next != 0
                    && (next < name_offset
                        || next % size_of::<u64>() != 0
                        || next > buffer_len - offset)
                {
                    return result;
                }
                let record_name_capacity = if next == 0 {
                    buffer_len.saturating_sub(offset + name_offset)
                } else {
                    next - name_offset
                };
                if short_len > std::mem::size_of_val(&entry.ShortName)
                    || short_len % size_of::<u16>() != 0
                    || file_len % size_of::<u16>() != 0
                    || file_len > record_name_capacity
                {
                    return result;
                }
                if short_len != 0 {
                    let short_units = &entry.ShortName[..short_len / size_of::<u16>()];
                    let short_name = OsString::from_wide(short_units);
                    if let Some(alias) = canonical_83(&short_name, self.guest_code_page) {
                        let file_units = unsafe {
                            std::slice::from_raw_parts(
                                std::ptr::addr_of!(entry.FileName).cast::<u16>(),
                                file_len / size_of::<u16>(),
                            )
                        };
                        let file_name = OsString::from_wide(file_units);
                        if file_name != OsString::from(".") && file_name != OsString::from("..") {
                            result.insert(file_name, alias);
                        }
                    }
                }

                if next == 0 {
                    break;
                }
                offset += next;
            }
        }
        result
    }
}

fn sort_directory_names<T, F>(items: Vec<T>, name: F) -> Vec<T>
where
    F: for<'a> Fn(&'a T) -> &'a OsStr,
{
    let mut keyed: Vec<_> = items
        .into_iter()
        .map(|item| {
            let sort_key = name(&item).to_string_lossy().to_ascii_lowercase();
            (sort_key, item)
        })
        .collect();
    keyed.sort_by(|(left_key, left), (right_key, right)| {
        left_key
            .cmp(right_key)
            .then_with(|| name(left).cmp(name(right)))
    });
    keyed.into_iter().map(|(_, item)| item).collect()
}

fn make_alias_table(
    names: Vec<OsString>,
    previous: AliasTable,
    native_short_names: BTreeMap<OsString, String>,
    case_sensitivity: DirectoryCaseSensitivity,
    page: text_codec::CodePage,
) -> Result<AliasTable, DosHostError> {
    let mut table = AliasTable {
        case_sensitivity,
        ..AliasTable::default()
    };

    // Keep every still-active mapping first. A newly-created short filename
    // can't steal an alias previously emitted for a long filename.
    for name in &names {
        if let Some(alias) = previous.by_real_name.get(name) {
            if !table.by_alias.contains_key(alias) {
                table.by_alias.insert(alias.clone(), name.clone());
                table.by_real_name.insert(name.clone(), alias.clone());
            }
        }
    }

    // A name that already fits the guest OEM 8.3 namespace needs no alias.
    // Native short names may use another OEM page (or ASCII substitutions),
    // so preferring them here would hide legal names from FCB patterns.
    for name in &names {
        if table.by_real_name.contains_key(name) {
            continue;
        }
        if let Some(alias) = canonical_83(name, page) {
            if !table.by_alias.contains_key(&alias) {
                table.by_alias.insert(alias.clone(), name.clone());
                table.by_real_name.insert(name.clone(), alias);
            }
        }
    }

    // Prefer the filesystem's own alias for remaining long names when legal
    // and unclaimed. Existing assignments above still retain their identity.
    for name in &names {
        if table.by_real_name.contains_key(name) {
            continue;
        }
        if let Some(alias) = native_short_names.get(name) {
            if !table.by_alias.contains_key(alias) {
                table.by_alias.insert(alias.clone(), name.clone());
                table.by_real_name.insert(name.clone(), alias.clone());
            }
        }
    }

    // Allocate deterministic, collision-free 8.3 names for all remaining
    // entries, including names colliding with a previous or real short name.
    for name in &names {
        if !table.by_real_name.contains_key(name) {
            allocate_alias(name, &mut table)?;
        }
    }

    Ok(table)
}

// FILE_CS_FLAG_CASE_SENSITIVE_DIR from FILE_CASE_SENSITIVE_INFO.
const FILE_CS_FLAG_CASE_SENSITIVE_DIR: u32 = 0x0000_0001;

fn allocate_alias(name: &OsString, table: &mut AliasTable) -> Result<(), DosHostError> {
    let (stem, extension) = alias_parts(name);
    // Six digits plus '~' and one stem character is the largest valid base.
    // Never emit a malformed alias or silently skip an entry on exhaustion.
    for serial in 1..=999_999u32 {
        let digits = serial.to_string();
        let prefix_len = 8usize - 1 - digits.len();
        let prefix: String = stem.chars().take(prefix_len).collect();
        let mut alias = format!("{prefix}~{digits}");
        if !extension.is_empty() {
            alias.push('.');
            alias.push_str(&extension);
        }
        if !table.by_alias.contains_key(&alias) {
            table.by_alias.insert(alias.clone(), name.clone());
            table.by_real_name.insert(name.clone(), alias);
            return Ok(());
        }
    }
    Err(invalid(DosErrorCode::InvalidData))
}

fn allowed_short_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"$%'-_@~`!(){}^#&".contains(&byte)
}

fn alias_parts(name: &OsString) -> (String, String) {
    let text = name.to_string_lossy();
    let (stem, extension) = match text.rsplit_once('.') {
        Some((stem, extension)) => (stem, extension),
        None => (text.as_ref(), ""),
    };
    let clean = |part: &str| -> String {
        part.chars()
            .filter_map(|character| {
                if character.is_ascii() && allowed_short_byte(character as u8) {
                    Some(character.to_ascii_uppercase())
                } else {
                    None
                }
            })
            .collect()
    };
    let stem = clean(stem);
    let extension: String = clean(extension).chars().take(3).collect();
    (
        if stem.is_empty() { "FILE".into() } else { stem },
        extension,
    )
}
