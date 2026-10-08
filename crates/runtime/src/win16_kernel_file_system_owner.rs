//! Per-task DOS drive state and guest path normalization for KERNEL files.

use std::collections::BTreeMap;

use dos_kernel::DosError;
use guest_core::{OwnerId, Registers};
use text_codec::{CodePage, decode};
use win16_abi::MAX_WIN16_STRING_BYTES;

use super::{
    FileCdrCallbackState, Win16CanonicalPath, Win16GuestPath, Win16HostFileSystemCall,
    Win16HostFileSystemOperation, Win16HostFileSystemResult, Win16HostSearchId, Win16PathComponent,
    Win16PathComponentSource, Win16PathNamespace,
};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

#[derive(Clone, Debug, Eq, PartialEq)]
struct OwnerDirectories {
    current_drive: u8,
    /// Resolved identities are retained per drive. Guest names are translated
    /// only on the component tagged `GuestInput`; canonical cwd components are
    /// never reinterpreted as virtual DOS aliases.
    current_directories: BTreeMap<u8, Win16CanonicalPath>,
}

/// Runtime-side per-TDB directory state and WORD-to-host search identities.
#[derive(Clone, Debug, Default)]
pub struct Win16KernelFileSystemState {
    owners: BTreeMap<OwnerId, OwnerDirectories>,
    searches: BTreeMap<(OwnerId, u16), Win16HostSearchId>,
    next_search: BTreeMap<OwnerId, u16>,
    pub(super) file_cdr: FileCdrCallbackState,
}

impl Win16KernelFileSystemState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed the initial Win16 TDB from DOS host state before guest code runs.
    /// Runtime callers must do this at task startup, never lazily after a
    /// different task has activated its virtual current directory.
    pub fn seed_owner_from_host(
        &mut self,
        owner: OwnerId,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        if self.owners.contains_key(&owner) {
            return Ok(());
        }
        let drive = host.current_drive();
        if drive > 25 {
            return Err(invariant("DOS host returned an invalid current drive"));
        }
        let mut relative = [0_u8; 63];
        let length = host
            .directory_get_current(drive, &mut relative)
            .map_err(|error| crate::runtime_error(DosError::HostOperation(error)))?;
        if length > relative.len() {
            return Err(invariant(
                "DOS host current directory exceeded its output buffer",
            ));
        }
        let relative = host
            .guest_code_page()
            .decode(&relative[..length])
            .map_err(|_| invariant("DOS host returned an invalid OEM current directory"))?;
        let path = guest_path_from_relative(drive, &relative, Win16PathNamespace::DosVirtual)?;
        let Some(path) = host.normalize_win16_dos_directory(owner, &path)? else {
            return Err(invariant(
                "initial DOS current directory could not be normalized",
            ));
        };
        validate_canonical_path(&path)?;
        if path.drive != drive {
            return Err(invariant(
                "normalized initial DOS directory changed its drive",
            ));
        }
        self.seed_owner(owner, path)
    }

    /// Validate that task startup installed this TDB's independent DOS
    /// directory state before any file or directory service runs.
    pub fn ensure_owner(&self, owner: OwnerId) -> Result<(), RuntimeError> {
        if self.owners.contains_key(&owner) {
            Ok(())
        } else {
            Err(invariant(
                "Win16 task reached a file service before its DOS directory state was seeded",
            ))
        }
    }

    /// Seed or replace one owner only while wiring initial DOS state.
    pub fn seed_owner(
        &mut self,
        owner: OwnerId,
        current_directory: Win16CanonicalPath,
    ) -> Result<(), RuntimeError> {
        validate_canonical_path(&current_directory)?;
        let current_drive = current_directory.drive;
        let mut current_directories = BTreeMap::new();
        current_directories.insert(current_drive, current_directory);
        self.owners.insert(
            owner,
            OwnerDirectories {
                current_drive,
                current_directories,
            },
        );
        Ok(())
    }

    /// Seed another drive's existing DOS current directory for this task
    /// without selecting it as the task's default drive.
    pub fn seed_drive_directory(
        &mut self,
        owner: OwnerId,
        directory: Win16CanonicalPath,
    ) -> Result<(), RuntimeError> {
        validate_canonical_path(&directory)?;
        let drive = directory.drive;
        let state = self
            .owners
            .get_mut(&owner)
            .ok_or_else(|| invariant("DOS drive directory seed has no Win16 owner"))?;
        state.current_directories.insert(drive, directory);
        Ok(())
    }

    /// Called by the shared DOS adapter only after DOS accepts a directory
    /// change, or by public KERNEL SetCurrentDirectory after its Win32-style
    /// directory query succeeds. The path is the AH=47 form: relative to its
    /// drive root. DOS AH=3Bh passes `false` because it does not select the
    /// default drive; public KERNEL SetCurrentDirectory passes `true` because
    /// a drive-qualified path changes the task's default drive.
    pub fn record_dos_directory_change(
        &mut self,
        owner: OwnerId,
        directory: Win16CanonicalPath,
        change_default_drive: bool,
    ) -> Result<(), RuntimeError> {
        validate_canonical_path(&directory)?;
        let drive = directory.drive;
        let state = self
            .owners
            .get_mut(&owner)
            .ok_or_else(|| invariant("DOS directory change has no seeded Win16 owner"))?;
        state.current_directories.insert(drive, directory);
        if change_default_drive {
            state.current_drive = drive;
        }
        Ok(())
    }

    /// Called after a successful DOS default-drive selection. DOS directory
    /// changes on a different drive must not alter this value.
    pub fn record_dos_current_drive(
        &mut self,
        owner: OwnerId,
        drive: u8,
    ) -> Result<(), RuntimeError> {
        validate_drive(drive)?;
        let state = self
            .owners
            .get_mut(&owner)
            .ok_or_else(|| invariant("DOS drive selection has no seeded Win16 owner"))?;
        state.current_drive = drive;
        Ok(())
    }

    pub fn current_drive(&self, owner: OwnerId) -> Result<u8, RuntimeError> {
        self.owners
            .get(&owner)
            .map(|state| state.current_drive)
            .ok_or_else(|| invariant("Win16 file call has no seeded task directory state"))
    }

    /// Return a drive's directory only when DOS has supplied or successfully
    /// changed it for this task. Callers may query the mounted DOS host for an
    /// unseeded drive and then cache that result here.
    pub fn directory_for_drive(
        &self,
        owner: OwnerId,
        drive: u8,
    ) -> Result<Option<&Win16CanonicalPath>, RuntimeError> {
        validate_drive(drive)?;
        let state = self
            .owners
            .get(&owner)
            .ok_or_else(|| invariant("Win16 file call has no seeded task directory state"))?;
        Ok(state.current_directories.get(&drive))
    }

    pub fn current_directory_text(&self, owner: OwnerId) -> Result<String, RuntimeError> {
        let state = self
            .owners
            .get(&owner)
            .ok_or_else(|| invariant("Win16 file call has no seeded task directory state"))?;
        let directory = state
            .current_directories
            .get(&state.current_drive)
            .ok_or_else(|| invariant("Win16 current drive has no retained directory"))?;
        canonical_text(directory)
    }

    pub fn current_directory_canonical(
        &self,
        owner: OwnerId,
    ) -> Result<&Win16CanonicalPath, RuntimeError> {
        let state = self
            .owners
            .get(&owner)
            .ok_or_else(|| invariant("Win16 file call has no seeded task directory state"))?;
        state
            .current_directories
            .get(&state.current_drive)
            .ok_or_else(|| invariant("Win16 current drive has no retained directory"))
    }

    /// Convert an OEM DOS path into Unicode and retain the original input
    /// components separately from canonical cwd components.
    /// Relative paths use the named drive's TDB directory; root-relative paths
    /// use that drive's root. Wildcards are allowed only in a FindFirst leaf.
    pub fn resolve_guest_path(
        &self,
        owner: OwnerId,
        path: &[u8],
        code_page: CodePage,
        allow_leaf_wildcards: bool,
    ) -> Result<Win16GuestPath, RuntimeError> {
        validate_guest_path_bytes(path)?;
        let input = decode(path, code_page).map_err(|_| invalid_path())?;
        self.resolve_guest_path_text(owner, &input, allow_leaf_wildcards)
    }

    /// Normalize a Unicode path after decoding it with the API's own text
    /// codec. Raw guest strings are bounded before decoding; UTF-8 storage
    /// length is not a guest capacity. Keeping cwd and paths as Unicode avoids
    /// mixing DOS OEM bytes with public KERNEL ANSI bytes in owner state.
    pub fn resolve_guest_path_text(
        &self,
        owner: OwnerId,
        input: &str,
        allow_leaf_wildcards: bool,
    ) -> Result<Win16GuestPath, RuntimeError> {
        self.resolve_path_text_in_namespace(
            owner,
            input,
            allow_leaf_wildcards,
            Win16PathNamespace::DosVirtual,
        )
    }

    /// Public KERNEL AutoThunk path bytes are ANSI text using native Windows
    /// filename semantics, while classic OpenFile/_lopen callers stay on the
    /// DOS path service. The caller selects this typed namespace at dispatch.
    pub fn resolve_kernel_path_text(
        &self,
        owner: OwnerId,
        input: &str,
        allow_leaf_wildcards: bool,
    ) -> Result<Win16GuestPath, RuntimeError> {
        self.resolve_path_text_in_namespace(
            owner,
            input,
            allow_leaf_wildcards,
            Win16PathNamespace::NativeWindows,
        )
    }

    fn resolve_path_text_in_namespace(
        &self,
        owner: OwnerId,
        input: &str,
        allow_leaf_wildcards: bool,
        namespace: Win16PathNamespace,
    ) -> Result<Win16GuestPath, RuntimeError> {
        let state = self
            .owners
            .get(&owner)
            .ok_or_else(|| invariant("Win16 file call has no seeded task directory state"))?;
        if input.is_empty() || input.contains('\0') {
            return Err(invalid_path());
        }
        if input.starts_with("\\\\") || input.starts_with("//") {
            return Err(invalid_path());
        }

        let (drive, remainder, rooted) = match drive_prefix(input) {
            Some((drive, remainder)) => {
                let rooted = remainder.starts_with(['\\', '/']);
                (drive, remainder, rooted)
            }
            None => (state.current_drive, input, input.starts_with(['\\', '/'])),
        };
        validate_drive(drive)?;

        let mut components = if rooted {
            Vec::new()
        } else {
            let base = state
                .current_directories
                .get(&drive)
                .ok_or_else(|| invariant("selected DOS drive has no retained directory"))?;
            validate_canonical_path(base)?;
            if base.drive != drive {
                return Err(invariant(
                    "stored canonical directory has a different drive",
                ));
            }
            base.components
                .iter()
                .map(|text| Win16PathComponent {
                    text: text.clone(),
                    source: Win16PathComponentSource::CanonicalCwd,
                })
                .collect()
        };
        normalized_append(&mut components, remainder, allow_leaf_wildcards, namespace)?;
        Ok(Win16GuestPath {
            drive,
            namespace,
            components,
        })
    }

    /// Refuse to remove a directory that is the current directory, or an
    /// ancestor of one, for any live TDB drive state.
    pub fn would_remove_current_directory(&self, path: &Win16CanonicalPath) -> bool {
        self.owners.values().any(|owner| {
            owner
                .current_directories
                .values()
                .any(|current| is_same_or_descendant(current, path))
        })
    }

    /// Rename updates cached virtual working directories by normalized path
    /// prefix, matching DOS host rename behavior without copying a shared
    /// host's last-active cwd into another owner.
    pub fn record_successful_rename(
        &mut self,
        source: &Win16CanonicalPath,
        destination: &Win16CanonicalPath,
    ) -> Result<(), RuntimeError> {
        validate_canonical_path(source)?;
        validate_canonical_path(destination)?;
        if source.drive != destination.drive {
            return Err(invariant("successful DOS rename crossed drive namespaces"));
        }
        for owner in self.owners.values_mut() {
            for directory in owner.current_directories.values_mut() {
                if let Some(updated) = replace_directory_prefix(directory, source, destination) {
                    *directory = updated;
                }
            }
        }
        Ok(())
    }

    pub fn register_file_cdr(&mut self, owner: OwnerId, procedure: u32) -> bool {
        self.file_cdr.register(owner, procedure)
    }

    pub fn file_cdr_query(&self) -> u32 {
        self.file_cdr.query()
    }

    /// Guest HFILE is a WORD scoped to OwnerId; it never reuses a native ID.
    pub(super) fn allocate_guest_search(
        &mut self,
        owner: OwnerId,
        host: Win16HostSearchId,
    ) -> Option<u16> {
        let next = self.next_search.entry(owner).or_insert(1);
        let start = *next;
        loop {
            let candidate = *next;
            *next = if candidate >= u16::MAX - 1 {
                1
            } else {
                candidate + 1
            };
            if candidate != 0
                && candidate != u16::MAX
                && !self.searches.contains_key(&(owner, candidate))
            {
                self.searches.insert((owner, candidate), host);
                return Some(candidate);
            }
            if *next == start {
                return None;
            }
        }
    }

    pub(super) fn host_search(&self, owner: OwnerId, guest: u16) -> Option<Win16HostSearchId> {
        self.searches.get(&(owner, guest)).copied()
    }

    pub(super) fn remove_guest_search(&mut self, owner: OwnerId, guest: u16) {
        self.searches.remove(&(owner, guest));
    }

    pub fn code_references(&self) -> Vec<u32> {
        self.file_cdr.code_references().collect()
    }

    pub fn has_active_callback(&self) -> bool {
        self.file_cdr.has_active_invocations()
    }

    pub fn retire_task(
        &mut self,
        owner: OwnerId,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let result = host.win16_file_system(Win16HostFileSystemCall {
            owner,
            ansi_code_page: host.win16_ansi_code_page(),
            operation: Win16HostFileSystemOperation::RetireTask,
        })?;
        if result != Win16HostFileSystemResult::TaskRetired {
            return Err(invariant(
                "host file-system retirement returned the wrong result",
            ));
        }
        self.owners.remove(&owner);
        self.next_search.remove(&owner);
        self.searches
            .retain(|(search_owner, _), _| *search_owner != owner);
        self.file_cdr.retire_task(owner);
        Ok(())
    }
}

pub(super) fn drive_prefix(path: &str) -> Option<(u8, &str)> {
    let bytes = path.as_bytes();
    if bytes.len() < 2 || bytes[1] != b':' || !bytes[0].is_ascii_alphabetic() {
        return None;
    }
    Some((bytes[0].to_ascii_uppercase() - b'A', &path[2..]))
}

fn normalized_append(
    components: &mut Vec<Win16PathComponent>,
    path: &str,
    allow_leaf_wildcards: bool,
    namespace: Win16PathNamespace,
) -> Result<(), RuntimeError> {
    let items: Vec<_> = path.split(['\\', '/']).collect();
    let last_nonempty = items.iter().rposition(|component| !component.is_empty());
    for (index, component) in items.iter().enumerate() {
        if component.is_empty() || *component == "." {
            continue;
        }
        if *component == ".." {
            components.pop();
            continue;
        }
        let leaf_wildcard = allow_leaf_wildcards && Some(index) == last_nonempty;
        let invalid_guest_dos_component = namespace == Win16PathNamespace::DosVirtual
            && (component.chars().any(|character| {
                matches!(character, ':' | '<' | '>' | '"' | '|')
                    || (!leaf_wildcard && matches!(character, '*' | '?'))
            }) || component.ends_with(' ')
                || component.ends_with('.'));
        if invalid_guest_dos_component {
            return Err(invalid_path());
        }
        components.push(Win16PathComponent {
            text: (*component).to_owned(),
            source: Win16PathComponentSource::GuestInput,
        });
    }
    Ok(())
}

pub(super) fn guest_path_from_relative(
    drive: u8,
    relative: &str,
    namespace: Win16PathNamespace,
) -> Result<Win16GuestPath, RuntimeError> {
    validate_drive(drive)?;
    if relative.starts_with(['\\', '/']) || drive_prefix(relative).is_some() {
        return Err(invariant(
            "DOS host returned a non-relative current directory",
        ));
    }
    let mut components = Vec::new();
    normalized_append(
        &mut components,
        relative,
        false,
        Win16PathNamespace::DosVirtual,
    )?;
    Ok(Win16GuestPath {
        drive,
        namespace,
        components,
    })
}

fn canonical_text(path: &Win16CanonicalPath) -> Result<String, RuntimeError> {
    validate_canonical_path(path)?;
    let mut text = String::from(char::from(b'A' + path.drive));
    text.push_str(":\\");
    text.push_str(&path.components.join("\\"));
    Ok(text)
}

fn validate_canonical_path(path: &Win16CanonicalPath) -> Result<(), RuntimeError> {
    if path.drive > 25 {
        return Err(invariant("canonical Win16 path has an invalid drive"));
    }
    if path.components.iter().any(|component| {
        component.is_empty()
            || matches!(component.as_str(), "." | "..")
            || component.contains(['\\', '/', ':', '\0'])
    }) {
        return Err(invariant("canonical Win16 path has a malformed component"));
    }
    Ok(())
}

pub(super) fn validate_drive(drive: u8) -> Result<(), RuntimeError> {
    if drive > 25 {
        return Err(invalid_path());
    }
    Ok(())
}

pub(super) fn validate_guest_path_bytes(path: &[u8]) -> Result<(), RuntimeError> {
    // Bound the original ANSI/OEM FAR string before decoding it. The old
    // 32-KiB check measured an internal UTF-8 String, not the Win16 ABI; the
    // selector bound and this 64-KiB NUL-terminated string limit are the
    // guest limits. Leave longer UTF-16 host-path policy to the filesystem API.
    if path.len() >= MAX_WIN16_STRING_BYTES {
        return Err(invalid_path());
    }
    Ok(())
}

fn is_same_or_descendant(current: &Win16CanonicalPath, directory: &Win16CanonicalPath) -> bool {
    current.drive == directory.drive
        && directory.components.len() <= current.components.len()
        && directory
            .components
            .iter()
            .zip(&current.components)
            .all(|(directory, current)| directory == current)
}

fn replace_directory_prefix(
    current: &Win16CanonicalPath,
    source: &Win16CanonicalPath,
    destination: &Win16CanonicalPath,
) -> Option<Win16CanonicalPath> {
    if current.drive != source.drive
        || source.drive != destination.drive
        || source.components.len() > current.components.len()
        || !source
            .components
            .iter()
            .zip(&current.components)
            .all(|(source, current)| source == current)
    {
        return None;
    }
    let mut components = destination.components.clone();
    components.extend(
        current
            .components
            .iter()
            .skip(source.components.len())
            .cloned(),
    );
    Some(Win16CanonicalPath {
        drive: destination.drive,
        components,
    })
}

pub(super) fn guest_api_failure(error: &RuntimeError) -> bool {
    matches!(error.kind(), Kind::GuestFault | Kind::InvalidInput)
}

pub(super) fn dos_failure(regs: &mut Registers, error_code: u16) {
    regs.set_ax(error_code);
    regs.set_carry(true);
}

pub(super) fn invalid_path() -> RuntimeError {
    RuntimeError::new(Kind::InvalidInput, "Win16 KERNEL file path is invalid")
}

pub(super) fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
