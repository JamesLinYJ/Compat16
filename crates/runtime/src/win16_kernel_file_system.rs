//! Owner-scoped Windows 3.1 KERNEL file and directory services.

use guest_core::{OwnerId, Registers, memory::Memory};
use win16_abi::{Access, Win16KernelFileSystemRequest};

use super::{
    Win16State,
    guest_ranges::{GuestOutputRange, commit_guest_writes},
};
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};
use dos_kernel::{
    DosAction, DosCallAddressSpace, DosError, DosErrorCode, DosPointerAccess, DosSpanPolicy,
};
use owner::{dos_failure, guest_api_failure, invariant};

#[path = "win16_kernel_file_system_dto.rs"]
mod dto;
pub use dto::{
    WIN16_FIND_DATA_BYTES, Win16CanonicalPath, Win16GuestPath, Win16HostDiskSpace,
    Win16HostFileSystemCall, Win16HostFileSystemOperation, Win16HostFileSystemPath,
    Win16HostFileSystemResult, Win16HostFindData, Win16HostFindFirst, Win16HostSearchId,
    Win16PathComponent, Win16PathComponentSource, Win16PathNamespace,
};
#[path = "win16_kernel_file_system_owner.rs"]
mod owner;
pub use owner::Win16KernelFileSystemState;
#[path = "win16_file_cdr_callback.rs"]
mod file_cdr;
pub(crate) use file_cdr::FileCdrCallbackState;
#[path = "win16_kernel_file_system_search.rs"]
mod search;

impl Win16State {
    /// Capture the initial DOS host drive and cwd before the Win16 task's
    /// first guest instruction. All later relative paths use retained owner
    /// state rather than whatever directory another task most recently used.
    pub(super) fn seed_initial_task_directory(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let owner = self.current_task_owner()?;
        self.kernel_file_system.seed_owner_from_host(owner, host)
    }

    /// Apply this task's drive-qualified DOS directory to the shared DOS host
    /// adapter before a DOS service resolves relative paths. The host call is
    /// virtual-only and never changes the process-wide native current dir.
    pub(super) fn activate_dos_directory_context(
        &mut self,
        host: &mut impl RuntimeHost,
    ) -> Result<(), RuntimeError> {
        let owner = self.current_task_owner()?;
        self.kernel_file_system.ensure_owner(owner)?;
        let path = self.kernel_file_system.current_directory_canonical(owner)?;
        host.activate_win16_dos_directory(owner, &path)
    }

    /// Intercept DOS drive and cwd services whose state must be scoped to the
    /// current TDB. Other DOS operations continue through DosKernel.
    pub(super) fn dispatch_dos_directory_service(
        &mut self,
        regs: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<Option<DosAction>, RuntimeError> {
        let service = regs.ah();
        if !matches!(service, 0x0e | 0x19 | 0x3b | 0x47) {
            return Ok(None);
        }
        let owner = self.current_task_owner()?;
        self.kernel_file_system.ensure_owner(owner)?;
        let action = match service {
            0x0e => {
                match host.select_drive(regs.dl()) {
                    Ok(()) => {
                        let count = host.logical_drive_count();
                        if count > 26 {
                            return Err(invariant("DOS host reported more than 26 drives"));
                        }
                        if self
                            .kernel_file_system
                            .directory_for_drive(owner, regs.dl())?
                            .is_none()
                        {
                            let mut relative = [0_u8; 63];
                            let length = match host.directory_get_current(regs.dl(), &mut relative)
                            {
                                Ok(length) if length <= relative.len() => length,
                                Ok(_) => {
                                    return Err(invariant(
                                        "DOS host current directory exceeded its output buffer",
                                    ));
                                }
                                Err(error) => {
                                    let error_code = error.code as u16;
                                    let primary =
                                        crate::runtime_error(DosError::HostOperation(error));
                                    if let Err(rollback) = host
                                        .select_drive(self.kernel_file_system.current_drive(owner)?)
                                    {
                                        return Err(primary.with_cleanup(
                                            "restore Win16 task drive after current-directory query failed",
                                            crate::runtime_error(DosError::HostOperation(rollback)),
                                        ));
                                    }
                                    dos_failure(regs, error_code);
                                    return Ok(Some(DosAction::Continue));
                                }
                            };
                            let relative = host
                                .guest_code_page()
                                .decode(&relative[..length])
                                .map_err(|_| {
                                    invariant("DOS host returned an invalid OEM current directory")
                                })?;
                            let Some(relative) =
                                normalize_drive_directory(owner, regs.dl(), &relative, host)?
                            else {
                                let primary = RuntimeError::new(
                                    Kind::InvalidInput,
                                    "DOS host current directory could not be normalized",
                                );
                                if let Err(rollback) =
                                    host.select_drive(self.kernel_file_system.current_drive(owner)?)
                                {
                                    return Err(primary.with_cleanup(
                                        "restore Win16 task drive after directory normalization failed",
                                        crate::runtime_error(DosError::HostOperation(rollback)),
                                    ));
                                }
                                dos_failure(regs, DosErrorCode::PathNotFound as u16);
                                return Ok(Some(DosAction::Continue));
                            };
                            self.kernel_file_system
                                .seed_drive_directory(owner, relative)?;
                        }
                        self.kernel_file_system
                            .record_dos_current_drive(owner, regs.dl())?;
                        regs.set_al(count);
                    }
                    Err(error) => dos_failure(regs, error.code as u16),
                }
                DosAction::Continue
            }
            0x19 => {
                regs.set_al(self.kernel_file_system.current_drive(owner)?);
                DosAction::Continue
            }
            0x3b => self.dos_change_current_directory(owner, regs, memory, host)?,
            0x47 => self.dos_get_current_directory(owner, regs, memory, host)?,
            _ => unreachable!("directory service set was checked above"),
        };
        Ok(Some(action))
    }

    /// DOS RMDIR's host guard only knows the adapter's currently activated
    /// cwd. Check every retained TDB drive state before it reaches DOS.
    pub(super) fn block_dos_remove_of_virtual_current_directory(
        &mut self,
        regs: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let owner = self.current_task_owner()?;
        let path = {
            let mut address_space = match self.dos_call_address_space(memory, owner) {
                Ok(address_space) => address_space,
                Err(error) => return Err(crate::runtime_error(error)),
            };
            let pointer = match address_space.resolve_caller_pointer(regs.ds, regs.dx()) {
                Ok(pointer) => pointer,
                Err(_) => return Ok(false),
            };
            match address_space.read_caller_terminated(pointer, 0, 66, DosSpanPolicy::Linear) {
                Ok(path) if path.len() <= 64 => path,
                Ok(_) | Err(DosError::MalformedGuestInput(_)) => return Ok(false),
                Err(error) => return Err(crate::runtime_error(error)),
            }
        };
        let resolved = match self.kernel_file_system.resolve_guest_path(
            owner,
            &path,
            host.guest_code_page(),
            false,
        ) {
            Ok(path) => path,
            Err(error) if guest_api_failure(&error) => return Ok(false),
            Err(error) => return Err(error),
        };
        let Some(path) = host.normalize_win16_dos_path(owner, &resolved)? else {
            return Ok(false);
        };
        if self
            .kernel_file_system
            .would_remove_current_directory(&path)
        {
            dos_failure(regs, DosErrorCode::CannotRemoveCurrentDirectory as u16);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(crate) fn execute_kernel_file_system(
        &mut self,
        request: Win16KernelFileSystemRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let owner = self.current_task_owner()?;
        self.kernel_file_system.ensure_owner(owner)?;
        match request {
            Win16KernelFileSystemRequest::FileCdr { procedure } => {
                self.execute_file_cdr(owner, procedure, memory)
            }
            Win16KernelFileSystemRequest::CreateDirectory {
                path,
                security_attributes,
            } => {
                // CreateDirectory's SECURITY_ATTRIBUTES is a Win16 pointer.
                // Until its structure and descriptor mapping are implemented,
                // do not claim success for a non-NULL request.
                if security_attributes != 0 {
                    return Ok(0);
                }
                self.with_resolved_path(owner, &path, false, host, |path| {
                    Win16HostFileSystemOperation::CreateDirectory { path }
                })
            }
            Win16KernelFileSystemRequest::RemoveDirectory { path } => {
                let resolved = match self.resolve_ansi_path(owner, &path, false, host) {
                    Ok(path) => path,
                    Err(error) if guest_api_failure(&error) => return Ok(0),
                    Err(error) => return Err(error),
                };
                let Some(path) = normalize_guest_path(owner, host, &resolved, false, true)? else {
                    return Ok(0);
                };
                if self
                    .kernel_file_system
                    .would_remove_current_directory(&path)
                {
                    return Ok(0);
                }
                self.file_system_boolean_path(
                    owner,
                    Win16HostFileSystemPath::Canonical(path),
                    host,
                    |path| Win16HostFileSystemOperation::RemoveDirectory { path },
                )
            }
            Win16KernelFileSystemRequest::DeleteFile { path } => {
                self.file_system_boolean(owner, &path, false, host, |path| {
                    Win16HostFileSystemOperation::DeleteFile { path }
                })
            }
            Win16KernelFileSystemRequest::GetCurrentDirectory { capacity, output } => {
                self.get_current_directory(owner, capacity, output, memory, host)
            }
            Win16KernelFileSystemRequest::SetCurrentDirectory { path } => {
                self.set_current_directory(owner, &path, host)
            }
            Win16KernelFileSystemRequest::FindFirstFile {
                search_file,
                find_data,
            } => self.find_first_file(owner, &search_file, find_data, memory, host),
            Win16KernelFileSystemRequest::FindNextFile {
                search_handle,
                find_data,
            } => self.find_next_file(owner, search_handle, find_data, memory, host),
            Win16KernelFileSystemRequest::FindClose { search_handle } => {
                self.find_close(owner, search_handle, host)
            }
            Win16KernelFileSystemRequest::GetFileAttributes { path } => {
                self.get_file_attributes(owner, &path, host)
            }
            Win16KernelFileSystemRequest::SetFileAttributes { path, attributes } => self
                .with_resolved_path(owner, &path, false, host, |path| {
                    Win16HostFileSystemOperation::SetFileAttributes { path, attributes }
                }),
            Win16KernelFileSystemRequest::GetDiskFreeSpace {
                root_path,
                sectors_per_cluster,
                bytes_per_sector,
                free_clusters,
                total_clusters,
            } => self.get_disk_free_space(
                owner,
                root_path.as_deref(),
                [
                    sectors_per_cluster,
                    bytes_per_sector,
                    free_clusters,
                    total_clusters,
                ],
                memory,
                host,
            ),
        }
    }

    fn execute_file_cdr(
        &mut self,
        owner: OwnerId,
        procedure: u32,
        memory: &Memory,
    ) -> Result<u32, RuntimeError> {
        if (procedure >> 16) as u16 == u16::MAX {
            return Ok(self.kernel_file_system.file_cdr_query());
        }
        if procedure != 0 {
            let pointer = self
                .selectors
                .pointer_from_far(procedure)
                .map_err(crate::runtime_error)?;
            self.selectors
                .translate(pointer, Access::Execute, 1, memory)
                .map_err(crate::runtime_error)?;
        }
        Ok(u32::from(
            self.kernel_file_system.register_file_cdr(owner, procedure),
        ))
    }

    fn get_current_directory(
        &mut self,
        owner: OwnerId,
        capacity: u32,
        output: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let path = self.kernel_file_system.current_directory_text(owner)?;
        let path = match host.encode_win16_ansi(&path) {
            Ok(path) => path,
            Err(error) if guest_api_failure(&error) => return Ok(0),
            Err(error) => return Err(error),
        };
        let required = path.len().checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 current-directory length overflow",
            )
        })?;
        let required = u32::try_from(required).map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 current-directory length exceeds DWORD",
            )
        })?;
        if capacity < required {
            return Ok(required);
        }
        let range = match self.capture_file_system_output(output, required as usize, memory) {
            Ok(range) => range,
            Err(error) if guest_api_failure(&error) => return Ok(0),
            Err(error) => return Err(error),
        };
        let mut bytes = path;
        bytes.push(0);
        commit_guest_writes(self, memory, vec![(range, bytes)])?;
        Ok(required - 1)
    }

    fn dos_change_current_directory(
        &mut self,
        owner: OwnerId,
        regs: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<DosAction, RuntimeError> {
        let path = {
            let mut address_space = self
                .dos_call_address_space(memory, owner)
                .map_err(crate::runtime_error)?;
            let pointer = address_space
                .resolve_caller_pointer(regs.ds, regs.dx())
                .map_err(crate::runtime_error)?;
            address_space.read_caller_terminated(pointer, 0, 66, DosSpanPolicy::Linear)
        };
        let path = match path {
            Ok(path) if path.len() <= 64 => path,
            Ok(_) | Err(DosError::MalformedGuestInput(_)) => {
                dos_failure(regs, DosErrorCode::PathNotFound as u16);
                return Ok(DosAction::Continue);
            }
            Err(error) => return Err(crate::runtime_error(error)),
        };

        let path = match host.guest_code_page().decode(&path) {
            Ok(path) => path,
            Err(_) => {
                dos_failure(regs, DosErrorCode::PathNotFound as u16);
                return Ok(DosAction::Continue);
            }
        };
        if self.change_current_directory(
            owner,
            &path,
            false,
            Win16PathNamespace::DosVirtual,
            host,
        )? {
            regs.set_carry(false);
        } else {
            dos_failure(regs, DosErrorCode::PathNotFound as u16);
        }
        Ok(DosAction::Continue)
    }

    fn dos_get_current_directory(
        &mut self,
        owner: OwnerId,
        regs: &mut Registers,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<DosAction, RuntimeError> {
        // DOS validates all 64 output bytes before consulting or seeding a
        // drive's cwd, matching the existing DOS service's preflight order.
        let pointer = {
            let mut address_space = self
                .dos_call_address_space(memory, owner)
                .map_err(crate::runtime_error)?;
            let pointer = address_space
                .resolve_caller_pointer(regs.ds, regs.si())
                .map_err(crate::runtime_error)?;
            address_space
                .validate_caller_range(
                    pointer,
                    0,
                    64,
                    DosPointerAccess::Write,
                    DosSpanPolicy::Linear,
                )
                .map_err(crate::runtime_error)?;
            pointer
        };
        let drive = match regs.dl() {
            0 => self.kernel_file_system.current_drive(owner)?,
            1..=26 => regs.dl() - 1,
            _ => {
                dos_failure(regs, DosErrorCode::UnknownUnit as u16);
                return Ok(DosAction::Continue);
            }
        };
        let directory = match self.kernel_file_system.directory_for_drive(owner, drive)? {
            Some(path) => path.clone(),
            None => {
                let mut path = [0_u8; 63];
                let count = match host.directory_get_current(drive, &mut path) {
                    Ok(count) if count <= path.len() => count,
                    Ok(_) => {
                        return Err(invariant(
                            "DOS host current directory exceeded its output buffer",
                        ));
                    }
                    Err(error) => {
                        dos_failure(regs, error.code as u16);
                        return Ok(DosAction::Continue);
                    }
                };
                let relative = match host.guest_code_page().decode(&path[..count]) {
                    Ok(path) => path,
                    Err(_) => {
                        dos_failure(regs, DosErrorCode::InvalidData as u16);
                        return Ok(DosAction::Continue);
                    }
                };
                let Some(directory) = normalize_drive_directory(owner, drive, &relative, host)?
                else {
                    dos_failure(regs, DosErrorCode::InvalidData as u16);
                    return Ok(DosAction::Continue);
                };
                self.kernel_file_system
                    .seed_drive_directory(owner, directory.clone())?;
                directory
            }
        };
        let relative = match host.win16_dos_current_directory(owner, &directory)? {
            Some(relative) => relative,
            None => {
                dos_failure(regs, DosErrorCode::InvalidData as u16);
                return Ok(DosAction::Continue);
            }
        };
        if relative.len() > 63 {
            dos_failure(regs, DosErrorCode::InvalidData as u16);
            return Ok(DosAction::Continue);
        }

        let mut terminated = relative;
        terminated.push(0);
        let mut address_space = self
            .dos_call_address_space(memory, owner)
            .map_err(crate::runtime_error)?;
        address_space
            .write_caller_range(pointer, 0, &terminated, DosSpanPolicy::Linear)
            .map_err(crate::runtime_error)?;
        // Match the DOS kernel's AH=47h success result. Win16 pathname
        // routines also rely on AL=0 when scanning the returned ASCIIZ path.
        regs.set_ax(0x0100);
        regs.set_carry(false);
        Ok(DosAction::Continue)
    }

    fn set_current_directory(
        &mut self,
        owner: OwnerId,
        path: &[u8],
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        if owner::validate_guest_path_bytes(path).is_err() {
            return Ok(0);
        }
        let path = match host.decode_win16_ansi(path) {
            Ok(path) => path,
            Err(error) if guest_api_failure(&error) => return Ok(0),
            Err(error) => return Err(error),
        };
        Ok(u32::from(self.change_current_directory(
            owner,
            &path,
            true,
            Win16PathNamespace::NativeWindows,
            host,
        )?))
    }

    fn change_current_directory(
        &mut self,
        owner: OwnerId,
        path: &str,
        change_default_drive: bool,
        namespace: Win16PathNamespace,
        host: &mut impl RuntimeHost,
    ) -> Result<bool, RuntimeError> {
        let resolved_result = match namespace {
            Win16PathNamespace::DosVirtual => self
                .kernel_file_system
                .resolve_guest_path_text(owner, path, false),
            Win16PathNamespace::NativeWindows => self
                .kernel_file_system
                .resolve_kernel_path_text(owner, path, false),
        };
        let resolved = match resolved_result {
            Ok(path) => path,
            Err(error) if guest_api_failure(&error) => return Ok(false),
            Err(error) => return Err(error),
        };
        let Some(absolute) = normalize_guest_path(owner, host, &resolved, true, false)? else {
            return Ok(false);
        };
        let result = host.win16_file_system(Win16HostFileSystemCall {
            owner,
            ansi_code_page: host.win16_ansi_code_page(),
            operation: Win16HostFileSystemOperation::QueryDirectory {
                path: Win16HostFileSystemPath::Canonical(absolute.clone()),
            },
        })?;
        let Win16HostFileSystemResult::Completed(exists) = result else {
            return Err(invariant("host directory query returned the wrong result"));
        };
        if !exists {
            return Ok(false);
        }
        if absolute.drive != resolved.drive {
            return Err(invariant("normalized directory changed its drive"));
        }
        self.kernel_file_system.record_dos_directory_change(
            owner,
            absolute,
            change_default_drive,
        )?;
        Ok(true)
    }

    fn file_system_boolean(
        &self,
        owner: OwnerId,
        path: &[u8],
        allow_wildcards: bool,
        host: &mut impl RuntimeHost,
        operation: impl FnOnce(Win16HostFileSystemPath) -> Win16HostFileSystemOperation,
    ) -> Result<u32, RuntimeError> {
        let resolved = match self.resolve_ansi_path(owner, path, allow_wildcards, host) {
            Ok(path) => path,
            Err(error) if guest_api_failure(&error) => return Ok(0),
            Err(error) => return Err(error),
        };
        self.file_system_boolean_resolved(owner, resolved, host, operation)
    }

    fn resolve_ansi_path(
        &self,
        owner: OwnerId,
        path: &[u8],
        allow_wildcards: bool,
        host: &impl RuntimeHost,
    ) -> Result<Win16GuestPath, RuntimeError> {
        owner::validate_guest_path_bytes(path)?;
        let text = host.decode_win16_ansi(path)?;
        self.kernel_file_system
            .resolve_kernel_path_text(owner, &text, allow_wildcards)
    }

    fn file_system_boolean_resolved(
        &self,
        owner: OwnerId,
        resolved: Win16GuestPath,
        host: &mut impl RuntimeHost,
        operation: impl FnOnce(Win16HostFileSystemPath) -> Win16HostFileSystemOperation,
    ) -> Result<u32, RuntimeError> {
        self.file_system_boolean_path(
            owner,
            Win16HostFileSystemPath::Guest(resolved),
            host,
            operation,
        )
    }

    fn file_system_boolean_path(
        &self,
        owner: OwnerId,
        path: Win16HostFileSystemPath,
        host: &mut impl RuntimeHost,
        operation: impl FnOnce(Win16HostFileSystemPath) -> Win16HostFileSystemOperation,
    ) -> Result<u32, RuntimeError> {
        let result = host.win16_file_system(Win16HostFileSystemCall {
            owner,
            ansi_code_page: host.win16_ansi_code_page(),
            operation: operation(path),
        })?;
        match result {
            Win16HostFileSystemResult::Completed(success) => Ok(u32::from(success)),
            _ => Err(invariant("host file operation returned the wrong result")),
        }
    }

    fn with_resolved_path(
        &self,
        owner: OwnerId,
        path: &[u8],
        allow_wildcards: bool,
        host: &mut impl RuntimeHost,
        operation: impl FnOnce(Win16HostFileSystemPath) -> Win16HostFileSystemOperation,
    ) -> Result<u32, RuntimeError> {
        self.file_system_boolean(owner, path, allow_wildcards, host, operation)
    }

    fn get_file_attributes(
        &self,
        owner: OwnerId,
        path: &[u8],
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let resolved = match self.resolve_ansi_path(owner, path, false, host) {
            Ok(path) => path,
            Err(error) if guest_api_failure(&error) => return Ok(u32::MAX),
            Err(error) => return Err(error),
        };
        let result = host.win16_file_system(Win16HostFileSystemCall {
            owner,
            ansi_code_page: host.win16_ansi_code_page(),
            operation: Win16HostFileSystemOperation::GetFileAttributes {
                path: Win16HostFileSystemPath::Guest(resolved),
            },
        })?;
        match result {
            Win16HostFileSystemResult::Attributes(Some(attributes)) => Ok(attributes),
            Win16HostFileSystemResult::Attributes(None) => Ok(u32::MAX),
            _ => Err(invariant("host attribute query returned the wrong result")),
        }
    }

    fn get_disk_free_space(
        &mut self,
        owner: OwnerId,
        root_path: Option<&[u8]>,
        outputs: [u32; 4],
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let mut ranges = Vec::new();
        ranges.try_reserve_exact(4).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve Win16 disk-space output ranges",
                error,
            )
        })?;
        for output in outputs {
            let range = match self.capture_file_system_output(output, 4, memory) {
                Ok(range) => range,
                Err(error) if guest_api_failure(&error) => return Ok(0),
                Err(error) => return Err(error),
            };
            ranges.push(range);
        }

        let ansi_code_page = host.win16_ansi_code_page();
        let path = match root_path {
            Some(path) => match self.resolve_ansi_path(owner, path, false, host) {
                Ok(path) => Win16HostFileSystemPath::Guest(path),
                Err(error) if guest_api_failure(&error) => return Ok(0),
                Err(error) => return Err(error),
            },
            None => Win16HostFileSystemPath::Canonical(
                self.kernel_file_system
                    .current_directory_canonical(owner)?
                    .clone(),
            ),
        };
        let result = host.win16_file_system(Win16HostFileSystemCall {
            owner,
            ansi_code_page,
            operation: Win16HostFileSystemOperation::GetDiskFreeSpace { path },
        })?;
        let space = match result {
            Win16HostFileSystemResult::DiskSpace(Some(space)) => space,
            Win16HostFileSystemResult::DiskSpace(None) => return Ok(0),
            _ => return Err(invariant("host disk-space query returned the wrong result")),
        };
        let values = [
            space.sectors_per_cluster,
            space.bytes_per_sector,
            space.free_clusters,
            space.total_clusters,
        ];
        let writes = ranges
            .into_iter()
            .zip(values)
            .map(|(range, value)| (range, value.to_le_bytes().to_vec()))
            .collect();
        commit_guest_writes(self, memory, writes)?;
        Ok(1)
    }

    /// KERNEL.274. The Windows 3.1 SDK does not publish this export. The
    /// result is the absolute `D:\` 8.3 spelling of an existing path, in the
    /// task ANSI code page. A missing path or a missing 8.3 alias returns 0.
    /// A short buffer is left untouched and the return includes the NUL when
    /// that size fits in a word.
    pub(super) fn short_path_name(
        &self,
        long_path: Option<Vec<u8>>,
        output: u32,
        capacity: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let Some(long_path) = long_path.filter(|bytes| !bytes.is_empty() && !bytes.contains(&0))
        else {
            return Ok(0);
        };
        let owner = self.current_task_owner()?;
        let text = match host.decode_win16_ansi(&long_path) {
            Ok(text) => text,
            Err(error) if guest_api_failure(&error) => return Ok(0),
            Err(error) => return Err(error),
        };
        let resolved = match self.kernel_file_system.resolve_kernel_path_text(owner, &text, false) {
            Ok(path) => path,
            Err(error) if guest_api_failure(&error) => return Ok(0),
            Err(error) => return Err(error),
        };
        let Some(canonical) = normalize_guest_path(owner, host, &resolved, true, false)? else {
            return Ok(0);
        };
        let result = host.win16_file_system(Win16HostFileSystemCall {
            owner,
            ansi_code_page: host.win16_ansi_code_page(),
            operation: Win16HostFileSystemOperation::ShortPath { path: canonical },
        })?;
        let Win16HostFileSystemResult::ShortPath(path) = result else {
            return Err(invariant("host short-path query returned the wrong result"));
        };
        let Some(path) = path else { return Ok(0); };
        if path.is_empty() || path.contains(&0) {
            return Err(invariant("host short path is not a plain ANSI path"));
        }
        let required = path.len().checked_add(1).ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted, "Win16 short-path length overflow"))?;
        let Ok(required_word) = u16::try_from(required) else { return Ok(0); };
        if usize::from(capacity) < required {
            return Ok(u32::from(required_word));
        }
        let range = match self.capture_file_system_output(output, required, memory) {
            Ok(range) => range,
            Err(error) if guest_api_failure(&error) => return Ok(0),
            Err(error) => return Err(error),
        };
        let mut bytes = path;
        bytes.push(0);
        match commit_guest_writes(self, memory, vec![(range, bytes)]) {
            Ok(()) => Ok((required - 1) as u32),
            Err(error) if guest_api_failure(&error) => Ok(0),
            Err(error) => Err(error),
        }
    }

    fn capture_file_system_output(
        &self,
        output: u32,
        length: usize,
        memory: &Memory,
    ) -> Result<GuestOutputRange, RuntimeError> {
        let pointer = self
            .selectors
            .pointer_from_far(output)
            .map_err(crate::runtime_error)?;
        self.selectors
            .translate(pointer, Access::Write, length, memory)
            .map_err(crate::runtime_error)?;
        GuestOutputRange::capture(self, memory, pointer, length)
    }
}

fn normalize_drive_directory(
    owner: OwnerId,
    drive: u8,
    relative: &str,
    host: &mut impl RuntimeHost,
) -> Result<Option<Win16CanonicalPath>, RuntimeError> {
    let guest = owner::guest_path_from_relative(drive, relative, Win16PathNamespace::DosVirtual)?;
    let Some(directory) = host.normalize_win16_dos_directory(owner, &guest)? else {
        return Ok(None);
    };
    if directory.drive != drive {
        return Err(invariant("normalized DOS directory changed its drive"));
    }
    Ok(Some(directory))
}

fn normalize_guest_path(
    owner: OwnerId,
    host: &mut impl RuntimeHost,
    path: &Win16GuestPath,
    follow_final: bool,
    allow_missing_final: bool,
) -> Result<Option<Win16CanonicalPath>, RuntimeError> {
    if path.drive > 25 {
        return Err(invariant("Win16 host path has an invalid drive"));
    }
    let result = host.win16_file_system(Win16HostFileSystemCall {
        owner,
        ansi_code_page: host.win16_ansi_code_page(),
        operation: Win16HostFileSystemOperation::NormalizePath {
            path: path.clone(),
            follow_final,
            allow_missing_final,
        },
    })?;
    match result {
        Win16HostFileSystemResult::NormalizedPath(canonical) => {
            if let Some(canonical) = &canonical {
                if canonical.drive != path.drive {
                    return Err(invariant("normalized host path changed its drive"));
                }
            }
            Ok(canonical)
        }
        _ => Err(invariant(
            "host path normalization returned the wrong result",
        )),
    }
}
