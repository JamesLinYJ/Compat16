use std::collections::BTreeMap;

use crate::caller_address_space::{DosCallAddressSpace, DosCallerId, DosPersistentFarPointer};
use crate::{DosAction, DosError, DosErrorCode, DosHost, DosHostError, DosHostFile, DosHostSearch};
use guest_core::{GuestMemory, Registers};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Handle {
    Standard(StandardHandle),
    File(DosHostFile),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StandardHandle {
    Input,
    Output,
    Error,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Mcb {
    pub(super) segment: u16,
    pub(super) raw: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct SearchKey {
    pub(super) psp_segment: u16,
    pub(super) caller: DosCallerId,
    pub(super) dta_segment: u16,
    pub(super) dta_offset: u16,
    pub(super) dta_lease: u64,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct DosSearchPattern {
    pub(super) name: [u8; 8],
    pub(super) extension: [u8; 3],
}

#[derive(Clone, Copy, Debug)]
pub(super) struct SearchState {
    pub(super) host_search: DosHostSearch,
    pub(super) identity: u32,
    pub(super) pattern: DosSearchPattern,
    pub(super) attributes: u8,
}

impl Mcb {
    pub(super) fn kind(self) -> u8 {
        self.raw[0]
    }
    pub(super) fn owner(self) -> u16 {
        u16::from_le_bytes([self.raw[1], self.raw[2]])
    }
    pub(super) fn size(self) -> u16 {
        u16::from_le_bytes([self.raw[3], self.raw[4]])
    }
    pub(super) fn set_kind(&mut self, value: u8) {
        self.raw[0] = value;
    }
    pub(super) fn set_owner(&mut self, value: u16) {
        self.raw[1..3].copy_from_slice(&value.to_le_bytes());
    }
    pub(super) fn set_size(&mut self, value: u16) {
        self.raw[3..5].copy_from_slice(&value.to_le_bytes());
    }
    pub(super) fn new(segment: u16, kind: u8, owner: u16, size: u16) -> Self {
        let mut value = Self {
            segment,
            raw: [0; 16],
        };
        value.set_kind(kind);
        value.set_owner(owner);
        value.set_size(size);
        value
    }
}

/// Per-process DOS state. Guest handles map to host-owned opaque file IDs.
#[derive(Debug)]
pub struct DosKernel {
    pub(super) psp_segment: u16,
    pub(super) dta_segment: u16,
    pub(super) dta_offset: u16,
    pub(super) dta_by_caller: BTreeMap<DosCallerId, DosPersistentFarPointer>,
    pub(super) retained_dta_by_caller: BTreeMap<DosCallerId, Vec<DosPersistentFarPointer>>,
    pub(super) mcb_head: Option<u16>,
    pub(super) block_leases: super::block_lease::DosBlockLeases,
    pub(super) system_tables: Option<super::system::SystemTables>,
    pub(super) message_addresses: super::message_addresses::DosMessageAddresses,
    pub(super) file_table: super::sft::FileTable,
    /// Handle ownership does not follow AH=50's selected PSP. Switching a
    /// complete DOS file context is separate from selecting a scalar PSP word.
    pub(super) jft_owner_psp: u16,
    pub(super) jft_capacity: u16,
    pub(super) jft_storage: Option<super::DosBlockLease>,
    /// Prepared replacements and retired tables remain owned until checked
    /// release succeeds, including when guest storage fails during publication.
    pub(super) retired_jft_storage: Vec<super::DosBlockLease>,
    pub(super) device_requests: [Option<(u16, u16)>; 2],
    pub(super) handles: BTreeMap<u16, Handle>,
    /// Host duplicates which could not be closed during an inheritance
    /// rollback. They remain owned until a later checked process cleanup.
    pub(super) orphan_file_handles: Vec<DosHostFile>,
    pub(super) searches: BTreeMap<SearchKey, SearchState>,
    /// Guest far pointers to ROM-backed collation tables, keyed by code page.
    pub(super) collating_table_addresses: BTreeMap<u16, (u16, u16)>,
    /// Guest far pointers to ROM-backed extended uppercase tables, keyed by code page.
    pub(super) uppercase_table_addresses: BTreeMap<u16, (u16, u16)>,
    /// Guest far pointers to ROM-backed country case-map callbacks, keyed by code page.
    pub(super) case_map_addresses: BTreeMap<u16, (u16, u16)>,
    pub(super) next_search_identity: u32,
    pub(super) next_temporary_name: u32,
    /// DOS INT 21h/AH=33 Ctrl-Break checking state (default: disabled).
    pub(super) break_check_enabled: bool,
    pub(super) pending_input: Option<u8>,
    pub(super) last_exit_code: u8,
}

/// A failed child start retains its partial DOS owner so runtime can close
/// every host duplicate and free its DOS blocks before reporting the DOS code.
#[derive(Debug)]
pub struct DosChildProcessFailure {
    child: DosKernel,
    error: DosError,
}

impl DosChildProcessFailure {
    pub fn into_parts(self) -> (DosKernel, DosError) {
        (self.child, self.error)
    }
}

impl std::fmt::Display for DosChildProcessFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "DOS child process setup failed: {}", self.error)
    }
}

impl std::error::Error for DosChildProcessFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl DosKernel {
    pub fn new(psp_segment: u16) -> Self {
        let mut handles = BTreeMap::new();
        handles.insert(0, Handle::Standard(StandardHandle::Input));
        handles.insert(1, Handle::Standard(StandardHandle::Output));
        handles.insert(2, Handle::Standard(StandardHandle::Error));
        Self {
            psp_segment,
            dta_segment: psp_segment,
            dta_offset: 0x80,
            dta_by_caller: BTreeMap::new(),
            retained_dta_by_caller: BTreeMap::new(),
            mcb_head: None,
            block_leases: super::block_lease::DosBlockLeases::new(),
            system_tables: None,
            message_addresses: super::message_addresses::DosMessageAddresses::default(),
            file_table: super::sft::FileTable::new(),
            jft_owner_psp: psp_segment,
            jft_capacity: super::sft::DEFAULT_JFT_LEN,
            jft_storage: None,
            retired_jft_storage: Vec::new(),
            device_requests: [None; 2],
            handles,
            orphan_file_handles: Vec::new(),
            searches: BTreeMap::new(),
            collating_table_addresses: BTreeMap::new(),
            uppercase_table_addresses: BTreeMap::new(),
            case_map_addresses: BTreeMap::new(),
            next_search_identity: 0,
            next_temporary_name: 0,
            break_check_enabled: false,
            pending_input: None,
            last_exit_code: 0,
        }
    }

    /// Create a child DOS process context from `parent`, inheriting the shared
    /// DOS tables, NLS service addresses, and duplicated JFT handles.
    ///
    /// The child starts with its own PSP as the default DTA owner and an empty
    /// directory-search table. Pending console input is transferred because
    /// it belongs to the DOS stream, not to two independently runnable
    /// processes.
    pub fn child_process(
        parent: &mut DosKernel,
        child_psp_segment: u16,
        host: &mut impl DosHost,
    ) -> Result<Self, DosChildProcessFailure> {
        let mut child = Self::child_allocation_owner(parent, child_psp_segment);
        if let Err(error) = child.begin_child_process(parent, host) {
            return Err(DosChildProcessFailure { child, error });
        }
        Ok(child)
    }

    /// Create the DOS owner for a reserved child PSP without transferring
    /// stream input or duplicating handles. Runtime uses this before creating
    /// the child environment so every later startup failure has an owner that
    /// can be aborted through the same checked close/free path.
    pub fn child_allocation_owner(parent: &DosKernel, child_psp_segment: u16) -> Self {
        let mut child = Self::new(child_psp_segment);
        child.mcb_head = parent.mcb_head;
        child.block_leases = parent.block_leases.clone();
        child.system_tables = parent.system_tables;
        child.message_addresses = parent.message_addresses.clone();
        child.device_requests = parent.device_requests;
        child.collating_table_addresses = parent.collating_table_addresses.clone();
        child.uppercase_table_addresses = parent.uppercase_table_addresses.clone();
        child.case_map_addresses = parent.case_map_addresses.clone();
        child.next_search_identity = parent.next_search_identity;
        child.break_check_enabled = parent.break_check_enabled;
        child
    }

    /// Transfer the shared DOS input byte and prepare inherited handles after
    /// all child memory is ready. A failure leaves its partial owner in `self`
    /// for `abort_child_process` to close before runtime reports the DOS code.
    pub fn begin_child_process(
        &mut self,
        parent: &mut DosKernel,
        host: &mut impl DosHost,
    ) -> Result<(), DosError> {
        self.block_leases.check_storage_state()?;
        parent.block_leases.check_storage_state()?;
        if self.pending_input.is_some()
            || self
                .handles
                .values()
                .any(|handle| matches!(handle, Handle::File(_)))
        {
            return Err(DosError::HostContractViolation(
                "child handle inheritance requires a fresh child DOS owner",
            ));
        }
        self.pending_input = parent.pending_input.take();
        self.inherit_handles_from(parent, host)
    }

    /// Reserve bookkeeping before opening a transient EXEC image handle. If
    /// its close later fails, runtime can retain the host identity without
    /// allocating after the side effect has already happened.
    pub fn reserve_file_cleanup_slot(&mut self) -> Result<(), DosHostError> {
        self.orphan_file_handles
            .try_reserve(1)
            .map_err(|error| DosHostError::with_source(DosErrorCode::InsufficientMemory, error))
    }

    /// Record a host file whose close failed. Callers reserve a slot before
    /// acquiring the resource, so this append cannot allocate during cleanup.
    pub fn retain_unclosed_file(&mut self, file: DosHostFile) -> Result<(), DosHostError> {
        if self.orphan_file_handles.contains(&file) {
            return Ok(());
        }
        if self.orphan_file_handles.len() == self.orphan_file_handles.capacity() {
            return Err(DosHostError::new(DosErrorCode::InsufficientMemory));
        }
        self.orphan_file_handles.push(file);
        Ok(())
    }

    /// A duplicate owns a new closeable identity, not merely a shared cursor.
    /// Include failed-close resources, which still belong to this process.
    pub(super) fn owns_file_token(&self, file: DosHostFile) -> bool {
        self.handles.values().any(|handle| *handle == Handle::File(file))
            || self.orphan_file_handles.contains(&file)
    }

    /// Current PSP segment, for the runtime and diagnostics.
    pub fn psp_segment(&self) -> u16 {
        self.psp_segment
    }

    /// Install the parent's currently open handles in a child PSP. File handles
    /// are duplicated through the host so both processes get valid identities.
    pub fn inherit_handles_from(
        &mut self,
        parent: &DosKernel,
        host: &mut impl DosHost,
    ) -> Result<(), DosError> {
        // This method is intended for a newly-created child kernel.
        self.block_leases.check_storage_state()?;
        parent.block_leases.check_storage_state()?;
        if self.jft_capacity != super::sft::DEFAULT_JFT_LEN
            || self.jft_storage.is_some()
            || !self.retired_jft_storage.is_empty()
            || !self.orphan_file_handles.is_empty()
            || self.handles.values().any(|h| matches!(h, Handle::File(_)))
        {
            return Err(DosError::HostContractViolation(
                "DOS handle inheritance requires an empty child handle table",
            ));
        }
        let mut inherited = BTreeMap::new();
        let mut duplicated = Vec::new();
        for (&guest, &handle) in &parent.handles {
            if guest >= super::sft::DEFAULT_JFT_LEN
                || !parent.file_table.is_handle_inheritable(guest) {
                continue;
            }
            let target = match handle {
                Handle::Standard(kind) => Handle::Standard(kind),
                Handle::File(file) => {
                    // Reserve all bookkeeping before the host creates a new
                    // handle. If allocation failed after duplication, there
                    // would be no reliable place to retain its identity when
                    // rollback close also failed.
                    if let Err(error) = duplicated.try_reserve(1) {
                        let primary = DosError::HostOperation(DosHostError::with_source(
                            DosErrorCode::InsufficientMemory,
                            error,
                        ));
                        return Err(self.rollback_inherited_handles(duplicated, host, primary));
                    }
                    if let Err(error) = self
                        .orphan_file_handles
                        .try_reserve(duplicated.len().saturating_add(1))
                    {
                        let primary = DosError::HostOperation(DosHostError::with_source(
                            DosErrorCode::InsufficientMemory,
                            error,
                        ));
                        return Err(self.rollback_inherited_handles(duplicated, host, primary));
                    }
                    match host.file_duplicate(file) {
                        Ok(copy) if !parent.owns_file_token(copy) => {
                            if duplicated.contains(&copy) {
                                return Err(self.rollback_inherited_handles(
                                    duplicated,
                                    host,
                                    DosError::HostContractViolation(
                                        "file_duplicate reused an earlier duplicated file identity",
                                    ),
                                ));
                            }
                            duplicated.push(copy);
                            Handle::File(copy)
                        }
                        Ok(_) => {
                            return Err(self.rollback_inherited_handles(
                                duplicated,
                                host,
                                DosError::HostContractViolation(
                                    "file_duplicate returned a file identity already owned by the parent",
                                ),
                            ));
                        }
                        Err(error) => {
                            return Err(self.rollback_inherited_handles(
                                duplicated,
                                host,
                                DosError::HostOperation(error),
                            ));
                        }
                    }
                }
            };
            inherited.insert(guest, target);
        }
        if !self.file_table.inherit_from(&parent.file_table) {
            return Err(self.rollback_inherited_handles(
                duplicated,
                host,
                DosError::HostOperation(DosHostError::new(DosErrorCode::TooManyOpenFiles)),
            ));
        }
        self.handles = inherited;
        Ok(())
    }

    fn rollback_inherited_handles(
        &mut self,
        duplicated: Vec<DosHostFile>,
        host: &mut impl DosHost,
        mut primary: DosError,
    ) -> DosError {
        for file in duplicated {
            if let Err(cleanup) = host.file_close(file) {
                if !self.orphan_file_handles.contains(&file) {
                    // Inheritance reserved one slot before each host duplicate.
                    // If this is not true, state bookkeeping itself is corrupt;
                    // retaining the identity is still preferable to dropping it.
                    self.orphan_file_handles.push(file);
                }
                primary = DosError::HostHandleRollbackFailure {
                    operation: "inherit DOS child handles",
                    cause: Box::new(primary),
                    rollback: Box::new(DosError::HostOperation(cleanup)),
                };
            }
        }
        primary
    }

    pub fn interrupt(
        &mut self,
        number: u8,
        regs: &mut Registers,
        memory: &mut impl GuestMemory,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        let mut address_space =
            crate::real_mode_address_space::RealModeDosAddressSpace::new(memory);
        self.interrupt_with_address_space(number, regs, &mut address_space, host)
    }

    /// Dispatch a DOS interrupt with an explicit caller pointer resolver.
    /// The same memory view backs internal real-mode DOS metadata, while
    /// caller operands use selector-aware methods on `address_space`.
    pub fn interrupt_with_address_space(
        &mut self,
        number: u8,
        regs: &mut Registers,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<DosAction, DosError> {
        self.block_leases.check_storage_state()?;
        if number == 0x21 && regs.ah() == 0x67 {
            // This storage-only operation owns its metadata lifecycle. In
            // particular, unsupported and unchanged requests must not run a
            // generic SFT/JFT refresh that could write through a guest pointer.
            return self.set_handle_count(regs, memory);
        }
        if number == 0x21 {
            self.validate_system_tables(memory)?;
            if self.system_tables.is_some() {
                // `refresh_system_tables` walks this chain after dispatch.
                // Check guest-owned MCB links before DOS services can change
                // host files or consume input, preserving the original guest
                // corruption error rather than surfacing it after the call.
                let _ = self.mcb_chain(memory)?;
            }
        }
        let action = match number {
            0x20 => Ok(DosAction::Exit(0)),
            0x21 => self.int21(regs, memory, host),
            _ => Ok(DosAction::Unhandled),
        }?;
        if let DosAction::Exit(code) = &action {
            self.close_searches_for_psp_checked(self.psp_segment, host)
                .map_err(DosError::HostOperation)?;
            self.close_all_handles_checked(host)
                .map_err(DosError::HostOperation)?;
            self.release_jft_storage(memory)?;
            self.last_exit_code = *code;
        } else if number == 0x21 && !matches!(&action, DosAction::Unhandled) {
            self.refresh_system_tables(memory, host)?;
        }
        Ok(action)
    }

    /// Complete the DOS return state for an EXEC request rejected by runtime
    /// image or memory handling after DOS decoded the request.
    pub fn complete_exec_failure(regs: &mut Registers, code: DosErrorCode) {
        Self::failure(regs, DosHostError::new(code));
    }

    /// Complete the successful return state for INT 21h/AH=4Bh.
    pub fn complete_exec_success(regs: &mut Registers) {
        Self::success(regs);
    }

    /// Close every host file token owned by this process. Also called on DOS exit.
    pub fn close_all_handles(&mut self, host: &mut impl DosHost) {
        if self.close_all_handles_checked(host).is_ok() {
            self.pending_input = None;
        }
    }

    /// Close one process's host handles while retaining each failed identity
    /// for a later runtime teardown retry. Successful closes retire their
    /// guest JFT/SFT entry immediately; a failure leaves that entry intact.
    pub fn close_all_handles_checked(
        &mut self,
        host: &mut impl DosHost,
    ) -> Result<(), DosHostError> {
        self.block_leases.check_storage_state().map_err(|error| {
            DosHostError::with_source(DosErrorCode::GeneralFailure, error)
        })?;
        loop {
            let next_file = self
                .handles
                .iter()
                .find_map(|(&guest, handle)| match handle {
                    Handle::File(file) => Some((guest, *file)),
                    Handle::Standard(_) => None,
                });
            let Some((guest, file)) = next_file else {
                break;
            };
            host.file_close(file)?;
            self.handles.remove(&guest);
            self.file_table.remove_handle(guest);
        }
        while let Some(&file) = self.orphan_file_handles.first() {
            host.file_close(file)?;
            self.orphan_file_handles.remove(0);
        }
        while let Some((&guest, _)) = self.handles.first_key_value() {
            self.handles.remove(&guest);
            self.file_table.remove_handle(guest);
        }
        Ok(())
    }

    /// Close every active directory search owned by `psp_segment`.
    pub fn close_searches_for_psp(&mut self, psp_segment: u16, host: &mut impl DosHost) {
        if self.block_leases.check_storage_state().is_err() { return; }
        let keys: Vec<_> = self
            .searches
            .keys()
            .copied()
            .filter(|key| key.psp_segment == psp_segment)
            .collect();
        for key in keys {
            if let Some(state) = self.searches.get(&key).copied() {
                if host.directory_search_close(state.host_search).is_ok() {
                    self.searches.remove(&key);
                }
            }
        }
    }

    /// Close owned searches without dropping a failed host identity. This is
    /// used by child-process finish/abort while the process frame is retained.
    pub fn close_searches_for_psp_checked(
        &mut self,
        psp_segment: u16,
        host: &mut impl DosHost,
    ) -> Result<(), DosHostError> {
        self.block_leases.check_storage_state().map_err(|error| {
            DosHostError::with_source(DosErrorCode::GeneralFailure, error)
        })?;
        loop {
            let key = self
                .searches
                .keys()
                .find(|key| key.psp_segment == psp_segment)
                .copied();
            let Some(key) = key else { return Ok(()) };
            let Some(state) = self.searches.get(&key).copied() else {
                return Err(DosHostError::new(DosErrorCode::InvalidHandle));
            };
            host.directory_search_close(state.host_search)?;
            self.searches.remove(&key);
        }
    }

    /// Close every native search identity retained by this DOS state. A child
    /// may change its current PSP with AH=50h, but its search ledger remains
    /// owned by this child kernel instance and must be drained in full.
    pub fn close_all_searches_checked(
        &mut self,
        host: &mut impl DosHost,
    ) -> Result<(), DosHostError> {
        self.block_leases.check_storage_state().map_err(|error| {
            DosHostError::with_source(DosErrorCode::GeneralFailure, error)
        })?;
        loop {
            let Some((key, state)) = self
                .searches
                .first_key_value()
                .map(|(key, state)| (*key, *state))
            else {
                return Ok(());
            };
            host.directory_search_close(state.host_search)?;
            self.searches.remove(&key);
        }
    }

    /// Return from a synchronously executed child process. Child searches,
    /// host file identities, and MCBs are released; DOS-global state is copied
    /// back to the suspended parent and AH=4Dh is prepared with `exit_code`.
    pub fn finish_child_process(
        &mut self,
        parent: &mut DosKernel,
        memory: &mut impl GuestMemory,
        host: &mut impl DosHost,
        exit_code: u8,
        allocation_owner_psp: u16,
    ) -> Result<(), DosError> {
        self.close_child_resources_and_merge(
            parent,
            memory,
            host,
            Some(exit_code),
            allocation_owner_psp,
        )
    }

    /// Roll back a DOS child that has not successfully returned to its parent.
    /// The parent's previous AH=4Dh status is preserved; pending input returns
    /// only after all child handles/searches and MCB-owned blocks are retired.
    pub fn abort_child_process(
        &mut self,
        parent: &mut DosKernel,
        memory: &mut impl GuestMemory,
        host: &mut impl DosHost,
        allocation_owner_psp: u16,
    ) -> Result<(), DosError> {
        self.close_child_resources_and_merge(parent, memory, host, None, allocation_owner_psp)
    }

    fn close_child_resources_and_merge(
        &mut self,
        parent: &mut DosKernel,
        memory: &mut impl GuestMemory,
        host: &mut impl DosHost,
        exit_code: Option<u8>,
        allocation_owner_psp: u16,
    ) -> Result<(), DosError> {
        self.block_leases.check_storage_state()?;
        if allocation_owner_psp == 0 || allocation_owner_psp != self.jft_owner_psp {
            return Err(DosError::HostContractViolation(
                "child cleanup requires its immutable allocation PSP",
            ));
        }
        self.close_all_searches_checked(host)
            .map_err(DosError::HostOperation)?;
        self.close_all_handles_checked(host)
            .map_err(DosError::HostOperation)?;
        self.release_jft_storage(memory)?;
        self.free_process_blocks(memory, allocation_owner_psp)?;

        parent.mcb_head = self.mcb_head;
        parent.system_tables = self.system_tables;
        parent.device_requests = self.device_requests;
        parent
            .collating_table_addresses
            .clone_from(&self.collating_table_addresses);
        parent
            .uppercase_table_addresses
            .clone_from(&self.uppercase_table_addresses);
        parent
            .case_map_addresses
            .clone_from(&self.case_map_addresses);
        parent.next_search_identity = self.next_search_identity;
        parent.break_check_enabled = self.break_check_enabled;
        if parent.pending_input.is_none() {
            parent.pending_input = self.pending_input.take();
        }
        if let Some(exit_code) = exit_code {
            parent.last_exit_code = exit_code;
        }
        Ok(())
    }
}
