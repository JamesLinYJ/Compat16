//! Portable PE32 generic-thunk ownership and dispatch state.
//!
//! This is nested under `win16_runtime`: all guest addresses remain checked
//! RAM offsets, while identities and recovery leases stay private to the task.

use guest_core::{arena::ReservedRegion, memory::Memory};
use win16_abi::{
    Win16CallFrame, Win16ReturnKind,
    generic_thunk::{
        Win16GenericThunkRequest, decode_generic_thunk_export, resolve_get_vdm_pointer32w,
    },
};
use x86_cpu::Cpu;

use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost,
    pe32::{
        Pe32ImageArena, Pe32ImageLease, Pe32LoadGroupId, Pe32LoadRecovery, Pe32LoadTransaction,
        Pe32ModuleIdentity, Pe32ModuleRegistry, Pe32ProcedureToken, Pe32RetirementInfo,
    },
    pe32_call::{Pe32CallNonce, Pe32ExecutingCall, Pe32GuestCodeRange},
    win32_import_state::Win32ImportState,
};

#[path = "win16_runtime_pe32/environment.rs"]
mod environment;
#[path = "win16_runtime_pe32/lifecycle.rs"]
mod lifecycle;
#[path = "win16_runtime_pe32/lifecycle_errors.rs"]
mod lifecycle_errors;
#[path = "win16_runtime_pe32/loading.rs"]
mod loading;
#[path = "win16_runtime_pe32/procedures.rs"]
mod procedures;
#[path = "win16_runtime_pe32/win32_service.rs"]
mod win32_service;
const PE32_STACK_BYTES: u32 = 0x0010_0000;
const PE32_GATE_PAGE_BYTES: u32 = 0x0000_1000;
const PE32_SUPPORT_BYTES: u32 = PE32_STACK_BYTES + PE32_GATE_PAGE_BYTES;
const PE32_SUPPORT_ALIGNMENT: u32 = 0x1000;
const MAX_PE32_NESTED_CALL_DEPTH: usize = 32;
// Bounds host-side graph queues and transactions. It is a project resource
// budget, not a Windows loader limit; exhaustion maps to guest ERROR_NOT_ENOUGH_MEMORY.
const MAX_PE32_LOAD_GROUP_MEMBERS: usize = 4096;
const FIRST_MODULE_HANDLE: u32 = 0x7000_0001;
const MODULE_HANDLE_END: u32 = 0x8000_0000;
const FIRST_PROCEDURE_HANDLE: u32 = 0xf000_0001;

#[derive(Debug)]
struct LoadedModule {
    transaction: Pe32LoadTransaction,
    handle: Option<u32>,
    basename: Vec<u8>,
    path: Vec<u8>,
    executable_ranges: Vec<Pe32GuestCodeRange>,
    pending_retirement: Option<Pe32RetirementInfo>,
    quarantined: bool,
    image_released: bool,
    system_dependencies: Vec<crate::win32_import_state::Win32SystemModuleIdentity>,
    group_member: Option<LoadGroupMember>,
}

#[derive(Debug)]
struct LoadGroupMember {
    group: Pe32LoadGroupId,
    load_handle: u32,
    guest_references: u32,
    pending_host_bindings: Vec<loading::HostImportBinding>,
    attached: bool,
    attach_sequence: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoadGroupPhase {
    Discovering,
    Linking,
    Attaching,
    RollingBack,
}

#[derive(Debug)]
struct ActiveLoadGroup {
    id: Pe32LoadGroupId,
    root: Option<Pe32ModuleIdentity>,
    members: Vec<Pe32ModuleIdentity>,
    attach_order: Vec<Pe32ModuleIdentity>,
    temporary_providers: Vec<crate::win32_import_state::Win32SystemModuleIdentity>,
    next_attach_sequence: u64,
    phase: LoadGroupPhase,
}

#[derive(Clone, Copy, Debug)]
struct ProcedureHandle {
    value: u32,
    module: Pe32ModuleIdentity,
    token: Pe32ProcedureToken,
}

/// Owns one task's PE32 allocator and every module, callable alias and retry.
pub(super) struct Pe32ThunkDispatcher {
    arena: Pe32ImageArena,
    registry: Pe32ModuleRegistry,
    application_path: Vec<u8>,
    support: Pe32ImageLease,
    modules: Vec<LoadedModule>,
    procedures: Vec<ProcedureHandle>,
    recoveries: Vec<Pe32LoadRecovery>,
    active: Vec<ActiveCall>,
    retained_frames: Vec<Pe32ExecutingCall>,
    charged_boundaries: u64,
    active_budget: Option<ActiveBudget>,
    active_load_group: Option<ActiveLoadGroup>,
    next_module_handle: Option<u32>,
    next_procedure_handle: Option<u32>,
    support_released: bool,
    retired: bool,
}

#[derive(Clone, Copy)]
struct ActiveCall {
    nonce: Pe32CallNonce,
    module: Option<Pe32ModuleIdentity>,
    paused_at_service: bool,
    stack_start: u32,
    stack_top: u32,
    stack_selector: u16,
}

#[derive(Clone, Copy)]
struct ActiveBudget {
    limit: u64,
    used: u64,
}

impl Pe32ThunkDispatcher {
    pub(super) fn new(
        region: ReservedRegion,
        memory: &mut Memory,
        application_path: &[u8],
    ) -> Result<(Self, Win32ImportState), RuntimeError> {
        let mut arena = Pe32ImageArena::new(region)?;
        // One arena lease permanently owns a 1 MiB guest call stack and a
        // separate return-gate page; image reservations use the same allocator.
        let support = arena.reserve(PE32_SUPPORT_BYTES, PE32_SUPPORT_ALIGNMENT, 0)?;
        let support_address = guest_core::PhysAddr(support.base());
        let stack_end = support
            .base()
            .checked_add(PE32_STACK_BYTES)
            .ok_or_else(|| {
                RuntimeError::new(Kind::ResourceExhausted, "PE32 stack address overflowed")
            })?;
        let gate_base = stack_end;
        let win32_imports =
            Win32ImportState::new(gate_base, PE32_GATE_PAGE_BYTES, support.base(), stack_end)?;
        let mut retained_application_path = Vec::new();
        retained_application_path
            .try_reserve_exact(application_path.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "retain PE32 application search path",
                    error,
                )
            })?;
        retained_application_path.extend_from_slice(application_path);
        memory
            .validate_ram_range(support_address, PE32_SUPPORT_BYTES as usize, true)
            .map_err(crate::runtime_error)?;
        // MemoryStorage does not promise zero-filled external backing. Give the
        // guest stack/return gate the zeroed commit semantics it expects.
        let zero_page = [0_u8; 0x1000];
        for offset in (0..PE32_SUPPORT_BYTES).step_by(zero_page.len()) {
            let address = support.base().checked_add(offset).ok_or_else(|| {
                RuntimeError::new(Kind::InternalInvariant, "PE32 support address overflowed")
            })?;
            memory
                .write_physical(guest_core::PhysAddr(address), &zero_page)
                .map_err(crate::runtime_error)?;
        }
        // Every service slot starts as a closed UD2 guard. If the runtime has
        // not published that exact provider/generation, normal CPU fetch faults.
        for address in win32_imports.service_gate_guard_addresses() {
            memory
                .write_physical(guest_core::PhysAddr(address), &[0x0f, 0x0b])
                .map_err(crate::runtime_error)?;
        }
        Ok((
            Self {
                arena,
                registry: Pe32ModuleRegistry::new(),
                application_path: retained_application_path,
                support,
                modules: Vec::new(),
                procedures: Vec::new(),
                recoveries: Vec::new(),
                active: Vec::new(),
                retained_frames: Vec::new(),
                charged_boundaries: 0,
                active_budget: None,
                active_load_group: None,
                next_module_handle: Some(FIRST_MODULE_HANDLE),
                next_procedure_handle: Some(FIRST_PROCEDURE_HANDLE),
                support_released: false,
                retired: false,
            },
            win32_imports,
        ))
    }

    pub(super) const fn has_active_call(&self) -> bool {
        !self.active.is_empty()
    }

    pub(super) fn take_charged_boundaries(&mut self) -> u64 {
        std::mem::take(&mut self.charged_boundaries)
    }

    fn allocate_module_handle(&mut self) -> Result<u32, RuntimeError> {
        let value = self
            .next_module_handle
            .ok_or_else(|| exhausted("PE32 module handles"))?;
        if value >= MODULE_HANDLE_END {
            return Err(exhausted("PE32 module handles"));
        }
        self.next_module_handle = value.checked_add(1);
        Ok(value)
    }

    fn allocate_procedure_handle(&mut self) -> Result<u32, RuntimeError> {
        let value = self
            .next_procedure_handle
            .ok_or_else(|| exhausted("PE32 procedure handles"))?;
        self.next_procedure_handle = value.checked_add(1);
        Ok(value)
    }

    fn module_index(&self, identity: Pe32ModuleIdentity) -> Option<usize> {
        self.modules
            .iter()
            .position(|entry| entry.transaction.module() == identity)
    }

    fn handle_index(&self, handle: u32) -> Option<usize> {
        self.modules
            .iter()
            .position(|entry| entry.handle == Some(handle))
    }

    fn active_load_group_for_current_call(&self) -> Option<Pe32LoadGroupId> {
        let group = self.active_load_group.as_ref()?;
        if group.phase != LoadGroupPhase::Attaching {
            return None;
        }
        let active = self.active.last()?;
        if !active.paused_at_service {
            return None;
        }
        let module = active.module?;
        (self.registry.load_group(module).ok()? == Some(group.id)).then_some(group.id)
    }

    fn group_handle_index(&self, group: Pe32LoadGroupId, handle: u32) -> Option<usize> {
        self.modules.iter().position(|module| {
            module
                .group_member
                .as_ref()
                .is_some_and(|member| member.group == group && member.load_handle == handle)
        })
    }

    fn remove_group_identity(&mut self, identity: Pe32ModuleIdentity) {
        let Some(group) = self.active_load_group.as_mut() else {
            return;
        };
        group.members.retain(|member| *member != identity);
        group.attach_order.retain(|member| *member != identity);
        if group.root == Some(identity) {
            group.root = group.members.first().copied();
        }
    }

    fn push_recovery(&mut self, recovery: Pe32LoadRecovery) {
        // Each creator reserves this slot before an operation can hand back an
        // owning recovery lease.
        self.recoveries.push(recovery);
    }

    fn record_steps(&mut self, count: u64) -> Result<(), RuntimeError> {
        self.charged_boundaries = self.charged_boundaries.checked_add(count).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "PE32 charged boundary counter overflowed",
            )
        })?;
        if let Some(budget) = self.active_budget.as_mut() {
            budget.used = budget.used.checked_add(count).ok_or_else(|| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "PE32 active execution budget overflowed",
                )
            })?;
        }
        Ok(())
    }

    fn begin_budget(&mut self, limit: u64) -> Result<bool, RuntimeError> {
        if self.active_budget.is_some() {
            return Ok(false);
        }
        if limit == 0 {
            return Err(RuntimeError::new(
                Kind::ExecutionLimit,
                "PE32 execution has no remaining boundary budget",
            ));
        }
        self.active_budget = Some(ActiveBudget { limit, used: 0 });
        Ok(true)
    }

    fn finish_budget(&mut self, owner: bool) {
        if owner {
            self.active_budget = None;
        }
    }

    fn ensure_budget(&self) -> Result<(), RuntimeError> {
        match self.active_budget {
            Some(budget) if budget.used < budget.limit => Ok(()),
            Some(_) => Err(RuntimeError::new(
                Kind::ExecutionLimit,
                "PE32 execution boundary budget exhausted",
            )),
            None => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "PE32 guest stepped without an active shared budget",
            )),
        }
    }

    fn charge_service_boundary(&mut self) -> Result<(), RuntimeError> {
        self.ensure_budget()?;
        self.charged_boundaries = self.charged_boundaries.checked_add(1).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "PE32 charged boundary counter overflowed",
            )
        })?;
        let budget = self.active_budget.as_mut().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "PE32 service boundary lost its shared budget",
            )
        })?;
        budget.used += 1;
        Ok(())
    }

    fn budget_position(&self) -> u64 {
        self.active_budget
            .map_or(self.charged_boundaries, |budget| budget.used)
    }

    fn remaining_active_steps(&self) -> u64 {
        self.active_budget
            .map_or(0, |budget| budget.limit.saturating_sub(budget.used))
    }

    fn remaining_steps(&self, dispatch_start: u64, limit: u64) -> u64 {
        limit.saturating_sub(self.budget_position().saturating_sub(dispatch_start))
    }

    fn default_stack_top(&self) -> Result<u32, RuntimeError> {
        self.support
            .base()
            .checked_add(PE32_STACK_BYTES)
            .ok_or_else(|| {
                RuntimeError::new(Kind::InternalInvariant, "PE32 support stack overflows")
            })
    }

    fn next_stack_top(&self, cpu: &Cpu) -> Result<u32, RuntimeError> {
        let Some(active) = self.active.last() else {
            return self.default_stack_top();
        };
        if !active.paused_at_service
            || cpu.regs.ss != active.stack_selector
            || cpu.regs.esp < active.stack_start
            || cpu.regs.esp > active.stack_top
        {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "nested PE32 entry is only supported from an owned service-gate boundary",
            ));
        }
        Ok(cpu.regs.esp)
    }
}

impl super::Win16State {
    /// Enter the portable PE32 dispatcher with one budget shared by callbacks.
    pub(super) fn begin_pe32_generic_thunk(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        ordinal: u16,
        frame: Win16CallFrame,
        step_limit: u64,
    ) -> Result<Option<u8>, RuntimeError> {
        if self.pe32_dispatch.has_active_call() {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "nested PE32 execution is not supported; the active outer frame was preserved",
            ));
        }
        if self.pe32_dispatch.retired {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "PE32 generic-thunk state was already retired",
            ));
        }
        if let Some(error) = memory.storage_failure() {
            return Err(crate::runtime_error(error));
        }
        let budget_owner = self.pe32_dispatch.begin_budget(step_limit)?;
        let result =
            self.dispatch_pe32_generic_thunk(cpu, memory, host, ordinal, frame, step_limit);
        self.pe32_dispatch.finish_budget(budget_owner);
        result
    }

    fn dispatch_pe32_generic_thunk(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        ordinal: u16,
        frame: Win16CallFrame,
        step_limit: u64,
    ) -> Result<Option<u8>, RuntimeError> {
        let decoded = decode_generic_thunk_export(ordinal, frame, &self.selectors, memory);
        if let Some(error) = memory.storage_failure() {
            return Err(crate::runtime_error(error));
        }
        let request = decoded.map_err(crate::runtime_error)?.ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "non-generic KERNEL ordinal reached PE32 thunk dispatch",
            )
        })?;
        host.observe_win16_io(&crate::Win16IoEvent::Pe32ThunkRequest { request: &request });
        let (return_to, value) = match request {
            Win16GenericThunkRequest::LoadLibraryEx32W {
                library_name,
                reserved_hfile,
                flags,
                source_stack_cleanup,
                ..
            } => {
                let return_to =
                    self.far_return(&cpu.regs, memory, source_stack_cleanup.callee_pop_bytes)?;
                let value = self.pe32_dispatch.load_library(
                    cpu,
                    memory,
                    &mut self.win32_imports,
                    host,
                    &library_name,
                    reserved_hfile,
                    flags,
                    &self.module_path,
                    step_limit,
                )?;
                (return_to, value)
            }
            Win16GenericThunkRequest::FreeLibrary32W {
                module_handle,
                source_stack_cleanup,
            } => {
                let return_to =
                    self.far_return(&cpu.regs, memory, source_stack_cleanup.callee_pop_bytes)?;
                let value = u32::from(self.pe32_dispatch.free_library(
                    cpu,
                    memory,
                    &mut self.win32_imports,
                    host,
                    module_handle,
                    step_limit,
                )?);
                (return_to, value)
            }
            Win16GenericThunkRequest::GetProcAddress32W {
                module_handle,
                procedure_name,
                source_stack_cleanup,
                ..
            } => {
                let return_to =
                    self.far_return(&cpu.regs, memory, source_stack_cleanup.callee_pop_bytes)?;
                let value = self.pe32_dispatch.get_proc_address(
                    &mut self.win32_imports,
                    module_handle,
                    &procedure_name,
                    memory,
                    host,
                )?;
                (return_to, value)
            }
            Win16GenericThunkRequest::GetVDMPointer32W {
                address_far,
                mode,
                source_stack_cleanup,
            } => {
                let return_to =
                    self.far_return(&cpu.regs, memory, source_stack_cleanup.callee_pop_bytes)?;
                let value = match resolve_get_vdm_pointer32w(address_far, mode, &self.selectors) {
                    Ok(resolved)
                        if memory.storage_failure().is_none()
                            && memory
                                .validate_ram_range(resolved.address, 1, false)
                                .is_ok() =>
                    {
                        resolved.address.0
                    }
                    _ => {
                        if let Some(error) = memory.storage_failure() {
                            return Err(crate::runtime_error(error));
                        }
                        0
                    }
                };
                (return_to, value)
            }
            Win16GenericThunkRequest::CallProc32W(call)
            | Win16GenericThunkRequest::CallProcEx32W(call) => {
                let cleanup = call.stack_cleanup.callee_pop_bytes.ok_or_else(|| {
                    RuntimeError::new(
                        Kind::CompatibilityGap,
                        "generic-thunk zero path has no verified Win16 stack cleanup",
                    )
                })?;
                let return_to = self.far_return(&cpu.regs, memory, cleanup)?;
                let value = self.pe32_dispatch.call_procedure(
                    cpu,
                    memory,
                    &mut self.win32_imports,
                    host,
                    &self.selectors,
                    call,
                    step_limit,
                )?;
                (return_to, value)
            }
        };
        let completion = self.complete_return(
            &mut cpu.regs,
            return_to.0,
            return_to.1,
            return_to.2,
            value,
            Win16ReturnKind::Dword,
        );
        if completion.is_ok() {
            host.observe_win16_io(&crate::Win16IoEvent::GenericThunkReturn { value });
        }
        completion
    }

    pub(super) fn close_pe32_dispatcher(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        step_limit: u64,
    ) -> Result<(), RuntimeError> {
        self.pe32_dispatch
            .retire_all(cpu, memory, &mut self.win32_imports, host, step_limit)
    }
}

fn exhausted(resource: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::ResourceExhausted, format!("{resource} exhausted"))
}

fn aggregate_errors(
    context: &'static str,
    primary: RuntimeError,
    cleanup: RuntimeError,
) -> RuntimeError {
    primary.with_cleanup(context, cleanup)
}

// Win32 module-name queries distinguish an omitted extension from a final
// period. Keep this query syntax separate from resolved file identity below:
// an actual extensionless file must remain extensionless when it is published.
pub(super) fn query_basename_key(name: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let leaf = module_name_leaf(name)?;
    let trailing_period = leaf.last() == Some(&b'.');
    let remove_query_marker = trailing_period && name.is_ascii();
    let key_leaf = if remove_query_marker {
        &leaf[..leaf.len() - 1]
    } else {
        leaf
    };
    if key_leaf.is_empty() {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "PE32 module path has no basename after query normalization",
        ));
    }
    let append_extension = query_default_extension_needed(leaf);
    let extension_bytes = if append_extension { 4 } else { 0 };
    let capacity = key_leaf.len().checked_add(extension_bytes).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "PE32 module basename length overflowed",
        )
    })?;
    let mut key = Vec::new();
    key.try_reserve_exact(capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve PE32 module query basename",
            error,
        )
    })?;
    key.extend(key_leaf.iter().map(u8::to_ascii_lowercase));
    if append_extension {
        key.extend_from_slice(b".dll");
    }
    Ok(key)
}

// A resolved Win16ModuleImage path is already the host-selected file identity.
// Do not apply the query API's implicit ".dll" spelling to its actual leaf.
pub(super) fn published_basename_key(path: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let leaf = module_name_leaf(path)?;
    let mut key = Vec::new();
    key.try_reserve_exact(leaf.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve published PE32 module basename",
            error,
        )
    })?;
    key.extend(leaf.iter().map(u8::to_ascii_lowercase));
    Ok(key)
}

pub(super) fn query_default_extension_needed(leaf: &[u8]) -> bool {
    if leaf.last() == Some(&b'.') {
        return false;
    }
    !leaf
        .iter()
        .rposition(|byte| *byte == b'.')
        .is_some_and(|dot| dot != 0)
}

// GetModuleHandle's full-path query is compared with a path already returned
// by GetFullPathNameA. Trim its syntax-only final period only for an ordinary
// ASCII drive-rooted DOS path; device, UNC, relative, and ACP paths stay literal.
pub(super) fn query_full_path_key(path: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    if path.is_empty() || path.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "PE32 module query path is empty or contains NUL",
        ));
    }
    let leaf_start = path
        .iter()
        .rposition(|byte| matches!(*byte, b'/' | b'\\' | b':'))
        .map_or(0, |index| index + 1);
    let leaf = &path[leaf_start..];
    if leaf.is_empty() {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "PE32 module query path has no basename",
        ));
    }
    let trailing_period = leaf.last() == Some(&b'.');
    let remove_query_marker = trailing_period && is_ordinary_ascii_drive_path(path);
    if remove_query_marker && leaf.len() == 1 {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "PE32 module query path has no basename after query normalization",
        ));
    }
    let append_extension = query_default_extension_needed(leaf);
    let marker_length = if remove_query_marker { 1 } else { 0 };
    let normalized_length = path.len() - marker_length;
    let output_length = normalized_length
        .checked_add(if append_extension { 4 } else { 0 })
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "PE32 module query path length overflowed",
            )
        })?;
    let mut key = Vec::new();
    key.try_reserve_exact(output_length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve PE32 module query path",
            error,
        )
    })?;
    key.extend_from_slice(&path[..normalized_length]);
    if append_extension {
        key.extend_from_slice(b".DLL");
    }
    Ok(key)
}

fn is_ordinary_ascii_drive_path(path: &[u8]) -> bool {
    path.is_ascii()
        && path.len() >= 3
        && path[0].is_ascii_alphabetic()
        && path[1] == b':'
        && matches!(path[2], b'/' | b'\\')
}

fn module_name_leaf(name: &[u8]) -> Result<&[u8], RuntimeError> {
    if name.is_empty() || name.contains(&0) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "PE32 module name is empty or contains NUL",
        ));
    }
    let leaf = name
        .rsplit(|byte| matches!(*byte, b'/' | b'\\' | b':'))
        .next()
        .unwrap_or_default();
    if leaf.is_empty() {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "PE32 module path has no basename",
        ));
    }
    Ok(leaf)
}
