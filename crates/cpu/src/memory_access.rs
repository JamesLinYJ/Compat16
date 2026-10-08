//! Planned, checked access to process-owned guest memory.
//!
//! Instruction fetches and execution use this CPU-side bus boundary. Known
//! architectural modes use hidden segment caches and the i486 page walker;
//! unknown legacy projections stay behind the machine's checked resolver and
//! never acquire an invented CPL.

#[path = "system/paging_access.rs"]
mod paging_access;
pub(crate) use paging_access::PagingAddressSpace;
#[path = "memory_access/request.rs"]
mod request;
#[path = "memory_access/debug.rs"]
mod debug;
#[path = "memory_access/prepare.rs"]
mod prepare;
#[path = "memory_access/cpu_bus.rs"]
mod cpu_bus;
#[path = "memory_access/target_validation.rs"]
mod target_validation;
#[path = "memory_access/segment_faults.rs"]
mod segment_faults;
pub(crate) use request::{
    AccessKind, AccessOrigin, AccessRequest, DataAlignment, DataBreakpointHits, LogicalSpan,
};

use std::sync::Arc;

use guest_core::{AtomicMemoryRange, GuestMemory, LinearAddr, MemoryError, PhysAddr};

use crate::{
    CpuCompatibilityGap, CpuError, CpuExecutionMode, SegmentResolver,
    registers::SegmentRegister,
    system::{
        CR0_PE, CpuSystem, SegmentCache,
    },
};

/// Identifies the guest instruction that requested an access plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AccessSite {
    pub(crate) opcode: u8,
    pub(crate) ip: u32,
    pub(crate) eflags: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PhysicalChunk {
    pub(crate) address: PhysAddr,
    pub(crate) buffer_offset: usize,
    pub(crate) len: usize,
}

/// Opaque mapping produced only after segment/page checks and backing-store
/// range validation have succeeded. It cannot be cloned or moved to another
/// bus instance, and system-state mutation invalidates its epoch.
pub(crate) struct PreparedAccess {
    owner: Arc<()>,
    epoch: u64,
    len: usize,
    linear_start: Option<LinearAddr>,
    kind: AccessKind,
    alignment: DataAlignment,
    alignment_cpl: Option<u8>,
    origin: Option<AccessOrigin>,
    can_read: bool,
    can_write: bool,
    read_chunks: Vec<PhysicalChunk>,
    write_chunks: Vec<PhysicalChunk>,
}

impl PreparedAccess {
    pub(crate) fn physical_chunks(&self, write: bool) -> &[PhysicalChunk] {
        if write {
            &self.write_chunks
        } else {
            &self.read_chunks
        }
    }
}

struct AccessParts {
    linear_start: Option<LinearAddr>,
    len: usize,
    can_read: bool,
    can_write: bool,
    read_chunks: Vec<PhysicalChunk>,
    write_chunks: Vec<PhysicalChunk>,
}

/// Collection of fully preflighted accesses for operations such as stack-frame
/// construction. Every member's segment, page, and backing range is checked
/// before any member's #AC gate; callers prepare the whole group before writes.
/// Callers describe slots and instruction-specific stack rules; this does not
/// make address-size wrap between legal slots a segment-limit condition.
pub(crate) struct PreparedGroup {
    accesses: Vec<PreparedAccess>,
}

impl PreparedGroup {
    pub(crate) fn into_accesses(self) -> Vec<PreparedAccess> {
        self.accesses
    }
}

/// Guest-memory interface used by instruction execution. It deliberately does
/// not inherit `GuestMemory`: all transfers must use a prepared, checked plan.
pub(crate) trait CpuBus {
    fn instruction_site(&self) -> AccessSite;
    fn prepare(&mut self, request: AccessRequest) -> Result<PreparedAccess, CpuError>;
    fn prepare_group(&mut self, requests: &[AccessRequest]) -> Result<PreparedGroup, CpuError>;
    /// Prepare an architectural span against a temporary segment cache while
    /// retaining the current architectural CPL. This does not publish the
    /// supplied cache into CpuSystem.
    fn prepare_logical_with_cache(
        &mut self,
        span: LogicalSpan,
        kind: AccessKind,
        alignment: DataAlignment,
        origin: AccessOrigin,
        cache: SegmentCache,
    ) -> Result<PreparedAccess, CpuError>;
    /// Preflight a protected-mode target stack on a temporary SS cache. Only
    /// SS stack reads/writes are accepted, and published CPU state is unchanged.
    fn prepare_group_for_stack(
        &mut self,
        requests: &[AccessRequest],
        temporary_ss: SegmentCache,
        target_cpl: u8,
    ) -> Result<PreparedGroup, CpuError>;
    /// Prepare a supervisor SystemLinear access through the explicit target
    /// CR3. SystemLinear page permissions always use CPL 0.
    fn prepare_system_linear_in_address_space(
        &mut self,
        address: LinearAddr,
        len: usize,
        kind: AccessKind,
        address_space: PagingAddressSpace,
    ) -> Result<PreparedAccess, CpuError>;
    /// Preflight protected/virtual-8086 target-stack spans through an explicit
    /// address space while retaining the supplied hidden SS cache only in the
    /// plan.
    fn prepare_group_for_stack_in_address_space(
        &mut self,
        requests: &[AccessRequest],
        temporary_ss: SegmentCache,
        address_space: PagingAddressSpace,
    ) -> Result<PreparedGroup, CpuError>;
    fn invlpg_linear_address(&mut self, span: LogicalSpan) -> Result<LinearAddr, CpuError>;
    fn read_prepared(&mut self, access: &PreparedAccess, bytes: &mut [u8]) -> Result<(), CpuError>;
    fn write_prepared(&mut self, access: PreparedAccess, bytes: &[u8]) -> Result<(), CpuError>;
    /// Atomically replace a preflighted physical range only when it still has
    /// the expected image. Descriptor leases use this so a provider that
    /// cannot serialize the publication declines before mutating guest bytes.
    fn atomic_replace_prepared(
        &mut self,
        read_access: &PreparedAccess,
        write_access: &PreparedAccess,
        expected: &[u8],
        replacement: &[u8],
    ) -> Result<bool, CpuError>;
    /// Complete an already-preflighted read/modify/write through guest memory.
    fn atomic_update(
        &mut self,
        request: AccessRequest,
        update: &mut dyn FnMut(&mut [u8]),
    ) -> Result<(), CpuError>;
    /// Validate a near target against CS without walking target pages or fetching it.
    fn validate_near_code_target(
        &mut self,
        selector: u16,
        target: u32,
    ) -> Result<(), CpuError>;
    /// Take debug-register bits produced by completed checked data transfers.
    fn take_data_breakpoint_hits(&mut self) -> DataBreakpointHits;

    /// Mark subsequent processor-frame accesses with the EXT value a #AC
    /// raised during this event's delivery must carry.
    fn set_processor_event_error_ext(&mut self, external: bool);
    /// Supply incoming-task flags for accesses after a task-gate commit while
    /// retaining the initiating event's instruction site.
    fn set_access_context_eflags(&mut self, eflags: u32);

    fn system(&self) -> &CpuSystem;
    fn system_mut(&mut self) -> &mut CpuSystem;
    fn code_bits(&self) -> u32;
    fn stack32(&self) -> bool;
    fn protected_mode_format_hint(&self) -> bool;
    fn execution_mode(&self) -> Option<CpuExecutionMode>;
    fn current_privilege_level(&self) -> Option<u8>;
    fn architectural_mode_active(&self) -> bool;
}

/// CPU bus backed only by checked guest RAM and a machine-owned segment
/// resolver. All access planning and transfers require `&mut self` so page
/// walks, access plans, and architecturally visible state share one boundary.
pub(crate) struct CpuMemoryAccess<'a, M: GuestMemory, S: SegmentResolver> {
    memory: &'a mut M,
    resolver: &'a S,
    system: &'a mut CpuSystem,
    site: AccessSite,
    access_context_eflags: Option<u32>,
    owner: Arc<()>,
    epoch: u64,
    data_breakpoint_hits: DataBreakpointHits,
    processor_event_error_ext: bool,
}

impl<'a, M: GuestMemory, S: SegmentResolver> CpuMemoryAccess<'a, M, S> {
    pub(crate) fn new(
        memory: &'a mut M,
        resolver: &'a S,
        system: &'a mut CpuSystem,
        site: AccessSite,
    ) -> Self {
        Self {
            memory,
            resolver,
            system,
            site,
            access_context_eflags: None,
            owner: Arc::new(()),
            epoch: 0,
            data_breakpoint_hits: DataBreakpointHits::default(),
            processor_event_error_ext: false,
        }
    }

    pub(crate) fn set_instruction_opcode(&mut self, opcode: u8) {
        self.site.opcode = opcode;
    }

    /// Validate a segmented range with the guest's real CPL and paging rights,
    /// then verify that its physical chunks match the runtime's direct-memory
    /// selector projection.
    pub(crate) fn logical_range_is_identity_mapped(
        &mut self,
        span: LogicalSpan,
        kind: AccessKind,
        cache: SegmentCache,
    ) -> Result<bool, CpuError> {
        let access = self.prepare_logical_with_cache(
            span,
            kind,
            DataAlignment::Unaligned,
            AccessOrigin::ProcessorEvent,
            cache,
        )?;
        let Some(linear_start) = access.linear_start else {
            return Ok(false);
        };
        let chunks = if kind.writes() {
            &access.write_chunks
        } else {
            &access.read_chunks
        };
        for chunk in chunks {
            let Some(expected) = u32::try_from(chunk.buffer_offset)
                .ok()
                .and_then(|offset| linear_start.0.checked_add(offset))
            else {
                return Ok(false);
            };
            if chunk.address.0 != expected {
                return Ok(false);
            }
        }
        Ok(!chunks.is_empty())
    }

    fn error_site(&self) -> CpuError {
        CpuError::InvalidMemoryAccessPlan { ip: self.site.ip }
    }

    fn unsupported_mode(&self) -> CpuError {
        CpuError::UnsupportedSystemMode {
            opcode: self.site.opcode,
            ip: self.site.ip,
        }
    }

    fn compatibility_gap(&self, feature: CpuCompatibilityGap) -> CpuError {
        CpuError::CompatibilityGap {
            opcode: self.site.opcode,
            ip: self.site.ip,
            feature,
        }
    }

    fn access_context_eflags(&self) -> u32 {
        self.access_context_eflags.unwrap_or(self.site.eflags)
    }

    fn invalidate_plans(&mut self) {
        if self.epoch == u64::MAX {
            self.owner = Arc::new(());
            self.epoch = 0;
        } else {
            self.epoch += 1;
        }
    }

    fn execution_mode_checked(&self) -> Option<CpuExecutionMode> {
        self.checked_execution_mode().ok().flatten()
    }

    fn checked_execution_mode(&self) -> Result<Option<CpuExecutionMode>, CpuError> {
        if self.uses_legacy_projection() {
            return Ok(self.resolver.execution_mode());
        }
        let Some(cpu_mode) = self.system.execution_mode(self.access_context_eflags()) else {
            return Err(self.unsupported_mode());
        };
        Ok(Some(cpu_mode))
    }

    fn checked_cpl(&self) -> Option<u8> {
        if self.uses_legacy_projection() {
            return self.resolver.current_privilege_level();
        }
        match self.execution_mode_checked()? {
            CpuExecutionMode::RealAddress => Some(0),
            CpuExecutionMode::Virtual8086 => Some(3),
            CpuExecutionMode::Protected => (self.system.cpl <= 3).then_some(self.system.cpl),
        }
    }

    fn uses_legacy_projection(&self) -> bool {
        // Unknown or protected selector projections remain behind the checked
        // resolver until a machine-owned hidden-state boundary is established.
        // A known RealAddress/CPL0 resolver is initialized once at step entry;
        // the hint alone never manufactures either value.
        !self.system.architectural_context_initialized
            && self.system.cr0 & CR0_PE == 0
            && self.access_context_eflags() & (1 << 17) == 0
            && !(self.resolver.execution_mode() == Some(CpuExecutionMode::RealAddress)
                && self.resolver.current_privilege_level() == Some(0)
                && !self.resolver.protected_mode())
    }

    fn resolve_logical_byte(
        &self,
        selector: u16,
        offset: u32,
        kind: AccessKind,
        write: bool,
    ) -> Result<PhysAddr, CpuError> {
        // `offset` is canonical within this span: data/stack applied one
        // address-size truncation above, while fetch offsets came canonical
        // from the decoder. Pass a 32-bit width so the resolver does not wrap
        // each byte of the span independently.
        if write {
            self.resolver.resolve_write(selector, offset, true)
        } else if kind == AccessKind::Fetch {
            self.resolver.resolve_execute(selector, offset, true)
        } else {
            self.resolver.resolve_read(selector, offset, true)
        }
    }

    fn real_mode_limit_fault(&self, span: LogicalSpan) -> CpuError {
        if span.register == SegmentRegister::Ss {
            CpuError::StackSegmentFault {
                error_code: 0,
                ip: self.site.ip,
            }
        } else {
            CpuError::GeneralProtectionFault {
                error_code: 0,
                ip: self.site.ip,
            }
        }
    }

    fn validate_chunks(&self, chunks: &[PhysicalChunk], read: bool) -> Result<(), CpuError> {
        for chunk in chunks {
            if read {
                self.memory.validate_read(chunk.address, chunk.len)?;
            } else {
                self.memory.validate_write(chunk.address, chunk.len)?;
            }
        }
        Ok(())
    }

    fn validate_plan(
        &self,
        access: &PreparedAccess,
        bytes_len: usize,
        write: bool,
    ) -> Result<(), CpuError> {
        if !Arc::ptr_eq(&access.owner, &self.owner)
            || access.epoch != self.epoch
            || access.len != bytes_len
            || (write && !access.can_write)
            || (!write && !access.can_read)
        {
            return Err(self.error_site());
        }
        let chunks = if write {
            &access.write_chunks
        } else {
            &access.read_chunks
        };
        self.validate_chunks(chunks, !write)
    }

}

impl<M: GuestMemory, S: SegmentResolver> CpuBus for CpuMemoryAccess<'_, M, S> {
    fn prepare(&mut self, request: AccessRequest) -> Result<PreparedAccess, CpuError> {
        self.prepare_request(request)
    }

    fn prepare_group(&mut self, requests: &[AccessRequest]) -> Result<PreparedGroup, CpuError> {
        let mut accesses = Vec::new();
        accesses
            .try_reserve_exact(requests.len())
            .map_err(|_| CpuError::Memory(MemoryError::AllocationFailed))?;
        for request in requests {
            accesses.push(self.prepare_request_unchecked_alignment(*request)?);
        }
        // The selected generic IA-32 policy preflights every segment, page,
        // and backing range before applying any #AC gate. Intel leaves the
        // same-class data #PF/#AC order implementation-dependent.
        for access in &accesses {
            self.check_prepared_alignment(access)?;
        }
        Ok(PreparedGroup { accesses })
    }

    fn prepare_logical_with_cache(
        &mut self,
        span: LogicalSpan,
        kind: AccessKind,
        alignment: DataAlignment,
        origin: AccessOrigin,
        cache: SegmentCache,
    ) -> Result<PreparedAccess, CpuError> {
        if self.uses_legacy_projection() {
            return Err(self.unsupported_mode());
        }
        let parts = self.prepare_architectural_logical_with_cache(span, kind, cache)?;
        self.check_alignment(kind, alignment, origin, None, parts.linear_start)?;
        Ok(self.prepared_logical(parts, kind, alignment, origin, None))
    }

    fn prepare_group_for_stack(
        &mut self,
        requests: &[AccessRequest],
        temporary_ss: SegmentCache,
        target_cpl: u8,
    ) -> Result<PreparedGroup, CpuError> {
        if self.uses_legacy_projection() || target_cpl > 3 {
            return Err(self.unsupported_mode());
        }
        let address_space = PagingAddressSpace::for_protected_target(self.system.cr3, target_cpl)
            .ok_or_else(|| self.unsupported_mode())?;
        self.plan_group_for_stack_in_address_space(requests, temporary_ss, address_space)
    }

    fn prepare_system_linear_in_address_space(
        &mut self,
        address: LinearAddr,
        len: usize,
        kind: AccessKind,
        address_space: PagingAddressSpace,
    ) -> Result<PreparedAccess, CpuError> {
        if self.uses_legacy_projection() {
            return Err(self.unsupported_mode());
        }
        self.plan_system_linear_in_address_space(address, len, kind, address_space)
    }

    fn prepare_group_for_stack_in_address_space(
        &mut self,
        requests: &[AccessRequest],
        temporary_ss: SegmentCache,
        address_space: PagingAddressSpace,
    ) -> Result<PreparedGroup, CpuError> {
        if self.uses_legacy_projection() {
            return Err(self.unsupported_mode());
        }
        self.plan_group_for_stack_in_address_space(requests, temporary_ss, address_space)
    }

    fn invlpg_linear_address(&mut self, span: LogicalSpan) -> Result<LinearAddr, CpuError> {
        self.checked_invlpg_linear_address(span)
    }

    fn read_prepared(&mut self, access: &PreparedAccess, bytes: &mut [u8]) -> Result<(), CpuError> {
        self.validate_plan(access, bytes.len(), false)?;
        for chunk in &access.read_chunks {
            let end = chunk
                .buffer_offset
                .checked_add(chunk.len)
                .filter(|end| *end <= bytes.len())
                .ok_or_else(|| self.error_site())?;
            self.memory
                .read(chunk.address, &mut bytes[chunk.buffer_offset..end])?;
        }
        self.record_data_breakpoints(access, false);
        Ok(())
    }

    fn write_prepared(&mut self, access: PreparedAccess, bytes: &[u8]) -> Result<(), CpuError> {
        self.validate_plan(&access, bytes.len(), true)?;
        for chunk in &access.write_chunks {
            let end = chunk
                .buffer_offset
                .checked_add(chunk.len)
                .filter(|end| *end <= bytes.len())
                .ok_or_else(|| self.error_site())?;
            self.memory
                .write(chunk.address, &bytes[chunk.buffer_offset..end])?;
        }
        self.record_data_breakpoints(&access, true);
        Ok(())
    }

    fn atomic_replace_prepared(
        &mut self,
        read_access: &PreparedAccess,
        write_access: &PreparedAccess,
        expected: &[u8],
        replacement: &[u8],
    ) -> Result<bool, CpuError> {
        if expected.is_empty() || expected.len() != replacement.len() {
            return Err(self.error_site());
        }
        self.validate_plan(read_access, expected.len(), false)?;
        self.validate_plan(write_access, expected.len(), true)?;
        let mut ranges = Vec::new();
        ranges
            .try_reserve_exact(write_access.write_chunks.len())
            .map_err(|_| CpuError::Memory(MemoryError::AllocationFailed))?;
        for chunk in &write_access.write_chunks {
            ranges.push(AtomicMemoryRange {
                offset: chunk.address.0,
                length: chunk.len,
            });
        }
        let mut value = Vec::new();
        value
            .try_reserve_exact(expected.len())
            .map_err(|_| CpuError::Memory(MemoryError::AllocationFailed))?;
        value.resize(expected.len(), 0);
        let mut replaced = false;
        let mut update = |current: &mut [u8]| {
            if current == expected {
                current.copy_from_slice(replacement);
                replaced = true;
            }
        };
        match self.memory.atomic_update(&ranges, &mut value, &mut update) {
            Ok(()) => {
                if replaced {
                    self.record_data_breakpoints(read_access, false);
                    self.record_data_breakpoints(write_access, true);
                }
                Ok(replaced)
            }
            Err(MemoryError::AtomicityUnavailable) => Err(self
                .compatibility_gap(CpuCompatibilityGap::AtomicBusTransaction)),
            Err(error) => Err(CpuError::Memory(error)),
        }
    }

    fn atomic_update(
        &mut self,
        request: AccessRequest,
        update: &mut dyn FnMut(&mut [u8]),
    ) -> Result<(), CpuError> {
        cpu_bus::atomic_update(self, request, update)
    }

    fn validate_near_code_target(
        &mut self,
        selector: u16,
        target: u32,
    ) -> Result<(), CpuError> {
        target_validation::validate_near_code_target(self, selector, target)
    }

    fn take_data_breakpoint_hits(&mut self) -> DataBreakpointHits {
        std::mem::take(&mut self.data_breakpoint_hits)
    }

    fn set_processor_event_error_ext(&mut self, external: bool) {
        self.processor_event_error_ext = external;
    }

    fn set_access_context_eflags(&mut self, eflags: u32) {
        self.access_context_eflags = Some(eflags);
        self.invalidate_plans();
    }

    fn system(&self) -> &CpuSystem {
        self.system
    }

    fn instruction_site(&self) -> AccessSite {
        self.site
    }

    fn system_mut(&mut self) -> &mut CpuSystem {
        self.invalidate_plans();
        self.system
    }

    fn execution_mode(&self) -> Option<CpuExecutionMode> {
        self.execution_mode_checked()
    }

    fn current_privilege_level(&self) -> Option<u8> {
        self.checked_cpl()
    }

    fn architectural_mode_active(&self) -> bool {
        !self.uses_legacy_projection()
    }

    fn code_bits(&self) -> u32 {
        if self.uses_legacy_projection() {
            self.resolver.code_bits()
        } else {
            self.system.code_bits()
        }
    }

    fn stack32(&self) -> bool {
        if self.uses_legacy_projection() {
            self.resolver.stack32()
        } else {
            self.system.stack32()
        }
    }

    fn protected_mode_format_hint(&self) -> bool {
        if self.uses_legacy_projection() {
            self.resolver.protected_mode()
        } else {
            self.system.execution_mode(self.access_context_eflags())
                == Some(CpuExecutionMode::Protected)
        }
    }
}

fn coalesce_addresses(addresses: Vec<PhysAddr>) -> Result<Vec<PhysicalChunk>, CpuError> {
    let mut chunks: Vec<PhysicalChunk> = Vec::new();
    chunks
        .try_reserve_exact(addresses.len())
        .map_err(|_| CpuError::Memory(MemoryError::AllocationFailed))?;
    for (buffer_offset, address) in addresses.into_iter().enumerate() {
        if let Some(previous) = chunks.last_mut() {
            if u64::from(previous.address.0) + previous.len as u64 == u64::from(address.0) {
                previous.len = previous
                    .len
                    .checked_add(1)
                    .ok_or(CpuError::Memory(MemoryError::AddressOverflow))?;
                continue;
            }
        }
        chunks.push(PhysicalChunk {
            address,
            buffer_offset,
            len: 1,
        });
    }
    Ok(chunks)
}
