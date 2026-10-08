//! Exact, temporary leases for guest-visible LDT data descriptors.
//!
//! A machine owner may project one checked guest allocation into the active
//! LDT. The CPU writes and later restores the real descriptor-table bytes;
//! it never substitutes a hidden cache for the descriptor guest instructions
//! can observe through MOV, LAR, or LSL.

use std::sync::Arc;

use guest_core::{GuestMemory, LinearAddr, MemoryError};

use crate::{
    Cpu, CpuError, CpuExecutionMode, SegmentResolver,
    memory_access::{
        AccessKind, AccessRequest, AccessSite, CpuBus, CpuMemoryAccess,
        LogicalSpan, PhysicalChunk, PreparedAccess,
    },
    registers::SegmentRegister,
    system::{CpuSystem, DescriptorRecord, DescriptorType, SegmentCache, SegmentTableRegister, read_descriptor},
};

/// Exact temporary descriptor installed in the CPU's currently loaded LDT.
/// The descriptor is a present, writable, 16-bit data segment at the current
/// CPL; the selector's RPL must also match that CPL.
#[derive(Debug)]
pub struct CpuGuestLdtDataSegmentLease {
    selector: u16,
    address: LinearAddr,
    original: [u8; 8],
    installed: [u8; 8],
    physical_footprint: Vec<PhysicalChunk>,
    publication: CpuGuestLdtPublication,
    table_root: CpuGuestLdtRoot,
    cpu_origin: Arc<u8>,
}

#[derive(Debug)]
enum CpuGuestLdtPublication {
    NotPublished,
    Published,
    Indeterminate(CpuError),
}

impl CpuGuestLdtDataSegmentLease {
    pub const fn selector(&self) -> u16 {
        self.selector
    }
}

/// Failed restoration keeps the exact lease so the machine can retain it for
/// teardown retry instead of dropping a live descriptor owner.
#[derive(Debug)]
pub struct CpuGuestLdtDescriptorLeaseError {
    error: CpuError,
    lease: CpuGuestLdtDataSegmentLease,
}

/// Installation can fail after the descriptor publication attempt starts.
/// The optional lease must be retained whenever present: it records either
/// the exact published bytes or an indeterminate storage failure.
#[derive(Debug)]
pub struct CpuGuestLdtDescriptorInstallError {
    error: CpuError,
    lease: Option<CpuGuestLdtDataSegmentLease>,
}

impl CpuGuestLdtDescriptorInstallError {
    pub fn into_parts(self) -> (CpuError, Option<CpuGuestLdtDataSegmentLease>) {
        (self.error, self.lease)
    }
}

impl From<CpuError> for CpuGuestLdtDescriptorInstallError {
    fn from(error: CpuError) -> Self {
        Self { error, lease: None }
    }
}

impl CpuGuestLdtDescriptorLeaseError {
    pub fn into_parts(self) -> (CpuError, CpuGuestLdtDataSegmentLease) {
        (self.error, self.lease)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CpuGuestLdtRoot {
    cr0: u32,
    cr3: u32,
    cpl: u8,
    gdtr: SegmentTableRegister,
    idtr: SegmentTableRegister,
    ldtr_selector: u16,
    ldtr_base: u32,
    ldtr_limit: u32,
    ldtr_system_type: u8,
    ldtr_present: bool,
    ldtr_valid: bool,
    task_selector: u16,
    task_base: u32,
    task_limit: u32,
    task_system_type: u8,
    task_present: bool,
    task_valid: bool,
    architectural_context_initialized: bool,
}

impl CpuGuestLdtRoot {
    fn capture(system: &CpuSystem) -> Self {
        Self {
            cr0: system.cr0,
            cr3: system.cr3,
            cpl: system.cpl,
            gdtr: system.gdtr,
            idtr: system.idtr,
            ldtr_selector: system.ldtr.selector,
            ldtr_base: system.ldtr.base,
            ldtr_limit: system.ldtr.limit,
            ldtr_system_type: system.ldtr.system_type,
            ldtr_present: system.ldtr.present,
            ldtr_valid: system.ldtr.valid,
            task_selector: system.task.selector,
            task_base: system.task.base,
            task_limit: system.task.limit,
            task_system_type: system.task.system_type,
            task_present: system.task.present,
            task_valid: system.task.valid,
            architectural_context_initialized: system.architectural_context_initialized,
        }
    }
}

/// Current CPL when architectural segment caches are active.
fn current_privilege_level(cpu: &Cpu) -> Option<u8> {
    cpu.architectural_execution_mode().map(|_| cpu.system.cpl)
}

/// Snapshot the current hidden SS projection without exposing mutable CPU
/// state. Runtime owners use it to prove that their checked selector mapping
/// addresses the same guest bytes before preparing an event frame.
fn current_stack_segment_projection(cpu: &Cpu) -> crate::CpuSegmentCacheState {
    let cache = cpu
        .system
        .segment_cache(crate::registers::SegmentRegister::Ss);
    let (access, flags) = cache.descriptor.cache_fields();
    crate::CpuSegmentCacheState {
        selector: cache.selector,
        base: cache.descriptor.base,
        limit: cache.descriptor.limit,
        access,
        flags,
        usable: !cache.unusable,
    }
}

impl Cpu {
    pub fn current_privilege_level(&self) -> Option<u8> {
        current_privilege_level(self)
    }

    pub fn current_stack_segment_projection(&self) -> crate::CpuSegmentCacheState {
        current_stack_segment_projection(self)
    }

    /// Validate a candidate 16-bit stack selector through the active CPU
    /// tables and current-CPL page permissions, without loading it into SS.
    pub fn guest_stack_range_is_identity_mapped(
        &self,
        selector: u16,
        offset: u16,
        len: usize,
        write: bool,
        memory: &mut impl GuestMemory,
        segments: &impl SegmentResolver,
    ) -> Result<bool, CpuError> {
        let site = self.observer_site();
        let mut system = self.system;
        let cache = match self.architectural_execution_mode() {
            Some(CpuExecutionMode::RealAddress) => SegmentCache::real_mode(selector, false),
            Some(CpuExecutionMode::Protected) => {
                let cpl = system.cpl;
                let mut bus = CpuMemoryAccess::new(memory, segments, &mut system, site);
                let Some(record) = read_guest_descriptor_for_projection(&mut bus, selector)? else {
                    return Ok(false);
                };
                if record.descriptor.default_big
                    || record.descriptor.validate_stack_load(selector, cpl).is_err()
                {
                    return Ok(false);
                }
                SegmentCache::from_descriptor(selector, record.descriptor)
            }
            Some(CpuExecutionMode::Virtual8086) | None => return Ok(false),
        };
        let span = LogicalSpan {
            register: SegmentRegister::Ss,
            selector,
            offset: u32::from(offset),
            len,
            address32: false,
        };
        let kind = if write { AccessKind::StackWrite } else { AccessKind::StackRead };
        let mut bus = CpuMemoryAccess::new(memory, segments, &mut system, site);
        bus.logical_range_is_identity_mapped(span, kind, cache)
    }

    /// Resolve the hardware code selector for a machine-owned guest selector
    /// projection. Protected mode accepts only a descriptor in the live GDT
    /// or LDT with the same base/limit and a same-CPL 16-bit code contract.
    /// Real-address mode requires the selector's architectural `<< 4` base to
    /// match the runtime mapping exactly.
    pub fn guest_code_selector_for_projection(
        &self,
        projected_selector: u16,
        base: u32,
        limit: u32,
        target: u16,
        memory: &mut impl GuestMemory,
        segments: &impl SegmentResolver,
    ) -> Result<Option<u16>, CpuError> {
        match self.architectural_execution_mode() {
            Some(CpuExecutionMode::RealAddress) => {
                if base != (u32::from(projected_selector) << 4)
                    || u32::from(target) > limit
                {
                    return Ok(None);
                }
                let mut system = self.system;
                let cache = SegmentCache::real_mode(projected_selector, true);
                let mut bus = CpuMemoryAccess::new(
                    memory,
                    segments,
                    &mut system,
                    self.observer_site(),
                );
                let span = LogicalSpan {
                    register: SegmentRegister::Cs,
                    selector: projected_selector,
                    offset: u32::from(target),
                    len: 1,
                    address32: false,
                };
                Ok(bus
                    .logical_range_is_identity_mapped(span, AccessKind::Fetch, cache)?
                    .then_some(projected_selector))
            }
            Some(CpuExecutionMode::Protected) => {
                let Some(cpl) = self.current_privilege_level() else {
                    return Ok(None);
                };
                let gdt = (projected_selector & !0x07) | u16::from(cpl);
                let ldt = gdt | 0x04;
                let candidates = if projected_selector & 0x04 != 0 {
                    [ldt, gdt]
                } else {
                    [gdt, ldt]
                };
                for selector in candidates {
                    let mut system = self.system;
                    let site = self.observer_site();
                    let mut bus = CpuMemoryAccess::new(memory, segments, &mut system, site);
                    let Some(record) = read_guest_descriptor_for_projection(&mut bus, selector)? else {
                        continue;
                    };
                    if record.descriptor.base != base
                        || record.descriptor.limit != limit
                        || record.descriptor.default_big
                        || !matches!(record.descriptor.descriptor_type, DescriptorType::Code { .. })
                        || u32::from(target) > record.descriptor.limit
                        || record.descriptor.validate_direct_code_transfer(selector, cpl).is_err()
                    {
                        continue;
                    }
                    let cache = SegmentCache::from_descriptor(selector, record.descriptor);
                    drop(bus);
                    let site = self.observer_site();
                    let mut system = self.system;
                    let mut bus = CpuMemoryAccess::new(memory, segments, &mut system, site);
                    if bus.logical_range_is_identity_mapped(
                        LogicalSpan {
                            register: SegmentRegister::Cs,
                            selector,
                            offset: u32::from(target),
                            len: 1,
                            address32: false,
                        },
                        AccessKind::Fetch,
                        cache,
                    )? {
                        return Ok(Some(selector));
                    }
                }
                Ok(None)
            }
            Some(CpuExecutionMode::Virtual8086) | None => Ok(None),
        }
    }

    /// Return whether `selector` names an all-zero descriptor slot in the
    /// active LDT. Only selector-table slots that are both runtime-free and
    /// CPU-table-free may be used for a temporary guest projection.
    pub fn guest_ldt_slot_is_empty(
        &self,
        selector: u16,
        memory: &mut impl GuestMemory,
        segments: &impl SegmentResolver,
    ) -> Result<bool, CpuError> {
        let address = self.checked_guest_ldt_address(selector)?;
        let site = self.observer_site();
        let mut system = self.system;
        let mut bus = CpuMemoryAccess::new(memory, segments, &mut system, site);
        let access = bus.prepare(AccessRequest::SystemLinear {
            address,
            len: 8,
            kind: AccessKind::SystemTableRead,
        })?;
        let mut bytes = [0_u8; 8];
        bus.read_prepared(&access, &mut bytes)?;
        Ok(bytes == [0; 8])
    }

    /// Publish a checked 16-bit writable data descriptor into one all-zero
    /// slot of the active LDT. The selector table and caller own the matching
    /// guest allocation; this CPU lease owns only the exact LDT bytes.
    pub fn install_guest_ldt_data_segment(
        &mut self,
        selector: u16,
        base: u32,
        limit: u32,
        memory: &mut impl GuestMemory,
        segments: &impl SegmentResolver,
    ) -> Result<CpuGuestLdtDataSegmentLease, CpuGuestLdtDescriptorInstallError> {
        let address = self.checked_guest_ldt_address(selector)?;
        if limit > 0x000f_ffff
            || self.system.cpl > 3
            || selector & 3 != u16::from(self.system.cpl)
        {
            return Err(CpuError::InvalidMemoryAccessPlan {
                ip: self.regs.eip,
            }
            .into());
        }
        let root = CpuGuestLdtRoot::capture(&self.system);
        let dpl = self.system.cpl;
        let site = self.observer_site();
        let mut system = self.system;
        let mut bus = CpuMemoryAccess::new(
            memory,
            segments,
            &mut system,
            site,
        );
        let read = bus.prepare(AccessRequest::SystemLinear {
            address,
            len: 8,
            kind: AccessKind::SystemTableRead,
        })?;
        let write = bus.prepare(AccessRequest::SystemLinear {
            address,
            len: 8,
            kind: AccessKind::SystemTableWrite,
        })?;
        let mut old = [0_u8; 8];
        bus.read_prepared(&read, &mut old)?;
        if old != [0; 8] {
            return Err(CpuError::GeneralProtectionFault {
                error_code: u32::from(selector & 0xfffc),
                ip: self.regs.eip,
            }
            .into());
        }

        let installed = encode_writable_16bit_data_segment(
            base,
            limit,
            dpl,
        )?;
        let read_footprint = physical_footprint(&read, false)?;
        let physical_footprint = physical_footprint(&write, true)?;
        if read_footprint != physical_footprint {
            return Err(CpuError::InvalidMemoryAccessPlan {
                ip: self.regs.eip,
            }
            .into());
        }
        let mut lease = CpuGuestLdtDataSegmentLease {
            selector,
            address,
            original: old,
            installed,
            physical_footprint,
            publication: CpuGuestLdtPublication::NotPublished,
            table_root: root,
            cpu_origin: Arc::clone(&self.call_continuation_origin),
        };
        // Ordinary writes may split across physical chunks and fail after
        // publishing only a prefix. Atomic replacement either declines before
        // invoking the update or reports a storage failure; in the latter case
        // the lease remains attached with an indeterminate publication state.
        match bus.atomic_replace_prepared(&read, &write, &old, &installed) {
            Ok(true) => {
                lease.publication = CpuGuestLdtPublication::Published;
                Ok(lease)
            }
            Ok(false) => Err(CpuGuestLdtDescriptorInstallError {
                error: CpuError::GeneralProtectionFault {
                    error_code: u32::from(selector & 0xfffc),
                    ip: self.regs.eip,
                },
                lease: Some(lease),
            }),
            Err(error) => {
                if matches!(
                    &error,
                    CpuError::Memory(MemoryError::StorageAccess { write: true, .. })
                ) {
                    // A partial backing transfer cannot be rolled back from a
                    // stale snapshot. Retain the owner and stop normal release.
                    lease.publication = CpuGuestLdtPublication::Indeterminate(error.clone());
                }
                Err(CpuGuestLdtDescriptorInstallError {
                    error,
                    lease: Some(lease),
                })
            }
        }
    }

    /// Restore the exact eight bytes originally present at a leased LDT slot.
    /// If the CPU table root or bytes changed while guest code ran, return the
    /// lease to its owner and leave the guest's changed descriptor untouched.
    pub fn restore_guest_ldt_data_segment(
        &mut self,
        mut lease: CpuGuestLdtDataSegmentLease,
        memory: &mut impl GuestMemory,
        segments: &impl SegmentResolver,
    ) -> Result<(), CpuGuestLdtDescriptorLeaseError> {
        let fail = |error, lease| CpuGuestLdtDescriptorLeaseError { error, lease };
        match &lease.publication {
            CpuGuestLdtPublication::NotPublished => return Ok(()),
            CpuGuestLdtPublication::Indeterminate(error) => {
                return Err(fail(error.clone(), lease));
            }
            CpuGuestLdtPublication::Published => {}
        }
        if !Arc::ptr_eq(&self.call_continuation_origin, &lease.cpu_origin)
            || CpuGuestLdtRoot::capture(&self.system) != lease.table_root
            || self.architectural_execution_mode() != Some(CpuExecutionMode::Protected)
        {
            return Err(fail(
                CpuError::InvalidMemoryAccessPlan {
                    ip: self.regs.eip,
                },
                lease,
            ));
        }
        let site = self.observer_site();
        let mut system = self.system;
        let mut bus = CpuMemoryAccess::new(
            memory,
            segments,
            &mut system,
            site,
        );
        let read = match bus.prepare(AccessRequest::SystemLinear {
            address: lease.address,
            len: 8,
            kind: AccessKind::SystemTableRead,
        }) {
            Ok(access) => access,
            Err(error) => return Err(fail(error, lease)),
        };
        let current_footprint = match physical_footprint(&read, false) {
            Ok(footprint) => footprint,
            Err(error) => return Err(fail(error, lease)),
        };
        if current_footprint != lease.physical_footprint {
            // The guest can remap the LDT linear slot without changing CR3.
            // Refuse to clear a descriptor from a different physical page.
            return Err(fail(
                CpuError::InvalidMemoryAccessPlan {
                    ip: self.regs.eip,
                },
                lease,
            ));
        }
        let mut current = [0_u8; 8];
        if let Err(error) = bus.read_prepared(&read, &mut current) {
            return Err(fail(error, lease));
        }
        if current != lease.installed {
            return Err(fail(
                CpuError::GeneralProtectionFault {
                    error_code: u32::from(lease.selector & 0xfffc),
                    ip: self.regs.eip,
                },
                lease,
            ));
        }
        let write = match bus.prepare(AccessRequest::SystemLinear {
            address: lease.address,
            len: 8,
            kind: AccessKind::SystemTableWrite,
        }) {
            Ok(access) => access,
            Err(error) => return Err(fail(error, lease)),
        };
        let write_footprint = match physical_footprint(&write, true) {
            Ok(footprint) => footprint,
            Err(error) => return Err(fail(error, lease)),
        };
        if write_footprint != lease.physical_footprint {
            return Err(fail(
                CpuError::InvalidMemoryAccessPlan {
                    ip: self.regs.eip,
                },
                lease,
            ));
        }
        match bus.atomic_replace_prepared(&read, &write, &lease.installed, &lease.original) {
            Ok(true) => {}
            Ok(false) => {
                return Err(fail(
                    CpuError::GeneralProtectionFault {
                        error_code: u32::from(lease.selector & 0xfffc),
                        ip: self.regs.eip,
                    },
                    lease,
                ));
            }
            Err(error) => {
                if matches!(
                    &error,
                    CpuError::Memory(MemoryError::StorageAccess { write: true, .. })
                ) {
                    lease.publication = CpuGuestLdtPublication::Indeterminate(error.clone());
                }
                return Err(fail(error, lease));
            }
        }
        Ok(())
    }

    fn checked_guest_ldt_address(&self, selector: u16) -> Result<LinearAddr, CpuError> {
        if self.architectural_execution_mode() != Some(CpuExecutionMode::Protected)
            || !self.system.ldtr.valid
            || !self.system.ldtr.present
            || selector & 0x04 == 0
        {
            return Err(CpuError::UnsupportedSystemMode {
                opcode: 0,
                ip: self.regs.eip,
            });
        }
        let table = SegmentTableRegister {
            base: LinearAddr(self.system.ldtr.base),
            limit: self.system.ldtr.limit,
        };
        table
            .descriptor_address(selector)
            .map_err(|_| CpuError::GeneralProtectionFault {
                error_code: u32::from(selector & 0xfffc),
                ip: self.regs.eip,
            })
    }

    fn observer_site(&self) -> AccessSite {
        AccessSite {
            opcode: 0,
            ip: self.regs.eip,
            eflags: self.regs.eflags,
        }
    }
}

/// Invalid guest selector/table references decline this optional projection;
/// host storage and resource failures must reach the caller and stop execution.
fn read_guest_descriptor_for_projection(
    bus: &mut impl CpuBus,
    selector: u16,
) -> Result<Option<DescriptorRecord>, CpuError> {
    match read_descriptor(bus, selector) {
        Ok(record) => Ok(Some(record)),
        Err(CpuError::GeneralProtectionFault { .. } | CpuError::PageFault { .. }) => Ok(None),
        Err(error) => Err(error),
    }
}

fn physical_footprint(
    access: &PreparedAccess,
    write: bool,
) -> Result<Vec<PhysicalChunk>, CpuError> {
    let chunks = access.physical_chunks(write);
    let mut footprint = Vec::new();
    footprint
        .try_reserve_exact(chunks.len())
        .map_err(|_| CpuError::Memory(MemoryError::AllocationFailed))?;
    footprint.extend_from_slice(chunks);
    Ok(footprint)
}

fn encode_writable_16bit_data_segment(
    base: u32,
    limit: u32,
    dpl: u8,
) -> Result<[u8; 8], CpuError> {
    if dpl > 3 || limit > 0x000f_ffff {
        return Err(CpuError::InvalidMemoryAccessPlan { ip: 0 });
    }
    let access = 0x93 | (dpl << 5);
    let limit_low = (limit & 0xffff) as u16;
    let limit_high = ((limit >> 16) & 0x0f) as u8;
    let base_low = base as u16;
    let base_middle = (base >> 16) as u8;
    let base_high = (base >> 24) as u8;
    Ok([
        limit_low as u8,
        (limit_low >> 8) as u8,
        base_low as u8,
        (base_low >> 8) as u8,
        base_middle,
        access,
        limit_high,
        base_high,
    ])
}
