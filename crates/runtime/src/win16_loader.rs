//! NE segment placement and checked Win16 selector execution context.
//!
//! Selectors describe ranges of the one process-owned guest memory buffer.
//! Import targets use the Win16 ABI catalog. Unimplemented imports retain
//! their identity at a service gate so an unused import can remain unresolved;
//! calling that gate reports the missing bridge without pretending success.

use std::collections::BTreeMap;

use x86_cpu::{CpuError, SegmentAccess, SegmentFaultReason, SegmentResolver};
use formats::{FormatError, NeImportTarget, NeImportValue, NeLoadResolver, NeModule};
use guest_core::{PhysAddr, Selector};
use win16_abi::{Access, AccessRights, SegmentedPointer, SelectorRef, SelectorTable, Win16Error};

const SEGMENT_DATA: u16 = 0x0001;
const SEGMENT_ALIGNMENT: u32 = 16;
// Automatic data segments may grow to the Win16 near-pointer address limit.
// Reserving adjacent ordinary RAM is allocator policy; the initial selector
// limit and reported allocation size remain the NE logical requirement.
pub(crate) const AUTOMATIC_DATA_CAPACITY: u32 = 0x1_0000;

pub(crate) struct StaticDataReservation {
    pub(crate) selector: SelectorRef,
    pub(crate) base: PhysAddr,
    pub(crate) size: u32,
    pub(crate) capacity: u32,
}

pub(crate) struct Win16LoadResolver<F> {
    pub(crate) selectors: SelectorTable,
    allocations: BTreeMap<u16, SelectorRef>,
    automatic_data: Option<StaticDataReservation>,
    next_base: u32,
    arena_end: u32,
    memory_len: u32,
    imports: F,
}

impl<F> Win16LoadResolver<F>
where
    F: FnMut(&[u8], &NeImportTarget) -> Result<NeImportValue, FormatError>,
{
    pub(crate) fn new(
        selectors: SelectorTable,
        arena_base: PhysAddr,
        arena_end: PhysAddr,
        memory_len: u32,
        imports: F,
    ) -> Result<Self, FormatError> {
        if arena_base.0 >= arena_end.0 || arena_end.0 > memory_len {
            return Err(FormatError::InvalidNeLoad("Win16 segment arena is outside guest memory"));
        }
        Ok(Self {
            selectors,
            allocations: BTreeMap::new(),
            automatic_data: None,
            next_base: arena_base.0,
            arena_end: arena_end.0,
            memory_len,
            imports,
        })
    }

    pub(crate) fn finish(self) -> (SelectorTable, PhysAddr, Option<StaticDataReservation>) {
        (self.selectors, PhysAddr(self.next_base), self.automatic_data)
    }
}

impl<F> NeLoadResolver for Win16LoadResolver<F>
where
    F: FnMut(&[u8], &NeImportTarget) -> Result<NeImportValue, FormatError>,
{
    fn allocate_segment(
        &mut self,
        module: &NeModule,
        segment_number: u16,
        size: u32,
        flags: u16,
    ) -> Result<Selector, FormatError> {
        let base = self.next_base.checked_add(SEGMENT_ALIGNMENT - 1)
            .map(|value| value & !(SEGMENT_ALIGNMENT - 1))
            .ok_or(FormatError::ArithmeticOverflow)?;
        let automatic = module.header.automatic_data_segment == segment_number
            && flags & SEGMENT_DATA != 0;
        let capacity = if automatic { AUTOMATIC_DATA_CAPACITY } else { size };
        let end = base.checked_add(capacity).ok_or(FormatError::ArithmeticOverflow)?;
        if size == 0 || end > self.arena_end {
            return Err(FormatError::AllocationFailed);
        }
        let rights = if flags & SEGMENT_DATA != 0 {
            AccessRights::read_write()
        } else {
            AccessRights::code()
        };
        let reference = self.selectors.alloc_block(
            PhysAddr(base), size, rights, &MemoryExtent(self.memory_len),
        ).map_err(|_| FormatError::AllocationFailed)?;
        self.next_base = end;
        self.allocations.insert(reference.raw().0, reference);
        if automatic {
            self.automatic_data = Some(StaticDataReservation {
                selector: reference, base: PhysAddr(base), size, capacity,
            });
        }
        Ok(reference.raw())
    }

    fn selector_range(&self, selector: Selector, offset: u32, length: usize) -> Result<PhysAddr, FormatError> {
        let offset = u16::try_from(offset)
            .map_err(|_| FormatError::InvalidNeLoad("NE selector offset exceeds 16 bits"))?;
        let pointer = self.selectors.pointer_from_raw(selector, offset)
            .map_err(|_| FormatError::InvalidNeLoad("NE selector is not allocated"))?;
        self.selectors.address_within(pointer, Access::Read, length, self.memory_len)
            .map_err(|_| FormatError::InvalidNeLoad("NE selector range exceeds its segment"))
    }

    fn release_segment(&mut self, selector: Selector) {
        if let Some(reference) = self.allocations.remove(&selector.0) {
            let _ = self.selectors.free_block(reference);
            if self.automatic_data.as_ref().is_some_and(|reservation| reservation.selector == reference) {
                self.automatic_data = None;
            }
        }
    }

    fn resolve_import(&mut self, module_name: &[u8], target: &NeImportTarget) -> Result<NeImportValue, FormatError> {
        (self.imports)(module_name, target)
    }
}

/// Metadata-only extent used while allocating selectors. NE segments are
/// placed entirely inside the runtime-owned ordinary RAM arena.
struct MemoryExtent(u32);

impl guest_core::GuestMemory for MemoryExtent {
    fn len(&self) -> u32 { self.0 }
    fn read(&self, _address: PhysAddr, _bytes: &mut [u8]) -> Result<(), guest_core::MemoryError> {
        Err(guest_core::MemoryError::InvalidMapping)
    }
    fn write(&mut self, _address: PhysAddr, _bytes: &[u8]) -> Result<(), guest_core::MemoryError> {
        Err(guest_core::MemoryError::InvalidMapping)
    }
}

pub(crate) struct Win16Segments<'a> {
    pub(crate) selectors: &'a SelectorTable,
    pub(crate) memory_len: u32,
}

impl Win16Segments<'_> {
    fn address(&self, selector: u16, offset: u32, access: Access) -> Result<PhysAddr, CpuError> {
        let cpu_access = match access {
            Access::Read => SegmentAccess::Read,
            Access::Write => SegmentAccess::Write,
            Access::Execute => SegmentAccess::Execute,
        };
        let fault = |reason| CpuError::SegmentFault { selector, offset, access: cpu_access, reason };
        let narrow = u16::try_from(offset).map_err(|_| fault(SegmentFaultReason::Limit))?;
        let pointer: SegmentedPointer = self.selectors.pointer_from_raw(Selector(selector), narrow)
            .map_err(|_| fault(SegmentFaultReason::NotPresent))?;
        self.selectors.address_within(pointer, access, 1, self.memory_len)
            .map_err(|error| fault(match error {
                Win16Error::AccessDenied { .. } => SegmentFaultReason::AccessDenied,
                Win16Error::LimitViolation { .. } | Win16Error::InvalidRange => SegmentFaultReason::Limit,
                _ => SegmentFaultReason::NotPresent,
            }))
    }
}

impl SegmentResolver for Win16Segments<'_> {
    fn jit_range(&self, selector: u16, offset: u32, length: usize, access: SegmentAccess) -> Option<PhysAddr> {
        let pointer = self.selectors.pointer_from_raw(Selector(selector), u16::try_from(offset).ok()?).ok()?;
        let access = match access { SegmentAccess::Read => Access::Read, SegmentAccess::Write => Access::Write, SegmentAccess::Execute => Access::Execute };
        self.selectors.address_within(pointer, access, length, self.memory_len).ok()
    }
    fn resolve(&self, selector: u16, offset: u32, _address32: bool) -> Result<PhysAddr, CpuError> {
        self.address(selector, offset, Access::Read)
    }
    fn resolve_read(&self, selector: u16, offset: u32, _address32: bool) -> Result<PhysAddr, CpuError> {
        self.address(selector, offset, Access::Read)
    }
    fn resolve_write(&self, selector: u16, offset: u32, _address32: bool) -> Result<PhysAddr, CpuError> {
        self.address(selector, offset, Access::Write)
    }
    fn resolve_execute(&self, selector: u16, offset: u32, _address32: bool) -> Result<PhysAddr, CpuError> {
        self.address(selector, offset, Access::Execute)
    }
    fn protected_mode(&self) -> bool { true }
}
