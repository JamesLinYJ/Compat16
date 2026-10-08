//! Fixed guest-heap storage and selector ownership for loaded Win16 NE segments.
//!
//! These allocations share the runtime's ordinary guest memory. The global
//! heap handle is retained only for kernel-side ownership; guest execution
//! addresses the block through its stable selector.

use std::error::Error;
use std::fmt;

use formats::{
    FormatError, NeImportTarget, NeImportValue, NeLoadResolver, NeLoadedModule, NeModule,
};
use guest_core::{memory::Memory, OwnerId, PhysAddr, Selector};
use win16_abi::{
    Access, AccessRights, AllocationFlags, GlobalHandle, GlobalHeap, SelectorRef,
    SelectorTable, SegmentedPointer, Win16Error,
};

use crate::{DiagnosticKind, RuntimeError};

const MODULE_ALLOCATION_OWNER: OwnerId = OwnerId(u32::MAX);
const SEGMENT_DATA: u16 = 0x0001;
const MAX_NE_SEGMENT_SIZE: u32 = 0x1_0000;

/// One fixed global-heap block paired with the selector used by the guest.
/// `handle` is internal bookkeeping and must not be returned as a Win16 module
/// handle; guest code receives the selector at `selector.raw().0`.
pub(super) struct ModuleAllocation {
    pub(super) handle: GlobalHandle,
    pub(super) selector: SelectorRef,
    locked: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ModuleAllocationRelease {
    Released,
    DeferredByGuestLock,
}

impl ModuleAllocation {
    /// Allocate a fixed block in the shared guest heap and retain exactly one
    /// lock so its selector remains stable for the lifetime of the segment.
    pub(super) fn allocate(
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
        memory: &mut Memory,
        size: u32,
        executable: bool,
    ) -> Result<Self, RuntimeError> {
        Self::allocate_reserved(heap, selectors, memory, size, size, executable)
    }

    /// The automatic data segment retains adjacent private capacity. The
    /// checked selector and GlobalSize expose only its current logical size;
    /// this reserve is released by the same module-allocation owner.
    pub(super) fn allocate_reserved(
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
        memory: &mut Memory,
        size: u32,
        capacity: u32,
        executable: bool,
    ) -> Result<Self, RuntimeError> {
        if size == 0 || size > MAX_NE_SEGMENT_SIZE {
            return Err(RuntimeError::new(
                DiagnosticKind::InvalidInput,
                "Win16 NE segment allocation size must be between 1 and 64 KiB",
            ));
        }
        if capacity < size || capacity > MAX_NE_SEGMENT_SIZE {
            return Err(RuntimeError::new(DiagnosticKind::InvalidInput,
                "Win16 NE segment capacity is outside its logical size and 64 KiB limit"));
        }

        let flags = if executable {
            AllocationFlags::fixed().with_zero_init().with_execute()
        } else {
            AllocationFlags::fixed().with_zero_init()
        };
        let handle = heap
            .alloc_reserved(memory, MODULE_ALLOCATION_OWNER, size, capacity, flags)
            .map_err(|error| RuntimeError::from(error).with_context("allocating a Win16 NE segment"))?;

        let pointer = match heap.lock(handle, selectors, memory) {
            Ok(pointer) => pointer,
            Err(primary_error) => {
                let primary = RuntimeError::from(primary_error)
                    .with_context("locking a newly allocated Win16 NE segment");
                return match heap.free(handle, selectors) {
                    Ok(()) => Err(primary),
                    Err(rollback_error) => Err(RuntimeError::with_source(
                        DiagnosticKind::InternalInvariant,
                        "failed to roll back a partially allocated Win16 NE segment",
                        AllocationRollbackFailure {
                            primary,
                            rollback: rollback_error,
                        },
                    )),
                };
            }
        };

        if pointer.offset() != 0 {
            let primary = RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "global-heap lock returned a nonzero Win16 segment offset",
            );
            let allocation = Self {
                handle,
                selector: pointer.selector(),
                locked: true,
            };
            return match allocation.release(heap, selectors) {
                Ok(()) => Err(primary),
                Err(rollback) => Err(RuntimeError::with_source(
                    DiagnosticKind::InternalInvariant,
                    "failed to roll back a malformed Win16 segment lock",
                    AllocationRollbackRuntimeFailure { primary, rollback },
                )),
            };
        }

        Ok(Self {
            handle,
            selector: pointer.selector(),
            locked: true,
        })
    }

    pub(super) fn extend_in_place(
        &self,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
        memory: &Memory,
        old_size: u32,
        new_size: u32,
    ) -> Result<(), RuntimeError> {
        if !self.locked {
            return Err(RuntimeError::new(DiagnosticKind::InternalInvariant,
                "Win16 data growth lost its module lifetime pin"));
        }
        heap.grow_reserved_in_place(self.handle, MODULE_ALLOCATION_OWNER,
            old_size, new_size, selectors, memory).map_err(crate::runtime_error)
    }

    /// Unlock this allocation's baseline heap pin and free the block.
    /// Consuming release is reserved for unpublished allocation rollback;
    /// published module owners use `release_in_place` so failures retain them.
    pub(super) fn release(
        mut self,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
    ) -> Result<(), RuntimeError> {
        match self.release_in_place(heap, selectors)? {
            ModuleAllocationRelease::Released => Ok(()),
            ModuleAllocationRelease::DeferredByGuestLock => Err(RuntimeError::new(
                DiagnosticKind::ResourceExhausted,
                "Win16 segment release is deferred while a guest lock or selector/page view remains live",
            )),
        }
    }

    pub(super) fn release_in_place(
        &mut self,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
    ) -> Result<ModuleAllocationRelease, RuntimeError> {
        // Windows 3.1 SDK Programmer's Reference, Vol. 2, pp. 600 and 959–960,
        // requires a LockSegment owner to remain resident until its matching
        // UnlockSegment. GlobalBlockInfo reports guest lock counts, not this
        // owner's internal loader pin. Keep that pin while guest locks remain
        // so FreeLibrary can retire logically and UnlockSegment can find it.
        let info = heap.info(self.handle)
            .map_err(|error| internal_module_error("querying Win16 segment guest locks", error))?;
        let aliases = heap.selector_alias_count(self.handle)
            .map_err(|error| internal_module_error("querying Win16 segment selector aliases", error))?;
        if info.lock_count != 0 || info.page_lock_count != 0 || aliases != 0 {
            return Ok(ModuleAllocationRelease::DeferredByGuestLock);
        }

        if self.locked {
            let pins = heap.internal_pin_count(self.handle)
                .map_err(|error| internal_module_error("querying a loaded Win16 segment pin", error))?;
            if pins != 1 {
                return Err(RuntimeError::new(
                    DiagnosticKind::InternalInvariant,
                    "loaded Win16 segment owner does not hold exactly its baseline selector pin",
                ));
            }
            let remaining = heap
                .unlock(self.handle, selectors)
                .map_err(|error| internal_module_error("unlocking a loaded Win16 segment", error))?;
            self.locked = false;
            if remaining != 0 {
                return Err(RuntimeError::new(
                    DiagnosticKind::InternalInvariant,
                    "loaded Win16 segment has an unexpected additional heap lock",
                ));
            }
        }

        let info = heap.info(self.handle)
            .map_err(|error| internal_module_error("rechecking Win16 segment guest locks", error))?;
        let aliases = heap.selector_alias_count(self.handle)
            .map_err(|error| internal_module_error("rechecking Win16 segment selector aliases", error))?;
        if info.lock_count != 0 || info.page_lock_count != 0 || aliases != 0 {
            return Ok(ModuleAllocationRelease::DeferredByGuestLock);
        }
        let pins = heap.internal_pin_count(self.handle)
            .map_err(|error| internal_module_error("rechecking a loaded Win16 segment pin", error))?;
        if pins != 0 || heap.retention_pin_count(self.handle)
            .map_err(|error| internal_module_error("rechecking Win16 segment retained owners", error))? != 0
        {
            return Err(RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "loaded Win16 segment retained an internal selector pin after its owner released",
            ));
        }

        heap.free(self.handle, selectors)
            .map_err(|error| internal_module_error("freeing a loaded Win16 segment", error))?;
        Ok(ModuleAllocationRelease::Released)
    }
}

/// NE resolver over segments allocated up front from `GlobalHeap`.
///
/// The caller owns the allocation vector. Entry zero is module metadata and
/// later entries are fixed segment blocks; segment identity is matched by
/// selector so removing one block during rollback does not shift identities.
pub(super) struct PreparedModuleResolver<'a, F> {
    heap: &'a mut GlobalHeap,
    selectors: &'a mut SelectorTable,
    allocations: &'a mut Vec<ModuleAllocation>,
    definition: &'a NeModule,
    plan: &'a NeLoadedModule,
    memory_len: u32,
    imports: F,
    release_error: Option<RuntimeError>,
}

impl<'a, F> PreparedModuleResolver<'a, F>
where
    F: FnMut(&[u8], &NeImportTarget) -> Result<NeImportValue, FormatError>,
{
    pub(super) fn new(
        heap: &'a mut GlobalHeap,
        selectors: &'a mut SelectorTable,
        allocations: &'a mut Vec<ModuleAllocation>,
        definition: &'a NeModule,
        plan: &'a NeLoadedModule,
        memory_len: u32,
        imports: F,
    ) -> Result<Self, FormatError> {
        let expected_allocation_count = plan
            .segments
            .len()
            .checked_add(1)
            .ok_or(FormatError::InvalidNeLoad("prepared NE segment count overflowed"))?;
        if definition.segments.len() != plan.segments.len()
            || allocations.len() != expected_allocation_count
            || allocations.is_empty()
        {
            return Err(FormatError::InvalidNeLoad(
                "prepared NE definition, plan, and allocation counts disagree",
            ));
        }

        validate_metadata_allocation(heap, selectors, &allocations[0])?;
        let mut planned_selectors = Vec::new();
        planned_selectors
            .try_reserve_exact(plan.segments.len())
            .map_err(|_| FormatError::AllocationFailed)?;
        for (index, (segment, loaded)) in definition
            .segments
            .iter()
            .zip(&plan.segments)
            .enumerate()
        {
            let expected_number = u16::try_from(index + 1)
                .map_err(|_| FormatError::InvalidNeLoad("prepared NE segment number exceeds its limit"))?;
            if segment.number != expected_number
                || loaded.number != expected_number
                || loaded.selector.0 == 0
                || loaded.memory_size == 0
                || loaded.memory_size > MAX_NE_SEGMENT_SIZE
            {
                return Err(FormatError::InvalidNeLoad(
                    "prepared NE plan has noncontiguous segments or invalid sizes",
                ));
            }
            if planned_selectors.contains(&loaded.selector) {
                return Err(FormatError::InvalidNeLoad(
                    "prepared NE plan contains duplicate segment selectors",
                ));
            }
            if loaded.selector == allocations[0].selector.raw() {
                return Err(FormatError::InvalidNeLoad(
                    "module metadata selector is also assigned to an NE segment",
                ));
            }
            let allocation_index = find_segment_allocation_index(allocations, loaded.selector)
                .ok_or(FormatError::InvalidNeLoad(
                    "prepared NE segment allocation is missing or duplicated",
                ))?;
            validate_allocation(
                heap,
                selectors,
                &allocations[allocation_index],
                loaded.selector,
                loaded.memory_size,
                segment.flags,
            )?;
            planned_selectors.push(loaded.selector);
        }

        Ok(Self {
            heap,
            selectors,
            allocations,
            definition,
            plan,
            memory_len,
            imports,
            release_error: None,
        })
    }

    /// A release failure cannot be returned through `NeLoadResolver`'s void
    /// rollback hook. The owning transaction can collect it after loading and
    /// then retry/free all allocations still present in its vector.
    pub(super) fn take_release_error(&mut self) -> Option<RuntimeError> {
        self.release_error.take()
    }
}

impl<F> NeLoadResolver for PreparedModuleResolver<'_, F>
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
        if module != self.definition {
            return Err(FormatError::InvalidNeLoad(
                "NE loader requested a segment from a different module definition",
            ));
        }
        let index = usize::from(segment_number.checked_sub(1).ok_or(
            FormatError::InvalidNeLoad("NE segment number zero is invalid"),
        )?);
        let segment = self.definition.segments.get(index).ok_or(FormatError::InvalidNeLoad(
            "requested NE segment is outside the parsed module",
        ))?;
        let loaded = self.plan.segments.get(index).ok_or(FormatError::InvalidNeLoad(
            "requested NE segment has no prepared allocation requirement",
        ))?;
        if segment.number != segment_number
            || loaded.number != segment_number
            || loaded.memory_size != size
            || segment.flags != flags
        {
            return Err(FormatError::InvalidNeLoad(
                "NE segment size or flags disagree with its prepared allocation",
            ));
        }

        let allocation_index = find_segment_allocation_index(self.allocations, loaded.selector)
            .ok_or(FormatError::InvalidNeLoad(
                "requested NE segment allocation is missing",
            ))?;
        validate_allocation(
            self.heap,
            self.selectors,
            &self.allocations[allocation_index],
            loaded.selector,
            loaded.memory_size,
            flags,
        )?;
        Ok(loaded.selector)
    }

    fn selector_range(
        &self,
        selector: Selector,
        offset: u32,
        length: usize,
    ) -> Result<PhysAddr, FormatError> {
        let loaded = self
            .plan
            .segments
            .iter()
            .find(|loaded| loaded.selector == selector)
            .ok_or(FormatError::InvalidNeLoad(
                "NE resolver was asked for a selector it does not own",
            ))?;
        let segment_index = usize::from(loaded.number.checked_sub(1).ok_or(
            FormatError::InvalidNeLoad("NE segment number zero is invalid"),
        )?);
        let flags = self
            .definition
            .segments
            .get(segment_index)
            .ok_or(FormatError::InvalidNeLoad(
                "NE selector has no corresponding definition",
            ))?
            .flags;
        let allocation_index = find_segment_allocation_index(self.allocations, selector)
            .ok_or(FormatError::InvalidNeLoad(
                "NE selector no longer has a live prepared allocation",
            ))?;
        validate_allocation(
            self.heap,
            self.selectors,
            &self.allocations[allocation_index],
            selector,
            loaded.memory_size,
            flags,
        )?;
        let offset = u16::try_from(offset)
            .map_err(|_| FormatError::InvalidNeLoad("NE selector offset exceeds 16 bits"))?;
        self.selectors
            .address_within(
                SegmentedPointer::new(self.allocations[allocation_index].selector, offset),
                Access::Read,
                length,
                self.memory_len,
            )
            .map_err(|_| FormatError::InvalidNeLoad("NE selector range exceeds its prepared segment"))
    }

    fn release_segment(&mut self, selector: Selector) {
        if !self.plan.segments.iter().any(|segment| segment.selector == selector) {
            self.record_release_error(RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "NE loader attempted to release an unowned prepared segment selector",
            ));
            return;
        }
        let Some(index) = find_segment_allocation_index(self.allocations, selector) else {
            self.record_release_error(RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "NE loader attempted to release a prepared segment that is already absent",
            ));
            return;
        };

        let release_result = self.allocations[index].release_in_place(self.heap, self.selectors);
        match release_result {
            Ok(ModuleAllocationRelease::Released) => {
                self.allocations.remove(index);
            }
            Ok(ModuleAllocationRelease::DeferredByGuestLock) => self.record_release_error(
                RuntimeError::new(
                    DiagnosticKind::ResourceExhausted,
                    "prepared Win16 NE segment still has an outstanding guest segment lock",
                ),
            ),
            Err(error) => self.record_release_error(error.with_context(
                format!("rolling back NE segment selector {:#06x}", selector.0),
            )),
        }
    }

    fn resolve_import(
        &mut self,
        module_name: &[u8],
        target: &NeImportTarget,
    ) -> Result<NeImportValue, FormatError> {
        (self.imports)(module_name, target)
    }
}

impl<F> PreparedModuleResolver<'_, F> {
    fn record_release_error(&mut self, error: RuntimeError) {
        if self.release_error.is_none() {
            self.release_error = Some(error);
        }
    }
}

fn validate_allocation(
    heap: &GlobalHeap,
    selectors: &SelectorTable,
    allocation: &ModuleAllocation,
    expected_selector: Selector,
    expected_size: u32,
    flags: u16,
) -> Result<(), FormatError> {
    let executable = flags & SEGMENT_DATA == 0;
    let block = heap.info(allocation.handle).map_err(|_| {
        FormatError::InvalidNeLoad("prepared NE segment has a stale global-heap handle")
    })?;
    // ModuleAllocation owns one internal selector pin. Guest lock counts are
    // independent and cannot establish ownership of this retained selector.
    let pins = heap.internal_pin_count(allocation.handle).map_err(|_| {
        FormatError::InvalidNeLoad("prepared NE segment has a stale global-heap handle")
    })?;
    if !allocation.locked
        || allocation.selector.raw() != expected_selector
        || block.size != expected_size
        || block.executable != executable
        || block.movable
        || pins != 1
    {
        return Err(FormatError::InvalidNeLoad(
            "prepared NE segment block has the wrong size, rights, or lock state",
        ));
    }

    let descriptor = selectors.describe(allocation.selector).map_err(|_| {
        FormatError::InvalidNeLoad("prepared NE segment has a stale selector")
    })?;
    let rights = if executable {
        AccessRights::read_write_execute()
    } else {
        AccessRights::read_write()
    };
    if descriptor.base != block.base
        || descriptor.limit.checked_add(1) != Some(expected_size)
        || descriptor.rights != rights
    {
        return Err(FormatError::InvalidNeLoad(
            "prepared NE segment selector does not match its guest-heap block",
        ));
    }
    Ok(())
}

fn validate_metadata_allocation(
    heap: &GlobalHeap,
    selectors: &SelectorTable,
    allocation: &ModuleAllocation,
) -> Result<(), FormatError> {
    let block = heap.info(allocation.handle).map_err(|_| {
        FormatError::InvalidNeLoad("module metadata has a stale global-heap handle")
    })?;
    let descriptor = selectors.describe(allocation.selector).map_err(|_| {
        FormatError::InvalidNeLoad("module metadata has a stale selector")
    })?;
    let pins = heap.internal_pin_count(allocation.handle).map_err(|_| {
        FormatError::InvalidNeLoad("module metadata has a stale global-heap handle")
    })?;
    if !allocation.locked
        || block.movable
        || pins != 1
        || block.executable
        || descriptor.base != block.base
        || descriptor.limit.checked_add(1) != Some(block.size)
        || descriptor.rights != AccessRights::read_write()
    {
        return Err(FormatError::InvalidNeLoad(
            "module metadata allocation has invalid size, rights, or lock state",
        ));
    }
    Ok(())
}

/// Return the unique segment allocation index for a planned selector. Index
/// zero is reserved for module metadata and is never returned.
fn find_segment_allocation_index(
    allocations: &[ModuleAllocation],
    selector: Selector,
) -> Option<usize> {
    let mut matches = allocations
        .iter()
        .enumerate()
        .skip(1)
        .filter_map(|(index, allocation)| {
            (allocation.selector.raw() == selector).then_some(index)
        });
    let index = matches.next()?;
    matches.next().is_none().then_some(index)
}

fn internal_module_error(operation: &'static str, error: Win16Error) -> RuntimeError {
    RuntimeError::with_source(DiagnosticKind::InternalInvariant, operation, error)
}

#[derive(Debug)]
struct AllocationRollbackFailure {
    primary: RuntimeError,
    rollback: Win16Error,
}

impl fmt::Display for AllocationRollbackFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}; freeing the partially allocated block also failed: {}",
            self.primary, self.rollback,
        )
    }
}

impl Error for AllocationRollbackFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.primary)
    }
}

#[derive(Debug)]
struct AllocationRollbackRuntimeFailure {
    primary: RuntimeError,
    rollback: RuntimeError,
}

impl fmt::Display for AllocationRollbackRuntimeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}; cleanup also failed: {}", self.primary, self.rollback)
    }
}

impl Error for AllocationRollbackRuntimeFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.primary)
    }
}
