use crate::{next_object_id, Win16Error};
use guest_core::{GuestMemory, PhysAddr, Selector};

mod allocation;
mod allocation_views;
mod descriptor;
mod exact_slot;
mod guest_api;

pub use descriptor::DescriptorInfo;
use descriptor::{AllocationResizePolicy, Descriptor};

const SEGMENT_BYTES: u64 = 0x1_0000;
const SELECTOR_SHIFT: usize = 3;
const DEFAULT_SELECTOR_SLOTS: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Access { Read, Write, Execute }

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AccessRights {
    readable: bool,
    writable: bool,
    executable: bool,
}

impl AccessRights {
    pub const fn read_only() -> Self {
        Self { readable: true, writable: false, executable: false }
    }
    pub const fn read_write() -> Self {
        Self { readable: true, writable: true, executable: false }
    }
    pub const fn read_write_execute() -> Self {
        Self { readable: true, writable: true, executable: true }
    }
    pub const fn code() -> Self {
        Self { readable: true, writable: false, executable: true }
    }
    pub const fn new(readable: bool, writable: bool, executable: bool) -> Self {
        Self { readable, writable, executable }
    }
    pub const fn readable(self) -> bool { self.readable }
    pub const fn writable(self) -> bool { self.writable }
    pub const fn executable(self) -> bool { self.executable }

    fn permits(self, access: Access) -> bool {
        match access {
            Access::Read => self.readable,
            Access::Write => self.writable,
            Access::Execute => self.executable,
        }
    }
}

/// A kernel-held selector identity scoped to one descriptor table. Its table
/// identity and generation prevent a freed or foreign selector reference from
/// validating even when another table has the same raw word and generation.
/// Mutable allocation extent remains in the descriptor, not this identity, so
/// an in-place growth can keep existing references valid. Guest code carries
/// only the raw selector, which may be reused and resolved to the current
/// descriptor under the Win16 ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SelectorRef {
    raw: Selector,
    generation: u64,
    table_id: u64,
    block_index: usize,
    segment_index: usize,
    segment_count: usize,
}

impl SelectorRef {
    pub const fn raw(self) -> Selector { self.raw }
    pub const fn generation(self) -> u64 { self.generation }
}

/// A checked Win16 far pointer. Its offset is a 16-bit guest value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SegmentedPointer {
    selector: SelectorRef,
    offset: u16,
}

impl SegmentedPointer {
    pub const fn new(selector: SelectorRef, offset: u16) -> Self { Self { selector, offset } }
    pub const fn selector(self) -> SelectorRef { self.selector }
    pub const fn offset(self) -> u16 { self.offset }
    pub const fn far_value(self) -> u32 {
        ((self.selector.raw.0 as u32) << 16) | self.offset as u32
    }
}

/// Exact snapshot of one complete selector block whose descriptors expose a
/// view into a process-owned allocation. The snapshot lets callers hide every
/// alias, then restore the same generation or retire it after backing deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectorAllocationView {
    table_id: u64,
    reference: SelectorRef,
    block_index: usize,
    segment_count: usize,
    resize_policy: AllocationResizePolicy,
    generation: u64,
    descriptors: Vec<Descriptor>,
}

impl SelectorAllocationView {
    /// Stable head identity for this captured block.
    pub const fn reference(&self) -> SelectorRef { self.reference }
}

/// Owns one descriptor table. Guest bytes remain in shared GuestMemory.
/// Selector refs are scoped to this table; cloning the table would duplicate
/// ownership and is deliberately unsupported.
#[derive(Debug)]
pub struct SelectorTable {
    id: u64,
    entries: Vec<Option<Descriptor>>,
    next_generation: u64,
}

impl SelectorTable {
    pub fn new() -> Result<Self, Win16Error> {
        Self::with_capacity(DEFAULT_SELECTOR_SLOTS)
    }

    /// Slot zero is reserved as the null selector; `slots` includes it.
    pub fn with_capacity(slots: usize) -> Result<Self, Win16Error> {
        if !(2..=DEFAULT_SELECTOR_SLOTS).contains(&slots) { return Err(Win16Error::InvalidRange); }
        Ok(Self {
            id: next_object_id()?,
            entries: vec![None; slots],
            next_generation: 1,
        })
    }

    pub fn alloc_block(
        &mut self,
        base: PhysAddr,
        size: u32,
        rights: AccessRights,
        memory: &impl GuestMemory,
    ) -> Result<SelectorRef, Win16Error> {
        self.alloc_block_with_policy(
            base,
            size,
            rights,
            memory,
            AllocationResizePolicy::FollowAllocationExtent,
        )
    }

    /// Allocate one independent descriptor while retaining its exact limit if
    /// a containing GlobalHeap allocation later grows. Its base can still be
    /// rebound if that backing allocation moves.
    pub fn alloc_fixed_selector_descriptor(
        &mut self,
        base: PhysAddr,
        size: u32,
        rights: AccessRights,
        memory: &impl GuestMemory,
    ) -> Result<SelectorRef, Win16Error> {
        self.alloc_block_with_policy(
            base,
            size,
            rights,
            memory,
            AllocationResizePolicy::PreserveDescriptorShape,
        )
    }

    fn alloc_block_with_policy(
        &mut self,
        base: PhysAddr,
        size: u32,
        rights: AccessRights,
        memory: &impl GuestMemory,
        resize_policy: AllocationResizePolicy,
    ) -> Result<SelectorRef, Win16Error> {
        self.check_range(base, size, rights, memory)?;
        let count = segment_count(size)?;
        if resize_policy == AllocationResizePolicy::PreserveDescriptorShape && count != 1 {
            return Err(Win16Error::InvalidSize);
        }
        let block_index = self.find_contiguous(count).ok_or(Win16Error::SelectorTableFull)?;
        let generation = self.take_generation()?;
        self.install_block(block_index, count, base, size, rights, resize_policy, generation);
        self.reference_for(block_index, 0).ok_or(Win16Error::StaleSelector)
    }

    /// Reserve a stable selector identity without mapping guest memory. It is
    /// not usable for reads or writes until rebound to a checked allocation.
    pub fn reserve_unbacked(&mut self) -> Result<SelectorRef, Win16Error> {
        self.reserve_unbacked_with_policy(AllocationResizePolicy::FollowAllocationExtent)
    }

    /// Reserve one unbacked descriptor for an independent AllocSelector
    /// identity. PrestoChango can later bind it without changing its identity.
    pub fn reserve_fixed_selector_descriptor(&mut self) -> Result<SelectorRef, Win16Error> {
        self.reserve_unbacked_with_policy(AllocationResizePolicy::PreserveDescriptorShape)
    }

    fn reserve_unbacked_with_policy(
        &mut self,
        resize_policy: AllocationResizePolicy,
    ) -> Result<SelectorRef, Win16Error> {
        let block_index = self.find_contiguous(1).ok_or(Win16Error::SelectorTableFull)?;
        let generation = self.take_generation()?;
        self.install_unbacked(block_index, 1, resize_policy, generation);
        self.reference_for(block_index, 0).ok_or(Win16Error::StaleSelector)
    }

    fn mark_unbacked(&mut self, reference: SelectorRef) -> Result<SelectorRef, Win16Error> {
        let descriptor = self.validate(reference)?;
        if descriptor.segment_index != 0 || selector_index(reference.raw) != descriptor.block_index {
            return Err(Win16Error::SelectorBlockInterior);
        }
        self.validate_all_segments(descriptor)?;
        let generation = self.take_generation()?;
        for segment in 0..descriptor.segment_count {
            self.entries[descriptor.block_index + segment] = None;
        }
        self.install_unbacked(
            descriptor.block_index,
            descriptor.segment_count,
            descriptor.resize_policy,
            generation,
        );
        self.reference_for(descriptor.block_index, 0).ok_or(Win16Error::StaleSelector)
    }

    /// Number of selector table slots, including the reserved null slot.
    pub fn slot_capacity(&self) -> usize { self.entries.len() }

    /// Retire every descriptor, including guest-created aliases, before task
    /// backing is released. Keep the generation counter so reusing this table
    /// cannot make a retained reference valid again. Native callbacks must
    /// already have stopped before the runtime ends their guest address space.
    pub fn invalidate_all(&mut self) {
        self.entries.fill(None);
    }

    /// Creates a fresh writable-data alias of a valid selector, as required by
    /// KERNEL.170. The source selector and its ownership remain unchanged.
    pub fn alloc_cs_to_ds_alias(
        &mut self,
        source: SelectorRef,
        memory: &impl GuestMemory,
    ) -> Result<SelectorRef, Win16Error> {
        let descriptor = self.validate(source)?;
        if !descriptor.present { return Err(Win16Error::InvalidSelector); }
        let size = descriptor.limit.checked_add(1).ok_or(Win16Error::InvalidRange)?;
        let rights = if descriptor.rights.executable() {
            AccessRights::new(true, descriptor.rights.readable(), false)
        } else {
            AccessRights::new(true, descriptor.rights.writable(), false)
        };
        let alias = self.alloc_fixed_selector_descriptor(
            descriptor.base, size, rights, memory,
        )?;
        let index = selector_index(alias.raw);
        let target = self.entries.get_mut(index).and_then(Option::as_mut)
            .ok_or(Win16Error::StaleSelector)?;
        target.access_flags = descriptor.access_flags ^ 0x0008;
        Ok(alias)
    }

    /// Resolves a raw selector in this runtime's table to its current generation.
    /// The Win16 ABI reuses raw selector words; an old raw word therefore may
    /// resolve to a later allocation. Retained `SelectorRef`s do not revive.
    pub fn reference(&self, raw: Selector) -> Result<SelectorRef, Win16Error> {
        let reference = self.reference_for(selector_index(raw), 0)
            .ok_or(Win16Error::InvalidSelector)?;
        if !self.validate(reference)?.present { return Err(Win16Error::InvalidSelector); }
        Ok(reference)
    }

    /// Resolves an installed selector identity even when it is currently
    /// unbacked. KERNEL.175 needs this to copy valid uninitialized selector
    /// descriptors; memory accesses must continue to use `reference`.
    pub fn reference_including_unbacked(
        &self,
        raw: Selector,
    ) -> Result<SelectorRef, Win16Error> {
        let reference = self.reference_for(selector_index(raw), 0)
            .ok_or(Win16Error::InvalidSelector)?;
        self.validate(reference)?;
        Ok(reference)
    }

    pub fn pointer_from_raw(&self, raw: Selector, offset: u16) -> Result<SegmentedPointer, Win16Error> {
        Ok(SegmentedPointer::new(self.reference(raw)?, offset))
    }

    /// Converts the Win16 `selector:offset` 32-bit representation.
    pub fn pointer_from_far(&self, far: u32) -> Result<SegmentedPointer, Win16Error> {
        self.pointer_from_raw(Selector((far >> 16) as u16), far as u16)
    }

    /// Size of the complete allocation containing this selector. A block may
    /// span several 64 KiB descriptors; one descriptor limit is not its size.
    pub fn allocation_size(&self, reference: SelectorRef) -> Result<u32, Win16Error> {
        Ok(self.validate(reference)?.block_size)
    }

    /// Returns the checked head identity and complete allocation range for
    /// any selector in a multi-segment block. Descriptor-local bases advance
    /// for interior selectors, while block_size remains the full allocation
    /// length; callers that resolve allocation owners must use this canonical
    /// range instead of pairing those two different extents.
    pub fn allocation_range(
        &self,
        reference: SelectorRef,
    ) -> Result<(SelectorRef, PhysAddr, u32), Win16Error> {
        let descriptor = self.validate(reference)?;
        self.validate_all_segments(descriptor)?;
        let head = self.reference_for(descriptor.block_index, 0)
            .ok_or(Win16Error::StaleSelector)?;
        let head_descriptor = self.validate(head)?;
        if head_descriptor.segment_index != 0
            || head_descriptor.block_index != descriptor.block_index
            || head_descriptor.segment_count != descriptor.segment_count
            || head_descriptor.generation != descriptor.generation
            || !head_descriptor.present
        {
            return Err(Win16Error::StaleSelector);
        }
        Ok((head, head_descriptor.base, head_descriptor.block_size))
    }

    pub fn describe(&self, reference: SelectorRef) -> Result<DescriptorInfo, Win16Error> {
        let descriptor = self.validate(reference)?;
        Ok(DescriptorInfo {
            selector: reference.raw,
            base: descriptor.base,
            limit: descriptor.limit,
            rights: descriptor.rights,
            segment_index: descriptor.segment_index,
            segment_count: descriptor.segment_count,
            present: descriptor.present,
        })
    }

    pub fn free_block(&mut self, reference: SelectorRef) -> Result<(), Win16Error> {
        let descriptor = self.validate(reference)?;
        if descriptor.segment_index != 0 || selector_index(reference.raw) != descriptor.block_index {
            return Err(Win16Error::SelectorBlockInterior);
        }
        self.validate_all_segments(descriptor)?;
        for segment in 0..descriptor.segment_count {
            self.entries[descriptor.block_index + segment] = None;
        }
        Ok(())
    }

    /// Frees one independently owned selector, as required by KERNEL.176.
    /// Multi-selector blocks are kept intact because the current ownership
    /// model represents them as one contiguous allocation; freeing one entry
    /// from such a run would require splitting that allocation and refreshing
    /// retained references to its segments.
    pub fn free_selector(&mut self, reference: SelectorRef) -> Result<(), Win16Error> {
        let descriptor = self.validate(reference)?;
        if descriptor.segment_count != 1 || descriptor.segment_index != 0 {
            return Err(Win16Error::SelectorBlockInterior);
        }
        self.free_block(reference)
    }

    /// Rebinds an owned block while preserving its raw selector. Shrinks and
    /// contiguous descriptor growth reuse its existing selector run. The method
    /// fails if growth would require moving the selector to another raw value.
    pub fn rebind(
        &mut self,
        reference: SelectorRef,
        base: PhysAddr,
        size: u32,
        rights: AccessRights,
        memory: &impl GuestMemory,
    ) -> Result<SelectorRef, Win16Error> {
        let plan = self.plan_rebind(reference, base, size, rights, memory)?;
        self.commit_rebind(plan).map(|(replacement, _undo)| replacement)
    }

    pub(crate) fn plan_rebind(
        &self,
        reference: SelectorRef,
        base: PhysAddr,
        size: u32,
        rights: AccessRights,
        memory: &impl GuestMemory,
    ) -> Result<SelectorRebindPlan, Win16Error> {
        let old = self.validate(reference)?;
        if old.segment_index != 0 || selector_index(reference.raw) != old.block_index {
            return Err(Win16Error::SelectorBlockInterior);
        }
        self.validate_all_segments(old)?;
        self.check_range(base, size, rights, memory)?;
        let new_count = segment_count(size)?;
        if !self.can_resize_in_place(old, new_count) { return Err(Win16Error::SelectorTableFull); }
        let next_generation = self.next_generation.checked_add(1).ok_or(Win16Error::GenerationExhausted)?;
        Ok(SelectorRebindPlan {
            table_id: self.id,
            old_reference: reference,
            old_descriptor: old,
            base,
            size,
            rights,
            access_flags: if rights == old.rights {
                old.access_flags
            } else {
                guest_api::canonical_access_flags(rights)
            },
            new_count,
            generation: self.next_generation,
            next_generation,
        })
    }

    pub(crate) fn commit_rebind(
        &mut self,
        plan: SelectorRebindPlan,
    ) -> Result<(SelectorRef, SelectorRebindUndo), Win16Error> {
        if plan.table_id != self.id || plan.generation != self.next_generation {
            return Err(Win16Error::StaleSelector);
        }
        if self.validate(plan.old_reference)? != plan.old_descriptor
            || !self.can_resize_in_place(plan.old_descriptor, plan.new_count)
        {
            return Err(Win16Error::StaleSelector);
        }

        let old = plan.old_descriptor;
        self.install_block_with_access_flags(
            old.block_index,
            plan.new_count,
            plan.base,
            plan.size,
            plan.rights,
            plan.access_flags,
            old.resize_policy,
            plan.generation,
        );
        for segment in plan.new_count..old.segment_count {
            self.entries[old.block_index + segment] = None;
        }
        self.next_generation = plan.next_generation;
        let replacement = match self.reference_for(old.block_index, 0) {
            Some(reference) => reference,
            None => {
                let run_len = old.segment_count.max(plan.new_count);
                for segment in 0..run_len {
                    self.entries[old.block_index + segment] = None;
                }
                self.restore_descriptor(old);
                self.next_generation = plan.generation;
                return Err(Win16Error::StaleSelector);
            }
        };
        let undo = SelectorRebindUndo {
            table_id: self.id,
            old_descriptor: old,
            new_count: plan.new_count,
            previous_next_generation: plan.generation,
        };
        Ok((replacement, undo))
    }

    /// Used only by the synchronous heap transaction before its mutable table
    /// borrow is released. Restores the exact prior generation and raw value.
    pub(crate) fn rollback_rebind(&mut self, undo: SelectorRebindUndo) {
        if undo.table_id != self.id { return; }
        let old = undo.old_descriptor;
        let run_len = old.segment_count.max(undo.new_count);
        for segment in 0..run_len {
            if let Some(entry) = self.entries.get_mut(old.block_index + segment) { *entry = None; }
        }
        self.restore_descriptor(old);
        self.next_generation = undo.previous_next_generation;
    }

    pub fn read(
        &self,
        memory: &impl GuestMemory,
        pointer: SegmentedPointer,
        output: &mut [u8],
    ) -> Result<(), Win16Error> {
        let address = self.translate(pointer, Access::Read, output.len(), memory)?;
        memory.read(address, output)?;
        Ok(())
    }

    pub fn write(
        &self,
        memory: &mut impl GuestMemory,
        pointer: SegmentedPointer,
        input: &[u8],
    ) -> Result<(), Win16Error> {
        let address = self.translate(pointer, Access::Write, input.len(), memory)?;
        memory.write(address, input)?;
        Ok(())
    }

    /// Returns the physical guest-memory address after selector, rights, and
    /// limit validation. This is an address in GuestMemory, never a host pointer.
    pub fn translate(
        &self,
        pointer: SegmentedPointer,
        access: Access,
        length: usize,
        memory: &impl GuestMemory,
    ) -> Result<PhysAddr, Win16Error> {
        let address = self.address_within(pointer, access, length, memory.len())?;
        match access {
            Access::Read | Access::Execute => memory.validate_read(address, length)?,
            Access::Write => memory.validate_write(address, length)?,
        }
        Ok(address)
    }

    /// Validate a selector against the configured guest address-space extent.
    /// Callers using this without a memory bus must own the described region
    /// and keep device/ROM access rules outside it.
    pub fn address_within(
        &self,
        pointer: SegmentedPointer,
        access: Access,
        length: usize,
        memory_len: u32,
    ) -> Result<PhysAddr, Win16Error> {
        let descriptor = self.validate(pointer.selector)?;
        if !descriptor.present { return Err(Win16Error::InvalidSelector); }
        if !descriptor.rights.permits(access) { return Err(Win16Error::AccessDenied { access }); }
        let end = u64::from(pointer.offset)
            .checked_add(u64::try_from(length).map_err(|_| Win16Error::InvalidRange)?)
            .ok_or(Win16Error::InvalidRange)?;
        if end > u64::from(descriptor.limit) + 1 {
            return Err(Win16Error::LimitViolation {
                offset: u32::from(pointer.offset), length, limit: descriptor.limit,
            });
        }
        let address = descriptor.base.0.checked_add(u32::from(pointer.offset)).ok_or(Win16Error::InvalidRange)?;
        let memory_end = u64::from(address)
            .checked_add(u64::try_from(length).map_err(|_| Win16Error::InvalidRange)?)
            .ok_or(Win16Error::InvalidRange)?;
        if memory_end > u64::from(memory_len) { return Err(Win16Error::InvalidRange); }
        Ok(PhysAddr(address))
    }

    /// Adds bytes across adjacent 64 KiB descriptors in the same owned block.
    pub fn add_bytes(
        &self,
        pointer: SegmentedPointer,
        amount: u32,
    ) -> Result<SegmentedPointer, Win16Error> {
        let descriptor = self.validate(pointer.selector)?;
        let local = (descriptor.segment_index as u64)
            .checked_mul(SEGMENT_BYTES)
            .and_then(|base| base.checked_add(u64::from(pointer.offset)))
            .and_then(|offset| offset.checked_add(u64::from(amount)))
            .ok_or(Win16Error::InvalidRange)?;
        if local >= u64::from(descriptor.block_size) {
            return Err(Win16Error::LimitViolation {
                offset: u32::try_from(local).unwrap_or(u32::MAX),
                length: 0,
                limit: descriptor.block_size.saturating_sub(1),
            });
        }
        let segment_index = usize::try_from(local / SEGMENT_BYTES).map_err(|_| Win16Error::InvalidRange)?;
        if segment_index >= descriptor.segment_count { return Err(Win16Error::InvalidRange); }
        let offset = u16::try_from(local % SEGMENT_BYTES).map_err(|_| Win16Error::InvalidRange)?;
        let selector = self.reference_for(descriptor.block_index, segment_index).ok_or(Win16Error::StaleSelector)?;
        Ok(SegmentedPointer::new(selector, offset))
    }

    fn validate(&self, reference: SelectorRef) -> Result<Descriptor, Win16Error> {
        if reference.table_id != self.id { return Err(Win16Error::ForeignSelector); }
        let index = selector_index(reference.raw);
        let descriptor = self.entries.get(index).and_then(|entry| *entry).ok_or(Win16Error::StaleSelector)?;
        if descriptor.generation != reference.generation
            || descriptor.block_index != reference.block_index
            || descriptor.segment_index != reference.segment_index
            || descriptor.segment_count != reference.segment_count
            || index != reference.block_index + reference.segment_index
        {
            return Err(Win16Error::StaleSelector);
        }
        Ok(descriptor)
    }

    fn validate_all_segments(&self, descriptor: Descriptor) -> Result<(), Win16Error> {
        for segment in 0..descriptor.segment_count {
            let entry = self.entries.get(descriptor.block_index + segment)
                .and_then(|entry| *entry).ok_or(Win16Error::StaleSelector)?;
            if entry.generation != descriptor.generation || entry.block_index != descriptor.block_index
                || entry.present != descriptor.present
            {
                return Err(Win16Error::StaleSelector);
            }
        }
        Ok(())
    }

    fn check_range(
        &self,
        base: PhysAddr,
        size: u32,
        rights: AccessRights,
        memory: &impl GuestMemory,
    ) -> Result<(), Win16Error> {
        if size == 0 { return Err(Win16Error::InvalidSize); }
        let end = u64::from(base.0) + u64::from(size);
        if end > u64::from(memory.len()) { return Err(Win16Error::InvalidRange); }
        let length = usize::try_from(size).map_err(|_| Win16Error::InvalidRange)?;
        if rights.readable() || rights.executable() { memory.validate_read(base, length)?; }
        if rights.writable() { memory.validate_write(base, length)?; }
        Ok(())
    }

    fn can_resize_in_place(&self, old: Descriptor, new_count: usize) -> bool {
        if new_count <= old.segment_count { return true; }
        let Some(old_end) = old.block_index.checked_add(old.segment_count) else { return false; };
        let Some(new_end) = old_end.checked_add(new_count - old.segment_count) else { return false; };
        new_end <= self.entries.len() && self.entries[old_end..new_end].iter().all(|entry| entry.is_none())
    }

    fn restore_descriptor(&mut self, old: Descriptor) {
        if old.present {
            self.install_block_with_access_flags(
                old.block_index, old.segment_count, old.base, old.block_size,
                old.rights, old.access_flags, old.resize_policy, old.generation,
            );
        } else {
            self.install_unbacked(
                old.block_index,
                old.segment_count,
                old.resize_policy,
                old.generation,
            );
        }
    }

    fn find_contiguous(&self, count: usize) -> Option<usize> {
        if count == 0 || count >= self.entries.len() { return None; }
        let mut run_start = 1;
        let mut run_len = 0;
        for index in 1..self.entries.len() {
            if self.entries[index].is_none() {
                if run_len == 0 { run_start = index; }
                run_len += 1;
                if run_len == count { return Some(run_start); }
            } else {
                run_len = 0;
            }
        }
        None
    }

    fn install_block(
        &mut self,
        block_index: usize,
        count: usize,
        base: PhysAddr,
        size: u32,
        rights: AccessRights,
        resize_policy: AllocationResizePolicy,
        generation: u64,
    ) {
        self.install_block_with_access_flags(
            block_index, count, base, size, rights,
            guest_api::canonical_access_flags(rights), resize_policy, generation,
        );
    }

    fn install_block_with_access_flags(
        &mut self,
        block_index: usize,
        count: usize,
        base: PhysAddr,
        size: u32,
        rights: AccessRights,
        access_flags: u16,
        resize_policy: AllocationResizePolicy,
        generation: u64,
    ) {
        for segment_index in 0..count {
            let byte_offset = segment_index as u64 * SEGMENT_BYTES;
            let remaining = u64::from(size) - byte_offset;
            let segment_size = remaining.min(SEGMENT_BYTES);
            let segment_base = base.0 + byte_offset as u32;
            self.entries[block_index + segment_index] = Some(Descriptor {
                base: PhysAddr(segment_base),
                limit: (segment_size - 1) as u32,
                rights,
                access_flags,
                resize_policy,
                generation,
                block_index,
                segment_index,
                segment_count: count,
                block_size: size,
                present: true,
            });
        }
    }

    fn install_unbacked(
        &mut self,
        block_index: usize,
        count: usize,
        resize_policy: AllocationResizePolicy,
        generation: u64,
    ) {
        for segment_index in 0..count {
            self.entries[block_index + segment_index] = Some(Descriptor {
                base: PhysAddr(0),
                limit: 0,
                rights: AccessRights::new(false, false, false),
                access_flags: 0,
                resize_policy,
                generation,
                block_index,
                segment_index,
                segment_count: count,
                block_size: 0,
                present: false,
            });
        }
    }

    fn reference_for(&self, block_index: usize, segment_index: usize) -> Option<SelectorRef> {
        let index = block_index.checked_add(segment_index)?;
        let descriptor = self.entries.get(index)?.as_ref()?;
        let raw = u16::try_from(index.checked_shl(SELECTOR_SHIFT as u32)?).ok()?;
        Some(SelectorRef {
            raw: Selector(raw),
            generation: descriptor.generation,
            table_id: self.id,
            block_index: descriptor.block_index,
            segment_index: descriptor.segment_index,
            segment_count: descriptor.segment_count,
        })
    }

    fn take_generation(&mut self) -> Result<u64, Win16Error> {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.checked_add(1).ok_or(Win16Error::GenerationExhausted)?;
        Ok(generation)
    }
}

pub(crate) struct SelectorRebindPlan {
    table_id: u64,
    old_reference: SelectorRef,
    old_descriptor: Descriptor,
    base: PhysAddr,
    size: u32,
    rights: AccessRights,
    access_flags: u16,
    new_count: usize,
    generation: u64,
    next_generation: u64,
}

pub(crate) struct SelectorRebindUndo {
    table_id: u64,
    old_descriptor: Descriptor,
    new_count: usize,
    previous_next_generation: u64,
}

fn selector_index(raw: Selector) -> usize { usize::from(raw.0 >> SELECTOR_SHIFT) }

fn segment_count(size: u32) -> Result<usize, Win16Error> {
    if size == 0 { return Err(Win16Error::InvalidSize); }
    let count = (u64::from(size) + SEGMENT_BYTES - 1) / SEGMENT_BYTES;
    usize::try_from(count).map_err(|_| Win16Error::InvalidRange)
}
