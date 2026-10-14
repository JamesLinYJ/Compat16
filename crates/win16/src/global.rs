use std::collections::{BTreeMap, VecDeque};

use crate::selector::{
    AccessRights, SelectorRebindPlan, SelectorRef, SelectorTable,
};
use crate::{next_object_id, Win16Error};
use guest_core::{GuestHandle as RawGuestHandle, GuestMemory, OwnerId, PhysAddr};

mod compact;
mod allocation;
mod lru;
mod owner;
mod selector_leases;

pub use owner::GuestMemoryOwner;

const HEAP_ALIGNMENT: u64 = 16;
// Win16 GlobalAlloc/GlobalReAlloc flags from the Windows 3.x KERNEL ABI.
pub const GMEM_MOVEABLE: u16 = 0x0002;
pub const GMEM_NOCOMPACT: u16 = 0x0010;
pub const GMEM_NODISCARD: u16 = 0x0020;
pub const GMEM_ZEROINIT: u16 = 0x0040;
pub const GMEM_MODIFY: u16 = 0x0080;
pub const GMEM_DISCARDABLE: u16 = 0x0100;
pub const GMEM_DDESHARE: u16 = 0x2000;
pub const GMEM_DISCARDED: u16 = 0x4000;
pub const GMEM_INVALID_HANDLE: u16 = 0x8000;
pub const GMEM_LOCKCOUNT_MASK: u16 = 0x00ff;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct AllocationFlags {
    pub movable: bool,
    pub zero_init: bool,
    pub executable: bool,
}

impl AllocationFlags {
    pub const fn fixed() -> Self {
        Self { movable: false, zero_init: false, executable: false }
    }

    pub const fn movable() -> Self {
        Self { movable: true, zero_init: false, executable: false }
    }

    pub const fn with_zero_init(mut self) -> Self {
        self.zero_init = true;
        self
    }

    pub const fn with_execute(mut self) -> Self {
        self.executable = true;
        self
    }
}

/// A guest-visible handle paired with its owning heap and kernel generation.
/// Host pointers and selectors are represented by different types. The guest
/// ABI carries only the raw 16-bit word, so its generation cannot accompany a
/// value stored in guest memory; kernel code should retain this typed wrapper.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct GlobalHandle {
    raw: RawGuestHandle,
    generation: u64,
    heap_id: u64,
}

impl GlobalHandle {
    pub const fn raw(self) -> RawGuestHandle { self.raw }
    pub const fn generation(self) -> u64 { self.generation }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GlobalBlockInfo {
    pub base: PhysAddr,
    /// Guest-visible logical size; reserved allocator capacity is queried
    /// separately and is not part of GlobalSize or a selector limit.
    pub size: u32,
    pub owner: OwnerId,
    pub guest_owner: Option<GuestMemoryOwner>,
    pub movable: bool,
    pub executable: bool,
    pub lock_count: u16,
    pub page_lock_count: u16,
    /// Requested Win16 allocation attributes retained by the owning block.
    /// Transient `GMEM_MODIFY` and returned-state bits are never stored here.
    pub allocation_flags: u16,
    pub discardable: bool,
    pub discarded: bool,
}

/// Read-only allocation state in guest address order. Allocation identities
/// belong to this allocator; the ABI layer supplies public HGLOBAL values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GlobalHeapRegion {
    Allocated {
        identity: GlobalHandle,
        info: GlobalBlockInfo,
        selector: Option<SelectorRef>,
    },
    Free { base: PhysAddr, size: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Block {
    base: PhysAddr,
    /// Guest-visible logical size (GlobalSize and selector limit source).
    size: u32,
    /// Physical heap range reserved for this block. The allocator never gives
    /// this tail to another allocation while the block remains resident.
    capacity: u32,
    owner: OwnerId,
    guest_owner: Option<GuestMemoryOwner>,
    flags: AllocationFlags,
    /// Guest GlobalLock references. Win3.1 protected mode counts these only
    /// while an effectively discardable object is locked.
    global_lock_count: u16,
    /// Guest GlobalFix references, independent of GlobalLock/GlobalUnlock.
    fix_count: u16,
    /// Win16 GlobalPageLock references are allocator pins, not GlobalFlags
    /// lock references; ToolHelp reports this count separately.
    page_lock_count: u16,
    /// Explicit LockSegment references, visible in ToolHelp but not GlobalFlags.
    segment_lock_count: u16,
    /// Runtime-owned pins used to retain internal selectors, such as loaded
    /// module segments. They block movement but are not returned by GlobalFlags.
    internal_pin_count: u16,
    /// Extra descriptor aliases that borrow this block's backing. Like other
    /// runtime pins these block movement/free without changing the guest lock
    /// count, but they are released independently from `GlobalHeap::unlock`.
    selector_alias_count: u16,
    /// Stable public GlobalAlloc selector owned with this exact heap
    /// generation. Internal heap.lock selectors remain in `selector`.
    runtime_primary: Option<SelectorRef>,
    selector: Option<SelectorRef>,
    allocation_flags: u16,
    discarded: bool,
}

/// A first-fit global heap carved from a range in the single guest memory.
/// This type stores metadata only; block bytes remain in `GuestMemory`.
#[derive(Debug)]
pub struct GlobalHeap {
    id: u64,
    base: PhysAddr,
    end: u64,
    blocks_by_base: BTreeMap<u32, u16>,
    blocks_by_handle: BTreeMap<u16, Block>,
    generations: BTreeMap<u16, u64>,
    lru: VecDeque<u16>,
    handle_capacity: u16,
    next_handle: u32,
    next_generation: u64,
}

impl GlobalHeap {
    pub fn new(base: PhysAddr, capacity: u32) -> Result<Self, Win16Error> {
        Self::with_handle_capacity(base, capacity, u16::MAX)
    }

    /// Allows a smaller guest handle table for constrained environments.
    /// Raw handle zero stays reserved as invalid.
    pub fn with_handle_capacity(
        base: PhysAddr,
        capacity: u32,
        handle_capacity: u16,
    ) -> Result<Self, Win16Error> {
        if capacity == 0 { return Err(Win16Error::InvalidSize); }
        if handle_capacity == 0 { return Err(Win16Error::InvalidRange); }
        let end = u64::from(base.0)
            .checked_add(u64::from(capacity))
            .ok_or(Win16Error::InvalidRange)?;
        if end > u64::from(u32::MAX) { return Err(Win16Error::InvalidRange); }
        Ok(Self {
            id: next_object_id()?,
            base,
            end,
            blocks_by_base: BTreeMap::new(),
            blocks_by_handle: BTreeMap::new(),
            generations: BTreeMap::new(),
            lru: VecDeque::new(),
            handle_capacity,
            next_handle: 1,
            next_generation: 1,
        })
    }

    /// Resizes a block. Locked blocks cannot move. Fixed blocks may only grow
    /// in place; movable unlocked blocks can copy into another free range.
    pub fn realloc(
        &mut self,
        handle: GlobalHandle,
        new_size: u32,
        zero_init: bool,
        memory: &mut impl GuestMemory,
        selectors: &mut SelectorTable,
    ) -> Result<GlobalHandle, Win16Error> {
        self.validate_memory(memory)?;
        if new_size == 0 { return Err(Win16Error::InvalidSize); }
        let block = self.lookup(handle)?;
        if block.runtime_primary.is_some() { return Err(Win16Error::Locked); }
        if new_size == block.size { return Ok(handle); }
        if block.is_pinned() { return Err(Win16Error::Locked); }
        let initialize_extension = zero_init || block.flags.zero_init;

        if block.discarded {
            if !block.flags.movable { return Err(Win16Error::InvalidHandle); }
            let base = self.find_range(new_size).ok_or(Win16Error::OutOfMemory)?;
            let target_len = usize::try_from(new_size).map_err(|_| Win16Error::OutOfMemory)?;
            memory.validate_write(base, target_len)?;
            if initialize_extension { memory.write(base, &zero_bytes(new_size)?)?; }
            let entry = self.blocks_by_handle.get_mut(&handle.raw.0)
                .ok_or(Win16Error::InvalidHandle)?;
            entry.base = base;
            entry.size = new_size;
            entry.capacity = new_size;
            entry.discarded = false;
            self.blocks_by_base.insert(base.0, handle.raw.0);
            return Ok(handle);
        }

        if self.can_fit_at(block.base, new_size, Some(handle.raw.0)) {
            let new_length = usize::try_from(new_size).map_err(|_| Win16Error::OutOfMemory)?;
            memory.validate_write(block.base, new_length)?;

            let extension = if new_size > block.size && initialize_extension {
                let extension_base = PhysAddr(
                    block.base.0.checked_add(block.size).ok_or(Win16Error::InvalidRange)?,
                );
                let extension_length = usize::try_from(new_size - block.size)
                    .map_err(|_| Win16Error::OutOfMemory)?;
                let mut previous_bytes = allocate_bytes(extension_length)?;
                memory.read(extension_base, &mut previous_bytes)?;
                Some((extension_base, previous_bytes, zero_bytes(new_size - block.size)?))
            } else {
                None
            };

            // Both the byte range and descriptor growth are checked before any
            // mutation. The descriptor commit is rolled back if the following
            // guest-memory write fails.
            let selector_plan: Option<SelectorRebindPlan> = match block.selector {
                Some(selector) => {
                    // SelectorAccessRights and PrestoChango can change the
                    // primary descriptor after allocation. Preserve that
                    // effective guest permission when its backing grows.
                    let descriptor = selectors.describe(selector)?;
                    let rights = if descriptor.present {
                        descriptor.rights
                    } else {
                        block_rights(block.flags)
                    };
                    Some(selectors.plan_rebind(
                        selector, block.base, new_size, rights, memory,
                    )?)
                }
                None => None,
            };
            let entry = self.blocks_by_handle.get_mut(&handle.raw.0).ok_or(Win16Error::InvalidHandle)?;
            let (selector, undo) = match selector_plan {
                Some(plan) => {
                    let (selector, undo) = selectors.commit_rebind(plan)?;
                    (Some(selector), Some(undo))
                }
                None => (None, None),
            };

            if let Some((extension_base, previous_bytes, zeroes)) = extension {
                if let Err(write_error) = memory.write(extension_base, &zeroes) {
                    if let Some(undo) = undo { selectors.rollback_rebind(undo); }
                    return match memory.write(extension_base, &previous_bytes) {
                        Ok(()) => Err(Win16Error::Memory(write_error)),
                        Err(rollback) => Err(Win16Error::ReallocRollbackFailed {
                            write: write_error,
                            rollback,
                        }),
                    };
                }
            }
            entry.size = new_size;
            entry.capacity = new_size;
            entry.selector = selector;
            return Ok(handle);
        }

        if !block.flags.movable { return Err(Win16Error::OutOfMemory); }
        let new_base = self.find_range(new_size).ok_or(Win16Error::OutOfMemory)?;
        let target_len = usize::try_from(new_size).map_err(|_| Win16Error::OutOfMemory)?;
        memory.validate_write(new_base, target_len)?;
        let mut target = zero_bytes(new_size)?;
        if !initialize_extension { memory.read(new_base, &mut target)?; }
        let copied_len = usize::try_from(block.size.min(new_size)).map_err(|_| Win16Error::OutOfMemory)?;
        let mut copied = allocate_bytes(copied_len)?;
        memory.read(block.base, &mut copied)?;
        target[..copied_len].copy_from_slice(&copied);
        if target.len() != target_len { return Err(Win16Error::InvalidRange); }
        memory.write(new_base, &target)?;

        self.blocks_by_base.remove(&block.base.0);
        self.blocks_by_base.insert(new_base.0, handle.raw.0);
        let entry = self.blocks_by_handle.get_mut(&handle.raw.0).ok_or(Win16Error::InvalidHandle)?;
        entry.base = new_base;
        entry.size = new_size;
        entry.capacity = new_size;
        entry.selector = None;
        entry.discarded = false;
        Ok(handle)
    }

    /// Reallocate with the Win16 `GMEM_MODIFY` and discard transitions applied
    /// before the ordinary resize path. An already-discarded zero-size handle
    /// is returned unchanged before `GMEM_MODIFY` is considered.
    pub fn realloc_global(
        &mut self,
        handle: GlobalHandle,
        new_size: u32,
        flags: u16,
        primary: Option<SelectorRef>,
        memory: &mut impl GuestMemory,
        selectors: &mut SelectorTable,
        selector_updates: &mut Vec<(SelectorRef, SelectorRef)>,
    ) -> Result<GlobalHandle, Win16Error> {
        let block = self.lookup(handle)?;
        if block.runtime_primary != primary { return Err(Win16Error::StaleSelector); }
        if new_size == 0 && block.discarded { return Ok(handle); }
        if flags & GMEM_MODIFY != 0 {
            // Win16 GMEM_MODIFY may make a fixed block movable, but cannot
            // reverse that transition. Only movable blocks change their
            // discardability; sharing is also a one-way ownership change.
            let next_flags = AllocationFlags {
                movable: block.flags.movable || flags & GMEM_MOVEABLE != 0,
                ..block.flags
            };
            let mut next_allocation_flags = block.allocation_flags | (flags & GMEM_DDESHARE);
            if next_flags.movable {
                next_allocation_flags = (next_allocation_flags & !GMEM_DISCARDABLE)
                    | (flags & GMEM_DISCARDABLE) | GMEM_MOVEABLE;
            }
            self.reserve_lru_slot(Some(handle.raw.0), next_flags, next_allocation_flags)?;
            let entry = self.blocks_by_handle.get_mut(&handle.raw.0)
                .ok_or(Win16Error::InvalidHandle)?;
            entry.flags = next_flags;
            entry.allocation_flags = next_allocation_flags;
            self.sync_lru_membership(handle.raw.0)?;
            return Ok(handle);
        }
        if new_size == 0 {
            if flags & GMEM_MOVEABLE == 0 { return Err(Win16Error::InvalidSize); }
            selector_updates.try_reserve(selectors.slot_capacity())
                .map_err(|_| Win16Error::OutOfMemory)?;
            match self.discard(handle, selectors) {
                Ok(replacements) => selector_updates.extend(replacements),
                Err(error) => return Err(error),
            }
            return Ok(handle);
        }

        self.validate_memory(memory)?;
        // A same-sized resident allocation needs no writes or descriptor
        // changes, even while a guest lock or retained host view is active.
        if new_size == block.size { return Ok(handle); }
        // Guest GlobalLock/GlobalFix counts constrain relocation, not an
        // in-place resize. Internal, page and selector-alias leases retain
        // backing ranges and must still prevent any size or base change.
        if self.retention_pin_count(handle)? != 0 { return Err(Win16Error::Locked); }
        selector_updates.try_reserve(selectors.slot_capacity())
            .map_err(|_| Win16Error::OutOfMemory)?;
        if block.discarded {
            if !block.flags.movable { return Err(Win16Error::InvalidHandle); }
            let base = self.find_range(new_size).ok_or(Win16Error::OutOfMemory)?;
            let length = usize::try_from(new_size).map_err(|_| Win16Error::OutOfMemory)?;
            memory.validate_write(base, length)?;
            if flags & GMEM_ZEROINIT != 0 {
                memory.write(base, &zero_bytes(new_size)?)?;
            }
            let replacement = match primary {
                Some(reference) => {
                    // The primary descriptor may have been retyped or had its
                    // access bits changed since allocation. Rebinding a
                    // discarded backing must retain those current rights.
                    let descriptor = selectors.describe(reference)?;
                    let rights = if descriptor.present {
                        descriptor.rights
                    } else {
                        block_rights(block.flags)
                    };
                    Some(selectors.rebind(reference, base, new_size, rights, memory)?)
                }
                None => None,
            };
            let entry = self.blocks_by_handle.get_mut(&handle.raw.0)
                .ok_or(Win16Error::InvalidHandle)?;
            entry.base = base;
            entry.size = new_size;
            entry.capacity = new_size;
            entry.discarded = false;
            if let (Some(old), Some(new)) = (primary, replacement) {
                entry.runtime_primary = Some(new);
                selector_updates.push((old, new));
            }
            self.blocks_by_base.insert(base.0, handle.raw.0);
            return Ok(handle);
        }

        let initialize_extension = flags & GMEM_ZEROINIT != 0 || block.flags.zero_init;
        if self.can_fit_at(block.base, new_size, Some(handle.raw.0)) {
            let new_length = usize::try_from(new_size).map_err(|_| Win16Error::OutOfMemory)?;
            memory.validate_write(block.base, new_length)?;
            let extension = if new_size > block.size && initialize_extension {
                let extension_base = PhysAddr(
                    block.base.0.checked_add(block.size).ok_or(Win16Error::InvalidRange)?,
                );
                let extension_length = usize::try_from(new_size - block.size)
                    .map_err(|_| Win16Error::OutOfMemory)?;
                let mut previous_bytes = allocate_bytes(extension_length)?;
                memory.read(extension_base, &mut previous_bytes)?;
                Some((extension_base, previous_bytes, zero_bytes(new_size - block.size)?))
            } else {
                None
            };
            if let Some((extension_base, _, zeroes)) = &extension {
                if let Err(error) = memory.write(*extension_base, zeroes) {
                    if let Some((_, previous_bytes, _)) = &extension {
                        return match memory.write(*extension_base, previous_bytes) {
                            Ok(()) => Err(Win16Error::Memory(error)),
                            Err(rollback) => Err(Win16Error::ReallocRollbackFailed { write: error, rollback }),
                        };
                    }
                    return Err(Win16Error::Memory(error));
                }
            }
            let replacements = match selectors.rebind_allocation_aliases(
                block.base, block.size, block.base, new_size, primary, memory,
            ) {
                Ok(replacements) => replacements,
                // The rebind helper preflights every alias and commits them
                // atomically. If it fails, heap metadata and selectors remain
                // unchanged; the attempted extension is still outside the
                // block's old logical selector limit.
                Err(error) => return Err(error),
            };
            let entry = self.blocks_by_handle.get_mut(&handle.raw.0)
                .ok_or(Win16Error::InvalidHandle)?;
            entry.size = new_size;
            entry.capacity = new_size;
            entry.selector = entry.selector.map(|old| replacement_for(&replacements, old).unwrap_or(old));
            entry.runtime_primary = entry.runtime_primary
                .map(|old| replacement_for(&replacements, old).unwrap_or(old));
            selector_updates.extend(replacements);
            return Ok(handle);
        }

        // The Win16 caller may explicitly permit moving a guest-locked block.
        // The retained backing leases above are never overridden by this flag.
        if block.reported_lock_count() != 0 && flags & GMEM_MOVEABLE == 0 {
            return Err(Win16Error::Locked);
        }
        // Win16 GMEM_MOVEABLE permits relocation of a fixed block for this
        // resize; only GMEM_MODIFY can convert a fixed allocation to movable.
        if !block.flags.movable && flags & GMEM_MOVEABLE == 0 {
            return Err(Win16Error::OutOfMemory);
        }
        let new_base = self.find_range(new_size).ok_or(Win16Error::OutOfMemory)?;
        let target_len = usize::try_from(new_size).map_err(|_| Win16Error::OutOfMemory)?;
        memory.validate_write(new_base, target_len)?;
        let mut target = zero_bytes(new_size)?;
        if !initialize_extension { memory.read(new_base, &mut target)?; }
        let copied_len = usize::try_from(block.size.min(new_size))
            .map_err(|_| Win16Error::OutOfMemory)?;
        let mut copied = allocate_bytes(copied_len)?;
        memory.read(block.base, &mut copied)?;
        target[..copied_len].copy_from_slice(&copied);
        memory.write(new_base, &target)?;
        let replacements = selectors.rebind_allocation_aliases(
            block.base, block.size, new_base, new_size, primary, memory,
        )?;

        self.blocks_by_base.remove(&block.base.0);
        self.blocks_by_base.insert(new_base.0, handle.raw.0);
        let entry = self.blocks_by_handle.get_mut(&handle.raw.0)
            .ok_or(Win16Error::InvalidHandle)?;
        entry.base = new_base;
        entry.size = new_size;
        entry.capacity = new_size;
        entry.selector = entry.selector.map(|old| replacement_for(&replacements, old).unwrap_or(old));
        entry.runtime_primary = entry.runtime_primary
            .map(|old| replacement_for(&replacements, old).unwrap_or(old));
        entry.discarded = false;
        selector_updates.extend(replacements);
        Ok(handle)
    }

    /// Mark an unlocked movable discardable block as nonresident. Its HGLOBAL
    /// generation and attributes survive while its guest memory range returns
    /// to the allocator.
    pub fn discard(
        &mut self,
        handle: GlobalHandle,
        selectors: &mut SelectorTable,
    ) -> Result<Vec<(SelectorRef, SelectorRef)>, Win16Error> {
        let block = self.lookup(handle)?;
        if block.discarded { return Ok(Vec::new()); }
        if !block.flags.movable || block.is_pinned() || !block.discardable() {
            return Err(Win16Error::Locked);
        }
        let selector_updates = selectors.unback_allocation_selector(block.base, block.size)?;
        self.blocks_by_base.remove(&block.base.0);
        let entry = self.blocks_by_handle.get_mut(&handle.raw.0)
            .ok_or(Win16Error::InvalidHandle)?;
        entry.base = PhysAddr(0);
        entry.size = 0;
        entry.capacity = 0;
        entry.selector = None;
        entry.runtime_primary = entry.runtime_primary
            .map(|old| replacement_for(&selector_updates, old).unwrap_or(old));
        entry.discarded = true;
        Ok(selector_updates)
    }

    pub fn free(
        &mut self,
        handle: GlobalHandle,
        selectors: &mut SelectorTable,
    ) -> Result<(), Win16Error> {
        let block = self.lookup(handle)?;
        if block.is_pinned() { return Err(Win16Error::Locked); }
        self.preflight_block_selectors(block, selectors)?;
        self.free_block_selectors(block, selectors)?;
        self.remove_block(handle.raw.0, block);
        Ok(())
    }

    /// Releases every block recorded to this owner, including locked blocks,
    /// and invalidates their selector references. Guest handle words may have
    /// been shared with other tasks; this ownership policy still reclaims the
    /// owner's blocks on teardown. A surviving raw word may later resolve to a
    /// reused handle, because only kernel-held `GlobalHandle`s carry generations.
    pub fn free_owner(
        &mut self,
        owner: OwnerId,
        selectors: &mut SelectorTable,
    ) -> Result<usize, Win16Error> {
        let owned: Vec<(u16, Block)> = self.blocks_by_handle.iter()
            .filter_map(|(&raw, &block)| (block.owner == owner).then_some((raw, block)))
            .collect();
        for (_, block) in &owned { self.preflight_block_selectors(*block, selectors)?; }
        for (_, block) in &owned { self.free_block_selectors(*block, selectors)?; }
        for (raw, block) in &owned { self.remove_block(*raw, *block); }
        Ok(owned.len())
    }

    pub fn info(&self, handle: GlobalHandle) -> Result<GlobalBlockInfo, Win16Error> {
        let block = self.lookup(handle)?;
        Ok(GlobalBlockInfo {
            base: block.base,
            size: block.size,
            owner: block.owner,
            guest_owner: block.guest_owner,
            movable: block.flags.movable,
            executable: block.flags.executable,
            lock_count: block.reported_lock_count(),
            page_lock_count: block.page_lock_count,
            allocation_flags: block.allocation_flags,
            discardable: block.discardable(),
            discarded: block.discarded,
        })
    }

    /// Physical byte capacity retained by a resident allocation. Discarded
    /// handles report zero because their former range is allocator-free.
    pub fn reserved_capacity(&self, handle: GlobalHandle) -> Result<u32, Win16Error> {
        Ok(self.lookup(handle)?.capacity)
    }

    /// Grow a module-owned block inside its already-reserved physical range.
    /// This path is intentionally separate from guest GlobalReAlloc: only the
    /// owning module with an internal lifetime pin may use it, and the caller
    /// must have completed any guest-memory changes before committing metadata.
    pub fn grow_reserved_in_place(
        &mut self,
        handle: GlobalHandle,
        expected_owner: OwnerId,
        expected_size: u32,
        new_size: u32,
        selectors: &mut SelectorTable,
        memory: &impl GuestMemory,
    ) -> Result<(), Win16Error> {
        let block = self.lookup(handle)?;
        if block.owner != expected_owner { return Err(Win16Error::InvalidHandle); }
        if block.internal_pin_count == 0 { return Err(Win16Error::Locked); }
        if block.discarded { return Err(Win16Error::InvalidHandle); }
        if block.size != expected_size || new_size < expected_size || new_size > block.capacity {
            return Err(Win16Error::InvalidSize);
        }
        let selector = block.selector.ok_or(Win16Error::InvalidSelector)?;
        let descriptor = selectors.describe(selector)?;
        if !descriptor.present
            || descriptor.base != block.base
            || descriptor.limit.checked_add(1) != Some(expected_size)
        {
            return Err(Win16Error::StaleSelector);
        }
        if new_size == expected_size { return Ok(()); }

        // SelectorTable preflights every matching alias and commits limits
        // without changing selector generations. On failure neither its
        // metadata nor this block's logical size changes.
        let entry = self.blocks_by_handle.get_mut(&handle.raw.0)
            .ok_or(Win16Error::InvalidHandle)?;
        selectors.extend_allocation_in_place(block.base, block.size, new_size, memory)?;
        entry.size = new_size;
        Ok(())
    }

    pub fn allocation_count(&self) -> usize { self.blocks_by_handle.len() }

    /// The allocator's fixed half-open guest reservation, including alignment
    /// padding omitted from `snapshot_regions` because padding is not allocatable.
    pub fn guest_range(&self) -> std::ops::Range<u64> {
        u64::from(self.base.0)..self.end
    }

    /// Reports logical allocation sizes and the gaps available to the first-fit
    /// allocator. Reserved tails remain inside allocated physical regions;
    /// alignment padding cannot begin an allocation and is omitted. This
    /// snapshot contains guest addresses and no borrowed heap metadata.
    pub fn snapshot_regions(&self) -> Result<Vec<GlobalHeapRegion>, Win16Error> {
        let discarded_count = self.blocks_by_handle.values().filter(|block| block.discarded).count();
        let capacity = self.blocks_by_base.len().checked_mul(2)
            .and_then(|count| count.checked_add(discarded_count))
            .and_then(|count| count.checked_add(1)).ok_or(Win16Error::OutOfMemory)?;
        let mut regions = Vec::new();
        regions.try_reserve_exact(capacity).map_err(|_| Win16Error::OutOfMemory)?;
        let mut next = align_up(u64::from(self.base.0));
        for (&base, &raw) in &self.blocks_by_base {
            let identity = self.resolve_handle(RawGuestHandle(raw))?;
            let block = self.lookup(identity)?;
            if block.base.0 != base || u64::from(base) < next {
                return Err(Win16Error::InvalidRange);
            }
            if next < u64::from(base) {
                regions.push(GlobalHeapRegion::Free {
                    base: PhysAddr(u32::try_from(next).map_err(|_| Win16Error::InvalidRange)?),
                    size: u32::try_from(u64::from(base) - next)
                        .map_err(|_| Win16Error::InvalidRange)?,
                });
            }
            regions.push(GlobalHeapRegion::Allocated {
                identity, info: self.info(identity)?, selector: block.selector,
            });
            if block.size == 0 || block.size > block.capacity {
                return Err(Win16Error::InvalidRange);
            }
            let end = u64::from(base) + u64::from(block.capacity);
            if end > self.end { return Err(Win16Error::InvalidRange); }
            next = align_up(end);
        }
        if next < self.end {
            regions.push(GlobalHeapRegion::Free {
                base: PhysAddr(u32::try_from(next).map_err(|_| Win16Error::InvalidRange)?),
                size: u32::try_from(self.end - next).map_err(|_| Win16Error::InvalidRange)?,
            });
        }
        for (&raw, block) in &self.blocks_by_handle {
            if !block.discarded { continue; }
            let identity = self.resolve_handle(RawGuestHandle(raw))?;
            regions.push(GlobalHeapRegion::Allocated {
                identity, info: self.info(identity)?, selector: block.selector,
            });
        }
        Ok(regions)
    }

    fn lookup(&self, handle: GlobalHandle) -> Result<Block, Win16Error> {
        if handle.heap_id != self.id { return Err(Win16Error::ForeignHandle); }
        match self.blocks_by_handle.get(&handle.raw.0) {
            Some(block) if self.generations.get(&handle.raw.0) == Some(&handle.generation) => Ok(*block),
            Some(_) => Err(Win16Error::StaleHandle),
            None => Err(Win16Error::InvalidHandle),
        }
    }

    fn find_handle_slot(&self) -> Option<u16> {
        let capacity = u32::from(self.handle_capacity);
        let start = self.next_handle.clamp(1, capacity);
        for offset in 0..capacity {
            let raw = ((start - 1 + offset) % capacity + 1) as u16;
            if !self.blocks_by_handle.contains_key(&raw) { return Some(raw); }
        }
        None
    }

    fn find_range(&self, size: u32) -> Option<PhysAddr> {
        let mut candidate = align_up(u64::from(self.base.0));
        let size = u64::from(size);
        for (&block_base, &raw) in &self.blocks_by_base {
            let block = self.blocks_by_handle.get(&raw)?;
            if block.discarded || block.size == 0 || block.size > block.capacity {
                return None;
            }
            let block_start = u64::from(block_base);
            if candidate.checked_add(size)? <= block_start {
                return u32::try_from(candidate).ok().map(PhysAddr);
            }
            let block_end = block_start.checked_add(u64::from(block.capacity))?;
            candidate = align_up(candidate.max(block_end));
        }
        if candidate.checked_add(size)? <= self.end {
            u32::try_from(candidate).ok().map(PhysAddr)
        } else {
            None
        }
    }

    fn can_fit_at(&self, base: PhysAddr, size: u32, ignored_handle: Option<u16>) -> bool {
        let start = u64::from(base.0);
        let Some(end) = start.checked_add(u64::from(size)) else { return false; };
        if start < u64::from(self.base.0) || end > self.end { return false; }
        for (&block_base, &raw) in &self.blocks_by_base {
            if Some(raw) == ignored_handle { continue; }
            let Some(block) = self.blocks_by_handle.get(&raw) else { return false; };
            if block.discarded || block.size == 0 || block.size > block.capacity {
                return false;
            }
            let other_start = u64::from(block_base);
            let Some(other_end) = other_start.checked_add(u64::from(block.capacity)) else { return false; };
            if start < other_end && other_start < end { return false; }
        }
        true
    }

    fn validate_memory(&self, memory: &impl GuestMemory) -> Result<(), Win16Error> {
        if self.end > u64::from(memory.len()) { return Err(Win16Error::InvalidRange); }
        Ok(())
    }

    fn remove_block(&mut self, raw: u16, block: Block) {
        self.blocks_by_handle.remove(&raw);
        if !block.discarded { self.blocks_by_base.remove(&block.base.0); }
        self.lru.retain(|candidate| *candidate != raw);
    }
}

impl Block {
    fn guest_lock_count(self) -> u16 {
        self.global_lock_count.saturating_add(self.fix_count)
    }

    fn total_pin_count(self) -> u32 {
        u32::from(self.global_lock_count)
            + u32::from(self.fix_count)
            + u32::from(self.page_lock_count)
            + u32::from(self.segment_lock_count)
            + u32::from(self.internal_pin_count)
            + u32::from(self.selector_alias_count)
    }

    fn reported_lock_count(self) -> u16 {
        self.guest_lock_count().saturating_add(self.segment_lock_count)
    }

    fn is_pinned(self) -> bool { self.total_pin_count() != 0 }

    fn discardable(self) -> bool {
        self.allocation_flags & GMEM_DISCARDABLE != 0
            && self.allocation_flags & GMEM_NODISCARD == 0
    }
}

fn persistent_global_flags(raw_flags: u16, flags: AllocationFlags) -> u16 {
    let mut stored = raw_flags & !(GMEM_MODIFY | GMEM_DISCARDED | GMEM_LOCKCOUNT_MASK
        | GMEM_ZEROINIT);
    if flags.movable { stored |= GMEM_MOVEABLE; }
    else { stored &= !GMEM_MOVEABLE; }
    stored
}

fn replacement_for(
    replacements: &[(SelectorRef, SelectorRef)],
    old: SelectorRef,
) -> Option<SelectorRef> {
    replacements.iter().find_map(|(previous, replacement)|
        (*previous == old).then_some(*replacement))
}

fn align_up(value: u64) -> u64 { (value + HEAP_ALIGNMENT - 1) & !(HEAP_ALIGNMENT - 1) }

fn block_rights(flags: AllocationFlags) -> AccessRights {
    if flags.executable { AccessRights::read_write_execute() } else { AccessRights::read_write() }
}

fn allocate_bytes(length: usize) -> Result<Vec<u8>, Win16Error> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| Win16Error::OutOfMemory)?;
    bytes.resize(length, 0);
    Ok(bytes)
}

fn zero_bytes(length: u32) -> Result<Vec<u8>, Win16Error> {
    allocate_bytes(usize::try_from(length).map_err(|_| Win16Error::OutOfMemory)?)
}
