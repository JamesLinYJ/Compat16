//! Allocation and Win16 lock-reference operations for the shared GlobalHeap.

use guest_core::{GuestMemory, OwnerId, PhysAddr};
use crate::SegmentedPointer;

use super::{
    block_rights, persistent_global_flags, zero_bytes, AllocationFlags, Block,
    GlobalHandle, GlobalHeap, RawGuestHandle, SelectorTable,
    GuestMemoryOwner, Win16Error, GMEM_MOVEABLE,
};

impl GlobalHeap {
    pub fn alloc(
        &mut self,
        memory: &mut impl GuestMemory,
        owner: OwnerId,
        size: u32,
        flags: AllocationFlags,
    ) -> Result<GlobalHandle, Win16Error> {
        self.alloc_with_global_flags(memory, owner, size, flags, 0)
    }

    /// Allocate a guest global block while retaining the Win16 allocation
    /// attributes in the block's single authoritative heap record.
    pub fn alloc_with_global_flags(
        &mut self,
        memory: &mut impl GuestMemory,
        owner: OwnerId,
        size: u32,
        flags: AllocationFlags,
        allocation_flags: u16,
    ) -> Result<GlobalHandle, Win16Error> {
        self.alloc_reserved_with_guest_owner(
            memory, owner, None, size, size, flags, allocation_flags,
        )
    }

    pub fn alloc_with_guest_owner(
        &mut self,
        memory: &mut impl GuestMemory,
        owner: OwnerId,
        guest_owner: GuestMemoryOwner,
        size: u32,
        flags: AllocationFlags,
        allocation_flags: u16,
    ) -> Result<GlobalHandle, Win16Error> {
        self.alloc_reserved_with_guest_owner(
            memory, owner, Some(guest_owner), size, size, flags, allocation_flags,
        )
    }

    /// Allocate a logical global block while retaining a larger physical range
    /// for runtime-owned in-place growth. Guest size and selector limits remain
    /// `logical_size`; only allocator occupancy uses `reserved_size`.
    pub fn alloc_reserved(
        &mut self,
        memory: &mut impl GuestMemory,
        owner: OwnerId,
        logical_size: u32,
        reserved_size: u32,
        flags: AllocationFlags,
    ) -> Result<GlobalHandle, Win16Error> {
        self.alloc_reserved_with_guest_owner(
            memory, owner, None, logical_size, reserved_size, flags, 0,
        )
    }

    fn alloc_reserved_with_guest_owner(
        &mut self,
        memory: &mut impl GuestMemory,
        owner: OwnerId,
        guest_owner: Option<GuestMemoryOwner>,
        logical_size: u32,
        reserved_size: u32,
        flags: AllocationFlags,
        allocation_flags: u16,
    ) -> Result<GlobalHandle, Win16Error> {
        self.validate_memory(memory)?;
        if logical_size == 0 || reserved_size < logical_size {
            return Err(Win16Error::InvalidSize);
        }
        self.reserve_lru_slot(None, flags, allocation_flags)?;
        let base = self.find_range(reserved_size).ok_or(Win16Error::OutOfMemory)?;
        memory.validate_write(
            base,
            usize::try_from(reserved_size).map_err(|_| Win16Error::OutOfMemory)?,
        )?;
        let raw = self.find_handle_slot().ok_or(Win16Error::HandleTableFull)?;
        let generation = self.next_generation;
        let next_generation = generation.checked_add(1).ok_or(Win16Error::GenerationExhausted)?;
        if flags.zero_init {
            let zeros = zero_bytes(logical_size)?;
            memory.write(base, &zeros)?;
        }

        let block = Block {
            base, size: logical_size, capacity: reserved_size, owner, guest_owner, flags,
            global_lock_count: 0, fix_count: 0, page_lock_count: 0,
            segment_lock_count: 0, internal_pin_count: 0, selector_alias_count: 0,
            runtime_primary: None, selector: None,
            allocation_flags: persistent_global_flags(allocation_flags, flags),
            discarded: false,
        };
        self.blocks_by_base.insert(base.0, raw);
        self.blocks_by_handle.insert(raw, block);
        self.generations.insert(raw, generation);
        self.next_handle = (u32::from(raw) % u32::from(self.handle_capacity)) + 1;
        self.next_generation = next_generation;
        self.sync_lru_membership(raw)?;
        Ok(GlobalHandle { raw: RawGuestHandle(raw), generation, heap_id: self.id })
    }

    /// Create the metadata identity for a zero-byte movable global object.
    /// It occupies no GuestMemory range and may be made resident later through
    /// `realloc`; the ABI layer remains responsible for its stable HGLOBAL word.
    pub fn alloc_discarded(
        &mut self,
        owner: OwnerId,
        flags: AllocationFlags,
        allocation_flags: u16,
    ) -> Result<GlobalHandle, Win16Error> {
        self.alloc_discarded_with_guest_owner(owner, None, flags, allocation_flags)
    }

    pub fn alloc_discarded_with_guest_owner(
        &mut self,
        owner: OwnerId,
        guest_owner: Option<GuestMemoryOwner>,
        flags: AllocationFlags,
        allocation_flags: u16,
    ) -> Result<GlobalHandle, Win16Error> {
        if !flags.movable { return Err(Win16Error::InvalidSize); }
        self.reserve_lru_slot(None, flags, allocation_flags | GMEM_MOVEABLE)?;
        let raw = self.find_handle_slot().ok_or(Win16Error::HandleTableFull)?;
        let generation = self.next_generation;
        let next_generation = generation.checked_add(1).ok_or(Win16Error::GenerationExhausted)?;
        let block = Block {
            base: PhysAddr(0), size: 0, capacity: 0, owner, guest_owner, flags, global_lock_count: 0,
            fix_count: 0, page_lock_count: 0, segment_lock_count: 0, internal_pin_count: 0,
            selector_alias_count: 0, runtime_primary: None, selector: None,
            allocation_flags: persistent_global_flags(
                allocation_flags | GMEM_MOVEABLE, flags,
            ),
            discarded: true,
        };
        self.blocks_by_handle.insert(raw, block);
        self.generations.insert(raw, generation);
        self.next_handle = (u32::from(raw) % u32::from(self.handle_capacity)) + 1;
        self.next_generation = next_generation;
        self.sync_lru_membership(raw)?;
        Ok(GlobalHandle { raw: RawGuestHandle(raw), generation, heap_id: self.id })
    }

    /// Resolves a raw guest handle to this heap's current kernel generation.
    /// Raw words are shareable Win16 guest values: any task that receives the
    /// word may resolve and use it while the block exists. The typed generation
    /// protects retained kernel references from handle reuse, but is not
    /// encoded in the guest ABI word.
    pub fn resolve_handle(&self, raw: RawGuestHandle) -> Result<GlobalHandle, Win16Error> {
        if raw.0 == 0 || !self.blocks_by_handle.contains_key(&raw.0) {
            return Err(Win16Error::InvalidHandle);
        }
        let generation = self.generations.get(&raw.0).copied()
            .ok_or(Win16Error::InvalidHandle)?;
        Ok(GlobalHandle { raw, generation, heap_id: self.id })
    }

    /// Internal pin that returns a checked FAR pointer to the block's first
    /// byte. This is used for selectors whose lifetime belongs to the runtime;
    /// public GlobalLock count rules are implemented separately below.
    pub fn lock(
        &mut self,
        handle: GlobalHandle,
        selectors: &mut SelectorTable,
        memory: &impl GuestMemory,
    ) -> Result<SegmentedPointer, Win16Error> {
        let block = self.lookup(handle)?;
        if block.discarded { return Err(Win16Error::InvalidHandle); }
        if block.internal_pin_count == u16::MAX { return Err(Win16Error::LockCountOverflow); }
        let selector = match block.selector {
            Some(selector) => selector,
            None => selectors.alloc_block(block.base, block.size, block_rights(block.flags), memory)?,
        };
        let entry = self.blocks_by_handle.get_mut(&handle.raw.0)
            .ok_or(Win16Error::InvalidHandle)?;
        entry.internal_pin_count += 1;
        entry.selector = Some(selector);
        Ok(SegmentedPointer::new(selector, 0))
    }

    /// Releases one internal pin. The last movable internal pin invalidates
    /// its temporary selector generation.
    pub fn unlock(
        &mut self,
        handle: GlobalHandle,
        selectors: &mut SelectorTable,
    ) -> Result<u16, Win16Error> {
        let block = self.lookup(handle)?;
        if block.internal_pin_count == 0 { return Err(Win16Error::LockUnderflow); }
        let remaining = block.internal_pin_count - 1;
        if remaining == 0 && block.flags.movable {
            if let Some(selector) = block.selector { selectors.free_block(selector)?; }
        }
        let entry = self.blocks_by_handle.get_mut(&handle.raw.0)
            .ok_or(Win16Error::InvalidHandle)?;
        entry.internal_pin_count = remaining;
        if remaining == 0 && entry.flags.movable { entry.selector = None; }
        Ok(remaining)
    }

    /// Retain one independently owned selector descriptor over this block.
    /// It is separate from guest GlobalLock/GlobalFix and from the heap's
    /// primary-selector lock, so GlobalFlags and UnlockSegment do not observe
    /// this alias owner as a caller lock.
    pub fn retain_selector_alias(&mut self, handle: GlobalHandle) -> Result<(), Win16Error> {
        let block = self.lookup(handle)?;
        if block.discarded { return Err(Win16Error::InvalidHandle); }
        if block.selector_alias_count == u16::MAX {
            return Err(Win16Error::LockCountOverflow);
        }
        self.blocks_by_handle.get_mut(&handle.raw.0)
            .ok_or(Win16Error::InvalidHandle)?.selector_alias_count += 1;
        Ok(())
    }

    /// Release one selector alias owner and return the remaining runtime pin
    /// count for module-retirement decisions. Guest lock counts stay unchanged.
    pub fn release_selector_alias(&mut self, handle: GlobalHandle) -> Result<u32, Win16Error> {
        let block = self.lookup(handle)?;
        if block.selector_alias_count == 0 { return Err(Win16Error::LockUnderflow); }
        let remaining = u32::from(block.internal_pin_count)
            + u32::from(block.selector_alias_count - 1)
            + u32::from(block.page_lock_count);
        self.blocks_by_handle.get_mut(&handle.raw.0)
            .ok_or(Win16Error::InvalidHandle)?.selector_alias_count -= 1;
        Ok(remaining)
    }

    /// Records a Win3.1 GlobalLock on a live HGLOBAL. Nondiscardable objects
    /// remain addressable while their selector is rebound after heap moves;
    /// only effectively discardable objects gain a guest-visible lock count.
    pub fn global_lock(&mut self, handle: GlobalHandle) -> Result<(), Win16Error> {
        let block = self.lookup(handle)?;
        if block.discarded { return Err(Win16Error::InvalidHandle); }
        self.reserve_lru_slot(Some(handle.raw.0), block.flags, block.allocation_flags)?;
        if !block.discardable() { return Ok(()); }
        if block.guest_lock_count() == u16::MAX {
            return Err(Win16Error::LockCountOverflow);
        }
        self.blocks_by_handle.get_mut(&handle.raw.0)
            .ok_or(Win16Error::InvalidHandle)?.global_lock_count += 1;
        self.touch_lru(handle)?;
        Ok(())
    }

    /// Releases one GlobalLock reference, if present. A remaining guest-visible
    /// GlobalLock or GlobalFix reference keeps the object pinned.
    pub fn global_unlock(&mut self, handle: GlobalHandle) -> Result<bool, Win16Error> {
        let block = self.lookup(handle)?;
        if block.global_lock_count == 0 {
            return Ok(block.guest_lock_count() != 0);
        }
        let entry = self.blocks_by_handle.get_mut(&handle.raw.0)
            .ok_or(Win16Error::InvalidHandle)?;
        entry.global_lock_count -= 1;
        Ok(entry.guest_lock_count() != 0)
    }

    /// GlobalFix pins a live allocation independently of GlobalLock, including
    /// nondiscardable blocks whose GlobalLock calls do not affect the count.
    pub fn fix(&mut self, handle: GlobalHandle) -> Result<(), Win16Error> {
        let block = self.lookup(handle)?;
        if block.discarded { return Err(Win16Error::InvalidHandle); }
        if block.guest_lock_count() == u16::MAX {
            return Err(Win16Error::LockCountOverflow);
        }
        self.blocks_by_handle.get_mut(&handle.raw.0)
            .ok_or(Win16Error::InvalidHandle)?.fix_count += 1;
        Ok(())
    }

    /// Releases one prior GlobalFix reference without consuming GlobalLock
    /// references.
    pub fn unfix(&mut self, handle: GlobalHandle) -> Result<u16, Win16Error> {
        let block = self.lookup(handle)?;
        if block.fix_count == 0 { return Err(Win16Error::LockUnderflow); }
        let entry = self.blocks_by_handle.get_mut(&handle.raw.0)
            .ok_or(Win16Error::InvalidHandle)?;
        entry.fix_count -= 1;
        Ok(entry.guest_lock_count())
    }

    pub fn page_lock(&mut self, handle: GlobalHandle) -> Result<u16, Win16Error> {
        let block = self.lookup(handle)?;
        if block.discarded { return Err(Win16Error::InvalidHandle); }
        if block.page_lock_count == u16::MAX { return Err(Win16Error::LockCountOverflow); }
        let entry = self.blocks_by_handle.get_mut(&handle.raw.0)
            .ok_or(Win16Error::InvalidHandle)?;
        entry.page_lock_count += 1;
        Ok(entry.page_lock_count)
    }

    pub fn page_unlock(&mut self, handle: GlobalHandle) -> Result<u16, Win16Error> {
        let block = self.lookup(handle)?;
        if block.page_lock_count == 0 { return Ok(0); }
        let entry = self.blocks_by_handle.get_mut(&handle.raw.0)
            .ok_or(Win16Error::InvalidHandle)?;
        entry.page_lock_count -= 1;
        Ok(entry.page_lock_count)
    }

    /// Lock a loaded NE segment while retaining the public segment-lock count
    /// separately from the module loader's own lifetime pin.
    pub fn lock_segment(
        &mut self,
        handle: GlobalHandle,
        selectors: &mut SelectorTable,
        memory: &impl GuestMemory,
    ) -> Result<SegmentedPointer, Win16Error> {
        let block = self.lookup(handle)?;
        if block.segment_lock_count == u16::MAX { return Err(Win16Error::LockCountOverflow); }
        let pointer = self.lock(handle, selectors, memory)?;
        self.blocks_by_handle.get_mut(&handle.raw.0)
            .ok_or(Win16Error::InvalidHandle)?.segment_lock_count += 1;
        Ok(pointer)
    }

    /// Release one caller-acquired LockSegment pin, preserving the loader's
    /// baseline pin until module teardown.
    pub fn unlock_segment(
        &mut self,
        handle: GlobalHandle,
        selectors: &mut SelectorTable,
    ) -> Result<u16, Win16Error> {
        if self.lookup(handle)?.segment_lock_count == 0 {
            return Err(Win16Error::LockUnderflow);
        }
        let remaining = self.unlock(handle, selectors)?;
        self.blocks_by_handle.get_mut(&handle.raw.0)
            .ok_or(Win16Error::InvalidHandle)?.segment_lock_count -= 1;
        Ok(remaining)
    }
}
