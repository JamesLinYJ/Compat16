//! Discardable-block recency order shared by GlobalLRU and compaction.

use super::{AllocationFlags, GlobalHandle, GlobalHeap, RawGuestHandle, Win16Error};
use crate::global::{
    GMEM_DISCARDABLE, GMEM_DISCARDED, GMEM_LOCKCOUNT_MASK, GMEM_NODISCARD,
};

impl GlobalHeap {
    /// Stored state for the Win16 GlobalFlags result: persistent allocation
    /// attributes plus the current low-byte lock count and discarded bit.
    pub fn global_flags(&self, handle: GlobalHandle) -> Result<u16, Win16Error> {
        let block = self.lookup(handle)?;
        let lock_count = block.guest_lock_count().min(GMEM_LOCKCOUNT_MASK);
        Ok((block.allocation_flags & !(GMEM_DISCARDED | GMEM_LOCKCOUNT_MASK))
            | lock_count | if block.discarded { GMEM_DISCARDED } else { 0 })
    }

    pub fn set_discardable(
        &mut self,
        handle: GlobalHandle,
        discardable: bool,
    ) -> Result<(), Win16Error> {
        let block = self.lookup(handle)?;
        if !block.flags.movable { return Err(Win16Error::InvalidHandle); }
        let allocation_flags = if discardable {
            block.allocation_flags | GMEM_DISCARDABLE
        } else {
            block.allocation_flags & !GMEM_DISCARDABLE
        };
        self.reserve_lru_slot(Some(handle.raw.0), block.flags, allocation_flags)?;
        let entry = self.blocks_by_handle.get_mut(&handle.raw.0)
            .ok_or(Win16Error::InvalidHandle)?;
        entry.allocation_flags = allocation_flags;
        self.sync_lru_membership(handle.raw.0)?;
        Ok(())
    }

    /// Reserve before an allocation or flag update publishes LRU membership.
    pub(super) fn reserve_lru_slot(
        &mut self,
        raw: Option<u16>,
        flags: AllocationFlags,
        allocation_flags: u16,
    ) -> Result<(), Win16Error> {
        if Self::lru_eligible(flags, allocation_flags)
            && !raw.is_some_and(|raw| self.lru.contains(&raw))
        {
            self.lru.try_reserve(1).map_err(|_| Win16Error::OutOfMemory)?;
        }
        Ok(())
    }

    pub(super) fn sync_lru_membership(&mut self, raw: u16) -> Result<(), Win16Error> {
        let block = self.blocks_by_handle.get(&raw).ok_or(Win16Error::InvalidHandle)?;
        let eligible = Self::lru_eligible(block.flags, block.allocation_flags);
        let present = self.lru.contains(&raw);
        match (eligible, present) {
            (true, false) => {
                self.lru.try_reserve(1).map_err(|_| Win16Error::OutOfMemory)?;
                self.lru.push_back(raw);
            }
            (false, true) => self.lru.retain(|candidate| *candidate != raw),
            _ => {}
        }
        Ok(())
    }

    pub fn move_lru_oldest(&mut self, handle: GlobalHandle) -> Result<(), Win16Error> {
        self.move_lru(handle, true)
    }

    pub fn move_lru_newest(&mut self, handle: GlobalHandle) -> Result<(), Win16Error> {
        self.move_lru(handle, false)
    }

    fn move_lru(&mut self, handle: GlobalHandle, oldest: bool) -> Result<(), Win16Error> {
        let block = self.lookup(handle)?;
        if !Self::lru_eligible(block.flags, block.allocation_flags) {
            return Err(Win16Error::InvalidHandle);
        }
        if !self.lru.contains(&handle.raw.0) {
            self.sync_lru_membership(handle.raw.0)?;
        }
        self.lru.retain(|candidate| *candidate != handle.raw.0);
        if oldest { self.lru.push_front(handle.raw.0); }
        else { self.lru.push_back(handle.raw.0); }
        Ok(())
    }

    /// A successful guest lock makes a resident discardable block newest.
    pub fn touch_lru(&mut self, handle: GlobalHandle) -> Result<(), Win16Error> {
        let block = self.lookup(handle)?;
        if !Self::lru_eligible(block.flags, block.allocation_flags) { return Ok(()); }
        self.move_lru_newest(handle)
    }

    /// GlobalInfo and ToolHelp consume this exact oldest-to-newest order.
    pub fn lru_handles(&self) -> Result<Vec<GlobalHandle>, Win16Error> {
        let mut handles = Vec::new();
        handles.try_reserve_exact(self.lru.len()).map_err(|_| Win16Error::OutOfMemory)?;
        for &raw in &self.lru {
            let handle = self.resolve_handle(RawGuestHandle(raw))?;
            let block = self.lookup(handle)?;
            if !Self::lru_eligible(block.flags, block.allocation_flags) {
                return Err(Win16Error::InvalidRange);
            }
            handles.push(handle);
        }
        Ok(handles)
    }

    pub fn lru_item_count(&self) -> Result<u16, Win16Error> {
        u16::try_from(self.lru.len()).map_err(|_| Win16Error::OutOfMemory)
    }

    fn lru_eligible(flags: AllocationFlags, allocation_flags: u16) -> bool {
        flags.movable && allocation_flags & GMEM_DISCARDABLE != 0
            && allocation_flags & GMEM_NODISCARD == 0
    }
}
