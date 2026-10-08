//! Exact selector-slot allocation for checked guest LDT projections.

use super::{
    AccessRights, AllocationResizePolicy, SelectorRef, SelectorTable, Win16Error, segment_count,
};
use guest_core::{GuestMemory, PhysAddr};

impl SelectorTable {
    /// Whether a usable descriptor slot is free before pairing it with a guest LDT slot.
    pub fn selector_slot_is_free(&self, slot_index: usize) -> bool {
        slot_index != 0 && self.entries.get(slot_index).is_some_and(Option::is_none)
    }

    /// Allocate at one exact runtime descriptor slot selected together with
    /// an architectural guest LDT projection. This table models selector
    /// indices only; the caller retains the architectural TI/RPL bits and
    /// publishes the matching descriptor lease separately.
    pub fn alloc_block_at_slot(
        &mut self,
        slot_index: usize,
        base: PhysAddr,
        size: u32,
        rights: AccessRights,
        memory: &impl GuestMemory,
    ) -> Result<SelectorRef, Win16Error> {
        self.check_range(base, size, rights, memory)?;
        let count = segment_count(size)?;
        let end = slot_index
            .checked_add(count)
            .ok_or(Win16Error::InvalidRange)?;
        if slot_index == 0
            || end > self.entries.len()
            || self.entries[slot_index..end].iter().any(Option::is_some)
        {
            return Err(Win16Error::SelectorTableFull);
        }
        let generation = self.take_generation()?;
        self.install_block(
            slot_index,
            count,
            base,
            size,
            rights,
            AllocationResizePolicy::FollowAllocationExtent,
            generation,
        );
        self.reference_for(slot_index, 0)
            .ok_or(Win16Error::StaleSelector)
    }
}
