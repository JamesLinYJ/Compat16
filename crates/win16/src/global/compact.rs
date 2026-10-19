use guest_core::{GuestMemory, PhysAddr};

use super::{
    align_up, allocate_bytes, GlobalHandle, GlobalHeap, RawGuestHandle, SelectorRef,
    SelectorTable, Win16Error, GMEM_NOCOMPACT, GMEM_NODISCARD,
};

/// A candidate is still resident. The runtime may suspend for its owning
/// task's GlobalNotify callback before committing the discard. Its exact
/// allocation generation must be revalidated after guest reentry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GlobalCompactStep {
    Complete(u32),
    DiscardCandidate(GlobalHandle),
}

impl GlobalHeap {
    /// Run a real allocator compaction pass: move unlocked movable blocks
    /// toward the heap's low end, then discard eligible blocks only if needed
    /// to reach the requested largest-free-range threshold. The return value
    /// is the actual largest allocatable contiguous range after the pass.
    /// Every stable selector and alias rebind is returned for the runtime to
    /// refresh its retained SelectorRefs after the physical move.
    pub fn compact(
        &mut self,
        minimum_free: u32,
        memory: &mut impl GuestMemory,
        selectors: &mut SelectorTable,
        selector_updates: &mut Vec<(SelectorRef, SelectorRef)>,
    ) -> Result<u32, Win16Error> {
        let mut skipped = Vec::new();
        skipped.try_reserve_exact(self.lru.len()).map_err(|_| Win16Error::OutOfMemory)?;
        loop {
            match self.compact_step(minimum_free, &skipped, true, true,
                memory, selectors, selector_updates)? {
                GlobalCompactStep::Complete(largest) => return Ok(largest),
                GlobalCompactStep::DiscardCandidate(identity) => {
                    skipped.push(identity);
                    selector_updates.try_reserve(selectors.slot_capacity())
                        .map_err(|_| Win16Error::OutOfMemory)?;
                    match self.discard(identity, selectors) {
                        Ok(replacements) => selector_updates.extend(replacements),
                        Err(Win16Error::SelectorBlockInterior | Win16Error::OutOfMemory
                            | Win16Error::Locked) => {},
                        Err(error) => return Err(error),
                    }
                }
            }
        }
    }

    /// Re-pack once, then select at most one discard without changing its
    /// residency. `skipped` contains full identities, so a reused raw handle
    /// is never mistaken for a candidate vetoed before a guest callback.
    pub fn compact_step(
        &mut self, minimum_free: u32, skipped: &[GlobalHandle],
        allow_move: bool, allow_discard: bool,
        memory: &mut impl GuestMemory, selectors: &mut SelectorTable,
        selector_updates: &mut Vec<(SelectorRef, SelectorRef)>,
    ) -> Result<GlobalCompactStep, Win16Error> {
        self.validate_memory(memory)?;
        selector_updates.try_reserve(selectors.slot_capacity())
            .map_err(|_| Win16Error::OutOfMemory)?;
        if allow_move { self.compact_movable_blocks(memory, selectors, selector_updates)?; }
        let largest = self.maximum_available()?;
        if largest >= minimum_free || !allow_discard {
            return Ok(GlobalCompactStep::Complete(largest));
        }
        for &raw in &self.lru {
            let block = self.blocks_by_handle.get(&raw).ok_or(Win16Error::InvalidHandle)?;
            if !block.discarded && block.flags.movable && !block.is_pinned() && block.discardable()
                && block.allocation_flags & GMEM_NODISCARD == 0
            {
                let identity = self.resolve_handle(RawGuestHandle(raw))?;
                if !skipped.contains(&identity) {
                    return Ok(GlobalCompactStep::DiscardCandidate(identity));
                }
            }
        }
        Ok(GlobalCompactStep::Complete(largest))
    }

    /// Largest single allocation that fits the current free ranges, without
    /// claiming that any compaction operation has already taken place.
    pub fn maximum_available(&self) -> Result<u32, Win16Error> {
        Ok(self.free_range_sizes()?.into_iter().max().unwrap_or(0))
    }

    /// Total allocator-available bytes. Alignment gaps that cannot begin an
    /// allocation are excluded consistently with `snapshot_regions`.
    pub fn total_available(&self) -> Result<u64, Win16Error> {
        self.free_range_sizes()?.into_iter().try_fold(0u64, |sum, size| {
            sum.checked_add(u64::from(size)).ok_or(Win16Error::InvalidRange)
        })
    }

    fn compact_movable_blocks(
        &mut self,
        memory: &mut impl GuestMemory,
        selectors: &mut SelectorTable,
        selector_updates: &mut Vec<(SelectorRef, SelectorRef)>,
    ) -> Result<(), Win16Error> {
        let mut order = Vec::new();
        order.try_reserve_exact(self.blocks_by_base.len())
            .map_err(|_| Win16Error::OutOfMemory)?;
        order.extend(self.blocks_by_base.iter().map(|(&base, &raw)| (base, raw)));
        let mut cursor = align_up(u64::from(self.base.0));
        for (old_base, raw) in order {
            let block = *self.blocks_by_handle.get(&raw).ok_or(Win16Error::InvalidHandle)?;
            if block.discarded { continue; }
            if !block.flags.movable || block.is_pinned()
                || block.allocation_flags & GMEM_NOCOMPACT != 0
            {
                let end = u64::from(old_base).checked_add(u64::from(block.capacity))
                    .ok_or(Win16Error::InvalidRange)?;
                cursor = cursor.max(align_up(end));
                continue;
            }
            let target = u32::try_from(cursor).map_err(|_| Win16Error::InvalidRange)?;
            if target < old_base {
                selector_updates.try_reserve(selectors.slot_capacity())
                    .map_err(|_| Win16Error::OutOfMemory)?;
                match self.move_block(raw, PhysAddr(target), memory, selectors, selector_updates) {
                    Ok(()) => {}
                    Err(Win16Error::SelectorTableFull | Win16Error::OutOfMemory
                        | Win16Error::SelectorBlockInterior) => {
                        cursor = align_up(u64::from(old_base)
                            .checked_add(u64::from(block.capacity)).ok_or(Win16Error::InvalidRange)?);
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }
            let updated = self.blocks_by_handle.get(&raw).ok_or(Win16Error::InvalidHandle)?;
            cursor = align_up(u64::from(updated.base.0)
                .checked_add(u64::from(updated.capacity)).ok_or(Win16Error::InvalidRange)?);
        }
        Ok(())
    }

    fn move_block(
        &mut self,
        raw: u16,
        target: PhysAddr,
        memory: &mut impl GuestMemory,
        selectors: &mut SelectorTable,
        selector_updates: &mut Vec<(SelectorRef, SelectorRef)>,
    ) -> Result<(), Win16Error> {
        let block = *self.blocks_by_handle.get(&raw).ok_or(Win16Error::InvalidHandle)?;
        if block.discarded || block.size == 0 || block.size > block.capacity {
            return Err(Win16Error::InvalidRange);
        }
        if !self.can_fit_at(target, block.capacity, Some(raw)) {
            return Err(Win16Error::InvalidRange);
        }
        let length = usize::try_from(block.capacity).map_err(|_| Win16Error::OutOfMemory)?;
        memory.validate_read(block.base, length)?;
        memory.validate_write(target, length)?;
        memory.validate_write(block.base, length)?;
        let mut bytes = allocate_bytes(length)?;
        memory.read(block.base, &mut bytes)?;
        // The source snapshot makes a leftward overlapping compaction move
        // safe: writing the target cannot consume bytes needed later in the
        // copy, and failure restores the complete old physical reservation.
        selectors.preflight_rebind_allocation_aliases(
            block.base, block.size, target, block.size,
            block.runtime_primary.or(block.selector), memory,
        )?;
        if let Err(write_error) = memory.write(target, &bytes) {
            return match memory.write(block.base, &bytes) {
                Ok(()) => Err(Win16Error::Memory(write_error)),
                Err(rollback) => Err(Win16Error::ReallocRollbackFailed {
                    write: write_error, rollback,
                }),
            };
        }
        let replacements = match selectors.rebind_allocation_aliases(
            block.base, block.size, target, block.size,
            block.runtime_primary.or(block.selector), memory,
        ) {
            Ok(replacements) => replacements,
            Err(error) => {
                return match memory.write(block.base, &bytes) {
                    Ok(()) => Err(error),
                    Err(rollback) => Err(Win16Error::Memory(rollback)),
                };
            }
        };
        self.blocks_by_base.remove(&block.base.0);
        self.blocks_by_base.insert(target.0, raw);
        let entry = self.blocks_by_handle.get_mut(&raw).ok_or(Win16Error::InvalidHandle)?;
        entry.base = target;
        entry.runtime_primary = entry.runtime_primary
            .map(|old| super::replacement_for(&replacements, old).unwrap_or(old));
        entry.selector = entry.selector
            .map(|old| super::replacement_for(&replacements, old).unwrap_or(old));
        selector_updates.extend(replacements);
        Ok(())
    }

    fn free_range_sizes(&self) -> Result<Vec<u32>, Win16Error> {
        let mut sizes = Vec::new();
        sizes.try_reserve_exact(self.blocks_by_base.len().saturating_add(1))
            .map_err(|_| Win16Error::OutOfMemory)?;
        let mut next = align_up(u64::from(self.base.0));
        for (&base, &raw) in &self.blocks_by_base {
            let block = self.blocks_by_handle.get(&raw).ok_or(Win16Error::InvalidHandle)?;
            if block.discarded || block.base.0 != base || u64::from(base) < next {
                return Err(Win16Error::InvalidRange);
            }
            if next < u64::from(base) {
                sizes.push(u32::try_from(u64::from(base) - next)
                    .map_err(|_| Win16Error::InvalidRange)?);
            }
            if block.size == 0 || block.size > block.capacity {
                return Err(Win16Error::InvalidRange);
            }
            next = align_up(u64::from(base).checked_add(u64::from(block.capacity))
                .ok_or(Win16Error::InvalidRange)?);
        }
        if next < self.end {
            sizes.push(u32::try_from(self.end - next).map_err(|_| Win16Error::InvalidRange)?);
        }
        Ok(sizes)
    }
}
