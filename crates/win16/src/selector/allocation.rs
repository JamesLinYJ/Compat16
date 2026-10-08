//! Selector transactions for moving or discarding GlobalHeap allocations.
use super::{
    AccessRights, AllocationResizePolicy, DescriptorInfo, SelectorRef, SelectorTable, SEGMENT_BYTES,
    Win16Error,
};
use guest_core::{GuestMemory, PhysAddr};

type Candidate = (SelectorRef, PhysAddr, u32, AccessRights);

impl SelectorTable {
    /// Checks whether every resident selector view at `base` permits an
    /// in-place extension. This is read-only so GlobalReAlloc can reject an
    /// ordinary no-grow case before writing any guest bytes.
    pub fn preflight_extend_allocation_in_place(
        &self,
        base: PhysAddr,
        old_size: u32,
        new_size: u32,
        memory: &impl GuestMemory,
    ) -> Result<(), Win16Error> {
        self.validate_in_place_extension(base, old_size, new_size, memory)
    }

    /// Captures the exact complete selector views whose limits this checked
    /// extension will change. The returned references preserve table and
    /// generation identity, and each descriptor is the pre-commit snapshot.
    /// Short aliases and `PreserveDescriptorShape` views are deliberately
    /// omitted because the extension leaves their limits unchanged.
    pub fn in_place_extension_targets(
        &self,
        base: PhysAddr,
        old_size: u32,
        new_size: u32,
        memory: &impl GuestMemory,
    ) -> Result<Vec<(SelectorRef, DescriptorInfo)>, Win16Error> {
        let mut targets = Vec::new();
        targets.try_reserve_exact(self.entries.len())
            .map_err(|_| Win16Error::OutOfMemory)?;
        self.visit_in_place_extension_targets(base, old_size, new_size, memory,
            |reference, descriptor| targets.push((reference, descriptor)))?;
        Ok(targets)
    }

    /// Extends every complete selector view of one resident allocation without
    /// changing its base, raw selector, generation, or rights. A precisely
    /// shorter view of the same base keeps its existing limit and allocation
    /// size. This is separate from rebind: no selector run is moved/resized,
    /// and no discarded selector is made resident by this operation.
    pub fn extend_allocation_in_place(
        &mut self,
        base: PhysAddr,
        old_size: u32,
        new_size: u32,
        memory: &impl GuestMemory,
    ) -> Result<(), Win16Error> {
        self.validate_in_place_extension(base, old_size, new_size, memory)?;

        // Validation has identified the complete candidate set. Re-scan the
        // immutable table shape and commit those same candidates without
        // allocating or introducing a new failure point.
        for entry in &mut self.entries[1..] {
            let Some(descriptor) = entry.as_mut() else { continue; };
            if follows_allocation_extent(*descriptor, base, old_size) {
                descriptor.limit = new_size - 1;
                descriptor.block_size = new_size;
            }
        }
        Ok(())
    }

    fn validate_in_place_extension(
        &self,
        base: PhysAddr,
        old_size: u32,
        new_size: u32,
        memory: &impl GuestMemory,
    ) -> Result<(), Win16Error> {
        self.visit_in_place_extension_targets(base, old_size, new_size, memory, |_, _| {})
    }

    fn visit_in_place_extension_targets(
        &self,
        base: PhysAddr,
        old_size: u32,
        new_size: u32,
        memory: &impl GuestMemory,
        mut visit: impl FnMut(SelectorRef, DescriptorInfo),
    ) -> Result<(), Win16Error> {
        const MAX_SINGLE_SELECTOR_BYTES: u32 = 0x1_0000;

        if old_size == 0 || old_size > MAX_SINGLE_SELECTOR_BYTES
            || new_size <= old_size || new_size > MAX_SINGLE_SELECTOR_BYTES
        {
            return Err(Win16Error::InvalidSize);
        }

        for index in 1..self.entries.len() {
            let Some(descriptor) = self.entries[index] else { continue; };
            if !descriptor.present || descriptor.base != base { continue; }

            if descriptor.segment_index != 0 || descriptor.block_index != index
                || descriptor.segment_count != 1
            {
                return Err(Win16Error::SelectorBlockInterior);
            }
            let reference = self.reference_for(index, 0).ok_or(Win16Error::StaleSelector)?;
            if self.validate(reference)? != descriptor {
                return Err(Win16Error::StaleSelector);
            }
            self.validate_all_segments(descriptor)?;

            let exposed_size = descriptor.limit.checked_add(1)
                .ok_or(Win16Error::InvalidRange)?;
            if follows_allocation_extent(descriptor, base, old_size)
                && exposed_size == old_size {
                self.check_range(base, new_size, descriptor.rights, memory)?;
                let reference = self.reference_for(index, 0).ok_or(Win16Error::StaleSelector)?;
                visit(reference, self.describe(reference)?);
            } else if descriptor.block_size <= old_size
                && exposed_size == descriptor.block_size
            {
                // Exact short views and AllocSelector copies keep their
                // current limits as the containing allocation grows.
                self.check_range(base, exposed_size, descriptor.rights, memory)?;
            } else {
                // A longer or inconsistent view, including a partial
                // PrestoChangoSelector projection, makes ownership ambiguous.
                return Err(Win16Error::SelectorBlockInterior);
            }
        }
        Ok(())
    }

    /// Check every selector and generation change before a caller overwrites
    /// any guest bytes that may overlap the old allocation.
    pub fn preflight_rebind_allocation_aliases(
        &self,
        old_base: PhysAddr,
        old_size: u32,
        new_base: PhysAddr,
        new_size: u32,
        primary: Option<SelectorRef>,
        memory: &impl GuestMemory,
    ) -> Result<(), Win16Error> {
        let candidates = self.rebind_candidates(
            old_base, old_size, new_base, new_size, primary, memory,
        )?;
        let count = u64::try_from(candidates.len()).map_err(|_| Win16Error::GenerationExhausted)?;
        self.next_generation.checked_add(count).ok_or(Win16Error::GenerationExhausted)?;
        Ok(())
    }

    /// Rebase all aliases fully contained in an allocation. Partial aliases,
    /// including aliases through a non-head selector in a multi-selector
    /// block, reject the operation rather than retaining stale guest pointers.
    pub fn rebind_allocation_aliases(
        &mut self,
        old_base: PhysAddr,
        old_size: u32,
        new_base: PhysAddr,
        new_size: u32,
        primary: Option<SelectorRef>,
        memory: &impl GuestMemory,
    ) -> Result<Vec<(SelectorRef, SelectorRef)>, Win16Error> {
        let candidates = self.rebind_candidates(
            old_base, old_size, new_base, new_size, primary, memory,
        )?;
        let count = u64::try_from(candidates.len()).map_err(|_| Win16Error::GenerationExhausted)?;
        self.next_generation.checked_add(count).ok_or(Win16Error::GenerationExhausted)?;

        let mut replacements = Vec::new();
        replacements.try_reserve_exact(candidates.len()).map_err(|_| Win16Error::OutOfMemory)?;
        let mut undos = Vec::new();
        undos.try_reserve_exact(candidates.len()).map_err(|_| Win16Error::OutOfMemory)?;
        for (reference, target, size, rights) in candidates {
            let plan = match self.plan_rebind(reference, target, size, rights, memory) {
                Ok(plan) => plan,
                Err(error) => {
                    for undo in undos.into_iter().rev() { self.rollback_rebind(undo); }
                    return Err(error);
                }
            };
            match self.commit_rebind(plan) {
                Ok((replacement, undo)) => {
                    replacements.push((reference, replacement));
                    undos.push(undo);
                }
                Err(error) => {
                    for undo in undos.into_iter().rev() { self.rollback_rebind(undo); }
                    return Err(error);
                }
            }
        }
        Ok(replacements)
    }

    /// Unback the sole selector block representing a discarded allocation.
    /// Extra aliases are refused because their later reload relationship is
    /// not represented by the Win16 HGLOBAL map.
    pub fn unback_allocation_selector(
        &mut self,
        base: PhysAddr,
        size: u32,
    ) -> Result<Vec<(SelectorRef, SelectorRef)>, Win16Error> {
        if size == 0 { return Err(Win16Error::InvalidSize); }
        let start = u64::from(base.0);
        let end = start.checked_add(u64::from(size)).ok_or(Win16Error::InvalidRange)?;
        let mut match_ref = None;
        for index in 1..self.entries.len() {
            let Some(descriptor) = self.entries[index] else { continue; };
            if !descriptor.present { continue; }
            let segment_start = u64::from(descriptor.base.0);
            let segment_end = segment_start
                .checked_add(u64::from(descriptor.limit) + 1)
                .ok_or(Win16Error::InvalidRange)?;
            if segment_start >= end || start >= segment_end { continue; }
            if descriptor.segment_index != 0 {
                let head = self.entries.get(descriptor.block_index)
                    .and_then(|entry| *entry).ok_or(Win16Error::StaleSelector)?;
                let head_start = u64::from(head.base.0);
                let head_end = head_start.checked_add(u64::from(head.block_size))
                    .ok_or(Win16Error::InvalidRange)?;
                if head_start < start || head_end > end {
                    return Err(Win16Error::SelectorBlockInterior);
                }
                let expected = head_start
                    .checked_add((descriptor.segment_index as u64).checked_mul(SEGMENT_BYTES)
                        .ok_or(Win16Error::InvalidRange)?)
                    .ok_or(Win16Error::InvalidRange)?;
                if segment_start != expected || descriptor.rights != head.rights
                    || descriptor.generation != head.generation
                {
                    return Err(Win16Error::SelectorBlockInterior);
                }
                continue;
            }
            let descriptor_start = u64::from(descriptor.base.0);
            let descriptor_end = descriptor_start.checked_add(u64::from(descriptor.block_size))
                .ok_or(Win16Error::InvalidRange)?;
            if descriptor_start < start || descriptor_end > end || match_ref.is_some() {
                return Err(Win16Error::SelectorBlockInterior);
            }
            match_ref = Some(self.reference_for(index, 0).ok_or(Win16Error::StaleSelector)?);
        }
        let Some(reference) = match_ref else { return Ok(Vec::new()); };
        let mut updates = Vec::new();
        updates.try_reserve_exact(1).map_err(|_| Win16Error::OutOfMemory)?;
        let replacement = self.mark_unbacked(reference)?;
        updates.push((reference, replacement));
        Ok(updates)
    }

    fn rebind_candidates(
        &self,
        old_base: PhysAddr,
        old_size: u32,
        new_base: PhysAddr,
        new_size: u32,
        primary: Option<SelectorRef>,
        memory: &impl GuestMemory,
    ) -> Result<Vec<Candidate>, Win16Error> {
        if old_size == 0 || new_size == 0 { return Err(Win16Error::InvalidSize); }
        let old_start = u64::from(old_base.0);
        let old_end = old_start.checked_add(u64::from(old_size))
            .ok_or(Win16Error::InvalidRange)?;
        let mut candidates = Vec::new();
        candidates.try_reserve_exact(self.entries.len())
            .map_err(|_| Win16Error::OutOfMemory)?;
        let mut candidate_heads = Vec::new();
        candidate_heads.try_reserve_exact(self.entries.len())
            .map_err(|_| Win16Error::OutOfMemory)?;
        candidate_heads.resize(self.entries.len(), false);
        for index in 1..self.entries.len() {
            let Some(descriptor) = self.entries[index] else { continue; };
            if descriptor.segment_index != 0 || !descriptor.present { continue; }
            let start = u64::from(descriptor.base.0);
            let end = start.checked_add(u64::from(descriptor.block_size))
                .ok_or(Win16Error::InvalidRange)?;
            if start >= old_end || old_start >= end { continue; }
            if start < old_start || end > old_end {
                return Err(Win16Error::SelectorBlockInterior);
            }
            let offset = start - old_start;
            let reference = self.reference_for(index, 0).ok_or(Win16Error::StaleSelector)?;
            let target_size = if Some(reference) == primary
                || (descriptor.resize_policy == AllocationResizePolicy::FollowAllocationExtent
                    && offset == 0
                    && descriptor.block_size == old_size)
            {
                new_size.checked_sub(u32::try_from(offset).map_err(|_| Win16Error::InvalidRange)?)
                    .ok_or(Win16Error::SelectorBlockInterior)?
            } else {
                descriptor.block_size
            };
            if u64::from(target_size).checked_add(offset)
                .ok_or(Win16Error::InvalidRange)? > u64::from(new_size)
            {
                return Err(Win16Error::SelectorBlockInterior);
            }
            let target = u32::try_from(u64::from(new_base.0).checked_add(offset)
                .ok_or(Win16Error::InvalidRange)?)
                .map_err(|_| Win16Error::InvalidRange)?;
            self.plan_rebind(reference, PhysAddr(target), target_size, descriptor.rights, memory)?;
            candidate_heads[index] = true;
            candidates.push((reference, PhysAddr(target), target_size, descriptor.rights));
        }

        // Detect a source pointer installed into a non-head selector by
        // PrestoChangoSelector. Ordinary large selector blocks have their head
        // in this allocation and are already included above; an interior alias
        // with a different head cannot be safely moved as a whole.
        for index in 1..self.entries.len() {
            let Some(descriptor) = self.entries[index] else { continue; };
            if !descriptor.present || descriptor.segment_index == 0 { continue; }
            let segment_start = u64::from(descriptor.base.0);
            let segment_end = segment_start.checked_add(u64::from(descriptor.limit) + 1)
                .ok_or(Win16Error::InvalidRange)?;
            if segment_start >= old_end || old_start >= segment_end { continue; }
            if !candidate_heads.get(descriptor.block_index).copied().unwrap_or(false) {
                return Err(Win16Error::SelectorBlockInterior);
            }
            let head = self.entries.get(descriptor.block_index)
                .and_then(|entry| *entry).ok_or(Win16Error::StaleSelector)?;
            let head_start = u64::from(head.base.0);
            let head_end = head_start.checked_add(u64::from(head.block_size))
                .ok_or(Win16Error::InvalidRange)?;
            if head_start < old_start || head_end > old_end {
                return Err(Win16Error::SelectorBlockInterior);
            }
            let expected_start = head_start
                .checked_add((descriptor.segment_index as u64).checked_mul(SEGMENT_BYTES)
                    .ok_or(Win16Error::InvalidRange)?)
                .ok_or(Win16Error::InvalidRange)?;
            if segment_start != expected_start || descriptor.rights != head.rights
                || descriptor.generation != head.generation
            {
                return Err(Win16Error::SelectorBlockInterior);
            }
        }
        Ok(candidates)
    }
}

fn follows_allocation_extent(
    descriptor: super::descriptor::Descriptor,
    base: PhysAddr,
    old_size: u32,
) -> bool {
    descriptor.present
        && descriptor.base == base
        && descriptor.block_size == old_size
        && descriptor.limit == old_size - 1
        && descriptor.resize_policy == AllocationResizePolicy::FollowAllocationExtent
}
