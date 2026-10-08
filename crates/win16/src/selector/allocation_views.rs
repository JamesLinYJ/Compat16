//! Exact selector-view suspension and retirement for process-owned allocations.

use guest_core::PhysAddr;

use super::{SelectorAllocationView, SelectorRef, SelectorTable, Win16Error};

impl SelectorTable {
    /// Captures and suspends every complete selector block that currently
    /// exposes bytes inside one allocation. Suspended descriptors retain their
    /// exact raw selectors and generations, but checked guest translations
    /// reject them until `resume_allocation_views` or retirement completes.
    ///
    /// A block crossing the allocation boundary is refused before mutation:
    /// retiring only part of a selector run could leave a view into unmapped
    /// storage. Independent short aliases wholly contained in the allocation
    /// are captured and suspended normally.
    pub fn suspend_allocation_views(
        &mut self,
        base: PhysAddr,
        size: u32,
    ) -> Result<Vec<SelectorAllocationView>, Win16Error> {
        if size == 0 {
            return Err(Win16Error::InvalidSize);
        }
        let allocation_start = u64::from(base.0);
        let allocation_end = allocation_start
            .checked_add(u64::from(size))
            .ok_or(Win16Error::InvalidRange)?;

        let mut views = Vec::new();
        views
            .try_reserve_exact(self.entries.len())
            .map_err(|_| Win16Error::OutOfMemory)?;
        let mut seen_blocks = Vec::new();
        seen_blocks
            .try_reserve_exact(self.entries.len())
            .map_err(|_| Win16Error::OutOfMemory)?;
        seen_blocks.resize(self.entries.len(), false);

        for index in 1..self.entries.len() {
            let Some(descriptor) = self.entries[index] else {
                continue;
            };
            if !descriptor.present {
                continue;
            }
            let view_start = u64::from(descriptor.base.0);
            let view_end = view_start
                .checked_add(u64::from(descriptor.limit) + 1)
                .ok_or(Win16Error::InvalidRange)?;
            if view_start >= allocation_end || allocation_start >= view_end {
                continue;
            }

            let block_index = descriptor.block_index;
            if seen_blocks.get(block_index).copied().unwrap_or(false) {
                continue;
            }
            let view =
                self.capture_allocation_view(block_index, allocation_start, allocation_end)?;
            seen_blocks[block_index] = true;
            views.push(view);
        }

        // Every fallible allocation and consistency check is complete before
        // changing the descriptors, so a failure leaves every alias live.
        for view in &views {
            for (segment, mut descriptor) in view.descriptors.iter().copied().enumerate() {
                descriptor.present = false;
                self.entries[view.block_index + segment] = Some(descriptor);
            }
        }
        Ok(views)
    }

    /// Verifies that captured views remain exactly suspended. This is useful
    /// during retryable cleanup after the native bitmap has already been
    /// deleted; a replaced selector identity must never be retired by mistake.
    pub fn validate_suspended_allocation_views(
        &self,
        views: &[SelectorAllocationView],
    ) -> Result<(), Win16Error> {
        self.validate_allocation_view_set(views, false)
    }

    /// Restores every suspended alias with its original descriptor generation
    /// after native DeleteObject returns FALSE. The commit contains no
    /// allocation and cannot partially restore the captured set.
    pub fn resume_allocation_views(
        &mut self,
        views: &[SelectorAllocationView],
    ) -> Result<(), Win16Error> {
        self.validate_allocation_view_set(views, false)?;
        for view in views {
            for (segment, original) in view.descriptors.iter().copied().enumerate() {
                let mut descriptor = original;
                descriptor.present = true;
                self.entries[view.block_index + segment] = Some(descriptor);
            }
        }
        Ok(())
    }

    /// Retires a complete suspended view set after its native backing has
    /// already been removed. `owned_blocks` are selector blocks explicitly
    /// owned by the caller and are freed. Other views become inaccessible
    /// reservations with fresh generations, preventing stale raw aliases from
    /// resolving to a later allocation. All identities are preflighted before
    /// any table mutation.
    pub fn retire_suspended_allocation_views(
        &mut self,
        views: &[SelectorAllocationView],
        owned_blocks: &[SelectorRef],
    ) -> Result<Vec<(SelectorRef, SelectorRef)>, Win16Error> {
        self.validate_allocation_view_set(views, false)?;

        for (index, reference) in owned_blocks.iter().enumerate() {
            if owned_blocks[..index].contains(reference)
                || !views.iter().any(|view| view.reference == *reference)
            {
                return Err(Win16Error::StaleSelector);
            }
        }
        let reservation_count = views
            .iter()
            .filter(|view| !owned_blocks.contains(&view.reference))
            .count();
        let reservation_count =
            u64::try_from(reservation_count).map_err(|_| Win16Error::GenerationExhausted)?;
        let next_generation = self
            .next_generation
            .checked_add(reservation_count)
            .ok_or(Win16Error::GenerationExhausted)?;
        let mut updates = Vec::new();
        updates
            .try_reserve_exact(
                usize::try_from(reservation_count).map_err(|_| Win16Error::OutOfMemory)?,
            )
            .map_err(|_| Win16Error::OutOfMemory)?;

        let mut generation = self.next_generation;
        for view in views {
            if owned_blocks.contains(&view.reference) {
                for segment in 0..view.segment_count {
                    self.entries[view.block_index + segment] = None;
                }
                continue;
            }
            self.install_unbacked(
                view.block_index,
                view.segment_count,
                view.resize_policy,
                generation,
            );
            let replacement = SelectorRef {
                raw: view.reference.raw,
                generation,
                table_id: self.id,
                block_index: view.block_index,
                segment_index: 0,
                segment_count: view.segment_count,
            };
            updates.push((view.reference, replacement));
            generation += 1;
        }
        self.next_generation = next_generation;
        Ok(updates)
    }

    fn capture_allocation_view(
        &self,
        block_index: usize,
        allocation_start: u64,
        allocation_end: u64,
    ) -> Result<SelectorAllocationView, Win16Error> {
        let head = *self
            .entries
            .get(block_index)
            .and_then(|entry| entry.as_ref())
            .ok_or(Win16Error::StaleSelector)?;
        if head.block_index != block_index
            || head.segment_index != 0
            || head.segment_count == 0
            || !head.present
        {
            return Err(Win16Error::SelectorBlockInterior);
        }
        let block_end = block_index
            .checked_add(head.segment_count)
            .ok_or(Win16Error::InvalidRange)?;
        if block_end > self.entries.len() {
            return Err(Win16Error::SelectorBlockInterior);
        }
        let reference = self
            .reference_for(block_index, 0)
            .ok_or(Win16Error::StaleSelector)?;
        if self.validate(reference)? != head {
            return Err(Win16Error::StaleSelector);
        }

        let mut descriptors = Vec::new();
        descriptors
            .try_reserve_exact(head.segment_count)
            .map_err(|_| Win16Error::OutOfMemory)?;
        let mut overlaps = false;
        for segment in 0..head.segment_count {
            let descriptor = *self.entries[block_index + segment]
                .as_ref()
                .ok_or(Win16Error::StaleSelector)?;
            if descriptor.block_index != block_index
                || descriptor.segment_index != segment
                || descriptor.segment_count != head.segment_count
                || descriptor.resize_policy != head.resize_policy
                || descriptor.generation != head.generation
                || descriptor.present != head.present
            {
                return Err(Win16Error::SelectorBlockInterior);
            }
            let start = u64::from(descriptor.base.0);
            let end = start
                .checked_add(u64::from(descriptor.limit) + 1)
                .ok_or(Win16Error::InvalidRange)?;
            if start < allocation_start || end > allocation_end {
                return Err(Win16Error::SelectorBlockInterior);
            }
            overlaps |= start < allocation_end && allocation_start < end;
            let segment_ref = self
                .reference_for(block_index, segment)
                .ok_or(Win16Error::StaleSelector)?;
            if self.validate(segment_ref)? != descriptor {
                return Err(Win16Error::StaleSelector);
            }
            descriptors.push(descriptor);
        }
        if !overlaps {
            return Err(Win16Error::SelectorBlockInterior);
        }
        Ok(SelectorAllocationView {
            table_id: self.id,
            reference,
            block_index,
            segment_count: head.segment_count,
            resize_policy: head.resize_policy,
            generation: head.generation,
            descriptors,
        })
    }

    fn validate_allocation_view_set(
        &self,
        views: &[SelectorAllocationView],
        present: bool,
    ) -> Result<(), Win16Error> {
        for (index, view) in views.iter().enumerate() {
            if view.table_id != self.id
                || view.reference.table_id != self.id
                || view.reference.block_index != view.block_index
                || view.reference.segment_index != 0
                || view.reference.segment_count != view.segment_count
                || view.reference.generation != view.generation
                || view.descriptors.len() != view.segment_count
                || views[..index]
                    .iter()
                    .any(|previous| previous.block_index == view.block_index)
            {
                return Err(Win16Error::StaleSelector);
            }
            let current_reference = self
                .reference_for(view.block_index, 0)
                .ok_or(Win16Error::StaleSelector)?;
            if current_reference != view.reference {
                return Err(Win16Error::StaleSelector);
            }
            for (segment, saved) in view.descriptors.iter().copied().enumerate() {
                if saved.resize_policy != view.resize_policy {
                    return Err(Win16Error::StaleSelector);
                }
                let current = self
                    .entries
                    .get(view.block_index + segment)
                    .and_then(|entry| *entry)
                    .ok_or(Win16Error::StaleSelector)?;
                let mut expected = saved;
                expected.present = present;
                if current != expected {
                    return Err(Win16Error::StaleSelector);
                }
            }
        }
        Ok(())
    }
}
