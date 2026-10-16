//! Checked contraction of resident allocation views without selector recycling.

use super::allocation::follows_allocation_extent;
use super::{DescriptorInfo, SelectorRef, SelectorTable, Win16Error};
use guest_core::{GuestMemory, PhysAddr};

impl SelectorTable {
    pub fn in_place_contraction_targets(
        &self,
        base: PhysAddr,
        old_size: u32,
        new_size: u32,
        memory: &impl GuestMemory,
    ) -> Result<Vec<(SelectorRef, DescriptorInfo)>, Win16Error> {
        let mut targets = Vec::new();
        targets
            .try_reserve_exact(self.entries.len())
            .map_err(|_| Win16Error::OutOfMemory)?;
        self.visit_contraction(base, old_size, new_size, memory, |reference, descriptor| {
            targets.push((reference, descriptor))
        })?;
        Ok(targets)
    }

    pub fn contract_allocation_in_place(
        &mut self,
        base: PhysAddr,
        old_size: u32,
        new_size: u32,
        memory: &impl GuestMemory,
    ) -> Result<(), Win16Error> {
        self.visit_contraction(base, old_size, new_size, memory, |_, _| {})?;
        // The checked candidate set cannot change during this synchronous
        // transaction. Descriptor generations, bases and access rights stay fixed.
        for entry in &mut self.entries[1..] {
            let Some(descriptor) = entry else {
                continue;
            };
            if follows_allocation_extent(*descriptor, base, old_size) {
                descriptor.limit = new_size - 1;
                descriptor.block_size = new_size;
            }
        }
        Ok(())
    }

    fn visit_contraction(
        &self,
        base: PhysAddr,
        old_size: u32,
        new_size: u32,
        memory: &impl GuestMemory,
        mut visit: impl FnMut(SelectorRef, DescriptorInfo),
    ) -> Result<(), Win16Error> {
        if new_size == 0 || new_size >= old_size || old_size > 0x10000 {
            return Err(Win16Error::InvalidSize);
        }
        let start = u64::from(base.0);
        let old_end = start + u64::from(old_size);
        let new_end = start + u64::from(new_size);
        for index in 1..self.entries.len() {
            let Some(descriptor) = self.entries[index] else {
                continue;
            };
            if !descriptor.present {
                continue;
            }
            let view_start = u64::from(descriptor.base.0);
            let view_end = view_start + u64::from(descriptor.limit) + 1;
            if view_start >= old_end || view_end <= start {
                continue;
            }
            if view_start < start
                || view_end > old_end
                || descriptor.segment_index != 0
                || descriptor.segment_count != 1
                || descriptor.block_index != index
            {
                return Err(Win16Error::SelectorBlockInterior);
            }
            let reference = self
                .reference_for(index, 0)
                .ok_or(Win16Error::StaleSelector)?;
            self.validate_all_segments(descriptor)?;
            if follows_allocation_extent(descriptor, base, old_size) {
                self.check_range(base, new_size, descriptor.rights, memory)?;
                visit(reference, self.describe(reference)?);
            } else if view_end > new_end {
                // An explicitly sized alias is a separate view contract. Do
                // not silently shorten it or leave a view into the retired tail.
                return Err(Win16Error::SelectorBlockInterior);
            }
        }
        Ok(())
    }
}
