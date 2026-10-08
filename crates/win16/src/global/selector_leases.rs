//! Runtime selector and page ownership counts kept separate from guest locks.

use super::{GlobalHandle, GlobalHeap, SelectorRef, SelectorTable};
use crate::Win16Error;

impl GlobalHeap {
    /// Confirms that this exact heap generation has already been retired.
    /// A raw handle from another heap or a generation never issued here is not
    /// retirement evidence.
    pub fn is_retired_identity(&self, handle: GlobalHandle) -> bool {
        if handle.heap_id != self.id || handle.raw.0 == 0 { return false; }
        let Some(last_generation) = self.generations.get(&handle.raw.0) else {
            return false;
        };
        if *last_generation < handle.generation { return false; }
        match self.blocks_by_handle.get(&handle.raw.0) {
            Some(_) => *last_generation > handle.generation,
            None => true,
        }
    }

    /// Attach the public Win16 primary selector to its exact allocation
    /// generation. Internal heap.lock selectors have a separate owner field.
    pub fn bind_runtime_primary(
        &mut self,
        handle: GlobalHandle,
        selector: SelectorRef,
    ) -> Result<(), Win16Error> {
        let block = self.lookup(handle)?;
        if block.runtime_primary == Some(selector) { return Ok(()); }
        if block.runtime_primary.is_some() || block.selector == Some(selector) {
            return Err(Win16Error::StaleSelector);
        }
        self.blocks_by_handle.get_mut(&handle.raw.0)
            .ok_or(Win16Error::InvalidHandle)?.runtime_primary = Some(selector);
        Ok(())
    }

    pub fn runtime_primary_selector(
        &self,
        handle: GlobalHandle,
    ) -> Result<Option<SelectorRef>, Win16Error> {
        Ok(self.lookup(handle)?.runtime_primary)
    }

    pub(super) fn preflight_block_selectors(
        &self,
        block: super::Block,
        selectors: &SelectorTable,
    ) -> Result<(), Win16Error> {
        let mut previous = None;
        for reference in [block.runtime_primary, block.selector].into_iter().flatten() {
            if previous == Some(reference) { continue; }
            selectors.describe(reference)?;
            previous = Some(reference);
        }
        Ok(())
    }

    pub(super) fn free_block_selectors(
        &self,
        block: super::Block,
        selectors: &mut SelectorTable,
    ) -> Result<(), Win16Error> {
        let mut previous = None;
        for reference in [block.runtime_primary, block.selector].into_iter().flatten() {
            if previous == Some(reference) { continue; }
            selectors.free_block(reference)?;
            previous = Some(reference);
        }
        Ok(())
    }

    /// Raw loader-owned selector pins, separate from guest locks and alias pins.
    pub fn internal_pin_count(&self, handle: GlobalHandle) -> Result<u16, Win16Error> {
        Ok(self.lookup(handle)?.internal_pin_count)
    }

    pub fn selector_alias_count(&self, handle: GlobalHandle) -> Result<u16, Win16Error> {
        Ok(self.lookup(handle)?.selector_alias_count)
    }

    pub fn page_lock_count(&self, handle: GlobalHandle) -> Result<u16, Win16Error> {
        Ok(self.lookup(handle)?.page_lock_count)
    }

    pub fn segment_lock_count(&self, handle: GlobalHandle) -> Result<u16, Win16Error> {
        Ok(self.lookup(handle)?.segment_lock_count)
    }

    pub fn retention_pin_count(&self, handle: GlobalHandle) -> Result<u32, Win16Error> {
        let block = self.lookup(handle)?;
        Ok(u32::from(block.internal_pin_count)
            + u32::from(block.selector_alias_count)
            + u32::from(block.page_lock_count))
    }

    /// Release an ended owner's block only after borrowed views are gone.
    pub fn free_on_teardown(
        &mut self,
        handle: GlobalHandle,
        selectors: &mut SelectorTable,
    ) -> Result<(), Win16Error> {
        let block = self.lookup(handle)?;
        if block.internal_pin_count != 0
            || block.selector_alias_count != 0
            || block.page_lock_count != 0
        {
            return Err(Win16Error::Locked);
        }
        self.preflight_block_selectors(block, selectors)?;
        self.free_block_selectors(block, selectors)?;
        self.remove_block(handle.raw.0, block);
        Ok(())
    }
}
