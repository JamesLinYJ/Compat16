//! GlobalPageLock/Unlock resolve checked selector views to their backing owner.

use guest_core::Selector;
use win16_abi::{GlobalHeapRegion, SelectorRef, Win16Error};

use super::Win16State;
use crate::RuntimeError;

impl Win16State {
    pub(super) fn kernel_global_page_lock(
        &mut self,
        selector_word: u16,
    ) -> Result<u16, RuntimeError> {
        let Some(selector) = self.checked_page_selector(selector_word) else { return Ok(0); };
        let (_head, base, size) = self.selectors.allocation_range(selector)
            .map_err(crate::runtime_error)?;
        if let Some(handle) = self.dos_global_blocks.iter().find_map(|(&handle, block)| {
            (!block.mcb_released && range_contains(block.extent.guest_base().map(|base| base.0),
                u64::from(block.size), base.0, u64::from(size))).then_some(handle)
        }) {
            let block = self.dos_global_blocks.get_mut(&handle).ok_or_else(|| RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "Win16 DOS page-lock owner disappeared after selector resolution",
            ))?;
            if block.page_lock_count == u16::MAX { return Ok(0); }
            block.page_lock_count += 1;
            return Ok(block.page_lock_count);
        }
        let identity = self.global_heap_identity_for_range(base.0, size)?;
        let Some(identity) = identity else { return Ok(0); };
        match self.heap.page_lock(identity) {
            Ok(count) => Ok(count),
            Err(Win16Error::InvalidHandle | Win16Error::LockCountOverflow) => Ok(0),
            Err(error) => Err(crate::runtime_error(error)
                .with_context("locking Win16 global pages by selector")),
        }
    }

    pub(super) fn kernel_global_page_unlock(
        &mut self,
        selector_word: u16,
    ) -> Result<u16, RuntimeError> {
        let Some(selector) = self.checked_page_selector(selector_word) else { return Ok(0); };
        let (_head, base, size) = self.selectors.allocation_range(selector)
            .map_err(crate::runtime_error)?;
        if let Some(handle) = self.dos_global_blocks.iter().find_map(|(&handle, block)| {
            (!block.mcb_released && range_contains(block.extent.guest_base().map(|base| base.0),
                u64::from(block.size), base.0, u64::from(size))).then_some(handle)
        }) {
            let block = self.dos_global_blocks.get_mut(&handle).ok_or_else(|| RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "Win16 DOS page-unlock owner disappeared after selector resolution",
            ))?;
            if block.page_lock_count != 0 { block.page_lock_count -= 1; }
            return Ok(block.page_lock_count);
        }
        let identity = self.global_heap_identity_for_range(base.0, size)?;
        let Some(identity) = identity else { return Ok(0); };
        match self.heap.page_unlock(identity) {
            Ok(count) => {
                self.module_reap_pending = true;
                Ok(count)
            }
            Err(Win16Error::InvalidHandle) => Ok(0),
            Err(error) => Err(crate::runtime_error(error)
                .with_context("unlocking Win16 global pages by selector")),
        }
    }

    fn checked_page_selector(&self, raw: u16) -> Option<SelectorRef> {
        if raw == 0 { return None; }
        self.selectors.reference(Selector(raw)).ok()
    }

    fn global_heap_identity_for_range(
        &self,
        base: u32,
        size: u32,
    ) -> Result<Option<win16_abi::GlobalHandle>, RuntimeError> {
        let regions = self.heap.snapshot_regions().map_err(crate::runtime_error)?;
        let mut found = None;
        for region in regions {
            let GlobalHeapRegion::Allocated { identity, info, .. } = region else { continue; };
            if info.discarded || !range_contains(Some(info.base.0), u64::from(info.size), base, u64::from(size)) {
                continue;
            }
            if found.replace(identity).is_some() {
                return Err(RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                    "Win16 selector range matches multiple global allocations"));
            }
        }
        Ok(found)
    }
}

fn range_contains(container_base: Option<u32>, container_size: u64, base: u32, size: u64) -> bool {
    let Some(container_base) = container_base else { return false; };
    let start = u64::from(container_base);
    let Some(container_end) = start.checked_add(container_size) else { return false; };
    let view_start = u64::from(base);
    let Some(view_end) = view_start.checked_add(size) else { return false; };
    view_start >= start && view_end <= container_end
}
