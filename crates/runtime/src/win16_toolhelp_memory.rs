//! ToolHelp memory information projected from the guest Win16 allocator.

use guest_core::memory::Memory;
use win16_abi::{toolhelp_abi::MemManInfo16, Access, GlobalHeapRegion};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError};

// The guest allocator does not expose a VMM page manager or swap file. Use a
// documented Win16-compatible page view over its real guest ranges instead of
// leaking the host process' unrelated virtual-memory totals into this ABI.
const GUEST_PAGE_SIZE: u32 = 4096;
const PAGE_ALLOCATED: u8 = 1;
const PAGE_LOCKED: u8 = 2;

impl Win16State {
    /// Report the real guest global-heap allocation window as the memory
    /// manager's compatibility projection. Allocatable bytes and the largest
    /// block come from the allocator; page counts are 4 KiB guest-linear pages.
    /// This intentionally makes no claim about host RAM, VMM capacity, or swap.
    pub(super) fn toolhelp_memman_info(
        &self,
        output: u32,
        memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Ok(pointer) = self.selectors.pointer_from_far(output) else { return Ok(0); };
        if self.selectors.translate(pointer, Access::Read, 4, memory).is_err() {
            return Ok(0);
        }
        let mut size_bytes = [0_u8; 4];
        self.selectors.read(memory, pointer, &mut size_bytes).map_err(crate::runtime_error)?;
        if u32::from_le_bytes(size_bytes) < MemManInfo16::SIZE as u32 {
            return Ok(0);
        }
        if self.selectors.translate(pointer, Access::Write, MemManInfo16::SIZE, memory).is_err() {
            return Ok(0);
        }

        let regions = self.heap.snapshot_regions().map_err(crate::runtime_error)?;
        // Region snapshots omit allocator alignment padding, so their minimum
        // and maximum addresses can undercount the fixed guest reservation.
        let heap_range = self.heap.guest_range();
        let largest_free_block = self.heap.maximum_available().map_err(crate::runtime_error)?;
        let page_start = align_up_page(heap_range.start);
        let page_end = heap_range.end & !u64::from(GUEST_PAGE_SIZE - 1);
        let page_count = page_end.saturating_sub(page_start) / u64::from(GUEST_PAGE_SIZE);
        let page_count = usize::try_from(page_count).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "ToolHelp guest heap page count exceeds addressable metadata",
            error,
        ))?;
        let mut pages = Vec::new();
        pages.try_reserve_exact(page_count).map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate ToolHelp guest heap page snapshot",
            error,
        ))?;
        pages.resize(page_count, 0_u8);
        for region in regions {
            let GlobalHeapRegion::Allocated { identity, info, .. } = region else { continue; };
            if info.discarded { continue; }
            let block_end = u64::from(info.base.0)
                .checked_add(u64::from(self.heap.reserved_capacity(identity)
                    .map_err(crate::runtime_error)?))
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "ToolHelp allocated guest block range overflowed"))?;
            let overlap_start = u64::from(info.base.0).max(page_start);
            let overlap_end = block_end.min(page_end);
            if overlap_start >= overlap_end { continue; }
            let first_page = usize::try_from(
                (overlap_start - page_start) / u64::from(GUEST_PAGE_SIZE),
            ).map_err(|error| RuntimeError::with_source(Kind::InternalInvariant,
                "ToolHelp guest page index exceeds host address width", error))?;
            let last_page = usize::try_from(
                (overlap_end - page_start + u64::from(GUEST_PAGE_SIZE - 1))
                    / u64::from(GUEST_PAGE_SIZE),
            ).map_err(|error| RuntimeError::with_source(Kind::InternalInvariant,
                "ToolHelp guest page range exceeds host address width", error))?;
            let flags = PAGE_ALLOCATED | if info.page_lock_count != 0 { PAGE_LOCKED } else { 0 };
            for page in pages.get_mut(first_page..last_page.min(page_count)).ok_or_else(||
                RuntimeError::new(Kind::InternalInvariant,
                    "ToolHelp guest heap snapshot contains an invalid page range"))? {
                *page |= flags;
            }
        }
        let free_page_count = pages.iter().filter(|flags| **flags & PAGE_ALLOCATED == 0).count();
        let unlocked_pages = pages.iter().filter(|flags| **flags & PAGE_LOCKED == 0).count();
        let page_value = |value: usize| u32::try_from(value).unwrap_or(u32::MAX);
        let total_pages = page_value(page_count);
        let free_pages = page_value(free_page_count);
        let unlocked_pages = page_value(unlocked_pages);
        // DPMI 0500h reports both linear-space quantities in pages. The
        // Windows XP TOOLHELP memman.asm copies those fields unchanged and
        // labels FreeLinearSpace as a page count; preserve that ABI unit in
        // this projection of the actual guest heap ranges.
        let total_linear_space = total_pages;
        let free_linear_space = free_pages;
        let value = MemManInfo16 {
            largest_free_block,
            max_pages_available: free_pages,
            max_pages_lockable: unlocked_pages,
            total_linear_space,
            total_unlocked_pages: unlocked_pages,
            free_pages,
            total_pages,
            free_linear_space,
            swap_file_pages: 0,
            page_size: GUEST_PAGE_SIZE as u16,
        };
        self.selectors.write(memory, pointer,
            &value.encode_with_size(u32::from_le_bytes(size_bytes)))
            .map_err(crate::runtime_error)?;
        Ok(1)
    }
}

fn align_up_page(value: u64) -> u64 {
    let page_size = u64::from(GUEST_PAGE_SIZE);
    value.saturating_add(page_size - 1) & !(page_size - 1)
}
