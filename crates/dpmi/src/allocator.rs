use std::collections::BTreeMap;
use std::convert::TryFrom;

use guest_core::{GuestMemory, LinearAddr, MemoryError, OwnerId, PhysAddr};

use crate::types::{
    Allocation, ArenaBounds, DpmiError, DpmiHandle, DpmiMemoryStats, LinearMapping, DPMI_PAGE_SIZE,
};

#[derive(Clone, Debug)]
struct Block {
    owner: OwnerId,
    handle: DpmiHandle,
    page_start: u32,
    page_count: u32,
    size: u32,
}

/// DPMI page allocator. Only metadata is stored here; guest bytes remain in
/// the shared `GuestMemory` supplied to operations.
#[derive(Clone, Debug)]
pub struct DpmiMemory {
    arena: ArenaBounds,
    total_pages: u32,
    /// Free extents keyed by first page index, with page count as the value.
    free_pages: BTreeMap<u32, u32>,
    blocks: BTreeMap<DpmiHandle, Block>,
    next_handle: u32,
}

impl DpmiMemory {
    /// Create an allocator over a caller-reserved physical arena and a guest
    /// linear range. Both bases and `arena_size` must be 4 KiB aligned. The
    /// mapping between them is offset-for-offset; no host pointer is exposed.
    ///
    /// `GuestMemory::len()` is checked whenever bytes are touched. The caller
    /// is responsible for assigning an arena that does not overlap memory
    /// reserved for other runtime services.
    pub fn new(
        physical_start: PhysAddr,
        linear_start: LinearAddr,
        arena_size: u32,
    ) -> Result<Self, DpmiError> {
        if arena_size == 0
            || arena_size % DPMI_PAGE_SIZE != 0
            || physical_start.0 % DPMI_PAGE_SIZE != 0
            || linear_start.0 % DPMI_PAGE_SIZE != 0
        {
            return Err(DpmiError::InvalidArenaConfiguration);
        }

        let physical_end = u64::from(physical_start.0) + u64::from(arena_size);
        let linear_end = u64::from(linear_start.0) + u64::from(arena_size);
        let address_space_end = u64::from(u32::MAX) + 1;
        if physical_end > address_space_end || linear_end > address_space_end {
            return Err(DpmiError::InvalidArenaConfiguration);
        }

        let total_pages = arena_size / DPMI_PAGE_SIZE;
        let mut free_pages = BTreeMap::new();
        free_pages.insert(0, total_pages);

        Ok(Self {
            arena: ArenaBounds {
                physical_start,
                linear_start,
                physical_end,
                linear_end,
                size: arena_size,
            },
            total_pages,
            free_pages,
            blocks: BTreeMap::new(),
            next_handle: 1,
        })
    }

    pub fn arena_bounds(&self) -> ArenaBounds {
        self.arena
    }

    /// Allocate a zero-filled, page-aligned block owned by `owner`.
    ///
    /// The free list and handle sequence change only after the selected guest
    /// range has been validated and initialized successfully.
    pub fn allocate(
        &mut self,
        owner: OwnerId,
        size: u32,
        memory: &mut impl GuestMemory,
    ) -> Result<Allocation, DpmiError> {
        let page_count = pages_for_size(size)?;
        let handle = self.peek_handle()?;
        let (page_start, free_count) = self
            .find_free_extent(page_count)
            .ok_or(DpmiError::LinearMemoryUnavailable)?;
        let physical = self.physical_at_page(page_start)?;
        let capacity = bytes_for_pages(page_count)?;
        self.zero_guest_range(memory, physical, capacity)?;

        self.consume_free_extent(page_start, free_count, page_count);
        self.blocks.insert(
            handle,
            Block {
                owner,
                handle,
                page_start,
                page_count,
                size,
            },
        );
        self.commit_handle();
        self.allocation_for(handle)
    }

    /// Resize a block while preserving `min(old_size, new_size)` bytes.
    ///
    /// A successful resize always returns a fresh handle and invalidates the
    /// old one. Growth first tries adjacent free pages; if that cannot satisfy
    /// the request, it stages a zero-filled replacement, copies the preserved
    /// bytes, and only then commits the new mapping. Failed staging leaves the
    /// old allocation and free-list metadata intact.
    pub fn resize(
        &mut self,
        owner: OwnerId,
        handle: DpmiHandle,
        new_size: u32,
        memory: &mut impl GuestMemory,
    ) -> Result<Allocation, DpmiError> {
        let new_page_count = pages_for_size(new_size)?;
        let old = self
            .blocks
            .get(&handle)
            .filter(|block| block.owner == owner)
            .cloned()
            .ok_or(DpmiError::InvalidHandle)?;
        let new_handle = self.peek_handle()?;
        let new_capacity = bytes_for_pages(new_page_count)?;
        let old_physical = self.physical_at_page(old.page_start)?;

        if new_page_count == old.page_count {
            if new_size > old.size {
                let grown_at = add_address(old_physical, old.size)?;
                self.zero_guest_range(memory, grown_at, new_size - old.size)?;
            }
            let mut block = old.clone();
            block.size = new_size;
            block.handle = new_handle;
            self.blocks.remove(&handle);
            self.blocks.insert(new_handle, block);
            self.commit_handle();
            return self.allocation_for(new_handle);
        }

        if new_page_count < old.page_count {
            let released_start = old.page_start + new_page_count;
            let released_count = old.page_count - new_page_count;
            let mut block = old.clone();
            block.page_count = new_page_count;
            block.size = new_size;
            block.handle = new_handle;
            self.blocks.remove(&handle);
            self.blocks.insert(new_handle, block);
            self.release_extent(released_start, released_count);
            self.commit_handle();
            return self.allocation_for(new_handle);
        }

        let following_page = old.page_start + old.page_count;
        if let Some(free_count) = self.free_pages.get(&following_page).copied() {
            let additional_pages = new_page_count - old.page_count;
            if free_count >= additional_pages {
                let old_logical_end = add_address(old_physical, old.size)?;
                self.zero_guest_range(memory, old_logical_end, new_size - old.size)?;
                self.consume_free_extent(following_page, free_count, additional_pages);
                let mut block = old.clone();
                block.page_count = new_page_count;
                block.size = new_size;
                block.handle = new_handle;
                self.blocks.remove(&handle);
                self.blocks.insert(new_handle, block);
                self.commit_handle();
                return self.allocation_for(new_handle);
            }
        }

        let (replacement_start, replacement_free_count) = self
            .find_free_extent(new_page_count)
            .ok_or(DpmiError::LinearMemoryUnavailable)?;
        let replacement_physical = self.physical_at_page(replacement_start)?;
        self.zero_guest_range(memory, replacement_physical, new_capacity)?;
        self.copy_guest_range(
            memory,
            old_physical,
            replacement_physical,
            old.size.min(new_size),
        )?;

        self.consume_free_extent(replacement_start, replacement_free_count, new_page_count);
        self.blocks.remove(&handle);
        self.release_extent(old.page_start, old.page_count);
        self.blocks.insert(
            new_handle,
            Block {
                owner: old.owner,
                handle: new_handle,
                page_start: replacement_start,
                page_count: new_page_count,
                size: new_size,
            },
        );
        self.commit_handle();
        self.allocation_for(new_handle)
    }

    /// Free a block only when both its opaque handle and owner match.
    pub fn free(&mut self, owner: OwnerId, handle: DpmiHandle) -> Result<(), DpmiError> {
        let block = self
            .blocks
            .get(&handle)
            .filter(|block| block.owner == owner)
            .cloned()
            .ok_or(DpmiError::InvalidHandle)?;
        self.blocks.remove(&handle);
        self.release_extent(block.page_start, block.page_count);
        Ok(())
    }

    /// Release all allocations owned by exactly `owner`; no default or
    /// ownerless cleanup path exists. Returns the number of released blocks.
    pub fn release_owner(&mut self, owner: OwnerId) -> usize {
        let handles: Vec<DpmiHandle> = self
            .blocks
            .iter()
            .filter_map(|(handle, block)| (block.owner == owner).then_some(*handle))
            .collect();
        for handle in &handles {
            if let Some(block) = self.blocks.remove(handle) {
                self.release_extent(block.page_start, block.page_count);
            }
        }
        handles.len()
    }

    /// Check that a whole non-empty linear range belongs to one allocation
    /// owned by `owner`, then return its physical GuestMemory offset.
    pub fn translate_linear(
        &self,
        owner: OwnerId,
        linear: LinearAddr,
        length: usize,
    ) -> Result<PhysAddr, DpmiError> {
        let length = u32::try_from(length).map_err(|_| DpmiError::InvalidSize)?;
        if length == 0 {
            return Err(DpmiError::InvalidSize);
        }
        let range_start = u64::from(linear.0);
        let range_end = range_start + u64::from(length);
        for block in self.blocks.values() {
            if block.owner != owner {
                continue;
            }
            let mapping = self.mapping_for(block)?;
            let start = u64::from(mapping.linear.0);
            let end = start + u64::from(mapping.size);
            if range_start >= start && range_end <= end {
                return add_address(mapping.physical, (range_start - start) as u32);
            }
        }
        Err(DpmiError::InvalidLinearAddress)
    }

    /// Read guest bytes after enforcing owner and allocation bounds.
    pub fn read_linear(
        &self,
        owner: OwnerId,
        linear: LinearAddr,
        output: &mut [u8],
        memory: &impl GuestMemory,
    ) -> Result<(), DpmiError> {
        let physical = self.translate_linear(owner, linear, output.len())?;
        memory
            .read(physical, output)
            .map_err(DpmiError::GuestMemory)
    }

    /// Write guest bytes after enforcing owner and allocation bounds.
    pub fn write_linear(
        &self,
        owner: OwnerId,
        linear: LinearAddr,
        input: &[u8],
        memory: &mut impl GuestMemory,
    ) -> Result<(), DpmiError> {
        let physical = self.translate_linear(owner, linear, input.len())?;
        memory
            .write(physical, input)
            .map_err(DpmiError::GuestMemory)
    }

    /// Enumerate only the mappings visible to `owner`.
    pub fn mappings_for(&self, owner: OwnerId) -> impl Iterator<Item = LinearMapping> + '_ {
        self.blocks
            .values()
            .filter(move |block| block.owner == owner)
            .filter_map(|block| self.mapping_for(block).ok())
    }

    pub fn stats(&self) -> DpmiMemoryStats {
        let free_pages: u32 = self.free_pages.values().copied().sum();
        let allocated_pages = self.total_pages - free_pages;
        let largest_free_pages = self.free_pages.values().copied().max().unwrap_or(0);
        let requested_bytes = self
            .blocks
            .values()
            .map(|block| u64::from(block.size))
            .sum();
        DpmiMemoryStats {
            page_size: DPMI_PAGE_SIZE,
            total_pages: self.total_pages,
            free_pages,
            allocated_pages,
            largest_free_block: u64::from(largest_free_pages) * u64::from(DPMI_PAGE_SIZE),
            free_bytes: u64::from(free_pages) * u64::from(DPMI_PAGE_SIZE),
            allocated_bytes: u64::from(allocated_pages) * u64::from(DPMI_PAGE_SIZE),
            requested_bytes,
            allocation_count: self.blocks.len(),
        }
    }

    fn allocation_for(&self, handle: DpmiHandle) -> Result<Allocation, DpmiError> {
        let block = self.blocks.get(&handle).ok_or(DpmiError::InvalidHandle)?;
        let linear = self.linear_at_page(block.page_start)?;
        Ok(Allocation {
            handle,
            linear,
            size: block.size,
        })
    }

    fn mapping_for(&self, block: &Block) -> Result<LinearMapping, DpmiError> {
        Ok(LinearMapping {
            linear: self.linear_at_page(block.page_start)?,
            physical: self.physical_at_page(block.page_start)?,
            size: block.size,
        })
    }

    fn linear_at_page(&self, page: u32) -> Result<LinearAddr, DpmiError> {
        let offset = u64::from(page) * u64::from(DPMI_PAGE_SIZE);
        let address = u64::from(self.arena.linear_start.0) + offset;
        let address = u32::try_from(address).map_err(|_| DpmiError::InvalidArenaConfiguration)?;
        Ok(LinearAddr(address))
    }

    fn physical_at_page(&self, page: u32) -> Result<PhysAddr, DpmiError> {
        let offset = u64::from(page) * u64::from(DPMI_PAGE_SIZE);
        let address = u64::from(self.arena.physical_start.0) + offset;
        let address = u32::try_from(address).map_err(|_| DpmiError::InvalidArenaConfiguration)?;
        Ok(PhysAddr(address))
    }

    fn find_free_extent(&self, pages: u32) -> Option<(u32, u32)> {
        self.free_pages
            .iter()
            .find_map(|(start, count)| (*count >= pages).then_some((*start, *count)))
    }

    fn consume_free_extent(&mut self, start: u32, available: u32, consumed: u32) {
        debug_assert!(consumed > 0 && consumed <= available);
        self.free_pages.remove(&start);
        if consumed < available {
            self.free_pages
                .insert(start + consumed, available - consumed);
        }
    }

    fn release_extent(&mut self, mut start: u32, mut count: u32) {
        if count == 0 {
            return;
        }

        if let Some((&previous_start, &previous_count)) = self.free_pages.range(..start).next_back()
        {
            if previous_start + previous_count == start {
                self.free_pages.remove(&previous_start);
                start = previous_start;
                count += previous_count;
            }
        }

        let end = start + count;
        if let Some((&next_start, &next_count)) = self.free_pages.range(end..).next() {
            if next_start == end {
                self.free_pages.remove(&next_start);
                count += next_count;
            }
        }
        self.free_pages.insert(start, count);
    }

    fn peek_handle(&self) -> Result<DpmiHandle, DpmiError> {
        if self.next_handle == 0 {
            Err(DpmiError::HandleSpaceExhausted)
        } else {
            Ok(DpmiHandle(self.next_handle))
        }
    }

    fn commit_handle(&mut self) {
        self.next_handle = self.next_handle.checked_add(1).unwrap_or(0);
    }

    fn zero_guest_range(
        &self,
        memory: &mut impl GuestMemory,
        start: PhysAddr,
        length: u32,
    ) -> Result<(), DpmiError> {
        validate_guest_range(memory, start, length)?;
        let zeros = [0u8; IO_CHUNK_SIZE];
        let mut offset = 0u32;
        while offset < length {
            let chunk_len = (length - offset).min(IO_CHUNK_SIZE as u32) as usize;
            let chunk_start = add_address(start, offset)?;
            memory
                .write(chunk_start, &zeros[..chunk_len])
                .map_err(DpmiError::GuestMemory)?;
            offset += chunk_len as u32;
        }
        Ok(())
    }

    fn copy_guest_range(
        &self,
        memory: &mut impl GuestMemory,
        source: PhysAddr,
        destination: PhysAddr,
        length: u32,
    ) -> Result<(), DpmiError> {
        validate_guest_range(memory, source, length)?;
        validate_guest_range(memory, destination, length)?;
        let mut buffer = [0u8; IO_CHUNK_SIZE];
        let mut offset = 0u32;
        while offset < length {
            let chunk_len = (length - offset).min(IO_CHUNK_SIZE as u32) as usize;
            let source_at = add_address(source, offset)?;
            let destination_at = add_address(destination, offset)?;
            memory
                .read(source_at, &mut buffer[..chunk_len])
                .map_err(DpmiError::GuestMemory)?;
            memory
                .write(destination_at, &buffer[..chunk_len])
                .map_err(DpmiError::GuestMemory)?;
            offset += chunk_len as u32;
        }
        Ok(())
    }
}

const IO_CHUNK_SIZE: usize = 4096;

fn pages_for_size(size: u32) -> Result<u32, DpmiError> {
    if size == 0 {
        return Err(DpmiError::InvalidSize);
    }
    let rounded = u64::from(size) + u64::from(DPMI_PAGE_SIZE - 1);
    let pages = rounded / u64::from(DPMI_PAGE_SIZE);
    u32::try_from(pages).map_err(|_| DpmiError::LinearMemoryUnavailable)
}

fn bytes_for_pages(pages: u32) -> Result<u32, DpmiError> {
    let bytes = u64::from(pages) * u64::from(DPMI_PAGE_SIZE);
    u32::try_from(bytes).map_err(|_| DpmiError::LinearMemoryUnavailable)
}

fn add_address(address: PhysAddr, offset: u32) -> Result<PhysAddr, DpmiError> {
    address
        .0
        .checked_add(offset)
        .map(PhysAddr)
        .ok_or(DpmiError::LinearMemoryUnavailable)
}

fn validate_guest_range(
    memory: &impl GuestMemory,
    start: PhysAddr,
    length: u32,
) -> Result<(), DpmiError> {
    let end = u64::from(start.0) + u64::from(length);
    if end > u64::from(memory.len()) {
        return Err(DpmiError::GuestMemory(MemoryError::OutOfBounds {
            address: start.0,
            length: length as usize,
        }));
    }
    Ok(())
}
