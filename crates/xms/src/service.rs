use guest_core::{GuestHandle, GuestMemory, MemoryError, OwnerId, PhysAddr};

use crate::model::{
    A20State, Block, FreeSpace, HandleInfo, XmsCapabilities, XmsConfig, XmsError, XmsVersion,
    FIRST_XMS_ADDRESS, HANDLE_COUNT, HMA_END_EXCLUSIVE, KIB, XMS_CAPABILITIES, XMS_VERSION,
};

/// State for one XMS service instance. Construct one per emulated machine.
pub struct XmsService {
    pub(super) config: XmsConfig,
    pub(super) blocks: [Option<Block>; HANDLE_COUNT],
    pub(super) hma_owner: Option<OwnerId>,
    hma_minimum_kb: u8,
    a20_global: bool,
    a20_local_count: u32,
}

impl Default for XmsService {
    fn default() -> Self {
        Self::new()
    }
}

impl XmsService {
    /// Create a service using the guest XMS arena `[0x110000, 0x1100000)`.
    pub fn new() -> Self {
        Self {
            config: XmsConfig::default(),
            blocks: [None; HANDLE_COUNT],
            hma_owner: None,
            hma_minimum_kb: 0,
            a20_global: false,
            a20_local_count: 0,
        }
    }

    /// Create a service with an alternate, KiB-aligned XMS arena.
    pub fn with_config(config: XmsConfig) -> Result<Self, XmsError> {
        let start = config.arena_start.0;
        let end = config.arena_end.0;
        let length = end
            .checked_sub(start)
            .ok_or(XmsError::InvalidConfiguration)?;
        let max_bytes = u32::from(u16::MAX) * KIB;
        if start < FIRST_XMS_ADDRESS
            || start % KIB != 0
            || end % KIB != 0
            || length == 0
            || length > max_bytes
        {
            return Err(XmsError::InvalidConfiguration);
        }
        Ok(Self {
            config,
            blocks: [None; HANDLE_COUNT],
            hma_owner: None,
            hma_minimum_kb: 0,
            a20_global: false,
            a20_local_count: 0,
        })
    }

    /// Alias emphasizing that the configured range is the physical XMS arena.
    pub fn with_arena(config: XmsConfig) -> Result<Self, XmsError> {
        Self::with_config(config)
    }

    pub fn config(&self) -> XmsConfig {
        self.config
    }

    pub fn version(&self) -> XmsVersion {
        XMS_VERSION
    }

    pub fn capabilities(&self) -> XmsCapabilities {
        XMS_CAPABILITIES
    }

    /// Allocate and zero an extended-memory handle for `owner`.
    ///
    /// A zero-sized allocation still consumes one handle under XMS 2.0.
    pub fn allocate(
        &mut self,
        owner: OwnerId,
        size_kb: u16,
        memory: &mut impl GuestMemory,
    ) -> Result<GuestHandle, XmsError> {
        let slot = self
            .blocks
            .iter()
            .position(Option::is_none)
            .ok_or(XmsError::HandleTableFull)?;
        let bytes = u32::from(size_kb) * KIB;
        let base = self.find_space(bytes, None).ok_or(XmsError::OutOfMemory)?;

        if bytes != 0 {
            self.ensure_arena_backed(memory)?;
            let len = usize::try_from(bytes).map_err(|_| XmsError::OutOfMemory)?;
            let zeros = zeroed_vec(len)?;
            memory.write(base, &zeros).map_err(XmsError::ArenaMemory)?;
        }

        self.blocks[slot] = Some(Block {
            base,
            size_kb,
            locks: 0,
            owner,
        });
        Ok(GuestHandle((slot + 1) as u16))
    }

    /// Release an unlocked handle.
    pub fn free(&mut self, handle: GuestHandle) -> Result<(), XmsError> {
        let index = Self::handle_index(handle)?;
        let block = self.blocks[index].ok_or(XmsError::InvalidHandle)?;
        if block.locks != 0 {
            return Err(XmsError::BlockLocked);
        }
        self.blocks[index] = None;
        Ok(())
    }

    /// Resize an unlocked handle, preserving existing bytes and zeroing any
    /// newly added portion. On any read or write error, handle metadata and
    /// existing bytes remain unchanged.
    pub fn reallocate(
        &mut self,
        handle: GuestHandle,
        new_size_kb: u16,
        memory: &mut impl GuestMemory,
    ) -> Result<(), XmsError> {
        let index = Self::handle_index(handle)?;
        let old = self.blocks[index].ok_or(XmsError::InvalidHandle)?;
        if old.locks != 0 {
            return Err(XmsError::BlockLocked);
        }

        let new_bytes = u32::from(new_size_kb) * KIB;
        let old_bytes = u32::from(old.size_kb) * KIB;
        if new_bytes <= old_bytes {
            self.blocks[index] = Some(Block {
                size_kb: new_size_kb,
                ..old
            });
            return Ok(());
        }

        self.ensure_arena_backed(memory)?;
        let new_base = self
            .find_space(new_bytes, Some(index))
            .ok_or(XmsError::OutOfMemory)?;
        let old_len = usize::try_from(old_bytes).map_err(|_| XmsError::OutOfMemory)?;
        let new_len = usize::try_from(new_bytes).map_err(|_| XmsError::OutOfMemory)?;
        let mut contents = zeroed_vec(new_len)?;
        if old_len != 0 {
            memory
                .read(old.base, &mut contents[..old_len])
                .map_err(XmsError::ArenaMemory)?;
        }
        memory
            .write(new_base, &contents)
            .map_err(XmsError::ArenaMemory)?;

        self.blocks[index] = Some(Block {
            base: new_base,
            size_kb: new_size_kb,
            locks: old.locks,
            owner: old.owner,
        });
        Ok(())
    }

    /// Lock a handle and return its physical base address. The returned
    /// address is split into DX:BX by the INT 2Fh adapter.
    pub fn lock(&mut self, handle: GuestHandle) -> Result<PhysAddr, XmsError> {
        let index = Self::handle_index(handle)?;
        let block = self.blocks[index].as_mut().ok_or(XmsError::InvalidHandle)?;
        block.locks = block
            .locks
            .checked_add(1)
            .ok_or(XmsError::LockCountOverflow)?;
        Ok(block.base)
    }

    /// Release one lock count from a handle.
    pub fn unlock(&mut self, handle: GuestHandle) -> Result<(), XmsError> {
        let index = Self::handle_index(handle)?;
        let block = self.blocks[index].as_mut().ok_or(XmsError::InvalidHandle)?;
        if block.locks == 0 {
            return Err(XmsError::BlockNotLocked);
        }
        block.locks -= 1;
        Ok(())
    }

    pub fn handle_info(&self, handle: GuestHandle) -> Result<HandleInfo, XmsError> {
        let block = self.block(handle)?;
        Ok(HandleInfo {
            size_kb: block.size_kb,
            lock_count: block.locks,
            owner: block.owner,
            free_handles: self.blocks.iter().filter(|slot| slot.is_none()).count() as u16,
        })
    }

    /// Return largest contiguous and total free space in the configured arena.
    pub fn free_space(&self) -> FreeSpace {
        let mut cursor = self.config.arena_start.0;
        let mut largest = 0_u32;
        let mut total = 0_u32;
        while let Some(block) = self.next_block(cursor, None) {
            let gap = block.base.0 - cursor;
            largest = largest.max(gap);
            total += gap;
            cursor = block.base.0 + u32::from(block.size_kb) * KIB;
        }
        let tail = self.config.arena_end.0 - cursor;
        largest = largest.max(tail);
        total += tail;
        FreeSpace {
            largest_kb: (largest / KIB) as u16,
            total_kb: (total / KIB) as u16,
        }
    }

    /// Free all handles owned by an exiting DOS process, including any lock
    /// counts it left behind, and release its HMA reservation. Returns the
    /// number of released handles.
    pub fn cleanup_owner(&mut self, owner: OwnerId) -> usize {
        let mut freed = 0;
        for block in &mut self.blocks {
            if block.is_some_and(|allocated| allocated.owner == owner) {
                *block = None;
                freed += 1;
            }
        }
        if self.hma_owner == Some(owner) {
            self.hma_owner = None;
        }
        freed
    }

    /// Set the XMM's `/HMAMIN=` threshold in KiB. XMS 2.0 HIMEM.SYS accepts
    /// values from 0 through 63; the default is zero (first request wins).
    pub fn set_hma_minimum_kb(&mut self, minimum_kb: u8) -> Result<(), XmsError> {
        if minimum_kb > 63 {
            return Err(XmsError::InvalidConfiguration);
        }
        self.hma_minimum_kb = minimum_kb;
        Ok(())
    }

    pub fn hma_minimum_kb(&self) -> u8 {
        self.hma_minimum_kb
    }

    pub fn hma_owner(&self) -> Option<OwnerId> {
        self.hma_owner
    }

    /// Request the single HMA for `owner`. `requested_bytes` is DX from
    /// function 01h. The physical HMA is the fixed range
    /// `[0x100000, 0x10fff0)` and is never part of the EMB arena.
    pub fn request_hma(
        &mut self,
        owner: OwnerId,
        requested_bytes: u16,
        memory: &impl GuestMemory,
    ) -> Result<(), XmsError> {
        if !Self::memory_has_hma(memory) {
            return Err(XmsError::HmaDoesNotExist);
        }
        if self.hma_owner.is_some() {
            return Err(XmsError::HmaAlreadyAllocated);
        }
        let minimum_bytes = u32::from(self.hma_minimum_kb) * KIB;
        if u32::from(requested_bytes) < minimum_bytes {
            return Err(XmsError::HmaMinimumNotMet);
        }
        self.hma_owner = Some(owner);
        Ok(())
    }

    /// Release the HMA only for the owner that reserved it.
    pub fn release_hma(
        &mut self,
        owner: OwnerId,
        memory: &impl GuestMemory,
    ) -> Result<(), XmsError> {
        if !Self::memory_has_hma(memory) {
            return Err(XmsError::HmaDoesNotExist);
        }
        if self.hma_owner != Some(owner) {
            return Err(XmsError::HmaNotAllocated);
        }
        self.hma_owner = None;
        Ok(())
    }

    /// XMS 2.0 UMB functions are not implemented, so report BL=80h rather than
    /// claiming that a UMB search succeeded and found no free region.
    pub fn request_umb(&mut self, _size_paragraphs: u16) -> Result<(u16, u16), XmsError> {
        Err(XmsError::UnsupportedFunction(0x10))
    }

    pub fn release_umb(&mut self, _segment: u16) -> Result<(), XmsError> {
        Err(XmsError::UnsupportedFunction(0x11))
    }

    pub fn a20_state(&self) -> A20State {
        A20State {
            global_enabled: self.a20_global,
            local_enable_count: self.a20_local_count,
            enabled: self.a20_global || self.a20_local_count != 0,
        }
    }

    /// Set the global A20 latch. Disabling it while local enables remain takes
    /// effect on the latch but reports that the A20 line remains enabled.
    pub fn set_global_a20(&mut self, enabled: bool) -> Result<A20State, XmsError> {
        self.a20_global = enabled;
        let state = self.a20_state();
        if !enabled && state.enabled {
            Err(XmsError::A20StillEnabled)
        } else {
            Ok(state)
        }
    }

    pub fn enable_local_a20(&mut self) -> Result<A20State, XmsError> {
        self.a20_local_count = self
            .a20_local_count
            .checked_add(1)
            .ok_or(XmsError::A20CounterOverflow)?;
        Ok(self.a20_state())
    }

    /// Disable one local A20 reference. A20 remains active if either the
    /// global latch or another local reference is still enabled.
    pub fn disable_local_a20(&mut self) -> Result<A20State, XmsError> {
        if self.a20_local_count == 0 {
            return Err(XmsError::A20CounterUnderflow);
        }
        self.a20_local_count -= 1;
        let state = self.a20_state();
        if state.enabled {
            Err(XmsError::A20StillEnabled)
        } else {
            Ok(state)
        }
    }

    pub fn unsupported_function(&self, function: u8) -> XmsError {
        XmsError::UnsupportedFunction(function)
    }

    pub(super) fn block(&self, handle: GuestHandle) -> Result<Block, XmsError> {
        let index = Self::handle_index(handle)?;
        self.blocks[index].ok_or(XmsError::InvalidHandle)
    }

    pub(super) fn handle_index(handle: GuestHandle) -> Result<usize, XmsError> {
        if handle.0 == 0 || usize::from(handle.0) > HANDLE_COUNT {
            return Err(XmsError::InvalidHandle);
        }
        Ok(usize::from(handle.0 - 1))
    }

    fn ensure_arena_backed(&self, memory: &impl GuestMemory) -> Result<(), XmsError> {
        if self.config.arena_end.0 > memory.len() {
            return Err(XmsError::ArenaMemory(MemoryError::OutOfBounds {
                address: memory.len(),
                length: (self.config.arena_end.0 - memory.len()) as usize,
            }));
        }
        Ok(())
    }

    pub(super) fn memory_has_hma(memory: &impl GuestMemory) -> bool {
        memory.len() >= HMA_END_EXCLUSIVE
    }

    fn find_space(&self, bytes: u32, skip: Option<usize>) -> Option<PhysAddr> {
        let mut cursor = self.config.arena_start.0;
        while let Some(block) = self.next_block(cursor, skip) {
            let gap = block.base.0.checked_sub(cursor)?;
            if bytes <= gap {
                return Some(PhysAddr(cursor));
            }
            cursor = block.base.0.checked_add(u32::from(block.size_kb) * KIB)?;
        }
        if bytes <= self.config.arena_end.0.checked_sub(cursor)? {
            Some(PhysAddr(cursor))
        } else {
            None
        }
    }

    fn next_block(&self, cursor: u32, skip: Option<usize>) -> Option<Block> {
        self.blocks
            .iter()
            .enumerate()
            .filter_map(|(index, block)| {
                if Some(index) == skip {
                    return None;
                }
                block
                    .as_ref()
                    .copied()
                    .filter(|block| block.size_kb != 0 && block.base.0 >= cursor)
            })
            .min_by_key(|block| block.base.0)
    }
}

pub(super) fn zeroed_vec(length: usize) -> Result<Vec<u8>, XmsError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| XmsError::Memory(MemoryError::AllocationFailed))?;
    bytes.resize(length, 0);
    Ok(bytes)
}
