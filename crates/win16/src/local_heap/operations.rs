use super::{
    ARENA_HEADER_BYTES, HEAP_HANDLE_DELTA_OFFSET,
    HEAP_TABLE_OFFSET, LMEM_DISCARDABLE, LMEM_DISCARDED, LMEM_INVALID_HANDLE,
    LMEM_MODIFY, LMEM_MOVEABLE, LMEM_NOCOMPACT, LMEM_ZEROINIT,
    MOVEABLE_PREFIX_BYTES,
    MIN_ARENA_EXTENT, LocalHeap, LocalHeapError, copy_within_range, fill_range,
    read_word, write_byte, write_word,
};
use super::arena::ArenaInfo;
use super::handles::{HandleEntry, HandleSlot};

impl LocalHeap<'_> {
    pub(super) fn alloc_inner(&mut self, flags: u16, size: u16) -> Result<u16, LocalHeapError> {
        let movable = flags & LMEM_MOVEABLE != 0;
        if size == 0 {
            if !movable {
                return Ok(0);
            }
            let Some(handle) = self.reserve_handle(flags)? else { return Ok(0) };
            self.write_entry(HandleEntry {
                handle,
                addr: 0,
                flags: LMEM_DISCARDED,
                lock: 0,
            })?;
            return Ok(handle);
        }

        let Some(extent) = requested_extent(size, if movable { MOVEABLE_PREFIX_BYTES } else { 0 }) else {
            return Ok(0);
        };
        let Some(payload) = self.allocate_extent(extent, flags)? else { return Ok(0) };
        if !movable {
            return Ok(payload);
        }

        let Some(handle) = self.reserve_handle(flags)? else {
            self.release_arena(payload - ARENA_HEADER_BYTES as u16)?;
            return Ok(0);
        };
        let address = payload.checked_add(MOVEABLE_PREFIX_BYTES as u16)
            .ok_or(LocalHeapError::CorruptArenaChain { offset: usize::from(payload) })?;
        write_word(self.dgroup, &mut self.write_spans, usize::from(payload), handle)
            .map_err(|error| LocalHeapError::preserve_write_error(error,
                LocalHeapError::CorruptArenaChain { offset: usize::from(payload) }))?;
        self.write_entry(HandleEntry {
            handle,
            addr: address,
            flags: ((flags & LMEM_DISCARDABLE) >> 8) as u8,
            lock: 0,
        })?;
        Ok(handle)
    }

    pub(super) fn realloc_inner(
        &mut self,
        handle: u16,
        size: u16,
        flags: u16,
    ) -> Result<u16, LocalHeapError> {
        if handle == 0 {
            return Ok(0);
        }

        let fixed = handle & 3 == 0;
        let fixed_block = if fixed { self.fixed_block(handle)? } else { None };
        let movable_slot = if fixed { None } else { self.slot(handle)? };
        if (fixed && fixed_block.is_none()) || (!fixed && movable_slot.is_none()) {
            return Ok(0);
        }

        if flags & LMEM_MODIFY != 0 {
            match movable_slot {
                Some(HandleSlot::Live(mut entry)) => {
                    entry.flags = ((flags & LMEM_DISCARDABLE) >> 8) as u8;
                    self.write_entry(entry)?;
                }
                Some(HandleSlot::Discarded(_)) => {}
                Some(HandleSlot::Unused) | None if !fixed => return Ok(0),
                _ => {}
            }
            return Ok(handle);
        }

        if size == 0 {
            return self.realloc_zero(handle, flags, fixed, fixed_block, movable_slot);
        }
        let prefix = if fixed { 0 } else { MOVEABLE_PREFIX_BYTES };
        let Some(required) = requested_extent(size, prefix) else { return Ok(0) };

        if fixed {
            let Some(old) = fixed_block else { return Ok(0) };
            if self.is_internal_heap_block(old.start)? {
                return Ok(0);
            }
            if required <= old.extent() {
                self.shrink_arena(old.start, required)?;
                return Ok(handle);
            }
            if self.grow_arena(old.start, required, flags & LMEM_ZEROINIT != 0)? {
                return Ok(handle);
            }
            if flags & LMEM_MOVEABLE == 0 {
                return Ok(0);
            }
            let Some(new_payload) = self.allocate_extent(required, flags)? else { return Ok(0) };
            let new_start = new_payload - ARENA_HEADER_BYTES as u16;
            let arenas = self.arenas()?;
            let old_now = self.arena_at(&arenas, old.start)?;
            let copy_bytes = usize::from(old_now.end.saturating_sub(handle))
                .min(usize::from(arenas[self.find_arena(&arenas, new_start)
                    .ok_or(LocalHeapError::CorruptArenaChain { offset: usize::from(new_start) })?]
                    .end.saturating_sub(new_payload)));
            let copy_start = usize::from(handle);
            let copy_end = copy_start.checked_add(copy_bytes)
                .ok_or(LocalHeapError::CorruptArenaChain { offset: copy_start })?;
            copy_within_range(self.dgroup, &mut self.write_spans, copy_start..copy_end,
                usize::from(new_payload))?;
            self.release_arena(old.start)?;
            return Ok(new_payload);
        }

        let Some(movable_slot) = movable_slot else { return Ok(0) };
        match movable_slot {
            HandleSlot::Unused => Ok(0),
            HandleSlot::Discarded(mut entry) => {
                let Some(payload) = self.allocate_extent(required, flags)? else { return Ok(0) };
                let address = payload.checked_add(MOVEABLE_PREFIX_BYTES as u16)
                    .ok_or(LocalHeapError::CorruptArenaChain { offset: usize::from(payload) })?;
                write_word(self.dgroup, &mut self.write_spans, usize::from(payload), handle)
                    .map_err(|error| LocalHeapError::preserve_write_error(error,
                        LocalHeapError::CorruptArenaChain { offset: usize::from(payload) }))?;
                entry.addr = address;
                entry.flags = ((flags & LMEM_DISCARDABLE) >> 8) as u8;
                entry.lock = 0;
                self.write_entry(entry)?;
                Ok(handle)
            }
            HandleSlot::Live(entry) => {
                let old_start = entry.addr.checked_sub((ARENA_HEADER_BYTES + MOVEABLE_PREFIX_BYTES) as u16)
                    .ok_or(LocalHeapError::CorruptHandleTable { offset: usize::from(handle) })?;
                let old = self.arena_at(&self.arenas()?, old_start)?;
                if required <= old.extent() {
                    self.shrink_arena(old.start, required)?;
                    return Ok(handle);
                }
                if self.grow_arena(old.start, required, flags & LMEM_ZEROINIT != 0)? {
                    return Ok(handle);
                }
                if entry.lock != 0 && flags & LMEM_MOVEABLE == 0 {
                    return Ok(0);
                }

                let Some(new_payload) = self.allocate_extent_protected(required, flags, Some(handle))? else {
                    return Ok(0);
                };
                // Allocation may have compacted other unlocked blocks; resolve
                // this movable object's current address again by its stable handle.
                let Some(HandleSlot::Live(mut current)) = self.slot(handle)? else {
                    self.release_arena(new_payload - ARENA_HEADER_BYTES as u16)?;
                    return Ok(0);
                };
                let current_start = current.addr - (ARENA_HEADER_BYTES + MOVEABLE_PREFIX_BYTES) as u16;
                let current_arena = self.arena_at(&self.arenas()?, current_start)?;
                let new_start = new_payload - ARENA_HEADER_BYTES as u16;
                let arenas = self.arenas()?;
                let new_arena = self.arena_at(&arenas, new_start)?;
                let new_address = new_payload.checked_add(MOVEABLE_PREFIX_BYTES as u16)
                    .ok_or(LocalHeapError::CorruptArenaChain { offset: usize::from(new_payload) })?;
                let copy_bytes = usize::from(current_arena.end.saturating_sub(current.addr))
                    .min(usize::from(new_arena.end.saturating_sub(new_address)));
                let copy_start = usize::from(current.addr);
                let copy_end = copy_start.checked_add(copy_bytes)
                    .ok_or(LocalHeapError::CorruptArenaChain { offset: copy_start })?;
                copy_within_range(self.dgroup, &mut self.write_spans, copy_start..copy_end,
                    usize::from(new_address))?;
                write_word(self.dgroup, &mut self.write_spans, usize::from(new_payload), handle)
                    .map_err(|error| LocalHeapError::preserve_write_error(error,
                        LocalHeapError::CorruptArenaChain { offset: usize::from(new_payload) }))?;
                self.release_arena(current_start)?;
                current.addr = new_address;
                self.write_entry(current)?;
                Ok(handle)
            }
        }
    }

    fn realloc_zero(
        &mut self,
        handle: u16,
        flags: u16,
        fixed: bool,
        fixed_block: Option<ArenaInfo>,
        movable_slot: Option<HandleSlot>,
    ) -> Result<u16, LocalHeapError> {
        if fixed {
            if flags & LMEM_MOVEABLE == 0 {
                return Ok(0);
            }
            let Some(block) = fixed_block else { return Ok(0) };
            if self.is_internal_heap_block(block.start)? {
                return Ok(0);
            }
            return self.free_fixed_block(handle, block.start);
        }
        match movable_slot {
            Some(HandleSlot::Unused) | None => Ok(0),
            Some(HandleSlot::Discarded(mut entry)) if flags & LMEM_MOVEABLE != 0 => {
                entry.addr = 0;
                entry.flags = LMEM_DISCARDED;
                entry.lock = 0;
                self.write_entry(entry)?;
                Ok(handle)
            }
            Some(HandleSlot::Discarded(_)) => Ok(0),
            Some(HandleSlot::Live(mut entry)) if flags & LMEM_MOVEABLE != 0 => {
                if entry.lock != 0 {
                    return Ok(0);
                }
                let start = entry.addr - (ARENA_HEADER_BYTES + MOVEABLE_PREFIX_BYTES) as u16;
                self.release_arena(start)?;
                entry.addr = 0;
                entry.flags = LMEM_DISCARDED;
                entry.lock = 0;
                self.write_entry(entry)?;
                Ok(handle)
            }
            // A zero-size request without LMEM_MOVEABLE fails without freeing
            // the live object. LocalDiscard explicitly supplies LMEM_MOVEABLE.
            Some(HandleSlot::Live(_)) => Ok(0),
        }
    }

    pub(super) fn free_inner(&mut self, handle: u16) -> Result<u16, LocalHeapError> {
        if handle == 0 {
            return Ok(0);
        }
        if handle & 3 == 0 {
            let Some(block) = self.fixed_block(handle)? else { return Ok(handle) };
            if self.is_internal_heap_block(block.start)? {
                return Ok(handle);
            }
            return self.free_fixed_block(handle, block.start);
        }
        let Some(slot) = self.slot(handle)? else { return Ok(handle) };
        match slot {
            HandleSlot::Unused => Ok(handle),
            HandleSlot::Discarded(_) => {
                self.clear_entry(handle)?;
                Ok(0)
            }
            HandleSlot::Live(entry) if entry.lock != 0 => Ok(handle),
            HandleSlot::Live(entry) => {
                self.release_arena(entry.addr - (ARENA_HEADER_BYTES + MOVEABLE_PREFIX_BYTES) as u16)?;
                self.clear_entry(handle)?;
                Ok(0)
            }
        }
    }

    fn free_fixed_block(&mut self, handle: u16, arena: u16) -> Result<u16, LocalHeapError> {
        self.release_arena(arena)?;
        let _ = handle;
        Ok(0)
    }

    pub(super) fn lock_inner(&mut self, handle: u16) -> Result<u16, LocalHeapError> {
        if handle == 0 {
            return Ok(0);
        }
        if handle & 3 == 0 {
            return Ok(if self.fixed_block(handle)?.is_some() { handle } else { 0 });
        }
        let Some(HandleSlot::Live(mut entry)) = self.slot(handle)? else { return Ok(0) };
        if entry.lock < 0xfe {
            entry.lock += 1;
            self.write_entry(entry)?;
        }
        Ok(entry.addr)
    }

    pub(super) fn unlock_inner(&mut self, handle: u16) -> Result<u16, LocalHeapError> {
        let Some(HandleSlot::Live(mut entry)) = self.slot(handle)? else { return Ok(0) };
        if entry.lock == 0 {
            return Ok(0);
        }
        entry.lock -= 1;
        self.write_entry(entry)?;
        Ok(u16::from(entry.lock))
    }

    pub(super) fn size_inner(&self, handle: u16) -> Result<u16, LocalHeapError> {
        if handle == 0 {
            return Ok(0);
        }
        if handle & 3 == 0 {
            let Some(block) = self.fixed_block(handle)? else { return Ok(0) };
            return block.end.checked_sub(handle).ok_or(LocalHeapError::CorruptArenaChain {
                offset: usize::from(block.start),
            });
        }
        let Some(slot) = self.slot(handle)? else { return Ok(0) };
        match slot {
            HandleSlot::Live(entry) => {
                let start = entry.addr - (ARENA_HEADER_BYTES + MOVEABLE_PREFIX_BYTES) as u16;
                let block = self.arena_at(&self.arenas()?, start)?;
                block.end.checked_sub(entry.addr).ok_or(LocalHeapError::CorruptArenaChain {
                    offset: usize::from(start),
                })
            }
            HandleSlot::Unused | HandleSlot::Discarded(_) => Ok(0),
        }
    }

    pub(super) fn handle_inner(&self, offset: u16) -> Result<u16, LocalHeapError> {
        if offset == 0 {
            return Ok(0);
        }
        for entry in self.handle_entries(&self.arenas()?)? {
            if entry.lock != 0xff && entry.addr == offset {
                return Ok(entry.handle);
            }
        }
        Ok(if self.fixed_pointer(offset)? { offset } else { 0 })
    }

    pub(super) fn flags_inner(&self, handle: u16) -> Result<u16, LocalHeapError> {
        if handle == 0 {
            return Ok(LMEM_INVALID_HANDLE);
        }
        if handle & 3 == 0 {
            return Ok(if self.fixed_block(handle)?.is_some() { 0 } else { LMEM_INVALID_HANDLE });
        }
        let Some(slot) = self.slot(handle)? else { return Ok(LMEM_INVALID_HANDLE) };
        match slot {
            HandleSlot::Unused => Ok(LMEM_INVALID_HANDLE),
            HandleSlot::Discarded(entry) | HandleSlot::Live(entry) => {
                Ok(u16::from(entry.lock) | (u16::from(entry.flags) << 8))
            }
        }
    }

    pub(super) fn count_free_inner(&self) -> Result<u16, LocalHeapError> {
        let total = self.arenas()?.iter()
            .filter(|arena| arena.free && arena.start != self.last)
            .try_fold(0u32, |sum, arena| sum.checked_add(u32::from(arena.extent())))
            .ok_or(LocalHeapError::CorruptFreeList { offset: usize::from(self.first) })?;
        u16::try_from(total).map_err(|_| LocalHeapError::CorruptFreeList {
            offset: usize::from(self.first),
        })
    }

    pub(super) fn largest_free_payload(&self) -> Result<u16, LocalHeapError> {
        let largest = self.arenas()?.iter()
            .filter(|arena| arena.free && arena.start != self.last)
            .map(|arena| arena.extent().saturating_sub(ARENA_HEADER_BYTES as u16))
            .max().unwrap_or(0);
        Ok(largest)
    }

    fn fixed_block(&self, handle: u16) -> Result<Option<ArenaInfo>, LocalHeapError> {
        if handle & 3 != 0 || handle < ARENA_HEADER_BYTES as u16 {
            return Ok(None);
        }
        let start = handle - ARENA_HEADER_BYTES as u16;
        let arenas = self.arenas()?;
        let Some(block) = arenas.iter().find(|arena| arena.start == start && !arena.free).copied() else {
            return Ok(None);
        };
        if start == self.first || start == self.info.saturating_sub(ARENA_HEADER_BYTES as u16) {
            return Ok(None);
        }
        if self.handle_tables(&arenas)?.iter().any(|table| table.arena_start == start)
            || self.handle_entries(&arenas)?.iter().any(|entry| entry.addr != 0
                && entry.addr.checked_sub((ARENA_HEADER_BYTES + MOVEABLE_PREFIX_BYTES) as u16) == Some(start))
        {
            return Ok(None);
        }
        Ok(Some(block))
    }

    fn fixed_pointer(&self, offset: u16) -> Result<bool, LocalHeapError> {
        let arenas = self.arenas()?;
        let tables = self.handle_tables(&arenas)?;
        let entries = self.handle_entries(&arenas)?;
        for arena in arenas.iter().filter(|arena| !arena.free) {
            if arena.start == self.first || arena.start == self.info.saturating_sub(ARENA_HEADER_BYTES as u16) {
                continue;
            }
            if tables.iter().any(|table| table.arena_start == arena.start)
                || entries.iter().any(|entry| entry.addr != 0
                    && entry.addr.checked_sub((ARENA_HEADER_BYTES + MOVEABLE_PREFIX_BYTES) as u16) == Some(arena.start))
            {
                continue;
            }
            let start = arena.start + ARENA_HEADER_BYTES as u16;
            if offset >= start && offset < arena.end {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn arena_at(&self, arenas: &[ArenaInfo], start: u16) -> Result<ArenaInfo, LocalHeapError> {
        arenas.iter().find(|arena| arena.start == start && !arena.free).copied()
            .ok_or(LocalHeapError::CorruptArenaChain { offset: usize::from(start) })
    }

    fn is_internal_heap_block(&self, arena_start: u16) -> Result<bool, LocalHeapError> {
        if arena_start == self.first || arena_start == self.info.saturating_sub(ARENA_HEADER_BYTES as u16) {
            return Ok(true);
        }
        Ok(self.handle_tables(&self.arenas()?)?.iter().any(|table| table.arena_start == arena_start))
    }

    pub(super) fn notify_installed(&self) -> Result<bool, LocalHeapError> {
        let offset = usize::from(self.info) + super::HEAP_NOTIFY_OFFSET;
        let low = read_word(self.dgroup, offset)
            .ok_or(LocalHeapError::CorruptHeapInfo { offset })?;
        let high = read_word(self.dgroup, offset + 2)
            .ok_or(LocalHeapError::CorruptHeapInfo { offset: offset + 2 })?;
        Ok(low != 0 || high != 0)
    }

    fn reserve_handle(&mut self, flags: u16) -> Result<Option<u16>, LocalHeapError> {
        if let Some(handle) = self.first_free_entry()? {
            return Ok(Some(handle));
        }
        let delta = read_word(self.dgroup, usize::from(self.info) + HEAP_HANDLE_DELTA_OFFSET)
            .ok_or(LocalHeapError::CorruptHeapInfo { offset: usize::from(self.info) + HEAP_HANDLE_DELTA_OFFSET })?;
        if delta == 0 {
            return Ok(None);
        }
        let bytes = usize::from(delta).checked_mul(4).and_then(|size| size.checked_add(4))
            .ok_or(LocalHeapError::OutOfMemory)?;
        let Ok(bytes) = u16::try_from(bytes) else { return Ok(None) };
        let Some(extent) = requested_extent(bytes, 0) else { return Ok(None) };
        let Some(table_pointer) = self.allocate_extent(extent, flags)? else { return Ok(None) };
        let old_head = read_word(self.dgroup, usize::from(self.info) + HEAP_TABLE_OFFSET)
            .ok_or(LocalHeapError::CorruptHandleTable { offset: usize::from(self.info) + HEAP_TABLE_OFFSET })?;
        write_word(self.dgroup, &mut self.write_spans, usize::from(table_pointer), delta)
            .map_err(|error| LocalHeapError::preserve_write_error(error,
                LocalHeapError::CorruptHandleTable { offset: usize::from(table_pointer) }))?;
        let first_entry = usize::from(table_pointer) + 2;
        for index in 0..usize::from(delta) {
            let entry_offset = first_entry + index * 4;
            write_word(self.dgroup, &mut self.write_spans, entry_offset, 0)
                .map_err(|error| LocalHeapError::preserve_write_error(error,
                    LocalHeapError::CorruptHandleTable { offset: entry_offset }))?;
            write_byte(self.dgroup, &mut self.write_spans, entry_offset + 2, 0xff)
                .map_err(|error| LocalHeapError::preserve_write_error(error,
                    LocalHeapError::CorruptHandleTable { offset: entry_offset }))?;
            write_byte(self.dgroup, &mut self.write_spans, entry_offset + 3, 0xff)
                .map_err(|error| LocalHeapError::preserve_write_error(error,
                    LocalHeapError::CorruptHandleTable { offset: entry_offset }))?;
        }
        let link_offset = first_entry + usize::from(delta) * 4;
        write_word(self.dgroup, &mut self.write_spans, link_offset, old_head)
            .map_err(|error| LocalHeapError::preserve_write_error(error,
                LocalHeapError::CorruptHandleTable { offset: link_offset }))?;
        write_word(self.dgroup, &mut self.write_spans,
            usize::from(self.info) + HEAP_TABLE_OFFSET, table_pointer)
            .map_err(|error| LocalHeapError::preserve_write_error(error,
                LocalHeapError::CorruptHandleTable { offset: usize::from(self.info) + HEAP_TABLE_OFFSET }))?;
        Ok(Some(table_pointer + 2))
    }

    fn clear_entry(&mut self, handle: u16) -> Result<(), LocalHeapError> {
        self.write_entry(HandleEntry { handle, addr: 0, flags: 0xff, lock: 0xff })
    }

    fn allocate_extent(&mut self, extent: u16, flags: u16) -> Result<Option<u16>, LocalHeapError> {
        self.allocate_extent_protected(extent, flags, None)
    }

    fn allocate_extent_protected(
        &mut self,
        extent: u16,
        flags: u16,
        protected_handle: Option<u16>,
    ) -> Result<Option<u16>, LocalHeapError> {
        if usize::from(extent) < MIN_ARENA_EXTENT || extent & 3 != 0 {
            return Ok(None);
        }
        let mut arenas = self.arenas()?;
        let mut candidate = arenas.iter().position(|arena| arena.free && arena.start != self.last
            && arena.extent() >= extent);
        if candidate.is_none() && flags & LMEM_NOCOMPACT == 0 {
            let needed_payload = extent.saturating_sub(ARENA_HEADER_BYTES as u16);
            self.compact_protected(needed_payload, flags, protected_handle)?;
            arenas = self.arenas()?;
            candidate = arenas.iter().position(|arena| arena.free && arena.start != self.last
                && arena.extent() >= extent);
        }
        let Some(index) = candidate else { return Ok(None) };
        let block = arenas[index];
        let remainder = block.extent() - extent;
        if remainder >= MIN_ARENA_EXTENT as u16 {
            let split = block.start.checked_add(extent)
                .ok_or(LocalHeapError::CorruptArenaChain { offset: usize::from(block.start) })?;
            arenas.try_reserve(1).map_err(|_| LocalHeapError::OutOfMemory)?;
            arenas[index] = ArenaInfo { start: block.start, end: split, free: false };
            arenas.insert(index + 1, ArenaInfo { start: split, end: block.end, free: true });
        } else {
            arenas[index].free = false;
        }
        let start = arenas[index].start;
        let end = arenas[index].end;
        self.store_arenas(&arenas)?;
        if flags & LMEM_ZEROINIT != 0 {
            let from = usize::from(start) + ARENA_HEADER_BYTES;
            let to = usize::from(end);
            fill_range(self.dgroup, &mut self.write_spans, from..to, 0)?;
        }
        start.checked_add(ARENA_HEADER_BYTES as u16)
            .map(Some)
            .ok_or(LocalHeapError::CorruptArenaChain { offset: usize::from(start) })
    }

    pub(super) fn release_arena(&mut self, start: u16) -> Result<(), LocalHeapError> {
        let mut arenas = self.arenas()?;
        let Some(mut index) = self.find_arena(&arenas, start) else {
            return Err(LocalHeapError::CorruptArenaChain { offset: usize::from(start) });
        };
        if index == 0 || index + 1 == arenas.len() || arenas[index].free {
            return Err(LocalHeapError::CorruptArenaChain { offset: usize::from(start) });
        }
        arenas[index].free = true;
        if index > 1 && arenas[index - 1].free {
            arenas[index - 1].end = arenas[index].end;
            arenas.remove(index);
            index -= 1;
        }
        if index + 1 < arenas.len() - 1 && arenas[index + 1].free {
            arenas[index].end = arenas[index + 1].end;
            arenas.remove(index + 1);
        }
        self.store_arenas(&arenas)
    }

    fn shrink_arena(&mut self, start: u16, required: u16) -> Result<(), LocalHeapError> {
        let mut arenas = self.arenas()?;
        let Some(index) = self.find_arena(&arenas, start) else {
            return Err(LocalHeapError::CorruptArenaChain { offset: usize::from(start) });
        };
        let old = arenas[index];
        if old.free || required >= old.extent() {
            return Ok(());
        }
        let remainder = old.extent() - required;
        if remainder < MIN_ARENA_EXTENT as u16 {
            return Ok(());
        }
        let split = start.checked_add(required)
            .ok_or(LocalHeapError::CorruptArenaChain { offset: usize::from(start) })?;
        arenas[index].end = split;
        if index + 1 < arenas.len() - 1 && arenas[index + 1].free {
            arenas[index + 1].start = split;
        } else {
            arenas.try_reserve(1).map_err(|_| LocalHeapError::OutOfMemory)?;
            arenas.insert(index + 1, ArenaInfo { start: split, end: old.end, free: true });
        }
        if arenas[index + 1].end <= arenas[index + 1].start {
            return Err(LocalHeapError::CorruptArenaChain { offset: usize::from(split) });
        }
        self.store_arenas(&arenas)
    }

    fn grow_arena(&mut self, start: u16, required: u16, zero_init: bool) -> Result<bool, LocalHeapError> {
        let mut arenas = self.arenas()?;
        let Some(index) = self.find_arena(&arenas, start) else {
            return Err(LocalHeapError::CorruptArenaChain { offset: usize::from(start) });
        };
        if arenas[index].free || required <= arenas[index].extent() {
            return Ok(required <= arenas[index].extent());
        }
        let Some(next) = arenas.get(index + 1).copied() else { return Ok(false) };
        if !next.free || next.start == self.last {
            return Ok(false);
        }
        let available_end = next.end;
        let required_end = start.checked_add(required)
            .ok_or(LocalHeapError::CorruptArenaChain { offset: usize::from(start) })?;
        if required_end > available_end {
            return Ok(false);
        }
        let old_end = arenas[index].end;
        let leftover = available_end - required_end;
        if leftover >= MIN_ARENA_EXTENT as u16 {
            arenas[index].end = required_end;
            arenas[index + 1] = ArenaInfo { start: required_end, end: available_end, free: true };
        } else {
            arenas[index].end = available_end;
            arenas.remove(index + 1);
        }
        self.store_arenas(&arenas)?;
        if zero_init && required_end > old_end {
            let start = usize::from(old_end);
            let end = usize::from(if leftover >= MIN_ARENA_EXTENT as u16 { required_end } else { available_end });
            fill_range(self.dgroup, &mut self.write_spans, start..end, 0)?;
        }
        Ok(true)
    }
}

fn requested_extent(size: u16, prefix: usize) -> Option<u16> {
    let needed = usize::from(size).checked_add(ARENA_HEADER_BYTES)?.checked_add(prefix)?;
    let aligned = needed.checked_add(3)? & !3;
    let extent = aligned.max(MIN_ARENA_EXTENT);
    u16::try_from(extent).ok()
}
