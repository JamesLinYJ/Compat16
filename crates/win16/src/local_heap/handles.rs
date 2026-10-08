use super::{
    ARENA_HEADER_BYTES, HEAP_TABLE_OFFSET, LMEM_DISCARDED, MOVEABLE_PREFIX_BYTES,
    UNUSED_HANDLE_BYTE, LocalHeap, LocalHeapError, read_word, write_byte, write_word,
};
use super::arena::ArenaInfo;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct HandleEntry {
    pub(super) handle: u16,
    pub(super) addr: u16,
    pub(super) flags: u8,
    pub(super) lock: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct HandleTable {
    pub(super) start: u16,
    pub(super) count: u16,
    pub(super) arena_start: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HandleSlot {
    Unused,
    Discarded(HandleEntry),
    Live(HandleEntry),
}

impl LocalHeap<'_> {
    pub(super) fn handle_tables(&self, arenas: &[ArenaInfo]) -> Result<Vec<HandleTable>, LocalHeapError> {
        let mut tables = Vec::new();
        let mut current = read_word(self.dgroup, usize::from(self.info) + HEAP_TABLE_OFFSET)
            .ok_or(LocalHeapError::CorruptHandleTable { offset: usize::from(self.info) + HEAP_TABLE_OFFSET })?;
        while current != 0 {
            if tables.iter().any(|table: &HandleTable| table.start == current) {
                return Err(LocalHeapError::CorruptHandleTable { offset: usize::from(current) });
            }
            let table_start = usize::from(current);
            let Some(owner) = arenas.iter().find(|arena| !arena.free
                && arena.start != self.first
                && arena.start != self.info.saturating_sub(ARENA_HEADER_BYTES as u16)
                && arena.start.checked_add(ARENA_HEADER_BYTES as u16) == Some(current)) else {
                return Err(LocalHeapError::CorruptHandleTable { offset: table_start });
            };
            let count = read_word(self.dgroup, table_start)
                .ok_or(LocalHeapError::CorruptHandleTable { offset: table_start })?;
            if count == 0 || current & 3 != 0 {
                return Err(LocalHeapError::CorruptHandleTable { offset: table_start });
            }
            let entry_bytes = usize::from(count).checked_mul(4)
                .ok_or(LocalHeapError::CorruptHandleTable { offset: table_start })?;
            let next_offset = table_start.checked_add(2)
                .and_then(|offset| offset.checked_add(entry_bytes))
                .ok_or(LocalHeapError::CorruptHandleTable { offset: table_start })?;
            let table_end = next_offset.checked_add(2)
                .ok_or(LocalHeapError::CorruptHandleTable { offset: table_start })?;
            if table_end > usize::from(owner.end) {
                return Err(LocalHeapError::CorruptHandleTable { offset: table_start });
            }
            let next = read_word(self.dgroup, next_offset)
                .ok_or(LocalHeapError::CorruptHandleTable { offset: next_offset })?;
            tables.try_reserve(1).map_err(|_| LocalHeapError::OutOfMemory)?;
            tables.push(HandleTable { start: current, count, arena_start: owner.start });
            current = next;
        }
        Ok(tables)
    }

    pub(super) fn handle_entries(&self, arenas: &[ArenaInfo]) -> Result<Vec<HandleEntry>, LocalHeapError> {
        let tables = self.handle_tables(arenas)?;
        let total = tables.iter().try_fold(0usize, |sum, table| sum.checked_add(usize::from(table.count)))
            .ok_or(LocalHeapError::CorruptHandleTable { offset: usize::from(self.info) + HEAP_TABLE_OFFSET })?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(total).map_err(|_| LocalHeapError::OutOfMemory)?;
        for table in tables {
            let mut offset = usize::from(table.start) + 2;
            for _ in 0..table.count {
                entries.push(self.read_entry(offset)?);
                offset += 4;
            }
        }
        Ok(entries)
    }

    pub(super) fn entry(&self, handle: u16) -> Result<Option<HandleEntry>, LocalHeapError> {
        if handle & 3 != 2 {
            return Ok(None);
        }
        let arenas = self.arenas()?;
        for table in self.handle_tables(&arenas)? {
            let first_entry = table.start.checked_add(2)
                .ok_or(LocalHeapError::CorruptHandleTable { offset: usize::from(table.start) })?;
            let table_bytes = table.count.checked_mul(4)
                .ok_or(LocalHeapError::CorruptHandleTable { offset: usize::from(table.start) })?;
            let end = first_entry.checked_add(table_bytes)
                .ok_or(LocalHeapError::CorruptHandleTable { offset: usize::from(table.start) })?;
            if handle >= first_entry && handle < end && (handle - first_entry) % 4 == 0 {
                return self.read_entry(usize::from(handle)).map(Some);
            }
        }
        Ok(None)
    }

    pub(super) fn slot(&self, handle: u16) -> Result<Option<HandleSlot>, LocalHeapError> {
        let Some(entry) = self.entry(handle)? else { return Ok(None) };
        if entry.lock == UNUSED_HANDLE_BYTE {
            return Ok(Some(HandleSlot::Unused));
        }
        if entry.addr == 0 && entry.flags == LMEM_DISCARDED && entry.lock == 0 {
            return Ok(Some(HandleSlot::Discarded(entry)));
        }
        if entry.addr != 0 && entry.lock != 0xff && entry.flags != LMEM_DISCARDED {
            return Ok(Some(HandleSlot::Live(entry)));
        }
        Err(LocalHeapError::CorruptHandleTable { offset: usize::from(handle) })
    }

    pub(super) fn write_entry(&mut self, entry: HandleEntry) -> Result<(), LocalHeapError> {
        let offset = usize::from(entry.handle);
        write_word(self.dgroup, &mut self.write_spans, offset, entry.addr)
            .map_err(|error| LocalHeapError::preserve_write_error(error,
                LocalHeapError::CorruptHandleTable { offset }))?;
        write_byte(self.dgroup, &mut self.write_spans, offset + 2, entry.flags)
            .map_err(|error| LocalHeapError::preserve_write_error(error,
                LocalHeapError::CorruptHandleTable { offset }))?;
        write_byte(self.dgroup, &mut self.write_spans, offset + 3, entry.lock)
            .map_err(|error| LocalHeapError::preserve_write_error(error,
                LocalHeapError::CorruptHandleTable { offset }))?;
        Ok(())
    }

    pub(super) fn first_free_entry(&self) -> Result<Option<u16>, LocalHeapError> {
        let arenas = self.arenas()?;
        for table in self.handle_tables(&arenas)? {
            let mut offset = usize::from(table.start) + 2;
            for _ in 0..table.count {
                let entry = self.read_entry(offset)?;
                if entry.lock == UNUSED_HANDLE_BYTE {
                    return Ok(Some(entry.handle));
                }
                offset += 4;
            }
        }
        Ok(None)
    }

    fn read_entry(&self, offset: usize) -> Result<HandleEntry, LocalHeapError> {
        let addr = read_word(self.dgroup, offset)
            .ok_or(LocalHeapError::CorruptHandleTable { offset })?;
        let flags = *self.dgroup.get(offset + 2)
            .ok_or(LocalHeapError::CorruptHandleTable { offset })?;
        let lock = *self.dgroup.get(offset + 3)
            .ok_or(LocalHeapError::CorruptHandleTable { offset })?;
        let handle = u16::try_from(offset)
            .map_err(|_| LocalHeapError::CorruptHandleTable { offset })?;
        if handle & 3 != 2 {
            return Err(LocalHeapError::CorruptHandleTable { offset });
        }
        Ok(HandleEntry { handle, addr, flags, lock })
    }
}

pub(super) fn validate_handle_tables(heap: &LocalHeap<'_>, arenas: &[ArenaInfo]) -> Result<(), LocalHeapError> {
    let tables = heap.handle_tables(arenas)?;
    let entries = heap.handle_entries(arenas)?;
    let mut owners = Vec::new();
    owners.try_reserve_exact(entries.len()).map_err(|_| LocalHeapError::OutOfMemory)?;
    for entry in entries {
        if entry.lock == UNUSED_HANDLE_BYTE {
            if entry.addr != 0 || entry.flags != UNUSED_HANDLE_BYTE {
                return Err(LocalHeapError::CorruptHandleTable { offset: usize::from(entry.handle) });
            }
            continue;
        }
        if entry.addr == 0 {
            if entry.flags == LMEM_DISCARDED && entry.lock == 0 {
                continue;
            }
            return Err(LocalHeapError::CorruptHandleTable { offset: usize::from(entry.handle) });
        }
        if entry.flags == LMEM_DISCARDED || entry.flags & !0x0f != 0
            || usize::from(entry.addr) < ARENA_HEADER_BYTES + MOVEABLE_PREFIX_BYTES
        {
            return Err(LocalHeapError::CorruptHandleTable { offset: usize::from(entry.handle) });
        }
        let arena_start = entry.addr - (ARENA_HEADER_BYTES + MOVEABLE_PREFIX_BYTES) as u16;
        let Some(arena) = arenas.iter().find(|arena| arena.start == arena_start && !arena.free) else {
            return Err(LocalHeapError::CorruptHandleTable { offset: usize::from(entry.handle) });
        };
        if arena.start == heap.first || arena.start == heap.info.saturating_sub(ARENA_HEADER_BYTES as u16)
            || arena.end <= entry.addr
            || read_word(heap.dgroup, usize::from(entry.addr) - MOVEABLE_PREFIX_BYTES) != Some(entry.handle)
            || owners.contains(&arena.start)
            || tables.iter().any(|table| table.arena_start == arena.start)
        {
            return Err(LocalHeapError::CorruptHandleTable { offset: usize::from(entry.handle) });
        }
        owners.push(arena.start);
    }
    Ok(())
}
