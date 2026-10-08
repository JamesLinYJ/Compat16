use super::{
    ARENA_FREE_NEXT_OFFSET, ARENA_FREE_PREVIOUS_OFFSET, ARENA_NEXT_OFFSET,
    ARENA_PREVIOUS_OFFSET, ARENA_SIZE_OFFSET, HEAP_ITEMS_OFFSET, HEAP_MAGIC_OFFSET,
    HEAP_FIRST_OFFSET, HEAP_LAST_OFFSET, LOCAL_ARENA_BYTES, LOCAL_ARENA_FIXED,
    LOCAL_ARENA_FREE, LOCAL_ARENA_PREVIOUS_OFFSET_MASK, LOCAL_ARENA_TYPE_MASK,
    LOCAL_HEAP_MAGIC, MIN_ARENA_EXTENT, LocalHeap, LocalHeapError, read_word, write_word,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ArenaInfo {
    pub(super) start: u16,
    /// Exclusive end. The terminal sentinel has `end == start`.
    pub(super) end: u16,
    pub(super) free: bool,
}

impl ArenaInfo {
    pub(super) fn extent(self) -> u16 {
        self.end.saturating_sub(self.start)
    }
}

impl LocalHeap<'_> {
    pub(super) fn validate(&self) -> Result<(), LocalHeapError> {
        let arenas = self.arenas()?;
        self.validate_free_list(&arenas)?;
        super::handles::validate_handle_tables(self, &arenas)?;
        Ok(())
    }

    pub(super) fn arenas(&self) -> Result<Vec<ArenaInfo>, LocalHeapError> {
        let info = usize::from(self.info);
        let fail_info = |offset| LocalHeapError::CorruptHeapInfo { offset };
        let fail_arena = |offset| LocalHeapError::CorruptArenaChain { offset };
        let info_end = info.checked_add(super::LOCAL_HEAP_INFO_BYTES)
            .ok_or_else(|| fail_info(info))?;
        if info < 4 || info_end > self.dgroup.len() {
            return Err(fail_info(info));
        }
        if read_word(self.dgroup, info + HEAP_MAGIC_OFFSET) != Some(LOCAL_HEAP_MAGIC) {
            return Err(fail_info(info + HEAP_MAGIC_OFFSET));
        }
        let first = read_word(self.dgroup, info + HEAP_FIRST_OFFSET)
            .ok_or_else(|| fail_info(info + HEAP_FIRST_OFFSET))?;
        let last = read_word(self.dgroup, info + HEAP_LAST_OFFSET)
            .ok_or_else(|| fail_info(info + HEAP_LAST_OFFSET))?;
        if first != self.first || last != self.last
            || usize::from(first) < super::INSTANCE_DATA_BYTES
            || first & 3 != 0 || last & 3 != 0 || first >= last
        {
            return Err(fail_info(info + HEAP_FIRST_OFFSET));
        }
        let info_arena = self.info.checked_sub(4)
            .ok_or_else(|| fail_info(info))?;
        if info_arena < first || info_arena >= last || info_arena & 3 != 0 {
            return Err(fail_info(info));
        }
        let items = read_word(self.dgroup, info + HEAP_ITEMS_OFFSET)
            .ok_or_else(|| fail_info(info + HEAP_ITEMS_OFFSET))?;
        if items < 3 || items as usize > self.dgroup.len() / MIN_ARENA_EXTENT + 1 {
            return Err(fail_info(info + HEAP_ITEMS_OFFSET));
        }

        let mut arenas = Vec::new();
        arenas.try_reserve_exact(usize::from(items))
            .map_err(|_| LocalHeapError::OutOfMemory)?;
        let mut expected_previous = first;
        let mut offset = first;
        let mut visited = 0u32;
        loop {
            visited += 1;
            if visited > u32::from(items) || arenas.len() >= usize::from(items) {
                return Err(fail_arena(usize::from(offset)));
            }
            let start = usize::from(offset);
            let arena_end = start.checked_add(LOCAL_ARENA_BYTES)
                .ok_or_else(|| fail_arena(start))?;
            if start & 3 != 0 || arena_end > self.dgroup.len() {
                return Err(fail_arena(start));
            }
            let previous_and_type = read_word(self.dgroup, start + ARENA_PREVIOUS_OFFSET)
                .ok_or_else(|| fail_arena(start))?;
            let previous = previous_and_type & LOCAL_ARENA_PREVIOUS_OFFSET_MASK;
            let arena_type = previous_and_type & LOCAL_ARENA_TYPE_MASK;
            let next = read_word(self.dgroup, start + ARENA_NEXT_OFFSET)
                .ok_or_else(|| fail_arena(start + ARENA_NEXT_OFFSET))?;
            if previous != expected_previous || (arena_type != LOCAL_ARENA_FREE && arena_type != LOCAL_ARENA_FIXED) {
                return Err(fail_arena(start));
            }
            let is_last = offset == last;
            if is_last {
                if arena_type != LOCAL_ARENA_FREE || next != last {
                    return Err(fail_arena(start));
                }
                arenas.push(ArenaInfo { start: offset, end: offset, free: true });
                break;
            }
            if next <= offset || next > last || next & 3 != 0 {
                return Err(fail_arena(start + ARENA_NEXT_OFFSET));
            }
            if usize::from(next - offset) < MIN_ARENA_EXTENT {
                return Err(fail_arena(start + ARENA_NEXT_OFFSET));
            }
            if arena_type == LOCAL_ARENA_FREE {
                let size = read_word(self.dgroup, start + ARENA_SIZE_OFFSET)
                    .ok_or_else(|| fail_arena(start + ARENA_SIZE_OFFSET))?;
                if size != next - offset || usize::from(size) < MIN_ARENA_EXTENT {
                    return Err(fail_arena(start + ARENA_SIZE_OFFSET));
                }
            }
            arenas.push(ArenaInfo { start: offset, end: next, free: arena_type == LOCAL_ARENA_FREE });
            expected_previous = offset;
            offset = next;
        }
        if arenas.len() != usize::from(items) || arenas.first().map(|a| a.start) != Some(first)
            || !arenas.first().is_some_and(|a| !a.free)
            || !arenas.iter().any(|a| a.start == info_arena && !a.free)
            || arenas.get(1).map(|arena| arena.start) != Some(info_arena)
        {
            return Err(fail_info(info + HEAP_ITEMS_OFFSET));
        }
        if arenas.last().map(|a| a.start) != Some(last) {
            return Err(fail_arena(usize::from(last)));
        }
        let info_owner = arenas.iter().find(|arena| arena.start == info_arena)
            .ok_or_else(|| fail_info(info))?;
        if usize::from(info_owner.end) < info_end {
            return Err(fail_info(info));
        }
        Ok(arenas)
    }

    fn validate_free_list(&self, arenas: &[ArenaInfo]) -> Result<(), LocalHeapError> {
        let first = usize::from(self.first);
        let last = usize::from(self.last);
        let mut current = read_word(self.dgroup, first + ARENA_FREE_NEXT_OFFSET)
            .ok_or(LocalHeapError::CorruptFreeList { offset: first })?;
        let head_previous = read_word(self.dgroup, first + ARENA_FREE_PREVIOUS_OFFSET)
            .ok_or(LocalHeapError::CorruptFreeList { offset: first })?;
        if head_previous != self.first {
            return Err(LocalHeapError::CorruptFreeList { offset: first + ARENA_FREE_PREVIOUS_OFFSET });
        }
        let terminal_next = read_word(self.dgroup, last + ARENA_FREE_NEXT_OFFSET)
            .ok_or(LocalHeapError::CorruptFreeList { offset: last })?;
        if terminal_next != self.last {
            return Err(LocalHeapError::CorruptFreeList { offset: last + ARENA_FREE_NEXT_OFFSET });
        }

        let expected_count = arenas.iter().filter(|a| a.free && a.start != self.last).count();
        let mut seen = Vec::new();
        seen.try_reserve_exact(expected_count)
            .map_err(|_| LocalHeapError::OutOfMemory)?;
        let mut previous = self.first;
        while current != self.last {
            if seen.len() >= expected_count || seen.contains(&current) {
                return Err(LocalHeapError::CorruptFreeList { offset: usize::from(current) });
            }
            let Some(arena) = arenas.iter().find(|arena| arena.start == current && arena.free) else {
                return Err(LocalHeapError::CorruptFreeList { offset: usize::from(current) });
            };
            let start = usize::from(current);
            let free_previous = read_word(self.dgroup, start + ARENA_FREE_PREVIOUS_OFFSET)
                .ok_or(LocalHeapError::CorruptFreeList { offset: start })?;
            let free_next = read_word(self.dgroup, start + ARENA_FREE_NEXT_OFFSET)
                .ok_or(LocalHeapError::CorruptFreeList { offset: start })?;
            if free_previous != previous || free_next == current || free_next < current {
                return Err(LocalHeapError::CorruptFreeList { offset: start });
            }
            if free_next != self.last {
                let reciprocal = read_word(self.dgroup, usize::from(free_next) + ARENA_FREE_PREVIOUS_OFFSET);
                if reciprocal != Some(current) {
                    return Err(LocalHeapError::CorruptFreeList { offset: usize::from(free_next) });
                }
            }
            if arena.extent() < MIN_ARENA_EXTENT as u16 {
                return Err(LocalHeapError::CorruptFreeList { offset: start });
            }
            seen.push(current);
            previous = current;
            current = free_next;
        }
        if seen.len() != expected_count {
            return Err(LocalHeapError::CorruptFreeList { offset: last });
        }
        let last_previous = read_word(self.dgroup, last + ARENA_FREE_PREVIOUS_OFFSET)
            .ok_or(LocalHeapError::CorruptFreeList { offset: last })?;
        if last_previous != previous {
            return Err(LocalHeapError::CorruptFreeList { offset: last + ARENA_FREE_PREVIOUS_OFFSET });
        }
        Ok(())
    }

    pub(super) fn store_arenas(&mut self, arenas: &[ArenaInfo]) -> Result<(), LocalHeapError> {
        if arenas.len() < 3 || arenas.first().map(|a| a.start) != Some(self.first)
            || arenas.last().map(|a| a.start) != Some(self.last)
            || arenas.len() > usize::from(u16::MAX)
        {
            return Err(LocalHeapError::CorruptArenaChain { offset: usize::from(self.first) });
        }
        for (index, arena) in arenas.iter().copied().enumerate() {
            let start = usize::from(arena.start);
            let next = arenas.get(index + 1).map_or(self.last, |next| next.start);
            let previous = if index == 0 { self.first } else { arenas[index - 1].start };
            let kind = if arena.free { LOCAL_ARENA_FREE } else { LOCAL_ARENA_FIXED };
            write_word(self.dgroup, &mut self.write_spans,
                start + ARENA_PREVIOUS_OFFSET, previous | kind)?;
            write_word(self.dgroup, &mut self.write_spans, start + ARENA_NEXT_OFFSET, next)?;
            if arena.free || index == 0 || index + 1 == arenas.len() {
                let extent = if index + 1 == arenas.len() {
                    MIN_ARENA_EXTENT as u16
                } else {
                    next.checked_sub(arena.start).ok_or(LocalHeapError::CorruptArenaChain { offset: start })?
                };
                write_word(self.dgroup, &mut self.write_spans, start + ARENA_SIZE_OFFSET, extent)?;
            }
        }

        let mut free_blocks = Vec::new();
        let free_count = arenas.iter().filter(|arena| arena.free && arena.start != self.last).count();
        free_blocks.try_reserve_exact(free_count).map_err(|_| LocalHeapError::OutOfMemory)?;
        free_blocks.extend(arenas.iter().filter(|arena| arena.free && arena.start != self.last)
            .map(|arena| arena.start));
        write_word(self.dgroup, &mut self.write_spans,
            usize::from(self.first) + ARENA_FREE_PREVIOUS_OFFSET, self.first)?;
        write_word(self.dgroup, &mut self.write_spans, usize::from(self.first) + ARENA_FREE_NEXT_OFFSET,
            free_blocks.first().copied().unwrap_or(self.last))?;
        for (index, block) in free_blocks.iter().copied().enumerate() {
            let start = usize::from(block);
            let previous = if index == 0 { self.first } else { free_blocks[index - 1] };
            let next = free_blocks.get(index + 1).copied().unwrap_or(self.last);
            write_word(self.dgroup, &mut self.write_spans,
                start + ARENA_FREE_PREVIOUS_OFFSET, previous)?;
            write_word(self.dgroup, &mut self.write_spans, start + ARENA_FREE_NEXT_OFFSET, next)?;
        }
        let last = usize::from(self.last);
        write_word(self.dgroup, &mut self.write_spans, last + ARENA_FREE_PREVIOUS_OFFSET,
            free_blocks.last().copied().unwrap_or(self.first))?;
        write_word(self.dgroup, &mut self.write_spans, last + ARENA_FREE_NEXT_OFFSET, self.last)?;
        write_word(self.dgroup, &mut self.write_spans,
            usize::from(self.info) + HEAP_ITEMS_OFFSET, arenas.len() as u16)
    }

    pub(super) fn find_arena(&self, arenas: &[ArenaInfo], start: u16) -> Option<usize> {
        arenas.iter().position(|arena| arena.start == start)
    }
}
