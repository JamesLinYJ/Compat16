use super::{
    ARENA_HEADER_BYTES, LMEM_DISCARDABLE, LMEM_NOCOMPACT, LMEM_NODISCARD,
    MOVEABLE_PREFIX_BYTES,
    LMEM_DISCARDED, MIN_ARENA_EXTENT, LocalHeap, LocalHeapError, copy_within_range,
};
use super::arena::ArenaInfo;
use super::handles::{HandleEntry, HandleSlot};

#[derive(Clone, Copy, Debug)]
struct MovePlan {
    entry: HandleEntry,
    old_start: u16,
    old_end: u16,
    new_start: u16,
}

impl LocalHeap<'_> {
    pub(super) fn compact_inner(&mut self, minimum: u16, flags: u16) -> Result<u16, LocalHeapError> {
        self.compact_protected(minimum, flags, None)
    }

    pub(super) fn compact_protected(
        &mut self,
        minimum: u16,
        flags: u16,
        protected_handle: Option<u16>,
    ) -> Result<u16, LocalHeapError> {
        if minimum == 0 {
            return self.largest_projected_free_payload(protected_handle);
        }
        let initial = self.largest_free_payload()?;
        if initial >= minimum || flags & LMEM_NOCOMPACT != 0 {
            return Ok(initial);
        }

        self.compact_unlocked_blocks(protected_handle)?;
        let mut largest = self.largest_free_payload()?;
        if largest < minimum && flags & LMEM_NODISCARD == 0 {
            let candidates = self.discard_candidates(protected_handle)?;
            if !candidates.is_empty() {
                if self.notify_installed()? {
                    return Err(LocalHeapError::CallbackRequired);
                }
                for handle in candidates {
                    if largest >= minimum {
                        break;
                    }
                    let Some(HandleSlot::Live(mut entry)) = self.slot(handle)? else { continue };
                    let arena_start = entry.addr.checked_sub((ARENA_HEADER_BYTES + MOVEABLE_PREFIX_BYTES) as u16)
                        .ok_or(LocalHeapError::CorruptHandleTable { offset: usize::from(handle) })?;
                    self.release_arena(arena_start)?;
                    entry.addr = 0;
                    entry.flags = LMEM_DISCARDED;
                    entry.lock = 0;
                    self.write_entry(entry)?;
                    self.compact_unlocked_blocks(protected_handle)?;
                    largest = self.largest_free_payload()?;
                }
            }
        }
        Ok(largest)
    }

    /// Projects the largest contiguous free payload available after unlocked
    /// movable blocks are compacted and eligible discardable blocks are
    /// removed. LocalCompact(0) is a query and must not alter guest memory.
    // Windows 3.1 Programmer's Reference, Vol. 2, printed p. 589 (PDF p. 596),
    // defines zero as a no-compaction query whose result is the largest block
    // Windows can generate by removing discardable objects. The projection
    // uses the same immovable barriers as the positive compaction path.
    fn largest_projected_free_payload(&self, protected: Option<u16>) -> Result<u16, LocalHeapError> {
        let arenas = self.arenas()?;
        let entries = self.handle_entries(&arenas)?;
        let movable_count = entries.iter().filter(|entry| {
            entry.addr != 0 && entry.lock != super::UNUSED_HANDLE_BYTE
        }).count();
        let mut movable_owners = Vec::new();
        movable_owners.try_reserve_exact(movable_count)
            .map_err(|_| LocalHeapError::OutOfMemory)?;
        for entry in entries.iter().copied() {
            if entry.addr == 0 || entry.lock == super::UNUSED_HANDLE_BYTE {
                continue;
            }
            let start = entry.addr.checked_sub((ARENA_HEADER_BYTES + MOVEABLE_PREFIX_BYTES) as u16)
                .ok_or(LocalHeapError::CorruptHandleTable { offset: usize::from(entry.handle) })?;
            movable_owners.push((start, entry));
        }
        movable_owners.sort_unstable_by_key(|(start, _)| *start);

        let mut available_extent = 0u32;
        let mut largest_extent = 0u32;
        for arena in arenas.iter().copied().skip(1).take(arenas.len().saturating_sub(2)) {
            if arena.free {
                available_extent = available_extent.checked_add(u32::from(arena.extent()))
                    .ok_or(LocalHeapError::CorruptArenaChain { offset: usize::from(arena.start) })?;
                continue;
            }

            let owner = movable_owners.binary_search_by_key(&arena.start, |(start, _)| *start)
                .ok().map(|index| movable_owners[index].1);
            let Some(entry) = owner.filter(|entry| {
                entry.lock == 0 && Some(entry.handle) != protected
            }) else {
                largest_extent = largest_extent.max(available_extent);
                available_extent = 0;
                continue;
            };
            let discardable = entry.flags & ((LMEM_DISCARDABLE >> 8) as u8) != 0;
            if discardable {
                available_extent = available_extent.checked_add(u32::from(arena.extent()))
                    .ok_or(LocalHeapError::CorruptArenaChain { offset: usize::from(arena.start) })?;
            }
            // An unlocked, non-discardable movable block occupies space after
            // compaction, but it can move to one side of this region. It does
            // not split the free extent between the surrounding arenas.
            // For example, free extents 16 and 16 around a movable extent 12
            // project to a 28-byte payload after one arena header remains.
        }
        largest_extent = largest_extent.max(available_extent);
        let largest_payload = largest_extent.saturating_sub(ARENA_HEADER_BYTES as u32);
        u16::try_from(largest_payload)
            .map_err(|_| LocalHeapError::CorruptArenaChain { offset: usize::from(self.last) })
    }

    fn compact_unlocked_blocks(&mut self, protected_handle: Option<u16>) -> Result<(), LocalHeapError> {
        let source = self.arenas()?;
        let entries = self.handle_entries(&source)?;
        let mut output = Vec::new();
        output.try_reserve_exact(source.len())
            .map_err(|_| LocalHeapError::OutOfMemory)?;
        let mut moves = Vec::new();
        moves.try_reserve_exact(source.len())
            .map_err(|_| LocalHeapError::OutOfMemory)?;
        output.push(source[0]);

        let mut movable_region = Vec::<(ArenaInfo, HandleEntry)>::new();
        let last_index = source.len() - 1;
        for block in source.iter().copied().skip(1).take(last_index - 1) {
            if block.free {
                continue;
            }
            let owner = entries.iter().find(|entry| entry.addr != 0
                && entry.lock != 0xff
                && entry.addr.checked_sub((ARENA_HEADER_BYTES + MOVEABLE_PREFIX_BYTES) as u16) == Some(block.start));
            if let Some(entry) = owner.filter(|entry| entry.lock == 0
                && Some(entry.handle) != protected_handle)
            {
                movable_region.try_reserve(1).map_err(|_| LocalHeapError::OutOfMemory)?;
                movable_region.push((block, *entry));
                continue;
            }
            self.flush_region(&mut output, &mut moves, &mut movable_region, block.start)?;
            output.push(block);
        }

        self.flush_region(&mut output, &mut moves, &mut movable_region, self.last)?;
        output.push(*source.last().ok_or(LocalHeapError::CorruptArenaChain {
            offset: usize::from(self.last),
        })?);
        if moves.is_empty() {
            return Ok(());
        }
        if self.notify_installed()? {
            return Err(LocalHeapError::CallbackRequired);
        }

        // Moves are sorted by old address and always go down. `copy_within`
        // handles overlap while earlier destinations cannot cover a later
        // source block.
        for movement in &moves {
            if movement.new_start == movement.old_start {
                continue;
            }
            let from = usize::from(movement.old_start) + ARENA_HEADER_BYTES;
            let to = usize::from(movement.old_end);
            let destination = usize::from(movement.new_start) + ARENA_HEADER_BYTES;
            let length = to.checked_sub(from)
                .ok_or(LocalHeapError::CorruptArenaChain { offset: from })?;
            let destination_end = destination.checked_add(length)
                .ok_or(LocalHeapError::CorruptArenaChain { offset: destination })?;
            if to > self.dgroup.len() || destination_end > self.dgroup.len() || destination > from {
                return Err(LocalHeapError::CorruptArenaChain { offset: destination });
            }
            copy_within_range(self.dgroup, &mut self.write_spans, from..to, destination)?;
            let new_address = movement.new_start.checked_add((ARENA_HEADER_BYTES + MOVEABLE_PREFIX_BYTES) as u16)
                .ok_or(LocalHeapError::CorruptArenaChain { offset: usize::from(movement.new_start) })?;
            let mut entry = movement.entry;
            entry.addr = new_address;
            self.write_entry(entry)?;
        }
        self.store_arenas(&output)
    }

    fn flush_region(
        &self,
        output: &mut Vec<ArenaInfo>,
        moves: &mut Vec<MovePlan>,
        region: &mut Vec<(ArenaInfo, HandleEntry)>,
        boundary: u16,
    ) -> Result<(), LocalHeapError> {
        let mut cursor = output.last().map(|arena| arena.end)
            .ok_or(LocalHeapError::CorruptArenaChain { offset: usize::from(boundary) })?;
        if cursor > boundary {
            return Err(LocalHeapError::CorruptArenaChain { offset: usize::from(boundary) });
        }
        for (block, entry) in region.drain(..) {
            if block.start < cursor {
                return Err(LocalHeapError::CorruptArenaChain { offset: usize::from(block.start) });
            }
            let extent = block.extent();
            let end = cursor.checked_add(extent)
                .ok_or(LocalHeapError::CorruptArenaChain { offset: usize::from(cursor) })?;
            if end > boundary {
                return Err(LocalHeapError::CorruptArenaChain { offset: usize::from(block.start) });
            }
            if cursor != block.start {
                moves.push(MovePlan {
                    entry,
                    old_start: block.start,
                    old_end: block.end,
                    new_start: cursor,
                });
            }
            output.push(ArenaInfo { start: cursor, end, free: false });
            cursor = end;
        }

        let gap = boundary - cursor;
        if gap >= MIN_ARENA_EXTENT as u16 {
            output.push(ArenaInfo { start: cursor, end: boundary, free: true });
        } else if gap != 0 {
            let Some(previous) = output.last_mut() else {
                return Err(LocalHeapError::CorruptArenaChain { offset: usize::from(cursor) });
            };
            if previous.free {
                return Err(LocalHeapError::CorruptArenaChain { offset: usize::from(cursor) });
            }
            previous.end = boundary;
        }
        Ok(())
    }

    fn discard_candidates(&self, protected: Option<u16>) -> Result<Vec<u16>, LocalHeapError> {
        let entries = self.handle_entries(&self.arenas()?)?;
        let mut candidates = Vec::new();
        candidates.try_reserve_exact(entries.len())
            .map_err(|_| LocalHeapError::OutOfMemory)?;
        for entry in entries {
            if entry.addr != 0 && entry.lock == 0
                && entry.flags & ((LMEM_DISCARDABLE >> 8) as u8) != 0
                && Some(entry.handle) != protected
            {
                candidates.push(entry.handle);
            }
        }
        Ok(candidates)
    }
}
