//! LocalShrink's arena relocation and terminal-boundary transaction.

use super::arena::ArenaInfo;
use super::{
    ARENA_HEADER_BYTES, HEAP_LAST_OFFSET, HEAP_MINIMUM_SIZE_OFFSET, LMEM_NOCOMPACT,
    LOCAL_ARENA_BYTES, LocalHeap, LocalHeapError, MIN_ARENA_EXTENT, MOVEABLE_PREFIX_BYTES,
    copy_within_range, read_word, write_word,
};

impl LocalHeap<'_> {
    pub(super) fn shrink_inner(&mut self, minimum: u16) -> Result<u16, LocalHeapError> {
        let initialized_minimum = read_word(
            self.dgroup,
            usize::from(self.info) + HEAP_MINIMUM_SIZE_OFFSET,
        )
        .ok_or(LocalHeapError::CorruptHeapInfo {
            offset: usize::from(self.info),
        })?;
        let minimum = minimum.max(initialized_minimum);
        let span = self.shrink_span()?;
        // KERNEL31 lshrink compacts with the maximum request, allowing all
        // eligible discardable blocks to be released, even if the current
        // extent already satisfies the requested minimum.
        self.compact_inner(u16::MAX, 0)?;
        if span <= minimum {
            return self.shrink_span();
        }
        loop {
            self.trim_free_tail(minimum)?;
            if self.shrink_span()? <= minimum {
                break;
            }
            let arenas = self.arenas()?;
            let Some(tail) = arenas.get(arenas.len().saturating_sub(2)).copied() else {
                return Err(LocalHeapError::CorruptArenaChain {
                    offset: usize::from(self.last),
                });
            };
            if tail.free {
                break;
            }
            let entries = self.handle_entries(&arenas)?;
            let Some(mut entry) = entries.into_iter().find(|entry| {
                entry.lock == 0
                    && entry
                        .addr
                        .checked_sub((ARENA_HEADER_BYTES + MOVEABLE_PREFIX_BYTES) as u16)
                        == Some(tail.start)
            }) else {
                break;
            };
            // Unlike ordinary compaction, a trailing movable block may cross
            // fixed-block barriers to occupy an earlier, sufficiently large hole.
            if !arenas.iter().any(|arena| {
                arena.free && arena.start < tail.start && arena.extent() >= tail.extent()
            }) {
                break;
            }
            if self.notify_installed()? {
                return Err(LocalHeapError::CallbackRequired);
            }
            let Some(payload) = self.allocate_extent(tail.extent(), LMEM_NOCOMPACT)? else {
                break;
            };
            let from = usize::from(tail.start) + ARENA_HEADER_BYTES;
            copy_within_range(
                self.dgroup,
                &mut self.write_spans,
                from..usize::from(tail.end),
                usize::from(payload),
            )?;
            entry.addr = payload.checked_add(MOVEABLE_PREFIX_BYTES as u16).ok_or(
                LocalHeapError::CorruptHandleTable {
                    offset: usize::from(entry.handle),
                },
            )?;
            self.write_entry(entry)?;
            self.release_arena(tail.start)?;
        }
        // Cross-barrier moves may have changed the free holes in earlier
        // regions. KERNEL31 compacts once more before returning the heap span.
        self.compact_inner(u16::MAX, 0)?;
        self.shrink_span()
    }

    fn shrink_span(&self) -> Result<u16, LocalHeapError> {
        self.last
            .checked_add(LOCAL_ARENA_BYTES as u16)
            .and_then(|end| end.checked_sub(self.first))
            .ok_or(LocalHeapError::CorruptHeapInfo {
                offset: usize::from(self.info),
            })
    }

    fn trim_free_tail(&mut self, minimum: u16) -> Result<(), LocalHeapError> {
        let mut arenas = self.arenas()?;
        let tail_index = arenas
            .len()
            .checked_sub(2)
            .ok_or(LocalHeapError::CorruptArenaChain {
                offset: usize::from(self.last),
            })?;
        let tail = arenas[tail_index];
        if !tail.free {
            return Ok(());
        }
        let floor = u32::from(self.first) + u32::from(minimum);
        let floor = floor.saturating_sub(LOCAL_ARENA_BYTES as u32);
        let floor = (floor + 3) & !3;
        let mut terminal = floor.max(u32::from(tail.start));
        let remainder = terminal - u32::from(tail.start);
        if remainder != 0 && remainder < MIN_ARENA_EXTENT as u32 {
            terminal = u32::from(tail.start) + MIN_ARENA_EXTENT as u32;
        }
        if terminal >= u32::from(self.last) {
            return Ok(());
        }
        let terminal = terminal as u16;
        arenas.pop();
        if terminal == tail.start {
            arenas.pop();
        } else {
            arenas[tail_index].end = terminal;
        }
        arenas.push(ArenaInfo {
            start: terminal,
            end: terminal,
            free: true,
        });
        self.last = terminal;
        write_word(
            self.dgroup,
            &mut self.write_spans,
            usize::from(self.info) + HEAP_LAST_OFFSET,
            terminal,
        )?;
        self.store_arenas(&arenas)
    }
}
