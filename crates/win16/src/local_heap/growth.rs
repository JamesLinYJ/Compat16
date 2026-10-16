use std::fmt;

use super::arena::ArenaInfo;
use super::{
    HEAP_LAST_OFFSET, HEAP_RESERVED_END_OFFSET, INSTANCE_DATA_BYTES, LOCAL_ARENA_BYTES,
    MAX_SEGMENT_BYTES, MIN_ARENA_EXTENT, LocalHeap, LocalHeapError, read_word, write_word,
};

/// Failure while extending a validated local heap into an already-grown DGROUP.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalHeapGrowthError {
    /// LocalInit left application-owned bytes after its explicit heap range.
    TailNotOwned,
    /// The old and new DGROUP byte lengths do not describe a supported growth.
    InvalidRange {
        old_dgroup_bytes: usize,
        new_dgroup_bytes: usize,
    },
    /// The existing terminal arena is not at the old DGROUP tail.
    NotAtTail {
        actual_last: u16,
        expected_last: u16,
    },
    /// The extension cannot provide a valid new free arena.
    NoUsableGrowth {
        old_last: u16,
        new_last: u16,
        available_extent: u16,
        minimum_extent: u16,
    },
    /// The existing local heap is malformed or could not be updated safely.
    Heap(LocalHeapError),
}

impl fmt::Display for LocalHeapGrowthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TailNotOwned => f.write_str("Win16 local heap does not own the enclosing segment tail"),
            Self::InvalidRange { old_dgroup_bytes, new_dgroup_bytes } => write!(
                f,
                "Win16 local-heap growth range {old_dgroup_bytes}..{new_dgroup_bytes} bytes is invalid",
            ),
            Self::NotAtTail { actual_last, expected_last } => write!(
                f,
                "Win16 local heap ends at 0x{actual_last:04X}, not the old DGROUP tail 0x{expected_last:04X}; refusing to consume adjacent data",
            ),
            Self::NoUsableGrowth {
                old_last,
                new_last,
                available_extent,
                minimum_extent,
            } => write!(
                f,
                "Win16 local-heap growth from terminal 0x{old_last:04X} to 0x{new_last:04X} adds {available_extent} bytes, below the {minimum_extent}-byte arena requirement",
            ),
            Self::Heap(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for LocalHeapGrowthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Heap(error) => Some(error),
            _ => None,
        }
    }
}

impl LocalHeap<'_> {
    /// Re-admit only a tail previously owned by this heap, within the current
    /// DGROUP limit. Explicit LocalInit ranges never consume adjacent data.
    pub fn reclaim_reserved_tail(&mut self) -> Result<bool, LocalHeapError> {
        let offset = usize::from(self.info) + HEAP_RESERVED_END_OFFSET;
        let reserved = read_word(self.dgroup, offset)
            .ok_or(LocalHeapError::CorruptHeapInfo { offset })?;
        if reserved == 0 { return Ok(false); }
        if reserved & 3 != 0 || reserved < self.last || reserved > 0xfff4 {
            return Err(LocalHeapError::CorruptHeapInfo { offset });
        }
        let terminal = reserved.min(terminal_for_segment_bytes(self.dgroup.len()));
        if terminal <= self.last { return Ok(false); }
        let old = self.last;
        let arenas = self.arenas()?;
        if terminal - old < MIN_ARENA_EXTENT as u16
            && !arenas.get(arenas.len().saturating_sub(2)).is_some_and(|arena| arena.free) {
            return Ok(false);
        }
        self.transaction(|heap| { heap.grow_inner(old, terminal)?; Ok(0) })?;
        self.last = terminal;
        Ok(true)
    }

    /// Extends the heap to the end of an already-grown caller-owned DGROUP.
    ///
    /// `old_dgroup_bytes` is the exact segment length before the caller grew
    /// its backing; `self` must view the new, longer segment. This method only
    /// changes guest heap metadata and does not resize backing, update a
    /// selector, or clear newly added bytes. The runtime first verifies owned
    /// adjacent capacity and initializes an expanded transaction copy. After
    /// an allocation retry succeeds, it publishes guest bytes and descriptor
    /// limits together; a failed retry does not expose the prepared growth.
    pub fn grow(&mut self, old_dgroup_bytes: usize) -> Result<(), LocalHeapGrowthError> {
        let new_dgroup_bytes = self.dgroup.len();
        if !(INSTANCE_DATA_BYTES..=MAX_SEGMENT_BYTES).contains(&old_dgroup_bytes)
            || !(INSTANCE_DATA_BYTES..=MAX_SEGMENT_BYTES).contains(&new_dgroup_bytes)
            || old_dgroup_bytes >= new_dgroup_bytes
        {
            return Err(LocalHeapGrowthError::InvalidRange {
                old_dgroup_bytes,
                new_dgroup_bytes,
            });
        }

        self.validate().map_err(LocalHeapGrowthError::Heap)?;
        if !self.owns_segment_tail() { return Err(LocalHeapGrowthError::TailNotOwned); }
        let old_last = terminal_for_segment_bytes(old_dgroup_bytes);
        if self.last != old_last {
            return Err(LocalHeapGrowthError::NotAtTail {
                actual_last: self.last,
                expected_last: old_last,
            });
        }

        let new_last = terminal_for_segment_bytes(new_dgroup_bytes);
        let available_extent = new_last.saturating_sub(old_last);
        let arenas = self.arenas().map_err(LocalHeapGrowthError::Heap)?;
        let previous = arenas.get(arenas.len().saturating_sub(2))
            .ok_or_else(|| LocalHeapGrowthError::Heap(LocalHeapError::CorruptArenaChain {
                offset: usize::from(old_last),
            }))?;
        let minimum_extent = if previous.free {
            1
        } else {
            MIN_ARENA_EXTENT as u16
        };
        if new_last <= old_last || available_extent < minimum_extent {
            return Err(LocalHeapGrowthError::NoUsableGrowth {
                old_last,
                new_last,
                available_extent,
                minimum_extent,
            });
        }

        self.transaction(|heap| {
            heap.grow_inner(old_last, new_last)?;
            Ok(0)
        }).map_err(LocalHeapGrowthError::Heap)?;
        // The transaction validated and committed both the header and arena
        // writes before refreshing this view's cached terminal offset.
        self.last = new_last;
        Ok(())
    }

    fn grow_inner(&mut self, old_last: u16, new_last: u16) -> Result<(), LocalHeapError> {
        if self.last != old_last || new_last <= old_last {
            return Err(LocalHeapError::CorruptHeapInfo {
                offset: usize::from(self.info) + HEAP_LAST_OFFSET,
            });
        }
        let mut arenas = self.arenas()?;
        let terminal = arenas.pop().ok_or(LocalHeapError::CorruptArenaChain {
            offset: usize::from(old_last),
        })?;
        if terminal != (ArenaInfo { start: old_last, end: old_last, free: true })
            || arenas.last().map(|arena| arena.end) != Some(old_last)
        {
            return Err(LocalHeapError::CorruptArenaChain { offset: usize::from(old_last) });
        }
        arenas.try_reserve(2).map_err(|_| LocalHeapError::OutOfMemory)?;

        if let Some(previous) = arenas.last_mut().filter(|arena| arena.free) {
            previous.end = new_last;
        } else {
            arenas.push(ArenaInfo { start: old_last, end: new_last, free: true });
        }
        arenas.push(ArenaInfo { start: new_last, end: new_last, free: true });

        self.last = new_last;
        let last_offset = usize::from(self.info) + HEAP_LAST_OFFSET;
        write_word(self.dgroup, &mut self.write_spans, last_offset, new_last)
            .map_err(|error| LocalHeapError::preserve_write_error(
                error,
                LocalHeapError::CorruptHeapInfo { offset: last_offset },
            ))?;
        let reserved_offset = usize::from(self.info) + HEAP_RESERVED_END_OFFSET;
        let reserved = read_word(self.dgroup, reserved_offset)
            .ok_or(LocalHeapError::CorruptHeapInfo { offset: reserved_offset })?;
        write_word(self.dgroup, &mut self.write_spans, reserved_offset, reserved.max(new_last))?;
        self.store_arenas(&arenas)
    }
}

fn terminal_for_segment_bytes(segment_bytes: usize) -> u16 {
    let usable_last = segment_bytes.saturating_sub(1).min(0xfffe);
    let terminal = (usable_last - LOCAL_ARENA_BYTES) & !3;
    terminal as u16
}
