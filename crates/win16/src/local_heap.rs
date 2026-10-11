//! Win16 DGROUP local-heap initialization and guest-resident heap services.
//!
//! The public `LocalInit` contract is documented by the Microsoft Windows 3.1
//! SDK Programmer's Reference, volume 1, chapter 3, and the Windows Guide to
//! Programming, section 20.3.1.1. The private arena and heap-info byte layout
//! below is an implementation detail, not a public Microsoft ABI.
//!
//! Arena bytes and movable-handle entries live in the guest's selected data
//! segment. Runtime callers locate that segment from the calling task's DS and
//! pass the corresponding checked byte slice here.

use std::fmt;
use std::ops::Range;

mod arena;
mod atoms;
mod compact;
mod growth;
mod handles;
mod operations;
mod write_tracking;

pub use atoms::LocalAtomEntry;
pub use growth::LocalHeapGrowthError;

use write_tracking::{copy_within_range, fill_range, write_byte, write_word};

const MAX_SEGMENT_BYTES: usize = 0x1_0000;
const INSTANCE_DATA_BYTES: usize = 0x10;
const INSTANCE_HEAP_POINTER_OFFSET: usize = 0x06;

// The compared packed declaration has five LOCALARENA WORDs; only the first
// two form the arena header immediately preceding a block's contents.
const LOCAL_ARENA_BYTES: usize = 10;
const LOCAL_ARENA_HEADER_BYTES: usize = 4;
const ARENA_HEADER_BYTES: usize = LOCAL_ARENA_HEADER_BYTES;
const LOCAL_HEAP_INFO_BYTES: usize = 0x2a;
const LOCAL_HEAP_MAGIC: u16 = 0x484c; // 'LH'
const LOCAL_ARENA_FIXED: u16 = 1;
const LOCAL_ARENA_FREE: u16 = 0;
const LOCAL_ARENA_TYPE_MASK: u16 = 0x0003;
const LOCAL_ARENA_PREVIOUS_OFFSET_MASK: u16 = 0xfffc;
const MIN_ARENA_EXTENT: usize = (LOCAL_ARENA_BYTES + 3) & !3;
const MOVEABLE_PREFIX_BYTES: usize = 2;
const LOCAL_HEAP_WRITES: usize = 6;

// LOCALARENA word offsets, from the compared packed declaration.
const ARENA_PREVIOUS_OFFSET: usize = 0x00;
const ARENA_NEXT_OFFSET: usize = 0x02;
const ARENA_SIZE_OFFSET: usize = 0x04;
const ARENA_FREE_PREVIOUS_OFFSET: usize = 0x06;
const ARENA_FREE_NEXT_OFFSET: usize = 0x08;

// LOCALHEAPINFO offsets, from the compared packed declaration.
const HEAP_ITEMS_OFFSET: usize = 0x04;
const HEAP_FIRST_OFFSET: usize = 0x06;
const HEAP_LAST_OFFSET: usize = 0x0a;
const HEAP_TABLE_OFFSET: usize = 0x14;
const HEAP_HANDLE_DELTA_OFFSET: usize = 0x18;
const HEAP_NOTIFY_OFFSET: usize = 0x1e;
const HEAP_EXPANSION_EXTRA_OFFSET: usize = 0x24;
const HEAP_MINIMUM_SIZE_OFFSET: usize = 0x26;
const HEAP_MAGIC_OFFSET: usize = 0x28;

const LMEM_MOVEABLE: u16 = 0x0002;
const LMEM_NOCOMPACT: u16 = 0x0010;
const LMEM_NODISCARD: u16 = 0x0020;
const LMEM_ZEROINIT: u16 = 0x0040;
const LMEM_MODIFY: u16 = 0x0080;
const LMEM_DISCARDABLE: u16 = 0x0f00;
const LMEM_DISCARDED: u8 = 0x40;
const LMEM_INVALID_HANDLE: u16 = 0x8000;
const UNUSED_HANDLE_BYTE: u8 = 0xff;

/// A checked local-heap view over the caller's guest DGROUP bytes.
///
/// This view owns no heap metadata outside `dgroup`; operations validate and
/// update the Win16 arena chain and handle table in that byte slice. It does
/// not resize the selected DGROUP backing, so an exhausted segment reports
/// the ordinary Win16 allocation failure result.
pub struct LocalHeap<'a> {
    dgroup: &'a mut [u8],
    write_spans: Vec<Range<usize>>,
    info: u16,
    first: u16,
    last: u16,
}

/// One guest local-heap arena exposed to Win16 diagnostic APIs.
///
/// Offsets are relative to the owning data segment. `next` is an opaque
/// continuation token containing the next arena's segment offset; it is never
/// used as a guest linear address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalHeapEntry {
    pub arena_offset: u16,
    pub handle: u16,
    pub address: u16,
    pub size: u16,
    pub flags: u16,
    pub lock_count: u16,
    pub kind: u16,
    pub next: u16,
}

/// Win16 ToolHelp local-arena flags.
pub const LOCAL_ENTRY_FIXED: u16 = 0x0001;
pub const LOCAL_ENTRY_FREE: u16 = 0x0002;
pub const LOCAL_ENTRY_MOVEABLE: u16 = 0x0004;
/// Win16 ToolHelp free-arena type.
pub const LOCAL_ENTRY_TYPE_FREE: u16 = 0x00ff;

/// Internal heap damage and implementation boundaries that cannot be
/// represented as ordinary Win16 API return values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalHeapError {
    /// The segment has no initialized local heap.
    Uninitialized,
    /// A temporary host-side transaction buffer could not be reserved.
    OutOfMemory,
    /// The heap has a LocalNotify callback that this implementation cannot run.
    CallbackRequired,
    /// The local-heap information header is malformed at this segment offset.
    CorruptHeapInfo { offset: usize },
    /// The arena chain is malformed at this segment offset.
    CorruptArenaChain { offset: usize },
    /// The arena free list is malformed at this segment offset.
    CorruptFreeList { offset: usize },
    /// A movable-handle table or entry is malformed at this segment offset.
    CorruptHandleTable { offset: usize },
    /// The guest-resident local atom table or one of its entries is malformed.
    CorruptAtomTable { offset: usize },
}

impl fmt::Display for LocalHeapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uninitialized => f.write_str("Win16 local heap is not initialized"),
            Self::OutOfMemory => f.write_str("Win16 local heap could not reserve a transaction buffer"),
            Self::CallbackRequired => f.write_str("Win16 local heap operation requires an unavailable LocalNotify callback"),
            Self::CorruptHeapInfo { offset } => write!(f, "Win16 local-heap information is corrupt at DGROUP offset 0x{offset:04X}"),
            Self::CorruptArenaChain { offset } => write!(f, "Win16 local-heap arena chain is corrupt at DGROUP offset 0x{offset:04X}"),
            Self::CorruptFreeList { offset } => write!(f, "Win16 local-heap free list is corrupt at DGROUP offset 0x{offset:04X}"),
            Self::CorruptHandleTable { offset } => write!(f, "Win16 local-heap handle table is corrupt at DGROUP offset 0x{offset:04X}"),
            Self::CorruptAtomTable { offset } => write!(f, "Win16 local atom table is corrupt at DGROUP offset 0x{offset:04X}"),
        }
    }
}

impl std::error::Error for LocalHeapError {}

impl LocalHeapError {
    pub(super) fn preserve_write_error(error: Self, fallback: Self) -> Self {
        match error {
            Self::OutOfMemory => Self::OutOfMemory,
            _ => fallback,
        }
    }
}

impl<'a> LocalHeap<'a> {
    /// Opens and validates a guest local heap in the exact caller-selected
    /// data segment. A zero instance heap pointer is an ordinary uninitialized
    /// heap; nonzero malformed metadata is reported as corruption.
    pub fn open(dgroup: &'a mut [u8]) -> Result<Self, LocalHeapError> {
        if dgroup.len() < INSTANCE_HEAP_POINTER_OFFSET + 2 {
            return Err(LocalHeapError::Uninitialized);
        }
        if dgroup.len() > MAX_SEGMENT_BYTES {
            return Err(LocalHeapError::CorruptHeapInfo { offset: 0 });
        }
        let info = read_word(dgroup, INSTANCE_HEAP_POINTER_OFFSET)
            .ok_or(LocalHeapError::Uninitialized)?;
        if info == 0 {
            return Err(LocalHeapError::Uninitialized);
        }
        let first = read_word(dgroup, usize::from(info) + HEAP_FIRST_OFFSET)
            .ok_or(LocalHeapError::CorruptHeapInfo { offset: usize::from(info) })?;
        let last = read_word(dgroup, usize::from(info) + HEAP_LAST_OFFSET)
            .ok_or(LocalHeapError::CorruptHeapInfo { offset: usize::from(info) })?;
        let heap = Self { dgroup, write_spans: Vec::new(), info, first, last };
        heap.validate()?;
        Ok(heap)
    }

    /// Allocates a fixed or movable guest block. `0` is the ordinary failure
    /// result, including a zero-sized fixed allocation.
    pub fn alloc(&mut self, flags: u16, size: u16) -> Result<u16, LocalHeapError> {
        self.transaction(|heap| heap.alloc_inner(flags, size))
    }

    /// Resizes a valid fixed or movable guest block without invalidating its
    /// original handle if allocation fails.
    pub fn realloc(&mut self, handle: u16, size: u16, flags: u16) -> Result<u16, LocalHeapError> {
        self.transaction(|heap| heap.realloc_inner(handle, size, flags))
    }

    /// Frees a guest block. Returns zero on success and the input handle on
    /// ordinary failure.
    pub fn free(&mut self, handle: u16) -> Result<u16, LocalHeapError> {
        self.transaction(|heap| heap.free_inner(handle))
    }

    /// Locks a movable block and returns its near offset; fixed handles return
    /// their own offset without changing heap bytes.
    pub fn lock(&mut self, handle: u16) -> Result<u16, LocalHeapError> {
        self.transaction(|heap| heap.lock_inner(handle))
    }

    /// Decrements a movable block's lock count, returning the new count.
    pub fn unlock(&mut self, handle: u16) -> Result<u16, LocalHeapError> {
        self.transaction(|heap| heap.unlock_inner(handle))
    }

    /// Returns the actual available guest payload bytes for a valid handle.
    pub fn size(&self, handle: u16) -> Result<u16, LocalHeapError> {
        self.size_inner(handle)
    }

    /// Maps a guest near pointer to its movable handle when it equals a
    /// movable block's current locked address; fixed-block pointers map to
    /// themselves.
    pub fn handle(&self, offset: u16) -> Result<u16, LocalHeapError> {
        self.handle_inner(offset)
    }

    /// Returns the movable lock/discard flags, zero for a valid fixed block,
    /// or `LMEM_INVALID_HANDLE` for an invalid handle.
    pub fn flags(&self, handle: u16) -> Result<u16, LocalHeapError> {
        self.flags_inner(handle)
    }

    /// Compacts the heap until it can provide `minimum` bytes, then returns
    /// the largest free payload. A zero minimum is query-only and reports the
    /// largest payload Windows could generate by compacting unlocked movable
    /// blocks and discarding eligible discardable blocks, without changing
    /// guest memory.
    pub fn compact(&mut self, minimum: u16) -> Result<u16, LocalHeapError> {
        self.transaction(|heap| heap.compact_inner(minimum, 0))
    }

    /// Queries (`delta == 0`) or sets the number of entries used by future
    /// movable-handle table expansions. Returns the current/new WORD. Existing
    /// tables are unchanged; oversized values remain stored exactly, while
    /// allocation keeps its checked size arithmetic and ordinary failure path.
    pub fn handle_delta(&mut self, delta: u16) -> Result<u16, LocalHeapError> {
        let offset = usize::from(self.info) + HEAP_HANDLE_DELTA_OFFSET;
        if delta == 0 {
            self.validate()?;
            return read_word(self.dgroup, offset)
                .ok_or(LocalHeapError::CorruptHeapInfo { offset });
        }
        self.transaction(|heap| {
            write_word(heap.dgroup, &mut heap.write_spans, offset, delta)
                .map_err(|error| LocalHeapError::preserve_write_error(error,
                    LocalHeapError::CorruptHeapInfo { offset }))?;
            Ok(delta)
        })
    }

    /// Returns the total size of all reusable free extents, including their
    /// arena headers but excluding the terminal sentinel.
    pub fn count_free(&self) -> Result<u16, LocalHeapError> {
        self.count_free_inner()
    }

    /// Returns the arena range from the first sentinel to the terminal one.
    pub fn heap_size(&self) -> Result<u16, LocalHeapError> {
        self.last.checked_sub(self.first).ok_or(LocalHeapError::CorruptHeapInfo {
            offset: usize::from(self.info) + HEAP_LAST_OFFSET,
        })
    }

    /// Returns a validated snapshot of the guest-resident arena chain.
    /// Sentinel arenas are omitted. Handle-table and heap-metadata arenas stay
    /// visible as fixed allocations because they occupy real local-heap space.
    pub fn snapshot_entries(&self) -> Result<Vec<LocalHeapEntry>, LocalHeapError> {
        let arenas = self.arenas()?;
        let handles = self.handle_entries(&arenas)?;
        let count = arenas.len().saturating_sub(2);
        let mut entries = Vec::new();
        entries.try_reserve_exact(count).map_err(|_| LocalHeapError::OutOfMemory)?;

        for (index, arena) in arenas.iter().enumerate().skip(1).take(count) {
            let following = arenas.get(index + 1).map_or(0, |next| next.start);
            if arena.free {
                entries.push(LocalHeapEntry {
                    arena_offset: arena.start,
                    handle: 0,
                    address: arena.start.saturating_add(ARENA_HEADER_BYTES as u16),
                    size: arena.extent().saturating_sub(ARENA_HEADER_BYTES as u16),
                    flags: LOCAL_ENTRY_FREE,
                    lock_count: 0,
                    kind: LOCAL_ENTRY_TYPE_FREE,
                    next: following,
                });
                continue;
            }

            let movable = handles.iter().find(|entry| {
                entry.lock != UNUSED_HANDLE_BYTE
                    && entry.addr == arena.start.saturating_add(
                        (ARENA_HEADER_BYTES + MOVEABLE_PREFIX_BYTES) as u16,
                    )
            });
            let (handle, address, flags, lock_count) = match movable {
                Some(entry) => (entry.handle, entry.addr, LOCAL_ENTRY_MOVEABLE,
                    u16::from(entry.lock)),
                None => {
                    let address = arena.start.saturating_add(ARENA_HEADER_BYTES as u16);
                    (address, address, LOCAL_ENTRY_FIXED, 0)
                }
            };
            entries.push(LocalHeapEntry {
                arena_offset: arena.start,
                handle,
                address,
                size: arena.end.saturating_sub(address),
                flags,
                lock_count,
                kind: 0,
                next: following,
            });
        }
        Ok(entries)
    }

    /// Takes the sorted, coalesced segment-relative ranges written since this
    /// view was opened or last drained. Same-value stores remain represented
    /// because ranges record write intent, not a diff of the transaction bytes.
    pub fn take_write_spans(&mut self) -> Vec<Range<usize>> {
        std::mem::take(&mut self.write_spans)
    }

    fn transaction(
        &mut self,
        operation: impl FnOnce(&mut LocalHeap<'_>) -> Result<u16, LocalHeapError>,
    ) -> Result<u16, LocalHeapError> {
        self.transaction_when(operation, |_| true)
    }

    // Atom allocation can require two fixed blocks. A failed attempt must
    // discard both allocations and any intermediate compaction, so callers can
    // retry against a larger DGROUP without publishing partial initialization.
    fn transaction_when(
        &mut self,
        operation: impl FnOnce(&mut LocalHeap<'_>) -> Result<u16, LocalHeapError>,
        commit: impl FnOnce(u16) -> bool,
    ) -> Result<u16, LocalHeapError> {
        let mut scratch = Vec::new();
        scratch.try_reserve_exact(self.dgroup.len()).map_err(|_| LocalHeapError::OutOfMemory)?;
        scratch.extend_from_slice(self.dgroup);
        let (value, writes) = {
            let mut heap = LocalHeap::open(&mut scratch)?;
            let value = operation(&mut heap)?;
            heap.validate()?;
            (value, heap.take_write_spans())
        };
        if commit(value) {
            self.apply_transaction_writes(&scratch, &writes)?;
        }
        Ok(value)
    }

    fn apply_transaction_writes(
        &mut self,
        source: &[u8],
        writes: &[Range<usize>],
    ) -> Result<(), LocalHeapError> {
        if source.len() != self.dgroup.len() {
            return Err(LocalHeapError::CorruptArenaChain { offset: 0 });
        }
        for range in writes {
            if range.start > range.end
                || self.dgroup.get(range.clone()).is_none()
                || source.get(range.clone()).is_none()
            {
                return Err(LocalHeapError::CorruptArenaChain { offset: range.start });
            }
        }
        self.write_spans.try_reserve(writes.len()).map_err(|_| LocalHeapError::OutOfMemory)?;
        for range in writes {
            self.dgroup[range.clone()].copy_from_slice(&source[range.clone()]);
            write_tracking::merge_write_span(&mut self.write_spans, range.clone());
        }
        Ok(())
    }
}

fn read_word(bytes: &[u8], offset: usize) -> Option<u16> {
    let pair = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([pair[0], pair[1]]))
}

/// The addresses and extent produced by one successful `LocalInit` layout.
/// All offsets are relative to the beginning of the selected DGROUP segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalHeapLayout {
    /// First fixed arena. The first 16 bytes of DGROUP remain instance data.
    pub first_arena: u16,
    /// Arena containing the local-heap information header.
    pub heap_info_arena: u16,
    /// Offset stored in `INSTANCEDATA.heap` and pointing to heap-info bytes.
    pub heap_info: u16,
    /// Initial free arena.
    pub free_arena: u16,
    /// Terminal arena used as the end marker for the arena/free lists.
    pub last_arena: u16,
    /// First byte after the free arena's four-byte arena header.
    pub first_free_byte: u16,
    /// Initial free arena extent, including its four-byte arena header.
    pub free_arena_bytes: u16,
}

/// A byte patch belonging to a prepared local-heap initialization.
///
/// The patch bytes are guest data in little-endian Win16 layout. Callers can
/// validate each `(offset, bytes().len())` against `GuestMemory` before
/// committing any of the plan's patches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalHeapWrite {
    offset: u16,
    length: u8,
    bytes: [u8; LOCAL_HEAP_INFO_BYTES],
}

impl LocalHeapWrite {
    /// Segment-relative byte offset of this patch.
    pub const fn offset(self) -> u16 {
        self.offset
    }

    /// Bytes to write at [`Self::offset`].
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }
}

/// A fully range-checked, side-effect-free LocalInit plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalHeapInitPlan {
    segment_bytes: usize,
    layout: LocalHeapLayout,
    writes: [LocalHeapWrite; LOCAL_HEAP_WRITES],
}

impl LocalHeapInitPlan {
    /// Resolved in-segment layout.
    pub const fn layout(&self) -> LocalHeapLayout {
        self.layout
    }

    /// The exact segment length used to prepare this plan.
    pub const fn segment_bytes(&self) -> usize {
        self.segment_bytes
    }

    /// The six patches, in increasing application order. The ranges are
    /// disjoint and already checked to fit in `segment_bytes()`.
    pub const fn writes(&self) -> &[LocalHeapWrite; LOCAL_HEAP_WRITES] {
        &self.writes
    }

    /// Applies the plan to an exact DGROUP byte slice.
    ///
    /// Slice length is checked before the first write. Once that check passes,
    /// all patch ranges are known to fit, so this method cannot fail midway.
    pub fn apply_to_slice(&self, dgroup: &mut [u8]) -> Result<(), LocalHeapInitError> {
        if dgroup.len() != self.segment_bytes {
            return Err(LocalHeapInitError::SegmentLengthMismatch {
                expected: self.segment_bytes,
                actual: dgroup.len(),
            });
        }

        // Validate every range before changing guest bytes. This also keeps
        // the commit phase atomic with respect to ordinary slice bounds.
        for patch in &self.writes {
            let start = usize::from(patch.offset);
            let end = start + patch.bytes().len();
            if end > dgroup.len() {
                return Err(LocalHeapInitError::InvalidPreparedPlan);
            }
        }
        for patch in &self.writes {
            let start = usize::from(patch.offset);
            let end = start + patch.bytes().len();
            dgroup[start..end].copy_from_slice(patch.bytes());
        }
        Ok(())
    }
}

/// Failure while checking a `LocalInit` request or applying its prepared plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalHeapInitError {
    /// A Win16 segment must have between 16 bytes and 64 KiB of backing.
    InvalidSegmentLength { length: usize },
    /// The segment slice passed to commit differs from the prepared segment.
    SegmentLengthMismatch { expected: usize, actual: usize },
    /// A nonzero-start range is reversed or extends beyond DGROUP.
    RangeOutsideDgroup {
        start: u16,
        end: u16,
        segment_bytes: usize,
    },
    /// The requested tail reserve cannot fit below the usable 16-bit endpoint.
    ReserveOutsideDgroup { requested: u16, available: usize },
    /// The range cannot hold the first arena, heap-info area, free arena, and
    /// terminal arena with the Win16 alignment rules.
    HeapRangeTooSmall,
    /// A private plan invariant failed before commit.
    InvalidPreparedPlan,
}

impl fmt::Display for LocalHeapInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSegmentLength { length } => write!(
                f,
                "Win16 LocalInit requires a DGROUP between 16 bytes and 64 KiB; got {length} bytes"
            ),
            Self::SegmentLengthMismatch { expected, actual } => write!(
                f,
                "Win16 LocalInit plan is for a {expected}-byte DGROUP, but received {actual} bytes"
            ),
            Self::RangeOutsideDgroup {
                start,
                end,
                segment_bytes,
            } => write!(
                f,
                "Win16 LocalInit range 0x{start:04X}..=0x{end:04X} exceeds the {segment_bytes}-byte DGROUP"
            ),
            Self::ReserveOutsideDgroup {
                requested,
                available,
            } => write!(
                f,
                "Win16 LocalInit tail reserve of {requested} bytes exceeds the {available}-byte usable DGROUP tail"
            ),
            Self::HeapRangeTooSmall => f.write_str(
                "Win16 LocalInit range is too small for local-heap metadata and a free arena",
            ),
            Self::InvalidPreparedPlan => {
                f.write_str("Win16 LocalInit prepared patch falls outside its DGROUP")
            }
        }
    }
}

impl std::error::Error for LocalHeapInitError {}

/// Prepares the guest-memory layout created by Win16 `LocalInit`.
///
/// `dgroup_bytes` must be the exact byte length of the selected data segment.
/// When `start != 0`, `start..=end` is the explicit inclusive byte range from
/// the LocalInit contract. The historical implementation treats `start == 0` as a special request
/// to place a heap of `end` bytes at the end of the segment; this branch uses
/// the same 0xFFFE maximum endpoint and refuses a reserve that cannot fit,
/// instead of wrapping a 16-bit subtraction or reporting success.
///
/// The returned plan performs no guest-memory writes. For cross-layer task
/// startup, validate all of `plan.writes()` alongside stack/instance patches,
/// then commit the writes. Only `INSTANCEDATA.heap` at offset 6 is changed in
/// the instance header; offsets 10 through 15 remain available to InitTask's
/// stack fields.
pub fn prepare_local_heap_init(
    dgroup_bytes: usize,
    start: u16,
    end: u16,
) -> Result<LocalHeapInitPlan, LocalHeapInitError> {
    if !(INSTANCE_DATA_BYTES..=MAX_SEGMENT_BYTES).contains(&dgroup_bytes) {
        return Err(LocalHeapInitError::InvalidSegmentLength {
            length: dgroup_bytes,
        });
    }

    let (heap_start, heap_end) = if start == 0 {
        let usable_last = dgroup_bytes.saturating_sub(1).min(0xfffe);
        let requested = usize::from(end.min(0xfffe));
        if requested > usable_last {
            return Err(LocalHeapInitError::ReserveOutsideDgroup {
                requested: end,
                available: usable_last,
            });
        }
        (usable_last - requested, usable_last)
    } else {
        let end_index = usize::from(end);
        if usize::from(start) > end_index || end_index >= dgroup_bytes {
            return Err(LocalHeapInitError::RangeOutsideDgroup {
                start,
                end,
                segment_bytes: dgroup_bytes,
            });
        }
        (usize::from(start), end_index)
    };

    let first_arena = align4(heap_start.max(INSTANCE_DATA_BYTES))?;
    let heap_info_arena = align4(
        first_arena
            .checked_add(LOCAL_ARENA_BYTES)
            .ok_or(LocalHeapInitError::HeapRangeTooSmall)?,
    )?;
    let heap_info = heap_info_arena
        .checked_add(LOCAL_ARENA_HEADER_BYTES)
        .ok_or(LocalHeapInitError::HeapRangeTooSmall)?;
    let free_arena = align4(
        heap_info
            .checked_add(LOCAL_HEAP_INFO_BYTES)
            .ok_or(LocalHeapInitError::HeapRangeTooSmall)?,
    )?;
    let last_arena = end_index_for_layout(heap_end)?
        .checked_sub(LOCAL_ARENA_BYTES)
        .ok_or(LocalHeapInitError::HeapRangeTooSmall)?
        & !3;
    let free_after_header = free_arena
        .checked_add(LOCAL_ARENA_BYTES)
        .ok_or(LocalHeapInitError::HeapRangeTooSmall)?;
    if free_after_header >= last_arena
        || heap_info + LOCAL_HEAP_INFO_BYTES > free_arena
        || first_arena + LOCAL_ARENA_BYTES > heap_info_arena
        || last_arena + LOCAL_ARENA_BYTES > dgroup_bytes
    {
        return Err(LocalHeapInitError::HeapRangeTooSmall);
    }

    let layout = LocalHeapLayout {
        first_arena: word_offset(first_arena)?,
        heap_info_arena: word_offset(heap_info_arena)?,
        heap_info: word_offset(heap_info)?,
        free_arena: word_offset(free_arena)?,
        last_arena: word_offset(last_arena)?,
        first_free_byte: word_offset(free_arena + LOCAL_ARENA_HEADER_BYTES)?,
        free_arena_bytes: word_offset(last_arena - free_arena)?,
    };
    let arena_allocated_bytes = word_offset(align4(LOCAL_ARENA_BYTES)?)?;

    let mut first_arena_bytes = [0; LOCAL_HEAP_INFO_BYTES];
    write_arena(
        &mut first_arena_bytes,
        layout.first_arena | LOCAL_ARENA_FIXED,
        layout.heap_info_arena,
        arena_allocated_bytes,
        layout.first_arena,
        layout.free_arena,
    );

    let mut heap_info_arena_bytes = [0; LOCAL_HEAP_INFO_BYTES];
    put_word(
        &mut heap_info_arena_bytes,
        0,
        layout.first_arena | LOCAL_ARENA_FIXED,
    );
    put_word(&mut heap_info_arena_bytes, 2, layout.free_arena);

    let mut heap_info_bytes = [0; LOCAL_HEAP_INFO_BYTES];
    put_word(&mut heap_info_bytes, HEAP_ITEMS_OFFSET, 4);
    put_word(&mut heap_info_bytes, HEAP_FIRST_OFFSET, layout.first_arena);
    put_word(&mut heap_info_bytes, HEAP_LAST_OFFSET, layout.last_arena);
    put_word(&mut heap_info_bytes, HEAP_HANDLE_DELTA_OFFSET, 0x20);
    put_word(&mut heap_info_bytes, HEAP_EXPANSION_EXTRA_OFFSET, 0x0200);
    put_word(
        &mut heap_info_bytes,
        HEAP_MINIMUM_SIZE_OFFSET,
        layout.free_arena_bytes,
    );
    put_word(&mut heap_info_bytes, HEAP_MAGIC_OFFSET, LOCAL_HEAP_MAGIC);

    let mut free_arena_bytes = [0; LOCAL_HEAP_INFO_BYTES];
    write_arena(
        &mut free_arena_bytes,
        layout.heap_info_arena | LOCAL_ARENA_FREE,
        layout.last_arena,
        layout.free_arena_bytes,
        layout.first_arena,
        layout.last_arena,
    );

    let mut last_arena_bytes = [0; LOCAL_HEAP_INFO_BYTES];
    write_arena(
        &mut last_arena_bytes,
        layout.free_arena | LOCAL_ARENA_FREE,
        layout.last_arena,
        arena_allocated_bytes,
        layout.free_arena,
        layout.last_arena,
    );

    Ok(LocalHeapInitPlan {
        segment_bytes: dgroup_bytes,
        layout,
        writes: [
            write_patch(
                INSTANCE_HEAP_POINTER_OFFSET,
                &layout.heap_info.to_le_bytes(),
            )?,
            write_patch(
                layout.first_arena as usize,
                &first_arena_bytes[..LOCAL_ARENA_BYTES],
            )?,
            write_patch(
                layout.heap_info_arena as usize,
                &heap_info_arena_bytes[..LOCAL_ARENA_HEADER_BYTES],
            )?,
            write_patch(layout.heap_info as usize, &heap_info_bytes)?,
            write_patch(
                layout.free_arena as usize,
                &free_arena_bytes[..LOCAL_ARENA_BYTES],
            )?,
            write_patch(
                layout.last_arena as usize,
                &last_arena_bytes[..LOCAL_ARENA_BYTES],
            )?,
        ],
    })
}

fn end_index_for_layout(end: usize) -> Result<usize, LocalHeapInitError> {
    if end > 0xffff {
        return Err(LocalHeapInitError::HeapRangeTooSmall);
    }
    Ok(end)
}

fn align4(value: usize) -> Result<usize, LocalHeapInitError> {
    value
        .checked_add(3)
        .map(|aligned| aligned & !3)
        .ok_or(LocalHeapInitError::HeapRangeTooSmall)
}

fn word_offset(value: usize) -> Result<u16, LocalHeapInitError> {
    u16::try_from(value).map_err(|_| LocalHeapInitError::HeapRangeTooSmall)
}

fn put_word(bytes: &mut [u8; LOCAL_HEAP_INFO_BYTES], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_arena(
    bytes: &mut [u8; LOCAL_HEAP_INFO_BYTES],
    prev: u16,
    next: u16,
    size: u16,
    free_prev: u16,
    free_next: u16,
) {
    let previous_offset = prev & LOCAL_ARENA_PREVIOUS_OFFSET_MASK;
    let arena_type = prev & LOCAL_ARENA_TYPE_MASK;
    put_word(bytes, ARENA_PREVIOUS_OFFSET, previous_offset | arena_type);
    put_word(bytes, ARENA_NEXT_OFFSET, next);
    put_word(bytes, ARENA_SIZE_OFFSET, size);
    put_word(bytes, ARENA_FREE_PREVIOUS_OFFSET, free_prev);
    put_word(bytes, ARENA_FREE_NEXT_OFFSET, free_next);
}

fn write_patch(offset: usize, bytes: &[u8]) -> Result<LocalHeapWrite, LocalHeapInitError> {
    let offset = word_offset(offset)?;
    let length = u8::try_from(bytes.len()).map_err(|_| LocalHeapInitError::InvalidPreparedPlan)?;
    if bytes.len() > LOCAL_HEAP_INFO_BYTES {
        return Err(LocalHeapInitError::InvalidPreparedPlan);
    }
    let mut storage = [0; LOCAL_HEAP_INFO_BYTES];
    storage[..bytes.len()].copy_from_slice(bytes);
    Ok(LocalHeapWrite {
        offset,
        length,
        bytes: storage,
    })
}

#[cfg(test)]
#[path = "local_heap/handle_delta_tests.rs"]
mod handle_delta_tests;
