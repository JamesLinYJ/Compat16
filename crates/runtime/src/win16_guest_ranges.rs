//! Saved selector identities and transactional writes for suspended host calls.
//!
//! Host workers can run while guest callbacks execute. Keeping a raw FAR
//! value is therefore insufficient: its selector may be freed and reused
//! before the native result arrives. A captured range retains every selector
//! generation and physical span crossed by the original range.

use guest_core::{GuestMemory, MemoryError, PhysAddr, memory::Memory};
use std::{error::Error, fmt};
use win16_abi::{Access, DescriptorInfo, SegmentedPointer, SelectorRef, SelectorTable};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RangeChunk {
    selector: SelectorRef,
    descriptor: DescriptorInfo,
    offset: u16,
    address: PhysAddr,
    logical_offset: usize,
    length: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct GuestOutputRange {
    start: SegmentedPointer,
    length: usize,
    chunks: Vec<RangeChunk>,
}

impl GuestOutputRange {
    pub(in crate::win16_runtime) fn capture(
        state: &Win16State,
        memory: &Memory,
        start: SegmentedPointer,
        length: usize,
    ) -> Result<Self, RuntimeError> {
        Self::capture_with_selectors(&state.selectors, memory, start, length)
    }

    pub(in crate::win16_runtime) fn capture_with_selectors(
        selectors: &SelectorTable,
        memory: &Memory,
        start: SegmentedPointer,
        length: usize,
    ) -> Result<Self, RuntimeError> {
        let chunks = resolve_chunks_with_selectors(selectors, memory, start, length, Access::Write)?;
        for chunk in &chunks {
            memory
                .validate_read(chunk.address, chunk.length)
                .map_err(crate::runtime_error)?;
            memory
                .validate_write(chunk.address, chunk.length)
                .map_err(crate::runtime_error)?;
        }
        Ok(Self {
            start,
            length,
            chunks,
        })
    }

    pub(in crate::win16_runtime) fn start(&self) -> SegmentedPointer {
        self.start
    }
    pub(in crate::win16_runtime) fn length(&self) -> usize {
        self.length
    }

    pub(in crate::win16_runtime) fn try_clone(&self) -> Result<Self, RuntimeError> {
        let mut chunks = Vec::new();
        chunks.try_reserve_exact(self.chunks.len()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "retain Win16 guest output-range identity", error))?;
        chunks.extend_from_slice(&self.chunks);
        Ok(Self { start: self.start, length: self.length, chunks })
    }

    /// Reject conflicting bytes when two checked guest structures alias the
    /// same emulated RAM. Their writes can then share one output transaction.
    pub(in crate::win16_runtime) fn ensure_compatible_output(
        &self,
        bytes: &[u8],
        other: &GuestOutputRange,
        other_bytes: &[u8],
    ) -> Result<(), RuntimeError> {
        if bytes.len() != self.length || other_bytes.len() != other.length {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "aliased Win16 output comparison does not cover both captured extents"));
        }
        for first in &self.chunks {
            let first_start = u64::from(first.address.0);
            let first_end = first_start + first.length as u64;
            for second in &other.chunks {
                let second_start = u64::from(second.address.0);
                let second_end = second_start + second.length as u64;
                let start = first_start.max(second_start);
                let end = first_end.min(second_end);
                if start >= end { continue; }
                let first_offset = first.logical_offset + (start - first_start) as usize;
                let second_offset = second.logical_offset + (start - second_start) as usize;
                let length = (end - start) as usize;
                if bytes[first_offset..first_offset + length]
                    != other_bytes[second_offset..second_offset + length]
                {
                    return Err(RuntimeError::new(Kind::GuestFault,
                        "Win16 output ranges alias with conflicting structure bytes"));
                }
            }
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn is_live(
        &self,
        state: &Win16State,
        memory: &Memory,
    ) -> Result<(), RuntimeError> {
        self.is_live_with_selectors(&state.selectors, memory)
    }

    pub(in crate::win16_runtime) fn is_live_with_selectors(
        &self,
        selectors: &SelectorTable,
        memory: &Memory,
    ) -> Result<(), RuntimeError> {
        let current = resolve_chunks_with_selectors(
            selectors, memory, self.start, self.length, Access::Write,
        )?;
        if current != self.chunks {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "Win16 output range changed selector identity while suspended",
            ));
        }
        for chunk in &current {
            memory
                .validate_read(chunk.address, chunk.length)
                .map_err(crate::runtime_error)?;
            memory
                .validate_write(chunk.address, chunk.length)
                .map_err(crate::runtime_error)?;
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn read(
        &self,
        state: &Win16State,
        memory: &Memory,
    ) -> Result<Vec<u8>, RuntimeError> {
        self.read_prefix(state, memory, self.length)
    }

    pub(in crate::win16_runtime) fn read_prefix(
        &self,
        state: &Win16State,
        memory: &Memory,
        length: usize,
    ) -> Result<Vec<u8>, RuntimeError> {
        self.is_live(state, memory)?;
        if length > self.length {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 guest read exceeds its captured output range"));
        }
        let mut bytes = allocate_bytes(length)?;
        for chunk in &self.chunks {
            if chunk.logical_offset >= length { break; }
            let count = chunk.length.min(length - chunk.logical_offset);
            memory.read(chunk.address, &mut bytes[chunk.logical_offset..chunk.logical_offset + count])
                .map_err(crate::runtime_error)?;
        }
        Ok(bytes)
    }
}

/// A retained read-only guest span for prepared WAVE and ACM input buffers.
/// Selector generations and readable extents remain checked across calls;
/// copying this descriptor does not grant host access to guest pointers.
#[derive(Clone, Debug)]
pub(in crate::win16_runtime) struct GuestInputRange {
    start: SegmentedPointer,
    length: usize,
    chunks: Vec<RangeChunk>,
}

impl GuestInputRange {
    pub(in crate::win16_runtime) fn capture(
        state: &Win16State,
        memory: &Memory,
        start: SegmentedPointer,
        length: usize,
    ) -> Result<Self, RuntimeError> {
        let chunks = resolve_chunks(state, memory, start, length, Access::Read)?;
        for chunk in &chunks {
            memory.validate_read(chunk.address, chunk.length).map_err(crate::runtime_error)?;
        }
        Ok(Self { start, length, chunks })
    }

    pub(in crate::win16_runtime) fn try_clone(&self) -> Result<Self, RuntimeError> {
        let mut chunks = Vec::new();
        chunks.try_reserve_exact(self.chunks.len()).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "retain Win16 guest input-range identity", error))?;
        chunks.extend_from_slice(&self.chunks);
        Ok(Self { start: self.start, length: self.length, chunks })
    }

    pub(in crate::win16_runtime) fn is_live(
        &self,
        state: &Win16State,
        memory: &Memory,
    ) -> Result<(), RuntimeError> {
        let current = resolve_chunks(state, memory, self.start, self.length, Access::Read)?;
        if current != self.chunks {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 input range changed selector identity while suspended"));
        }
        for chunk in &current {
            memory.validate_read(chunk.address, chunk.length).map_err(crate::runtime_error)?;
        }
        Ok(())
    }

    pub(in crate::win16_runtime) fn read_prefix(
        &self,
        state: &Win16State,
        memory: &Memory,
        length: usize,
    ) -> Result<Vec<u8>, RuntimeError> {
        self.is_live(state, memory)?;
        if length > self.length {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 guest read exceeds its captured input range"));
        }
        let mut bytes = allocate_bytes(length)?;
        for chunk in &self.chunks {
            if chunk.logical_offset >= length { break; }
            let count = chunk.length.min(length - chunk.logical_offset);
            memory.read(chunk.address, &mut bytes[chunk.logical_offset..chunk.logical_offset + count])
                .map_err(crate::runtime_error)?;
        }
        Ok(bytes)
    }
}

struct WriteChunk {
    address: PhysAddr,
    bytes: Vec<u8>,
    before: Vec<u8>,
}

// Error::source exposes one cause. This aggregate retains the primary transfer
// failure and every failed rollback as typed memory errors, including addresses.
#[derive(Debug)]
struct GuestOutputCommitFailure {
    primary: MemoryError,
    rollbacks: Vec<(PhysAddr, MemoryError)>,
}

impl fmt::Display for GuestOutputCommitFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "commit: {}", self.primary)?;
        for (address, error) in &self.rollbacks {
            write!(f, "; rollback at 0x{:08X}: {error}", address.0)?;
        }
        Ok(())
    }
}

impl Error for GuestOutputCommitFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> { Some(&self.primary) }
}

/// Preflights every guest destination and saves rollback bytes before the
/// first write. This keeps related structure/buffer outputs from
/// being partly committed when a later selector has gone stale.
pub(in crate::win16_runtime) fn commit_guest_writes(
    state: &Win16State,
    memory: &mut Memory,
    writes: Vec<(GuestOutputRange, Vec<u8>)>,
) -> Result<(), RuntimeError> {
    commit_guest_writes_with_selectors(&state.selectors, memory, writes)
}

pub(in crate::win16_runtime) fn commit_guest_writes_with_selectors(
    selectors: &SelectorTable,
    memory: &mut Memory,
    writes: Vec<(GuestOutputRange, Vec<u8>)>,
) -> Result<(), RuntimeError> {
    commit_guest_write_iter(
        selectors,
        memory,
        writes
            .iter()
            .map(|(range, bytes)| (range, bytes.as_slice())),
    )
}

/// Commits output through an already-retained selector-generation token.
/// The caller keeps ownership of `range` across retries, so a failed host
/// projection cannot silently recapture a FAR pointer against a new selector.
pub(in crate::win16_runtime) fn commit_guest_output(
    state: &Win16State,
    memory: &mut Memory,
    range: &GuestOutputRange,
    bytes: &[u8],
) -> Result<(), RuntimeError> {
    commit_guest_output_with_selectors(&state.selectors, memory, range, bytes)
}

pub(in crate::win16_runtime) fn commit_guest_output_with_selectors(
    selectors: &SelectorTable,
    memory: &mut Memory,
    range: &GuestOutputRange,
    bytes: &[u8],
) -> Result<(), RuntimeError> {
    commit_guest_write_iter(selectors, memory, std::iter::once((range, bytes)))
}

fn commit_guest_write_iter<'a>(
    selectors: &SelectorTable,
    memory: &mut Memory,
    writes: impl IntoIterator<Item = (&'a GuestOutputRange, &'a [u8])>,
) -> Result<(), RuntimeError> {
    let mut chunks = Vec::new();
    for (range, bytes) in writes {
        range.is_live_with_selectors(selectors, memory)?;
        if bytes.len() > range.length {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "host output exceeded its captured guest range",
            ));
        }
        let mut remaining = bytes.len();
        for chunk in &range.chunks {
            let count = remaining.min(chunk.length);
            if count == 0 {
                break;
            }
            let mut before = allocate_bytes(count)?;
            memory
                .read(chunk.address, &mut before)
                .map_err(crate::runtime_error)?;
            chunks.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve guest output transaction",
                    error,
                )
            })?;
            let mut output = allocate_bytes(count)?;
            output.copy_from_slice(&bytes[chunk.logical_offset..chunk.logical_offset + count]);
            chunks.push(WriteChunk {
                address: chunk.address,
                bytes: output,
                before,
            });
            remaining -= count;
        }
        if remaining != 0 {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "captured guest range did not cover its output prefix",
            ));
        }
    }

    // Allocate failure storage before any guest byte changes. A failed rollback
    // must not require another allocation or prevent restoring earlier chunks.
    let mut rollback_errors = Vec::new();
    rollback_errors.try_reserve_exact(chunks.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve guest output rollback diagnostics", error))?;
    for index in 0..chunks.len() {
        if let Err(error) = memory.write(chunks[index].address, &chunks[index].bytes) {
            for written in (0..=index).rev() {
                if let Err(rollback) =
                    memory.write(chunks[written].address, &chunks[written].before)
                {
                    rollback_errors.push((chunks[written].address, rollback));
                }
            }
            if !rollback_errors.is_empty() {
                return Err(RuntimeError::with_source(Kind::InternalInvariant,
                    "guest output commit and rollback failed",
                    GuestOutputCommitFailure { primary: error, rollbacks: rollback_errors }));
            }
            return Err(
                crate::runtime_error(error).with_context("committing host result to guest output")
            );
        }
    }
    Ok(())
}

fn resolve_chunks(
    state: &Win16State,
    memory: &Memory,
    start: SegmentedPointer,
    length: usize,
    access: Access,
) -> Result<Vec<RangeChunk>, RuntimeError> {
    resolve_chunks_with_selectors(&state.selectors, memory, start, length, access)
}

fn resolve_chunks_with_selectors(
    selectors: &SelectorTable,
    memory: &Memory,
    start: SegmentedPointer,
    length: usize,
    access: Access,
) -> Result<Vec<RangeChunk>, RuntimeError> {
    let mut chunks = Vec::new();
    if length == 0 {
        let descriptor = selectors.describe(start.selector()).map_err(crate::runtime_error)?;
        let address = selectors.translate(start, access, 0, memory)
            .map_err(crate::runtime_error)?;
        chunks.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve empty guest transfer range",
                error,
            )
        })?;
        chunks.push(RangeChunk {
            selector: start.selector(),
            descriptor,
            offset: start.offset(),
            address,
            logical_offset: 0,
            length: 0,
        });
        return Ok(chunks);
    }
    let mut consumed = 0usize;
    while consumed < length {
        let displacement = u32::try_from(consumed).map_err(|error| {
            RuntimeError::with_source(Kind::GuestFault, "guest range offset exceeds DWORD", error)
        })?;
        let pointer = selectors
            .add_bytes(start, displacement)
            .map_err(crate::runtime_error)?;
        let descriptor = selectors
            .describe(pointer.selector())
            .map_err(crate::runtime_error)?;
        let available = descriptor
            .limit
            .checked_sub(u32::from(pointer.offset()))
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::GuestFault,
                    "guest range begins beyond its selector limit",
                )
            })? as usize;
        let count = available.min(length - consumed);
        let address = selectors.translate(pointer, access, count, memory)
            .map_err(crate::runtime_error)?;
        chunks.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve guest transfer range",
                error,
            )
        })?;
        chunks.push(RangeChunk {
            selector: pointer.selector(),
            descriptor,
            offset: pointer.offset(),
            address,
            logical_offset: consumed,
            length: count,
        });
        consumed += count;
    }
    Ok(chunks)
}

fn allocate_bytes(length: usize) -> Result<Vec<u8>, RuntimeError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve guest transfer bytes",
            error,
        )
    })?;
    bytes.resize(length, 0);
    Ok(bytes)
}
