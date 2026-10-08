//! Selector-generation checked MIDIHDR and MIDI byte-buffer ranges.
//!
//! Win16 MIDIHDR carries DWORD lengths, so a MIDI buffer may cross the
//! guest's contiguous selector chain. The range captures that exact owned
//! allocation instead of extending a pointer into adjacent physical memory.

use guest_core::{GuestMemory, PhysAddr, memory::Memory};
use win16_abi::{Access, DescriptorInfo, SegmentedPointer, SelectorRef};

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MidiRangeChunk {
    selector: SelectorRef,
    descriptor: DescriptorInfo,
    offset: u16,
    address: PhysAddr,
    logical_offset: usize,
    length: usize,
}

#[derive(Clone, Debug)]
pub(super) struct MidiGuestRange {
    far: u32,
    length: usize,
    allocation_size: Option<u32>,
    chunks: Vec<MidiRangeChunk>,
    readable: bool,
    writable: bool,
}

impl MidiGuestRange {
    pub(super) fn capture(
        state: &Win16State,
        memory: &Memory,
        far: u32,
        length: usize,
        readable: bool,
        writable: bool,
    ) -> Result<Self, RuntimeError> {
        if length == 0 && far == 0 {
            return Ok(Self {
                far, length, allocation_size: None, chunks: Vec::new(), readable, writable,
            });
        }
        let start = state.selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
        let allocation_size = state.selectors.allocation_size(start.selector())
            .map_err(crate::runtime_error)?;
        let chunks = resolve(state, memory, start, length, readable, writable, allocation_size)?;
        Ok(Self {
            far, length, allocation_size: Some(allocation_size), chunks, readable, writable,
        })
    }

    pub(super) fn read(
        &self,
        state: &Win16State,
        memory: &Memory,
    ) -> Result<Vec<u8>, RuntimeError> {
        if !self.readable {
            return Err(invariant("Win16 MIDI range was not captured for reading"));
        }
        self.is_live(state, memory)?;
        let mut bytes = allocate(self.length, "Win16 MIDI guest input bytes")?;
        for chunk in &self.chunks {
            memory.read(chunk.address,
                &mut bytes[chunk.logical_offset..chunk.logical_offset + chunk.length])
                .map_err(crate::runtime_error)?;
        }
        Ok(bytes)
    }

    pub(super) fn commit(
        &self,
        state: &Win16State,
        memory: &mut Memory,
        bytes: &[u8],
    ) -> Result<(), RuntimeError> {
        commit_ranges(state, memory, &[(self, bytes)])
    }

    pub(super) fn is_live(&self, state: &Win16State, memory: &Memory) -> Result<(), RuntimeError> {
        if self.length == 0 && self.far == 0 { return Ok(()); }
        let start = state.selectors.pointer_from_far(self.far).map_err(crate::runtime_error)?;
        let allocation_size = state.selectors.allocation_size(start.selector())
            .map_err(crate::runtime_error)?;
        if Some(allocation_size) != self.allocation_size {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 MIDI allocation changed while a header was prepared"));
        }
        let current = resolve(state, memory, start, self.length, self.readable, self.writable,
            allocation_size)?;
        if current != self.chunks {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 MIDI selector identity changed while a header was prepared"));
        }
        Ok(())
    }
}

/// Preflight every destination and snapshot every old byte before the first
/// guest write. MIDI input completion updates both lpData and MIDIHDR16; the
/// grouped plan avoids committing one output before discovering that the
/// other range is stale or inaccessible.
pub(super) fn commit_ranges(
    state: &Win16State,
    memory: &mut Memory,
    ranges: &[(&MidiGuestRange, &[u8])],
) -> Result<(), RuntimeError> {
    let capacity = ranges.iter().try_fold(0usize, |count, (range, bytes)| {
        if !range.writable {
            return Err(invariant("Win16 MIDI range was not captured for writing"));
        }
        if bytes.len() > range.length {
            return Err(invariant("Win16 MIDI host output exceeds its captured destination"));
        }
        range.is_live(state, memory)?;
        count.checked_add(range.chunks.len())
            .ok_or_else(|| RuntimeError::new(Kind::ResourceExhausted,
                "Win16 MIDI output transaction plan overflowed"))
    })?;
    let mut writes = Vec::new();
    writes.try_reserve_exact(capacity).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve Win16 MIDI output transaction", error))?;
    let mut total_output = 0usize;
    for (range, bytes) in ranges {
        for chunk in &range.chunks {
            let count = chunk.length.min(bytes.len().saturating_sub(chunk.logical_offset));
            if count == 0 { break; }
            let mut previous = allocate(count, "Win16 MIDI output rollback bytes")?;
            memory.read(chunk.address, &mut previous).map_err(crate::runtime_error)?;
            let mut output = allocate(count, "Win16 MIDI output bytes")?;
            output.copy_from_slice(&bytes[chunk.logical_offset..chunk.logical_offset + count]);
            total_output = total_output.checked_add(count).ok_or_else(|| {
                RuntimeError::new(Kind::ResourceExhausted,
                    "Win16 MIDI output byte count overflowed")
            })?;
            writes.push(MidiWriteChunk { address: chunk.address, output, previous });
        }
    }
    let mut rollback_errors = Vec::new();
    rollback_errors.try_reserve_exact(writes.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve Win16 MIDI rollback errors", error))?;
    let mut written = 0usize;
    for index in 0..writes.len() {
        if let Err(error) = memory.write(writes[index].address, &writes[index].output) {
            for applied in (0..=index).rev() {
                if let Err(cause) = memory.write(
                    writes[applied].address,
                    &writes[applied].previous,
                ) {
                    rollback_errors.push(crate::runtime_error(cause));
                }
            }
            let primary = crate::runtime_error(error)
                .with_context(format!("Win16 MIDI output stopped after {written} bytes"));
            return if rollback_errors.is_empty() {
                Err(primary)
            } else {
                Err(RuntimeError::with_source(Kind::InternalInvariant,
                    format!("Win16 MIDI output failed after {written}/{total_output} bytes; rollback also failed"),
                    MidiWriteFailures { primary, rollback: rollback_errors }))
            };
        }
        written += writes[index].output.len();
    }
    Ok(())
}

struct MidiWriteChunk {
    address: PhysAddr,
    output: Vec<u8>,
    previous: Vec<u8>,
}

#[derive(Debug)]
struct MidiWriteFailures {
    primary: RuntimeError,
    rollback: Vec<RuntimeError>,
}

impl std::fmt::Display for MidiWriteFailures {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}; {} MIDI guest rollback write(s) failed",
            self.primary, self.rollback.len())
    }
}

impl std::error::Error for MidiWriteFailures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}

fn resolve(
    state: &Win16State,
    memory: &Memory,
    start: SegmentedPointer,
    length: usize,
    readable: bool,
    writable: bool,
    allocation_size: u32,
) -> Result<Vec<MidiRangeChunk>, RuntimeError> {
    let first = state.selectors.describe(start.selector()).map_err(crate::runtime_error)?;
    let start_offset = u64::try_from(first.segment_index).ok()
        .and_then(|index| index.checked_mul(0x1_0000))
        .and_then(|offset| offset.checked_add(u64::from(start.offset())))
        .ok_or_else(|| invariant("Win16 MIDI range start overflowed"))?;
    let end = start_offset.checked_add(u64::try_from(length).map_err(|error|
        RuntimeError::with_source(Kind::ResourceExhausted,
            "Win16 MIDI range exceeds host address width", error))?)
        .ok_or_else(|| invariant("Win16 MIDI range end overflowed"))?;
    if end > u64::from(allocation_size) {
        return Err(RuntimeError::new(Kind::GuestFault,
            "Win16 MIDI buffer exceeds its owned selector allocation"));
    }
    let capacity = length.checked_div(0x1_0000).and_then(|count| count.checked_add(2))
        .ok_or_else(|| RuntimeError::new(Kind::ResourceExhausted,
            "Win16 MIDI selector plan size overflowed"))?;
    let mut chunks = Vec::new();
    chunks.try_reserve_exact(capacity).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve Win16 MIDI selector plan", error))?;
    let mut copied = 0usize;
    while copied < length {
        let delta = u32::try_from(copied).map_err(|error| RuntimeError::with_source(
            Kind::GuestFault, "Win16 MIDI selector offset exceeds DWORD", error))?;
        let pointer = state.selectors.add_bytes(start, delta).map_err(crate::runtime_error)?;
        let descriptor = state.selectors.describe(pointer.selector()).map_err(crate::runtime_error)?;
        let logical_offset = start_offset.checked_add(copied as u64)
            .ok_or_else(|| invariant("Win16 MIDI selector offset overflowed"))?;
        if !descriptor.present || descriptor.segment_count != first.segment_count
            || descriptor.segment_index != usize::try_from(logical_offset / 0x1_0000)
                .map_err(|error| RuntimeError::with_source(Kind::InternalInvariant,
                    "Win16 MIDI selector index exceeds host width", error))?
        {
            return Err(RuntimeError::new(Kind::GuestFault,
                "Win16 MIDI selector chain is not one contiguous owned allocation"));
        }
        let remaining = usize::try_from(descriptor.limit + 1).ok()
            .and_then(|limit| limit.checked_sub(usize::from(pointer.offset())))
            .filter(|amount| *amount != 0)
            .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                "Win16 MIDI range starts outside its selector"))?;
        let count = remaining.min(length - copied);
        if readable {
            memory.validate_read(state.selectors.translate(pointer, Access::Read, count, memory)
                .map_err(crate::runtime_error)?, count).map_err(crate::runtime_error)?;
        }
        if writable {
            memory.validate_write(state.selectors.translate(pointer, Access::Write, count, memory)
                .map_err(crate::runtime_error)?, count).map_err(crate::runtime_error)?;
        }
        let address = state.selectors.translate(pointer,
            if writable { Access::Write } else { Access::Read }, count, memory)
            .map_err(crate::runtime_error)?;
        chunks.push(MidiRangeChunk {
            selector: pointer.selector(), descriptor, offset: pointer.offset(), address,
            logical_offset: copied, length: count,
        });
        copied = copied.checked_add(count).ok_or_else(|| invariant(
            "Win16 MIDI selector plan length overflowed"))?;
    }
    Ok(chunks)
}

fn allocate(length: usize, context: &'static str) -> Result<Vec<u8>, RuntimeError> {
    let mut output = Vec::new();
    output.try_reserve_exact(length).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, context, error))?;
    output.resize(length, 0);
    Ok(output)
}

fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
