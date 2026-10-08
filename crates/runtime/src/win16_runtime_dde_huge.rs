//! Checked selector-chain capture for Win16 DDE huge-object output.

use guest_core::{GuestMemory, PhysAddr, memory::Memory};
use win16_abi::{Access, DescriptorInfo, SegmentedPointer, SelectorRef, SelectorTable};

use super::super::{
    Win16State,
    guest_ranges::{GuestOutputRange, commit_guest_writes_with_selectors},
};
use crate::{DiagnosticKind as Kind, RuntimeError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DdeHugeRangeChunk {
    selector: SelectorRef,
    descriptor: DescriptorInfo,
    offset: u16,
    address: PhysAddr,
    logical_offset: usize,
    length: usize,
}

/// DdeGetData accepts huge output spans. The common output plan already
/// captures selector chunks and transactional rollback; this DDE wrapper also
/// binds those chunks to the same huge allocation extent and segment chain.
#[derive(Clone, Debug)]
pub(super) struct DdeHugeOutputRange {
    start: SegmentedPointer,
    length: usize,
    allocation_size: u32,
    chunks: Vec<DdeHugeRangeChunk>,
    transactional: GuestOutputRange,
}

impl DdeHugeOutputRange {
    pub(super) fn capture(
        state: &Win16State,
        memory: &Memory,
        start: SegmentedPointer,
        length: usize,
    ) -> Result<Self, RuntimeError> {
        let allocation_size = state
            .selectors
            .allocation_size(start.selector())
            .map_err(crate::runtime_error)?;
        let chunks = resolve_dde_huge_chunks(state, memory, start, length, allocation_size)?;
        let transactional = GuestOutputRange::capture(state, memory, start, length)?;
        Ok(Self {
            start,
            length,
            allocation_size,
            chunks,
            transactional,
        })
    }

    pub(super) fn commit(
        &self,
        state: &Win16State,
        memory: &mut Memory,
        bytes: Vec<u8>,
    ) -> Result<(), RuntimeError> {
        self.commit_with_selectors(&state.selectors, memory, bytes)
    }

    pub(in crate::win16_runtime) fn commit_with_selectors(
        &self,
        selectors: &SelectorTable,
        memory: &mut Memory,
        bytes: Vec<u8>,
    ) -> Result<(), RuntimeError> {
        if bytes.len() > self.length {
            return Err(invariant(
                "DDE GetData output exceeds its captured huge span",
            ));
        }
        if selectors
            .allocation_size(self.start.selector())
            .map_err(crate::runtime_error)?
            != self.allocation_size
            || resolve_dde_huge_chunks_with_selectors(
                selectors,
                memory,
                self.start,
                self.length,
                self.allocation_size,
            )? != self.chunks
        {
            return Err(RuntimeError::new(
                Kind::GuestFault,
                "Win16 DDE GetData huge output allocation changed while suspended",
            ));
        }
        self.transactional.is_live_with_selectors(selectors, memory)?;
        commit_guest_writes_with_selectors(selectors, memory, vec![(self.transactional.clone(), bytes)])
    }
}

fn resolve_dde_huge_chunks(
    state: &Win16State,
    memory: &Memory,
    start: SegmentedPointer,
    length: usize,
    allocation_size: u32,
) -> Result<Vec<DdeHugeRangeChunk>, RuntimeError> {
    resolve_dde_huge_chunks_with_selectors(&state.selectors, memory, start, length, allocation_size)
}

fn resolve_dde_huge_chunks_with_selectors(
    selectors: &SelectorTable,
    memory: &Memory,
    start: SegmentedPointer,
    length: usize,
    allocation_size: u32,
) -> Result<Vec<DdeHugeRangeChunk>, RuntimeError> {
    let initial = selectors
        .describe(start.selector())
        .map_err(crate::runtime_error)?;
    let start_offset = u64::try_from(initial.segment_index)
        .ok()
        .and_then(|index| index.checked_mul(0x1_0000))
        .and_then(|offset| offset.checked_add(u64::from(start.offset())))
        .ok_or_else(|| invariant("DDE huge output start offset overflowed"))?;
    let end = start_offset
        .checked_add(u64::try_from(length).map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "DDE huge output length exceeds host address width",
            )
        })?)
        .ok_or_else(|| invariant("DDE huge output end offset overflowed"))?;
    if end > u64::from(allocation_size) {
        return Err(RuntimeError::new(
            Kind::GuestFault,
            "DDE GetData huge output exceeds its selector allocation",
        ));
    }
    let mut chunks = Vec::new();
    let maximum = length
        .checked_div(0x1_0000)
        .and_then(|count| count.checked_add(2))
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "DDE huge output segment plan overflowed",
            )
        })?;
    chunks.try_reserve_exact(maximum).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve DDE huge output selector plan",
            error,
        )
    })?;
    let mut consumed = 0usize;
    while consumed < length {
        let delta = u32::try_from(consumed).map_err(|_| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "DDE huge output offset exceeds DWORD",
            )
        })?;
        let pointer = selectors
            .add_bytes(start, delta)
            .map_err(crate::runtime_error)?;
        let descriptor = selectors
            .describe(pointer.selector())
            .map_err(crate::runtime_error)?;
        let segment_delta = (usize::from(start.offset()) + consumed) / 0x1_0000;
        let expected_segment = initial
            .segment_index
            .checked_add(segment_delta)
            .ok_or_else(|| invariant("DDE huge output segment index overflowed"))?;
        let expected_base = u64::from(initial.base.0)
            .checked_sub(
                u64::try_from(initial.segment_index)
                    .ok()
                    .and_then(|index| index.checked_mul(0x1_0000))
                    .ok_or_else(|| invariant("DDE huge output base is invalid"))?,
            )
            .and_then(|base| {
                u64::try_from(expected_segment)
                    .ok()
                    .and_then(|index| index.checked_mul(0x1_0000))
                    .and_then(|offset| base.checked_add(offset))
            })
            .ok_or_else(|| invariant("DDE huge output selector base overflowed"))?;
        if pointer.selector().generation() != start.selector().generation()
            || descriptor.segment_index != expected_segment
            || descriptor.segment_count != initial.segment_count
            || selectors
                .allocation_size(pointer.selector())
                .map_err(crate::runtime_error)?
                != allocation_size
            || u64::from(descriptor.base.0) != expected_base
        {
            return Err(invariant(
                "DDE huge output crossed a different selector allocation",
            ));
        }
        let remaining = usize::try_from(descriptor.limit)
            .ok()
            .and_then(|limit| limit.checked_add(1))
            .and_then(|limit| limit.checked_sub(usize::from(pointer.offset())))
            .filter(|remaining| *remaining != 0)
            .ok_or_else(|| {
                RuntimeError::new(Kind::GuestFault, "DDE huge output selector span is invalid")
            })?;
        let amount = remaining.min(length - consumed);
        let address = selectors
            .translate(pointer, Access::Write, amount, memory)
            .map_err(crate::runtime_error)?;
        memory
            .validate_read(address, amount)
            .map_err(crate::runtime_error)?;
        memory
            .validate_write(address, amount)
            .map_err(crate::runtime_error)?;
        chunks.push(DdeHugeRangeChunk {
            selector: pointer.selector(),
            descriptor,
            offset: pointer.offset(),
            address,
            logical_offset: consumed,
            length: amount,
        });
        consumed = consumed
            .checked_add(amount)
            .ok_or_else(|| invariant("DDE huge output copied length overflowed"))?;
    }
    Ok(chunks)
}

fn invariant(message: &'static str) -> RuntimeError {
    super::invariant(message)
}
