//! Local-memory APIs operate on the caller's checked Win16 data segment.

use guest_core::{PhysAddr, Selector};
use guest_core::memory::Memory;
use win16_abi::{Access, LocalHeapInitError, SegmentedPointer, prepare_local_heap_init};
use win16_abi::local_heap::{LocalHeap, LocalHeapEntry, LocalHeapError};
use std::ops::Range;

use super::Win16State;
use crate::{DiagnosticKind as Kind, RuntimeError};

// A Win16 local pointer has a WORD offset within one data segment.
const LOCAL_SEGMENT_BYTES: usize = 0x1_0000;
const LMEM_INVALID_HANDLE: u16 = 0x8000;

pub(super) enum LocalOperation {
    Alloc { flags: u16, size: u16 },
    ReAlloc { handle: u16, size: u16, flags: u16 },
    Free { handle: u16 },
    Lock { handle: u16 },
    Unlock { handle: u16 },
    Size { handle: u16 },
    Handle { offset: u16 },
    Flags { handle: u16 },
    Compact { minimum: u16 },
    HandleDelta { delta: u16 },
    CountFree,
    HeapSize,
    AtomInit { buckets: i16 },
    AtomAdd { name: Vec<u8>, matching_atom: Option<u16>, hash: u32 },
    AtomDelete { atom: u16 },
    AtomHandle { atom: u16 },
}

impl LocalOperation {
    fn name(&self) -> &'static str {
        match self {
            Self::Alloc { .. } => "LocalAlloc",
            Self::ReAlloc { .. } => "LocalReAlloc",
            Self::Free { .. } => "LocalFree",
            Self::Lock { .. } => "LocalLock",
            Self::Unlock { .. } => "LocalUnlock",
            Self::Size { .. } => "LocalSize",
            Self::Handle { .. } => "LocalHandle",
            Self::Flags { .. } => "LocalFlags",
            Self::Compact { .. } => "LocalCompact",
            Self::HandleDelta { .. } => "LocalHandleDelta",
            Self::CountFree => "LocalCountFree",
            Self::HeapSize => "LocalHeapSize",
            Self::AtomInit { .. } => "InitAtomTable",
            Self::AtomAdd { .. } => "AddAtom",
            Self::AtomDelete { .. } => "DeleteAtom",
            Self::AtomHandle { .. } => "GetAtomHandle",
        }
    }

    fn changes_heap(&self) -> bool {
        if let Self::HandleDelta { delta } = self {
            return *delta != 0;
        }
        matches!(self, Self::Alloc { .. } | Self::ReAlloc { .. } | Self::Free { .. }
            | Self::Lock { .. } | Self::Unlock { .. } | Self::Compact { .. }
            | Self::AtomInit { .. } | Self::AtomAdd { .. } | Self::AtomDelete { .. })
    }

    fn failed_result(&self) -> u16 {
        match self {
            Self::Free { handle } => *handle,
            Self::AtomDelete { atom } => *atom,
            // LMEM_INVALID_HANDLE is the LocalFlags failure value.
            Self::Flags { .. } => LMEM_INVALID_HANDLE,
            _ => 0,
        }
    }

    pub(super) fn execute(&self, heap: &mut LocalHeap<'_>) -> Result<u16, LocalHeapError> {
        match *self {
            Self::Alloc { flags, size } => heap.alloc(flags, size),
            Self::ReAlloc { handle, size, flags } => heap.realloc(handle, size, flags),
            Self::Free { handle } => heap.free(handle),
            Self::Lock { handle } => heap.lock(handle),
            Self::Unlock { handle } => heap.unlock(handle),
            Self::Size { handle } => heap.size(handle),
            Self::Handle { offset } => heap.handle(offset),
            Self::Flags { handle } => heap.flags(handle),
            Self::Compact { minimum } => heap.compact(minimum),
            Self::HandleDelta { delta } => heap.handle_delta(delta),
            Self::CountFree => heap.count_free(),
            Self::HeapSize => heap.heap_size(),
            Self::AtomInit { buckets } => heap.atom_init(buckets),
            Self::AtomAdd { ref name, matching_atom, hash } => {
                heap.atom_add(name, matching_atom, hash)
            }
            Self::AtomDelete { atom } => heap.atom_delete(atom),
            Self::AtomHandle { atom } => heap.atom_handle(atom),
        }
    }

    fn growth_request(&self, heap: &LocalHeap<'_>) -> Result<Option<u16>, LocalHeapError> {
        // LMEM_MODIFY changes attributes, and a zero/null/invalid request
        // cannot become valid by extending the data segment.
        const LMEM_MODIFY: u16 = 0x0080;
        // SDK LocalAlloc: zero-sized movable blocks still need a handle-table
        // slot. Expanding that guest-resident table may require heap growth.
        const LMEM_MOVEABLE: u16 = 0x0002;
        Ok(match *self {
            Self::Alloc { flags, size } if size != 0 || flags & LMEM_MOVEABLE != 0 => Some(size.max(1)),
            Self::ReAlloc { handle, size, flags }
                if handle != 0 && size != 0 && flags & LMEM_MODIFY == 0
                    && heap.flags(handle)? != LMEM_INVALID_HANDLE => Some(size),
            Self::AtomInit { buckets } => heap.atom_allocation_size(Some(buckets), None)?,
            Self::AtomAdd { ref name, matching_atom: None, .. } => {
                heap.atom_allocation_size(None, Some(name.len()))?
            }
            _ => None,
        })
    }
}

impl Win16State {
    /// Detect an initialized local heap in an arbitrary global block. Ordinary
    /// data may contain any bytes, including a nonzero word at the instance
    /// header offset; that alone does not establish a damaged local heap.
    pub(super) fn toolhelp_local_heap_present(
        &self, selector: u16, memory: &Memory,
    ) -> Result<bool, RuntimeError> {
        let Ok(reference) = self.selectors.reference(Selector(selector)) else { return Ok(false); };
        let descriptor = self.selectors.describe(reference).map_err(crate::runtime_error)?;
        if !descriptor.rights.readable() || !descriptor.rights.writable()
            || u64::from(descriptor.limit) + 1 > LOCAL_SEGMENT_BYTES as u64
        {
            return Ok(false);
        }
        let (_, mut bytes) = self.local_segment(selector, false, memory)?;
        Ok(LocalHeap::open(&mut bytes).is_ok())
    }

    /// Snapshot a guest local heap identified by either its selector or its
    /// Win16 global handle. An invalid/uninitialized heap is a normal absence;
    /// malformed initialized metadata remains a guest fault.
    pub(super) fn toolhelp_local_heap_entries(
        &self,
        requested_heap: u16,
        memory: &Memory,
    ) -> Result<Option<(u16, Vec<LocalHeapEntry>)>, RuntimeError> {
        let selector = if requested_heap == 0 {
            self.instance_selector.raw().0
        } else {
            let global_selector = self.toolhelp_global_handle_to_sel(requested_heap);
            if global_selector != 0 {
                global_selector
            } else if self.selectors.reference(Selector(requested_heap)).is_ok() {
                requested_heap
            } else {
                return Ok(None);
            }
        };
        let Ok(reference) = self.selectors.reference(Selector(selector)) else {
            return Ok(None);
        };
        let descriptor = self.selectors.describe(reference).map_err(crate::runtime_error)?;
        if !descriptor.rights.readable() || !descriptor.rights.writable()
            || u64::from(descriptor.limit) + 1 > LOCAL_SEGMENT_BYTES as u64
        {
            return Ok(None);
        }
        let (_, mut bytes) = self.local_segment(selector, false, memory)?;
        match LocalHeap::open(&mut bytes) {
            Ok(heap) => Ok(Some((selector, heap.snapshot_entries().map_err(|error|
                RuntimeError::with_source(Kind::GuestFault,
                    format!("snapshot Win16 local heap in selector 0x{selector:04X}"), error))?))),
            Err(LocalHeapError::Uninitialized) => Ok(None),
            Err(LocalHeapError::OutOfMemory) => Err(RuntimeError::new(Kind::ResourceExhausted,
                "Win16 local heap snapshot could not reserve temporary storage")),
            Err(error) => Err(RuntimeError::with_source(Kind::GuestFault,
                format!("validate Win16 local heap in selector 0x{selector:04X}"), error)),
        }
    }

    pub(super) fn local_operation(
        &mut self,
        caller_ds: u16,
        operation: LocalOperation,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        let (address, length) = self.local_segment_range(caller_ds, operation.changes_heap(), memory)?;
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(length).is_err() {
            return Ok(u32::from(operation.failed_result()));
        }
        bytes.resize(length, 0);
        memory.read_physical(address, &mut bytes).map_err(crate::runtime_error)?;
        let mut heap = match LocalHeap::open(&mut bytes) {
            Ok(heap) => heap,
            Err(error) => {
                return match error {
                    LocalHeapError::Uninitialized | LocalHeapError::OutOfMemory => {
                        Ok(u32::from(operation.failed_result()))
                    }
                    error => {
                        let kind = if matches!(error, LocalHeapError::CallbackRequired) {
                            Kind::CompatibilityGap
                        } else {
                            Kind::GuestFault
                        };
                        Err(RuntimeError::with_source(kind,
                            format!("Win16 {} in data segment 0x{caller_ds:04X}", operation.name()), error))
                    }
                };
            }
        };
        let mut result = operation.execute(&mut heap);
        if matches!(&result, Ok(0)) && operation.growth_request(&heap).map_err(|error|
            RuntimeError::with_source(Kind::GuestFault,
                "validate local heap retained-tail request", error))?.is_some() {
            match heap.reclaim_reserved_tail() {
                Ok(true) => result = operation.execute(&mut heap),
                Ok(false) | Err(LocalHeapError::OutOfMemory) => {}
                Err(error) => return Err(RuntimeError::with_source(Kind::GuestFault,
                    "re-admit a previously shrunken local heap tail", error)),
            }
        }
        let growth_request = if matches!(&result, Ok(0)) {
            operation.growth_request(&heap).map_err(|error|
                RuntimeError::with_source(Kind::GuestFault,
                    "validate Win16 local-memory growth request", error))?
        } else { None };
        let write_spans = heap.take_write_spans();
        drop(heap);
        if let Some(requested) = growth_request {
            if let Some(value) = self.try_grow_local_operation(address, &bytes,
                &write_spans, &operation, requested, memory)? {
                return Ok(u32::from(value));
            }
        }
        let value = match result {
            Ok(value) => {
                // An API can return zero after a successful heap transaction,
                // such as freeing via LocalReAlloc(size = 0), and failed
                // allocation attempts can still commit heap compaction. The
                // transaction result, not AX, determines whether to write back.
                if operation.changes_heap() {
                    commit_local_spans(memory, address, &bytes, &write_spans)?;
                }
                value
            }
            // No heap and allocation pressure are ordinary API failures;
            // the transaction copy is discarded and no guest bytes change.
            Err(LocalHeapError::Uninitialized | LocalHeapError::OutOfMemory) => {
                operation.failed_result()
            }
            Err(error) => {
                let kind = if matches!(error, LocalHeapError::CallbackRequired) {
                    Kind::CompatibilityGap
                } else {
                    Kind::GuestFault
                };
                return Err(RuntimeError::with_source(kind,
                    format!("Win16 {} in data segment 0x{caller_ds:04X}", operation.name()), error));
            }
        };
        // Win16 LocalLock callers consume a near pointer in AX. This bridge's
        // wide gate also supplies DS in DX for a successful lock; that extra
        // high word is not required by the public near-pointer contract.
        // Keep failure fully null for consumers of the gate's full DWORD.
        Ok(if value != 0 && matches!(operation, LocalOperation::Lock { .. }) {
            (u32::from(caller_ds) << 16) | u32::from(value)
        } else {
            u32::from(value)
        })
    }

    pub(super) fn local_init(
        &self,
        selector: u16,
        caller_ds: u16,
        start: u16,
        end: u16,
        memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let selector = if selector == 0 { caller_ds } else { selector };
        // An invalid LocalInit target is an API failure, not a memory access.
        let Ok(reference) = self.selectors.reference(Selector(selector)) else {
            return Ok(0);
        };
        let descriptor = self.selectors.describe(reference).map_err(crate::runtime_error)?;
        if !descriptor.rights.readable() || !descriptor.rights.writable()
            || u64::from(descriptor.limit) + 1 > LOCAL_SEGMENT_BYTES as u64
        {
            return Ok(0);
        }
        let (address, segment_bytes) = self.local_segment_range(selector, true, memory)?;
        let plan = match prepare_local_heap_init(segment_bytes, start, end) {
            Ok(plan) => plan,
            // LocalInit reports an unusable range as FALSE. It has not
            // changed either the existing heap or the instance header.
            Err(LocalHeapInitError::InvalidSegmentLength { .. }
                | LocalHeapInitError::RangeOutsideDgroup { .. }
                | LocalHeapInitError::ReserveOutsideDgroup { .. }
                | LocalHeapInitError::HeapRangeTooSmall) => return Ok(0),
            Err(error) => return Err(RuntimeError::with_source(Kind::InternalInvariant,
                "prepare Win16 local heap", error)),
        };
        commit_local_init(memory, address, segment_bytes, &plan)?;
        Ok(1)
    }

    /// Take a bounded transaction copy. Local-heap metadata remains in guest
    /// memory, so a DLL's DS, selector aliases, and guest-written data all see
    /// the same heap. There is no second host handle table to go stale.
    pub(super) fn local_segment(
        &self,
        selector: u16,
        writable: bool,
        memory: &Memory,
    ) -> Result<(PhysAddr, Vec<u8>), RuntimeError> {
        let (address, length) = self.local_segment_range(selector, writable, memory)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|error|
            RuntimeError::with_source(Kind::ResourceExhausted,
                "allocate Win16 local heap transaction", error))?;
        bytes.resize(length, 0);
        memory.read_physical(address, &mut bytes).map_err(crate::runtime_error)?;
        Ok((address, bytes))
    }

    fn local_segment_range(
        &self,
        selector: u16,
        writable: bool,
        memory: &Memory,
    ) -> Result<(PhysAddr, usize), RuntimeError> {
        let reference = self.selectors.reference(Selector(selector))
            .map_err(crate::runtime_error)?;
        let descriptor = self.selectors.describe(reference).map_err(crate::runtime_error)?;
        let length = usize::try_from(u64::from(descriptor.limit) + 1)
            .ok().filter(|length| *length <= LOCAL_SEGMENT_BYTES)
            .ok_or_else(|| RuntimeError::new(Kind::GuestFault,
                "Win16 local heap data segment exceeds the 16-bit address space"))?;
        let pointer = SegmentedPointer::new(reference, 0);
        let address = self.selectors.translate(pointer, Access::Read, length, memory)
            .map_err(crate::runtime_error)?;
        if writable {
            self.selectors.translate(pointer, Access::Write, length, memory)
                .map_err(crate::runtime_error)?;
        }
        // Local heaps require ordinary RAM. A selector into a device aperture
        // must not turn a metadata read into device access or a heap write.
        memory.validate_ram_range(address, length, writable).map_err(crate::runtime_error)?;
        Ok((address, length))
    }
}

pub(super) fn commit_local_spans(
    memory: &mut Memory,
    address: PhysAddr,
    bytes: &[u8],
    spans: &[Range<usize>],
) -> Result<(), RuntimeError> {
    memory.validate_ram_range(address, bytes.len(), true).map_err(crate::runtime_error)?;
    for span in spans {
        let source = bytes.get(span.clone()).ok_or_else(||
            RuntimeError::new(Kind::InternalInvariant,
                format!("Win16 local-heap write span {}..{} exceeds its transaction buffer", span.start, span.end)))?;
        let write_address = segment_offset_address(address, span.start)?;
        memory.validate_ram_range(write_address, source.len(), true).map_err(crate::runtime_error)?;
    }
    for span in spans {
        let source = bytes.get(span.clone()).ok_or_else(||
            RuntimeError::new(Kind::InternalInvariant,
                format!("Win16 local-heap write span {}..{} exceeds its transaction buffer", span.start, span.end)))?;
        memory.write_physical(segment_offset_address(address, span.start)?, source)
            .map_err(crate::runtime_error)?;
    }
    Ok(())
}

fn commit_local_init(
    memory: &mut Memory,
    address: PhysAddr,
    segment_bytes: usize,
    plan: &win16_abi::LocalHeapInitPlan,
) -> Result<(), RuntimeError> {
    memory.validate_ram_range(address, segment_bytes, true).map_err(crate::runtime_error)?;
    for patch in plan.writes() {
        let start = usize::from(patch.offset());
        let end = start.checked_add(patch.bytes().len()).ok_or_else(||
            RuntimeError::with_source(Kind::InternalInvariant,
                "validate prepared Win16 local heap patch",
                LocalHeapInitError::InvalidPreparedPlan))?;
        if end > segment_bytes {
            return Err(RuntimeError::with_source(Kind::InternalInvariant,
                "validate prepared Win16 local heap patch",
                LocalHeapInitError::InvalidPreparedPlan));
        }
        memory.validate_ram_range(segment_offset_address(address, start)?, patch.bytes().len(), true)
            .map_err(crate::runtime_error)?;
    }
    for patch in plan.writes() {
        memory.write_physical(segment_offset_address(address, usize::from(patch.offset()))?, patch.bytes())
            .map_err(crate::runtime_error)?;
    }
    Ok(())
}

fn segment_offset_address(address: PhysAddr, offset: usize) -> Result<PhysAddr, RuntimeError> {
    let offset = u32::try_from(offset).map_err(|_| RuntimeError::new(Kind::InternalInvariant,
        "Win16 local-segment offset exceeds the physical-address width"))?;
    address.0.checked_add(offset).map(PhysAddr).ok_or_else(||
        RuntimeError::new(Kind::InternalInvariant,
            "Win16 local-segment physical address overflowed"))
}

#[cfg(test)]
#[path = "win16_local_handle_delta_tests.rs"]
mod handle_delta_tests;

#[cfg(test)]
#[path = "win16_local_realloc_zero_tests.rs"]
mod realloc_zero_tests;
