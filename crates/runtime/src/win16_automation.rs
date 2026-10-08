//! Guest-owned Win16 Automation allocations and checked record marshaling.
//!
//! BSTR and SAFEARRAY FAR values remain guest addresses. This module stores
//! their bytes in the shared guest heap and retains exact allocator handles
//! for release and task teardown; it never casts a guest address to a host
//! pointer or native Automation structure.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use compat_services::automation::{
    AutomationAbiError, BstrAllocation16, SAFEARRAY16_HEADER_SIZE, SafeArray16, bstr_prefix_far,
};
use guest_core::{GuestMemory, OwnerId, memory::Memory};
use win16_abi::{
    Access, AllocationFlags, GlobalHandle, GlobalHeap, SegmentedPointer, SelectorTable,
};

use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError};

mod bstr;
mod guest_ops;
mod ownership;
mod safe_array;
use guest_ops::AutomationInterfaceAction;
pub(crate) use guest_ops::Win16AutomationGuestResult;

const MAX_AUTOMATION_ALLOCATION: usize = 1 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AllocationKind {
    Bstr,
    SafeArrayDescriptor,
    SafeArrayData,
}

#[derive(Clone, Debug)]
struct GuestAllocation {
    owner: OwnerId,
    handle: GlobalHandle,
    kind: AllocationKind,
    retirement_cause: Option<Arc<RuntimeError>>,
}

/// Runtime bookkeeping for Automation memory returned to Win16 callers.
///
/// Every allocation is in `GlobalHeap`, uses the caller's task owner, and is
/// freed with its retained generation. The key is the public guest FAR value,
/// not a native pointer.
#[derive(Debug, Default)]
pub(crate) struct Win16AutomationState {
    allocations: BTreeMap<u32, GuestAllocation>,
}

fn read_safe_array_descriptor(
    selectors: &SelectorTable,
    memory: &Memory,
    far: u32,
) -> Result<(SegmentedPointer, SafeArray16), RuntimeError> {
    if far == 0 {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 SAFEARRAY FAR value is null",
        ));
    }
    let pointer = selectors
        .pointer_from_far(far)
        .map_err(crate::runtime_error)?;
    let prefix = read_guest_far_bytes(selectors, memory, pointer, SAFEARRAY16_HEADER_SIZE)?;
    let dimensions = u16::from_le_bytes([prefix[0], prefix[1]]);
    if dimensions == 0 {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 SAFEARRAY has no dimensions",
        ));
    }
    let bounds_bytes = usize::from(dimensions).checked_mul(8).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 SAFEARRAY bound list length overflows",
        )
    })?;
    let descriptor_length = SAFEARRAY16_HEADER_SIZE
        .checked_add(bounds_bytes)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 SAFEARRAY descriptor length overflows",
            )
        })?;
    if descriptor_length > MAX_AUTOMATION_ALLOCATION {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 SAFEARRAY descriptor exceeds the bounded copy size",
        ));
    }
    let descriptor_bytes = read_guest_far_bytes(selectors, memory, pointer, descriptor_length)?;
    let descriptor = SafeArray16::decode(&descriptor_bytes).map_err(array_abi_error)?;
    Ok((pointer, descriptor))
}

fn write_safe_array_descriptor(
    selectors: &SelectorTable,
    memory: &mut Memory,
    pointer: SegmentedPointer,
    descriptor: &SafeArray16,
) -> Result<(), RuntimeError> {
    let bytes = descriptor.encode().map_err(array_abi_error)?;
    write_guest_far_bytes(selectors, memory, pointer, &bytes)
}

fn allocate_guest_bytes(
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    bytes: &[u8],
) -> Result<(GlobalHandle, SegmentedPointer), RuntimeError> {
    allocate_guest_bytes_with_span(
        heap,
        selectors,
        memory,
        owner,
        bytes,
        GuestAllocationSpan::Far,
    )
}

fn allocate_safe_array_data_bytes(
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    bytes: &[u8],
) -> Result<(GlobalHandle, SegmentedPointer), RuntimeError> {
    allocate_guest_bytes_with_span(
        heap,
        selectors,
        memory,
        owner,
        bytes,
        GuestAllocationSpan::SafeArrayData,
    )
}

#[derive(Clone, Copy)]
enum GuestAllocationSpan {
    Far,
    SafeArrayData,
}

fn allocate_guest_bytes_with_span(
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    bytes: &[u8],
    span: GuestAllocationSpan,
) -> Result<(GlobalHandle, SegmentedPointer), RuntimeError> {
    if bytes.is_empty() || bytes.len() > MAX_AUTOMATION_ALLOCATION {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 Automation guest allocation has an invalid or excessive size",
        ));
    }
    if matches!(span, GuestAllocationSpan::Far) && bytes.len() > 0x1_0000 {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 Automation FAR allocation exceeds one selector",
        ));
    }
    let size = u32::try_from(bytes.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "Win16 Automation allocation exceeds guest heap range",
            error,
        )
    })?;
    let handle = heap
        .alloc(memory, owner, size, AllocationFlags::fixed())
        .map_err(crate::runtime_error)?;
    let base = match heap.lock(handle, selectors, memory) {
        Ok(pointer) => pointer,
        Err(error) => {
            heap.free_on_teardown(handle, selectors)
                .map_err(crate::runtime_error)?;
            return Err(crate::runtime_error(error));
        }
    };
    let write_result = match span {
        GuestAllocationSpan::Far => write_guest_far_bytes(selectors, memory, base, bytes),
        GuestAllocationSpan::SafeArrayData => {
            write_safe_array_huge_bytes(selectors, memory, base, bytes)
        }
    };
    if let Err(error) = write_result {
        let cleanup = match heap.unlock(handle, selectors) {
            Ok(_) => free_untracked_allocation(heap, selectors, handle),
            Err(_) => heap
                .free_on_teardown(handle, selectors)
                .map_err(crate::runtime_error),
        };
        cleanup.map_err(|cleanup| {
            RuntimeError::with_source(
                Kind::InternalInvariant,
                format!("Automation guest write failed ({error}) and its untracked allocation rollback also failed"),
                cleanup,
            )
        })?;
        return Err(error);
    }
    if let Err(error) = heap.unlock(handle, selectors).map_err(crate::runtime_error) {
        heap.free_on_teardown(handle, selectors)
            .map_err(crate::runtime_error)
            .map_err(|cleanup| {
                RuntimeError::with_source(
                    Kind::InternalInvariant,
                    format!("Automation allocation unlock failed ({error}) and teardown rollback also failed"),
                    cleanup,
                )
            })?;
        return Err(error);
    }
    Ok((handle, base))
}

fn free_untracked_allocation(
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    handle: GlobalHandle,
) -> Result<(), RuntimeError> {
    match heap.free(handle, selectors) {
        Ok(()) => Ok(()),
        Err(free_error) => match heap.free_on_teardown(handle, selectors) {
            Ok(()) => Ok(()),
            Err(teardown_error) => Err(RuntimeError::with_source(
                Kind::InternalInvariant,
                format!(
                    "untracked Automation allocation rollback failed after normal free reported {free_error}"
                ),
                crate::runtime_error(teardown_error),
            )),
        },
    }
}

/// Read `SAFEARRAY::pvData` as a checked huge span. A historical Win16
/// implementation advances SAFEARRAY data by 64 KiB selector steps. The
/// Windows 3.1 SDK defines no separate OLE2 huge-span contract, so this
/// compatibility rule is limited to `pvData`.
pub(super) fn read_safe_array_huge_bytes(
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
    pointer: SegmentedPointer,
    length: usize,
) -> Result<Vec<u8>, RuntimeError> {
    let chunks = checked_safe_array_huge_chunks(selectors, memory, pointer, length, Access::Read)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate Win16 SAFEARRAY huge-span copy",
            error,
        )
    })?;
    bytes.resize(length, 0);
    let mut offset = 0;
    for (chunk_pointer, chunk_length) in chunks {
        selectors
            .read(
                memory,
                chunk_pointer,
                &mut bytes[offset..offset + chunk_length],
            )
            .map_err(crate::runtime_error)?;
        offset += chunk_length;
    }
    Ok(bytes)
}

fn write_safe_array_huge_bytes(
    selectors: &SelectorTable,
    memory: &mut Memory,
    pointer: SegmentedPointer,
    bytes: &[u8],
) -> Result<(), RuntimeError> {
    let chunks =
        checked_safe_array_huge_chunks(selectors, memory, pointer, bytes.len(), Access::Write)?;
    let mut offset = 0;
    for (chunk_pointer, chunk_length) in chunks {
        selectors
            .write(memory, chunk_pointer, &bytes[offset..offset + chunk_length])
            .map_err(crate::runtime_error)?;
        offset += chunk_length;
    }
    Ok(())
}

fn checked_safe_array_huge_chunks(
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
    start: SegmentedPointer,
    length: usize,
    access: Access,
) -> Result<Vec<(SegmentedPointer, usize)>, RuntimeError> {
    if length > MAX_AUTOMATION_ALLOCATION {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 SAFEARRAY huge span exceeds the bounded copy size",
        ));
    }
    if length == 0 {
        return Ok(Vec::new());
    }
    let start_descriptor = selectors
        .describe(start.selector())
        .map_err(crate::runtime_error)?;
    let allocation_size = selectors
        .allocation_size(start.selector())
        .map_err(crate::runtime_error)?;
    let start_offset = u64::try_from(start_descriptor.segment_index)
        .ok()
        .and_then(|index| index.checked_mul(0x1_0000))
        .and_then(|offset| offset.checked_add(u64::from(start.offset())))
        .ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted, "SAFEARRAY data offset overflows")
        })?;
    let end_offset = start_offset
        .checked_add(u64::try_from(length).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "SAFEARRAY data span exceeds guest allocation range",
                error,
            )
        })?)
        .ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted, "SAFEARRAY data span overflows")
        })?;
    if end_offset > u64::from(allocation_size) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 SAFEARRAY pvData span exceeds its selector allocation",
        ));
    }

    let mut chunks = Vec::new();
    let last_byte_offset = u64::from(start.offset())
        .checked_add(u64::try_from(length - 1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "SAFEARRAY selector-span length exceeds guest range",
                error,
            )
        })?)
        .ok_or_else(|| {
            RuntimeError::new(Kind::ResourceExhausted, "SAFEARRAY span offset overflows")
        })?;
    let max_chunks = usize::try_from(last_byte_offset / 0x1_0000 + 1).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "SAFEARRAY selector-span plan exceeds host range",
            error,
        )
    })?;
    chunks.try_reserve_exact(max_chunks).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate Win16 SAFEARRAY selector-span plan",
            error,
        )
    })?;
    let mut consumed = 0_usize;
    while consumed < length {
        let delta = u32::try_from(consumed).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "SAFEARRAY selector offset exceeds guest range",
                error,
            )
        })?;
        let pointer = selectors
            .add_bytes(start, delta)
            .map_err(crate::runtime_error)?;
        let descriptor = selectors
            .describe(pointer.selector())
            .map_err(crate::runtime_error)?;
        let segment_delta = consumed / 0x1_0000
            + usize::from(start.offset()).saturating_add(consumed % 0x1_0000) / 0x1_0000;
        let expected_segment = start_descriptor
            .segment_index
            .checked_add(segment_delta)
            .ok_or_else(|| {
                RuntimeError::new(Kind::ResourceExhausted, "SAFEARRAY segment index overflows")
            })?;
        let expected_base = u64::from(start_descriptor.base.0)
            .checked_sub(
                u64::try_from(start_descriptor.segment_index)
                    .ok()
                    .and_then(|index| index.checked_mul(0x1_0000))
                    .ok_or_else(|| {
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "SAFEARRAY starting selector has an invalid block offset",
                        )
                    })?,
            )
            .and_then(|base| {
                u64::try_from(expected_segment)
                    .ok()
                    .and_then(|index| index.checked_mul(0x1_0000))
                    .and_then(|offset| base.checked_add(offset))
            })
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "SAFEARRAY allocation base is inconsistent",
                )
            })?;
        if pointer.selector().generation() != start.selector().generation()
            || descriptor.segment_index != expected_segment
            || descriptor.segment_count != start_descriptor.segment_count
            || descriptor.base.0 != u32::try_from(expected_base).unwrap_or(u32::MAX)
            || selectors
                .allocation_size(pointer.selector())
                .map_err(crate::runtime_error)?
                != allocation_size
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 SAFEARRAY huge span changed selector allocation identity",
            ));
        }
        let pointer_offset = usize::from(pointer.offset());
        let descriptor_remaining = usize::try_from(descriptor.limit)
            .ok()
            .and_then(|limit| limit.checked_add(1))
            .and_then(|limit| limit.checked_sub(pointer_offset))
            .ok_or_else(|| {
                RuntimeError::new(Kind::InvalidInput, "SAFEARRAY selector span is invalid")
            })?;
        let chunk_length = descriptor_remaining.min(length - consumed);
        if chunk_length == 0 {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 SAFEARRAY huge span has an empty selector chunk",
            ));
        }
        selectors
            .translate(pointer, access, chunk_length, memory)
            .map_err(crate::runtime_error)?;
        chunks.push((pointer, chunk_length));
        consumed += chunk_length;
    }
    Ok(chunks)
}

fn read_guest_far_bytes(
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
    pointer: SegmentedPointer,
    length: usize,
) -> Result<Vec<u8>, RuntimeError> {
    if length > MAX_AUTOMATION_ALLOCATION {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 Automation guest read exceeds the bounded copy size",
        ));
    }
    selectors
        .translate(pointer, Access::Read, length, memory)
        .map_err(crate::runtime_error)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "allocate Win16 Automation guest copy",
            error,
        )
    })?;
    bytes.resize(length, 0);
    selectors
        .read(memory, pointer, &mut bytes)
        .map_err(crate::runtime_error)?;
    Ok(bytes)
}

fn write_guest_far_bytes(
    selectors: &SelectorTable,
    memory: &mut Memory,
    pointer: SegmentedPointer,
    bytes: &[u8],
) -> Result<(), RuntimeError> {
    if bytes.len() > MAX_AUTOMATION_ALLOCATION {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 Automation guest write exceeds the bounded copy size",
        ));
    }
    selectors
        .translate(pointer, Access::Write, bytes.len(), memory)
        .map_err(crate::runtime_error)?;
    selectors
        .write(memory, pointer, bytes)
        .map_err(crate::runtime_error)
}

pub(super) fn validate_guest_far_range(
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
    far: u32,
    length: usize,
    access: Access,
) -> Result<(), RuntimeError> {
    if length > MAX_AUTOMATION_ALLOCATION {
        return Err(RuntimeError::new(
            Kind::ResourceExhausted,
            "Win16 Automation FAR range exceeds the bounded access size",
        ));
    }
    let pointer = selectors
        .pointer_from_far(far)
        .map_err(crate::runtime_error)?;
    selectors
        .translate(pointer, access, length, memory)
        .map(|_| ())
        .map_err(crate::runtime_error)
}

fn validate_array_data(descriptor: &SafeArray16, actual_length: usize) -> Result<(), RuntimeError> {
    let expected = expected_array_data_length(descriptor)?;
    if expected != actual_length {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 SAFEARRAY data length does not match its bounds and element size",
        ));
    }
    Ok(())
}

fn validate_readable_range(
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
    far: u32,
    length: usize,
) -> Result<(), RuntimeError> {
    validate_guest_far_range(selectors, memory, far, length, Access::Read)
}

fn expected_array_data_length(descriptor: &SafeArray16) -> Result<usize, RuntimeError> {
    if descriptor.dimensions == 0 || usize::from(descriptor.dimensions) != descriptor.bounds.len() {
        return Err(array_abi_error(
            AutomationAbiError::InvalidSafeArrayDimensions,
        ));
    }
    if descriptor.element_size == 0 {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 SAFEARRAY element size is zero",
        ));
    }
    let elements = descriptor
        .bounds
        .iter()
        .try_fold(1_usize, |count, bound| {
            count.checked_mul(usize::try_from(bound.elements).ok()?)
        })
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 SAFEARRAY element count overflows host address space",
            )
        })?;
    elements
        .checked_mul(usize::from(descriptor.element_size))
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 SAFEARRAY byte length overflows host address space",
            )
        })
}

fn bstr_abi_error(error: AutomationAbiError) -> RuntimeError {
    let kind = match error {
        AutomationAbiError::AllocationFailed | AutomationAbiError::LengthOverflow => {
            Kind::ResourceExhausted
        }
        _ => Kind::InvalidInput,
    };
    RuntimeError::with_source(
        kind,
        format!("invalid Win16 BSTR allocation image: {error}"),
        error,
    )
}

fn array_abi_error(error: AutomationAbiError) -> RuntimeError {
    let kind = match error {
        AutomationAbiError::AllocationFailed | AutomationAbiError::LengthOverflow => {
            Kind::ResourceExhausted
        }
        _ => Kind::InvalidInput,
    };
    RuntimeError::with_source(
        kind,
        format!("invalid Win16 SAFEARRAY descriptor: {error}"),
        error,
    )
}
