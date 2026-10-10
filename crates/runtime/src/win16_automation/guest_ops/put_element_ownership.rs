//! Allocation-identity and extent checks for SAFEARRAY element replacement.

use super::*;
use compat_services::automation::SafeArray16;
use win16_abi::{GlobalBlockInfo, GlobalHandle};
use super::super::super::{AllocationKind, checked_safe_array_huge_chunks, expected_array_data_length};

pub(super) struct ProtectedStorage {
    blocks: [(GlobalHandle, GlobalBlockInfo); 2],
}

pub(super) fn unsupported_storage() -> AutomationFailure {
    AutomationFailure::HResult(super::super::E_NOTIMPL)
}

pub(super) fn validate_destination(
    state: &Win16AutomationState,
    descriptor: &SafeArray16,
    array_far: u32,
    heap: &GlobalHeap,
    selectors: &SelectorTable,
    memory: &Memory,
    owner: OwnerId,
) -> Result<ProtectedStorage, AutomationFailure> {
    let descriptor_length = 16 + usize::from(descriptor.dimensions) * 8;
    let data_length = expected_array_data_length(descriptor)?;
    if descriptor.data == 0 || data_length == 0 || descriptor.locks == u16::MAX {
        return Err(AutomationFailure::HResult(E_INVALIDARG));
    }
    let mut blocks = Vec::new();
    blocks.try_reserve_exact(2)
        .map_err(|_| AutomationFailure::HResult(super::super::E_OUTOFMEMORY))?;
    for (far, kind, length) in [
        (array_far, AllocationKind::SafeArrayDescriptor, descriptor_length),
        (descriptor.data, AllocationKind::SafeArrayData, data_length),
    ] {
        // A valid external/static descriptor needs its own ownership contract;
        // never pretend it is malformed simply because this path is bounded.
        if !state.allocations.contains_key(&far) {
            return Err(unsupported_storage());
        }
        let allocation = state.require_owned_allocation(owner, far, kind)?;
        let info = heap.info(allocation.handle).map_err(crate::runtime_error)?;
        if info.owner != owner || info.discarded || length > info.size as usize {
            return Err(AutomationFailure::HResult(E_INVALIDARG));
        }
        let pointer = selectors.pointer_from_far(far).map_err(crate::runtime_error)?;
        let chunks = checked_safe_array_huge_chunks(selectors, memory, pointer, length, Access::Write)?;
        let mut consumed = 0_u64;
        for (chunk, length) in chunks {
            let address = selectors.translate(chunk, Access::Write, length, memory)
                .map_err(crate::runtime_error)?;
            // The tracked handle, not FAR equality, is authoritative. A guest
            // can retarget a selector; reject a remapped/aliased owned key.
            if u64::from(address.0) != u64::from(info.base.0) + consumed {
                return Err(AutomationFailure::HResult(E_INVALIDARG));
            }
            consumed += length as u64;
        }
        blocks.push((allocation.handle, info));
    }
    let blocks: [(GlobalHandle, GlobalBlockInfo); 2] = blocks.try_into()
        .map_err(|_| AutomationFailure::HResult(E_INVALIDARG))?;
    if overlaps(blocks[0].1, blocks[1].1) || blocks[0].0 == blocks[1].0 {
        return Err(AutomationFailure::HResult(E_INVALIDARG));
    }
    Ok(ProtectedStorage { blocks })
}

pub(super) fn preflight_replacement(
    state: &Win16AutomationState,
    old: Variant16,
    protected: &ProtectedStorage,
    heap: &GlobalHeap,
    selectors: &SelectorTable,
    memory: &Memory,
    owner: OwnerId,
    reject: &mut impl FnMut(AutomationInterfaceAction, u32) -> Result<(), RuntimeError>,
) -> Result<(), AutomationFailure> {
    let mut arrays = BTreeSet::new();
    let mut bstrs = BTreeSet::new();
    super::super::variant::preflight_variant_release(
        state, old, selectors, memory, owner, reject, &mut arrays, &mut bstrs, 0, true,
    )?;
    let mut retiring = Vec::new();
    let count = arrays.len().checked_mul(2).and_then(|n| n.checked_add(bstrs.len()))
        .ok_or(AutomationFailure::HResult(super::super::E_OUTOFMEMORY))?;
    retiring.try_reserve_exact(count)
        .map_err(|_| AutomationFailure::HResult(super::super::E_OUTOFMEMORY))?;
    for far in arrays {
        check_retirement(state, far, AllocationKind::SafeArrayDescriptor, protected, heap, owner, &mut retiring)?;
        let descriptor = state.read_safe_array_descriptor(selectors, memory, far)?;
        if descriptor.data != 0 {
            check_retirement(state, descriptor.data, AllocationKind::SafeArrayData, protected, heap, owner, &mut retiring)?;
        }
    }
    for far in bstrs {
        check_retirement(state, far, AllocationKind::Bstr, protected, heap, owner, &mut retiring)?;
    }
    Ok(())
}

fn check_retirement(
    state: &Win16AutomationState,
    far: u32,
    kind: AllocationKind,
    protected: &ProtectedStorage,
    heap: &GlobalHeap,
    owner: OwnerId,
    retiring: &mut Vec<(GlobalHandle, GlobalBlockInfo)>,
) -> Result<(), AutomationFailure> {
    let allocation = state.require_owned_allocation(owner, far, kind)?;
    let info = heap.info(allocation.handle).map_err(crate::runtime_error)?;
    if protected.blocks.iter().any(|(handle, block)|
        *handle == allocation.handle || overlaps(*block, info))
    {
        return Err(AutomationFailure::HResult(E_INVALIDARG));
    }
    // Distinct nested descriptors must not retire the same data block twice.
    // Check allocator identity and physical extent, not guest FAR bits.
    if retiring.iter().any(|(handle, block)|
        *handle == allocation.handle || overlaps(*block, info))
    {
        return Err(AutomationFailure::HResult(E_INVALIDARG));
    }
    retiring.push((allocation.handle, info));
    Ok(())
}

fn overlaps(a: GlobalBlockInfo, b: GlobalBlockInfo) -> bool {
    u64::from(a.base.0) < u64::from(b.base.0) + u64::from(b.size)
        && u64::from(b.base.0) < u64::from(a.base.0) + u64::from(a.size)
}
