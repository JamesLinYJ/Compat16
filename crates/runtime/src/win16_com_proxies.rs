//! Guest-memory COM interface proxies and owned reference bookkeeping.
//!
//! A proxy is an ordinary guest object record containing a FAR pointer to a
//! guest vtable. Each vtable slot is a guest FAR procedure supplied by the
//! runtime's COM service gate. The native object remains an opaque `ComObjectId`;
//! native pointers never enter guest memory.

use std::collections::BTreeMap;

use compat_services::com::{
    ComObjectId, ComReferenceError, ComRelease, GuestComPointer,
    GuestComReferences, Guid,
};
use guest_core::{memory::Memory, OwnerId};
use win16_abi::{AllocationFlags, GlobalHandle, GlobalHeap, SelectorTable, Win16Error};

use crate::{DiagnosticKind, RuntimeError};

const OBJECT_VTABLE_OFFSET: u16 = 4;
const FAR_POINTER_BYTES: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProxyAllocation {
    handle: GlobalHandle,
    object: ComObjectId,
}

/// Per-guest-task COM identity map and the heap blocks that contain guest
/// interface objects and vtables.
#[derive(Default)]
pub(crate) struct Win16ComProxies {
    references: GuestComReferences,
    allocations: BTreeMap<GuestComPointer, ProxyAllocation>,
}

impl Win16ComProxies {
    pub(crate) fn interface_for_pointer(
        &self,
        pointer: GuestComPointer,
    ) -> Option<compat_services::com::GuestInterfaceRef> {
        self.references.interface_for_pointer(pointer)
    }

    pub(crate) fn pointer_for(
        &self,
        object: ComObjectId,
        iid: Guid,
    ) -> Option<GuestComPointer> {
        self.references.pointer_for(object, iid)
    }

    pub(crate) fn reference_count(&self, object: ComObjectId) -> Option<u32> {
        self.references.reference_count(object)
    }

    /// Consume one owned native result reference. A repeated interface result
    /// reuses its proxy and increments the guest count; a new IID gets a new
    /// proxy but shares the same canonical object's count.
    pub(crate) fn bind_owned_interface(
        &mut self,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
        memory: &mut Memory,
        owner: OwnerId,
        object: ComObjectId,
        iid: Guid,
        vtable_entries: &[u32],
    ) -> Result<(GuestComPointer, u32), RuntimeError> {
        if let Some(pointer) = self.references.pointer_for(object, iid) {
            let count = self.references.add_ref(pointer).map_err(reference_error)?;
            return Ok((pointer, count));
        }
        if self.references.reference_count(object).is_some() {
            self.bind_queried_interface(heap, selectors, memory, owner, object, iid, vtable_entries)
        } else {
            let pointer = self.bind_initial(heap, selectors, memory, owner, object, iid, vtable_entries)?;
            Ok((pointer, 1))
        }
    }

    /// Materialize the first interface pointer for a native identity whose
    /// result reference is already owned by the host object table.
    pub(crate) fn bind_initial(
        &mut self,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
        memory: &mut Memory,
        owner: OwnerId,
        object: ComObjectId,
        iid: Guid,
        vtable_entries: &[u32],
    ) -> Result<GuestComPointer, RuntimeError> {
        let (pointer, allocation) = allocate_proxy(
            heap, selectors, memory, owner, object, vtable_entries,
        )?;
        if let Err(error) = self.references.bind_initial(object, iid, pointer) {
            free_allocation(heap, selectors, allocation)?;
            return Err(reference_error(error));
        }
        self.allocations.insert(pointer, allocation);
        Ok(pointer)
    }

    /// Bind one additional IID view after native QueryInterface returned a
    /// successful owned reference. The object key remains canonical while
    /// each guest interface has its own correctly shaped vtable.
    pub(crate) fn bind_queried_interface(
        &mut self,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
        memory: &mut Memory,
        owner: OwnerId,
        object: ComObjectId,
        iid: Guid,
        vtable_entries: &[u32],
    ) -> Result<(GuestComPointer, u32), RuntimeError> {
        let (pointer, allocation) = allocate_proxy(
            heap, selectors, memory, owner, object, vtable_entries,
        )?;
        match self.references.bind_queried_interface(object, iid, pointer) {
            Ok(count) => {
                self.allocations.insert(pointer, allocation);
                Ok((pointer, count))
            }
            Err(error) => {
                free_allocation(heap, selectors, allocation)?;
                Err(reference_error(error))
            }
        }
    }

    /// Record an ordinary guest `IUnknown::AddRef` after the host object table
    /// has successfully acquired its matching native reference.
    pub(crate) fn add_ref(
        &mut self,
        pointer: GuestComPointer,
    ) -> Result<u32, RuntimeError> {
        self.references.add_ref(pointer).map_err(reference_error)
    }

    /// Record guest `IUnknown::Release`. The caller releases the matching
    /// native reference first; if that operation succeeds, this returns every
    /// proxy allocation to retire when the identity reaches zero references.
    pub(crate) fn release(
        &mut self,
        pointer: GuestComPointer,
    ) -> Result<ComRelease, RuntimeError> {
        self.references.release(pointer).map_err(reference_error)
    }

    /// Free all guest-side object/vtable blocks reported by the final release.
    pub(crate) fn retire_released_interfaces(
        &mut self,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
        released: &ComRelease,
    ) -> Result<(), RuntimeError> {
        for pointer in &released.removed_pointers {
            let allocation = self.allocations.remove(pointer).ok_or_else(|| {
                RuntimeError::new(DiagnosticKind::InternalInvariant,
                    "Win16 COM proxy allocation is missing during final Release")
            })?;
            if allocation.object != released.object {
                return Err(RuntimeError::new(DiagnosticKind::InternalInvariant,
                    "Win16 COM proxy allocation belongs to another object identity"));
            }
            heap.free(allocation.handle, selectors).map_err(crate::runtime_error)?;
        }
        Ok(())
    }

    /// Release every proxy block after the host has released task-owned native
    /// COM identities. This is for deterministic runtime teardown.
    pub(crate) fn drain_allocations(
        &mut self,
        heap: &mut GlobalHeap,
        selectors: &mut SelectorTable,
    ) -> Result<Vec<(ComObjectId, u32)>, RuntimeError> {
        let mut references_by_object = BTreeMap::new();
        for allocation in self.allocations.values() {
            if let Some(count) = self.references.reference_count(allocation.object) {
                references_by_object.insert(allocation.object, count);
            }
        }
        for allocation in std::mem::take(&mut self.allocations).into_values() {
            heap.free(allocation.handle, selectors).map_err(crate::runtime_error)?;
        }
        self.references = GuestComReferences::default();
        Ok(references_by_object.into_iter().collect())
    }
}

fn allocate_proxy(
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    memory: &mut Memory,
    owner: OwnerId,
    object: ComObjectId,
    vtable_entries: &[u32],
) -> Result<(GuestComPointer, ProxyAllocation), RuntimeError> {
    if vtable_entries.len() < 3 {
        return Err(RuntimeError::new(DiagnosticKind::InternalInvariant,
            "Win16 COM proxy vtable is missing IUnknown methods"));
    }
    let bytes = vtable_entries.len()
        .checked_mul(FAR_POINTER_BYTES)
        .and_then(|length| length.checked_add(usize::from(OBJECT_VTABLE_OFFSET)))
        .filter(|length| *length <= u16::MAX as usize + 1)
        .ok_or_else(|| RuntimeError::new(DiagnosticKind::ResourceExhausted,
            "Win16 COM proxy vtable exceeds one guest segment"))?;
    let handle = heap.alloc(
        memory,
        owner,
        u32::try_from(bytes).map_err(|_| RuntimeError::new(
            DiagnosticKind::ResourceExhausted, "Win16 COM proxy size exceeds the guest heap range"))?,
        AllocationFlags::fixed().with_zero_init(),
    ).map_err(heap_error)?;
    let base = match heap.lock(handle, selectors, memory) {
        Ok(pointer) => pointer,
        Err(error) => {
            heap.free_on_teardown(handle, selectors).map_err(crate::runtime_error)?;
            return Err(heap_error(error));
        }
    };
    let vtable = u32::from(base.selector().raw().0) << 16
        | u32::from(base.offset() + OBJECT_VTABLE_OFFSET);
    let mut contents = Vec::new();
    if contents.try_reserve_exact(bytes).is_err() {
        heap.unlock(handle, selectors).map_err(crate::runtime_error)?;
        heap.free(handle, selectors).map_err(crate::runtime_error)?;
        return Err(RuntimeError::new(DiagnosticKind::ResourceExhausted,
            "allocate Win16 COM proxy bytes"));
    }
    contents.extend_from_slice(&vtable.to_le_bytes());
    for entry in vtable_entries {
        contents.extend_from_slice(&entry.to_le_bytes());
    }
    let write = selectors.write(memory, base, &contents).map_err(crate::runtime_error);
    let unlock = heap.unlock(handle, selectors).map_err(crate::runtime_error);
    if let Err(error) = write {
        if unlock.is_ok() {
            heap.free(handle, selectors).map_err(crate::runtime_error)?;
        } else {
            heap.free_on_teardown(handle, selectors).map_err(crate::runtime_error)?;
        }
        return Err(error);
    }
    if let Err(error) = unlock {
        heap.free_on_teardown(handle, selectors).map_err(crate::runtime_error)?;
        return Err(error);
    }
    Ok((GuestComPointer(base.far_value()), ProxyAllocation { handle, object }))
}

fn free_allocation(
    heap: &mut GlobalHeap,
    selectors: &mut SelectorTable,
    allocation: ProxyAllocation,
) -> Result<(), RuntimeError> {
    heap.free(allocation.handle, selectors).map_err(crate::runtime_error)
}

fn heap_error(error: Win16Error) -> RuntimeError {
    RuntimeError::with_source(DiagnosticKind::ResourceExhausted,
        "allocate Win16 COM guest proxy", error)
}

fn reference_error(error: ComReferenceError) -> RuntimeError {
    RuntimeError::with_source(DiagnosticKind::InternalInvariant,
        "update Win16 COM guest references", error)
}

#[allow(dead_code)]
