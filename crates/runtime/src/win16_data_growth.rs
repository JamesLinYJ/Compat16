//! Activation of adjacent, privately reserved Win16 automatic data capacity.
//!
//! The SDK permits a local heap to grow within its automatic data segment.
//! Existing fixed and locked pointers remain valid because the guest base,
//! selector identities and stack offsets stay unchanged. Capacity is runtime
//! allocation policy; only a successful allocation publishes a larger limit.

use std::{error::Error, fmt, ops::Range};

use guest_core::{PhysAddr, memory::Memory};
use win16_abi::local_heap::{LocalHeap, LocalHeapError, LocalHeapGrowthError};
use win16_abi::Win16Error;

use super::{
    Win16State,
    legacy_cpu_binding::AutomaticDataOwner,
    local_heap::{LocalOperation, commit_local_spans},
};
use crate::{DiagnosticKind as Kind, RuntimeError};

impl Win16State {
    pub(super) fn try_grow_local_operation(
        &mut self,
        address: PhysAddr,
        original: &[u8],
        original_writes: &[Range<usize>],
        operation: &LocalOperation,
        requested: u16,
        memory: &mut Memory,
    ) -> Result<Option<u16>, RuntimeError> {
        let Some(owner) = self.local_data_owner(address, original.len())? else {
            return Ok(None);
        };
        let capacity = owner.capacity() as usize;
        if capacity <= original.len() { return Ok(None); }
        let old_size = u32::try_from(original.len()).map_err(|error|
            RuntimeError::with_source(Kind::InternalInvariant,
                "convert Win16 automatic-data extent for growth", error))?;

        // Geometric growth reduces repeat transactions; it is an allocator
        // policy rather than an ABI constant. Doubling also leaves room for
        // arena headers and movable-handle tables. A failed retry can request
        // the remaining capacity, still capped by the near-pointer limit.
        let mut size = original.len().saturating_mul(2)
            .max(original.len().saturating_add(usize::from(requested)))
            .min(capacity);
        let mut previous_size = original.len();
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(capacity).is_err() { return Ok(None); }
        bytes.extend_from_slice(original);
        let mut writes = Vec::new();
        if writes.try_reserve(original_writes.len()).is_err() { return Ok(None); }
        writes.extend_from_slice(original_writes);

        loop {
            bytes.resize(size, 0);
            let (value, changed) = {
                let mut heap = match LocalHeap::open(&mut bytes) {
                    Ok(heap) => heap,
                    Err(LocalHeapError::OutOfMemory) => return Ok(None),
                    Err(error) => return Err(growth_heap_error(error)),
                };
                match heap.grow(previous_size) {
                    Ok(()) => {}
                    Err(LocalHeapGrowthError::NotAtTail { .. } | LocalHeapGrowthError::NoUsableGrowth { .. }) => {
                        return Ok(None);
                    }
                    Err(LocalHeapGrowthError::Heap(LocalHeapError::OutOfMemory)) => return Ok(None),
                    Err(error @ LocalHeapGrowthError::InvalidRange { .. }) => {
                        return Err(RuntimeError::with_source(Kind::InternalInvariant,
                            "prepare Win16 automatic data growth lengths", error));
                    }
                    Err(error) => return Err(RuntimeError::with_source(Kind::GuestFault,
                        "extend Win16 local heap within its automatic data segment", error)),
                }
                let value = match operation.execute(&mut heap) {
                    Ok(value) => value,
                    Err(LocalHeapError::OutOfMemory | LocalHeapError::Uninitialized) => return Ok(None),
                    Err(error) => return Err(growth_heap_error(error)),
                };
                (value, heap.take_write_spans())
            };
            if writes.try_reserve(changed.len()).is_err() { return Ok(None); }
            writes.extend(changed);
            if value != 0 {
                // A legal short or PrestoChango view need not be expandable.
                // Refusing such growth is an ordinary allocation failure;
                // validate it before publishing any prepared guest writes.
                let new_size = u32::try_from(size).map_err(|error|
                    RuntimeError::with_source(Kind::InternalInvariant,
                        "convert Win16 automatic-data target extent", error))?;
                let targets = match self.selectors.in_place_extension_targets(
                    address, old_size, new_size, memory,
                ) {
                    Ok(targets) => targets,
                    Err(Win16Error::SelectorBlockInterior | Win16Error::OutOfMemory) => return Ok(None),
                    Err(error) => return Err(crate::runtime_error(error)),
                };
                if targets.is_empty() { return Ok(None); }
                let growth_plan = match self.prepare_legacy_cpu_data_growth(
                    owner, old_size, new_size, &targets, memory,
                ) {
                    Ok(plan) => plan,
                    Err(super::legacy_cpu_binding::Win16LegacyCpuBindingError::Runtime(error))
                        if error.kind() == Kind::ResourceExhausted => return Ok(None),
                    Err(error) => return Err(RuntimeError::with_source(Kind::InternalInvariant,
                        "prepare exact automatic-data continuation growth receipts", error)),
                };
                if let AutomaticDataOwner::Main { module, selector, segment_flags, base, .. } = owner {
                    self.preflight_module_image_extent_growth(
                        module, selector, base, segment_flags, old_size, new_size,
                    )?;
                }
                if writes.try_reserve(1).is_err() { return Ok(None); }
                writes.push(original.len()..size);
                let Some(previous) = copy_ram(memory, address, size)? else { return Ok(None); };
                let commit = commit_local_spans(memory, address, &bytes, &writes)
                    .and_then(|()| self.extend_data_owner(owner, original.len(), size, memory));
                if let Err(primary_error) = commit {
                    return match memory.write_physical(address, &previous) {
                        Ok(()) if primary_error.kind() == Kind::ResourceExhausted => Ok(None),
                        Ok(()) => Err(primary_error),
                        Err(rollback) => Err(RuntimeError::with_source(Kind::InternalInvariant,
                            "Win16 data growth could not restore its guest bytes",
                            GrowthRollbackFailure { primary: primary_error, rollback })),
                    };
                }
                if let AutomaticDataOwner::Main { module, selector, segment_flags, base, .. } = owner {
                    self.commit_module_image_extent_growth(
                        module, selector, base, segment_flags, old_size, new_size,
                    );
                }
                self.commit_legacy_cpu_data_growth(growth_plan);
                self.update_loaded_data_size(owner, new_size);
                return Ok(Some(value));
            }
            if size == capacity { return Ok(None); }
            previous_size = size;
            size = capacity;
        }
    }

    fn local_data_owner(
        &self, address: PhysAddr, size: usize,
    ) -> Result<Option<AutomaticDataOwner>, RuntimeError> {
        if let Some(reservation) = &self.automatic_data {
            if reservation.base == address {
                let module = self.modules.main;
                let record = self.modules.records.get(&module).ok_or_else(||
                    RuntimeError::new(Kind::InternalInvariant,
                        "Win16 main automatic-data module record is absent"))?;
                if record.handle != module {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 main module key disagrees with its exact handle"));
                }
                let definition = record.definition.as_ref().ok_or_else(||
                    RuntimeError::new(Kind::InternalInvariant,
                        "Win16 main automatic-data module definition is absent"))?;
                let segment = definition.header.automatic_data_segment;
                let segment_flags = definition.segments.iter()
                    .find(|definition| definition.number == segment)
                    .map(|definition| definition.flags)
                    .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                        "Win16 main automatic-data segment definition is absent"))?;
                let loaded = record.loaded.as_ref().ok_or_else(||
                    RuntimeError::new(Kind::InternalInvariant,
                        "Win16 main automatic-data loaded image is absent"))?;
                let data = loaded.segments.iter().find(|loaded| loaded.number == segment)
                    .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                        "Win16 main automatic-data loaded segment is absent"))?;
                if data.selector.0 != reservation.selector.raw().0
                    || data.memory_size != reservation.size
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 main automatic-data owner disagrees with its loaded segment"));
                }
                let main_data = self.loaded.segments.iter()
                    .find(|loaded| loaded.number == segment);
                if main_data.is_none_or(|loaded|
                    loaded.selector.0 != reservation.selector.raw().0
                        || loaded.memory_size != reservation.size)
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 main loaded-data extent disagrees with its reservation"));
                }
                if self.selectors.reference(reservation.selector.raw()).ok()
                    != Some(reservation.selector)
                {
                    return Ok(None);
                }
                let descriptor = self.selectors.describe(reservation.selector).map_err(crate::runtime_error)?;
                // A guest may deliberately select a shorter alias or change a
                // descriptor with PrestoChangoSelector. Such a view does not
                // authorize activation of this owner's complete data reserve.
                if !descriptor.present || descriptor.base != address
                    || descriptor.limit + 1 != reservation.size || reservation.size as usize != size {
                    return Ok(None);
                }
                return Ok(Some(AutomaticDataOwner::Main {
                    module, selector: reservation.selector, segment, segment_flags,
                    base: address, capacity: reservation.capacity,
                }));
            }
        }
        for (&module, record) in &self.modules.records {
            if record.handle != module { continue; }
            let (Some(definition), Some(loaded)) = (&record.definition, &record.loaded) else { continue; };
            let segment = definition.header.automatic_data_segment;
            let Some(data) = loaded.segments.iter().find(|entry| entry.number == segment) else { continue; };
            let Some(allocation) = record.allocations.iter()
                .find(|allocation| allocation.selector.raw().0 == data.selector.0) else { continue; };
            let descriptor = self.selectors.describe(allocation.selector).map_err(crate::runtime_error)?;
            if descriptor.base != address { continue; }
            let info = self.heap.info(allocation.handle).map_err(crate::runtime_error)?;
            if data.memory_size != info.size {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 DLL automatic data size disagrees with its allocation record"));
            }
            if !descriptor.present || descriptor.limit + 1 != info.size
                || info.base != address || info.size as usize != size { return Ok(None); }
            let segment_flags = definition.segments.iter()
                .find(|entry| entry.number == segment)
                .map(|entry| entry.flags)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "Win16 DLL automatic-data segment definition is absent"))?;
            if self.selectors.reference(allocation.selector.raw()).ok()
                != Some(allocation.selector)
            {
                return Ok(None);
            }
            let capacity = self.heap.reserved_capacity(allocation.handle).map_err(crate::runtime_error)?;
            return Ok(Some(AutomaticDataOwner::Library {
                module, allocation: allocation.handle, selector: allocation.selector,
                segment, segment_flags, base: address, capacity,
            }));
        }
        Ok(None)
    }

    fn extend_data_owner(
        &mut self, owner: AutomaticDataOwner, old_size: usize, new_size: usize, memory: &Memory,
    ) -> Result<(), RuntimeError> {
        match owner {
            AutomaticDataOwner::Main {
                module, selector, segment, segment_flags, base, capacity,
            } => {
                let main_module = self.modules.main;
                let segment_owner_matches = self.modules.records.get(&module)
                    .and_then(|record| {
                        let definition = record.definition.as_ref()?;
                        let flags = definition.segments.iter()
                            .find(|entry| entry.number == segment)?.flags;
                        (module == main_module
                            && definition.header.automatic_data_segment == segment
                            && flags == segment_flags)
                            .then_some(())
                    }).is_some();
                if !segment_owner_matches {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 main automatic-data module identity changed before commit"));
                }
                let reservation = self.automatic_data.as_mut().ok_or_else(||
                    RuntimeError::new(Kind::InternalInvariant,
                        "Win16 automatic data owner is absent"))?;
                if reservation.selector != selector || reservation.base != base
                    || reservation.size as usize != old_size
                    || capacity != reservation.capacity
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 main automatic-data growth owner changed before commit"));
                }
                self.selectors.extend_allocation_in_place(base,
                    old_size as u32, new_size as u32, memory).map_err(crate::runtime_error)?;
                reservation.size = new_size as u32;
                Ok(())
            }
            AutomaticDataOwner::Library {
                module, allocation: handle, selector, segment, segment_flags, base, capacity,
            } => {
                let record = self.modules.records.get(&module).ok_or_else(||
                    RuntimeError::new(Kind::InternalInvariant, "Win16 DLL data owner is absent"))?;
                let definition = record.definition.as_ref().ok_or_else(||
                    RuntimeError::new(Kind::InternalInvariant, "Win16 DLL definition is absent"))?;
                let loaded = record.loaded.as_ref().ok_or_else(||
                    RuntimeError::new(Kind::InternalInvariant, "Win16 DLL loaded image is absent"))?;
                let loaded_segment = loaded.segments.iter().find(|entry| entry.number == segment)
                    .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                        "Win16 DLL automatic-data segment is absent"))?;
                let definition_flags = definition.segments.iter()
                    .find(|entry| entry.number == segment).map(|entry| entry.flags);
                let allocation = record.allocations.iter().find(|entry|
                    entry.handle == handle && entry.selector == selector).ok_or_else(||
                        RuntimeError::new(Kind::InternalInvariant, "Win16 DLL data owner is absent"))?;
                let old_size_u32 = u32::try_from(old_size).map_err(|error|
                    RuntimeError::with_source(Kind::InternalInvariant,
                        "convert Win16 DLL automatic-data extent", error))?;
                if definition.header.automatic_data_segment != segment
                    || definition_flags != Some(segment_flags)
                    || loaded_segment.selector.0 != selector.raw().0
                    || loaded_segment.memory_size != old_size_u32
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 DLL automatic-data metadata changed before commit"));
                }
                if self.heap.info(allocation.handle).map_err(crate::runtime_error)?.base != base
                    || self.heap.reserved_capacity(allocation.handle).map_err(crate::runtime_error)? != capacity
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "Win16 DLL automatic-data growth owner changed before commit"));
                }
                allocation.extend_in_place(&mut self.heap, &mut self.selectors, memory,
                    old_size as u32, new_size as u32)
            }
        }
    }

    fn update_loaded_data_size(&mut self, owner: AutomaticDataOwner, size: u32) {
        match owner {
            AutomaticDataOwner::Main { module, selector, segment, .. } => {
                for loaded_segment in &mut self.loaded.segments {
                    if loaded_segment.number == segment && loaded_segment.selector.0 == selector.raw().0 {
                        loaded_segment.memory_size = size;
                    }
                }
                if let Some(loaded) = self.modules.records.get_mut(&module)
                    .and_then(|record| record.loaded.as_mut())
                {
                    for loaded_segment in &mut loaded.segments {
                        if loaded_segment.number == segment && loaded_segment.selector.0 == selector.raw().0 {
                            loaded_segment.memory_size = size;
                        }
                    }
                }
            }
            AutomaticDataOwner::Library { module, allocation, selector, segment, .. } => {
                let is_exact_allocation = self.modules.records.get(&module).is_some_and(|record|
                    record.allocations.iter().any(|entry|
                        entry.handle == allocation && entry.selector == selector));
                if is_exact_allocation {
                    if let Some(loaded) = self.modules.records.get_mut(&module)
                        .and_then(|record| record.loaded.as_mut())
                    {
                        for loaded_segment in &mut loaded.segments {
                            if loaded_segment.number == segment && loaded_segment.selector.0 == selector.raw().0 {
                                loaded_segment.memory_size = size;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn copy_ram(memory: &Memory, address: PhysAddr, size: usize) -> Result<Option<Vec<u8>>, RuntimeError> {
    memory.validate_ram_range(address, size, true).map_err(crate::runtime_error)?;
    let mut previous = Vec::new();
    if previous.try_reserve_exact(size).is_err() { return Ok(None); }
    previous.resize(size, 0);
    memory.read_physical(address, &mut previous).map_err(crate::runtime_error)?;
    Ok(Some(previous))
}

fn growth_heap_error(error: LocalHeapError) -> RuntimeError {
    let kind = if matches!(error, LocalHeapError::CallbackRequired) {
        Kind::CompatibilityGap
    } else { Kind::GuestFault };
    RuntimeError::with_source(kind, "prepare Win16 local heap growth", error)
}

#[derive(Debug)]
struct GrowthRollbackFailure {
    primary: RuntimeError,
    rollback: guest_core::MemoryError,
}

impl fmt::Display for GrowthRollbackFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}; restoring guest bytes also failed: {}", self.primary, self.rollback)
    }
}

impl Error for GrowthRollbackFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> { Some(&self.primary) }
}
