//! Canonical backing leases for guest-created selector views.

use dos_kernel::{DosBlockExtent, DosBlockLease, DosKernel};
use guest_core::{PhysAddr, Selector};
use guest_core::memory::{Memory, ROM_START, ROM_END};
use win16_abi::{Access, AccessRights, GlobalHandle, SegmentedPointer, SelectorRef};

use super::{Win16State, runtime_arena_backing::{RuntimeArenaBackingIdentity, RuntimeArenaBackingLease}};
use crate::RuntimeError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SelectorBackingIdentity {
    GlobalHeap {
        allocation: GlobalHandle,
        module: Option<u16>,
        ne_segment_flags: Option<u16>,
    },
    Dos { extent: DosBlockExtent, primary: Option<SelectorRef> },
    ModuleImage {
        module: u16,
        primary: SelectorRef,
        base: PhysAddr,
        size: u32,
        segment_flags: u16,
    },
    FirmwareRom { primary: SelectorRef, base: PhysAddr, size: u32 },
    RuntimeArena(RuntimeArenaBackingIdentity),
}

#[derive(Debug)]
pub(super) enum SelectorBackingLease {
    GlobalHeap {
        allocation: GlobalHandle,
        module: Option<u16>,
        ne_segment_flags: Option<u16>,
    },
    Dos {
        lease: DosBlockLease,
        extent: DosBlockExtent,
        primary: Option<SelectorRef>,
    },
    ModuleImage {
        module: u16,
        primary: SelectorRef,
        base: PhysAddr,
        size: u32,
        segment_flags: u16,
    },
    /// Machine-owned ROM needs no allocation pin; this non-cloneable token is
    /// held only by a CPU frame, whose domain snapshot brands its memory owner.
    FirmwareRom { primary: SelectorRef, base: PhysAddr, size: u32 },
    RuntimeArena { lease: RuntimeArenaBackingLease },
}

impl SelectorBackingLease {
    pub(super) fn identity(&self) -> SelectorBackingIdentity {
        match self {
            Self::GlobalHeap { allocation, module, ne_segment_flags } =>
                SelectorBackingIdentity::GlobalHeap {
                    allocation: *allocation, module: *module,
                    ne_segment_flags: *ne_segment_flags,
                },
            Self::Dos { extent, primary, .. } =>
                SelectorBackingIdentity::Dos { extent: *extent, primary: *primary },
            Self::ModuleImage { module, primary, base, size, segment_flags } =>
                SelectorBackingIdentity::ModuleImage {
                    module: *module, primary: *primary, base: *base, size: *size,
                    segment_flags: *segment_flags,
                },
            Self::FirmwareRom { primary, base, size } => SelectorBackingIdentity::FirmwareRom {
                primary: *primary, base: *base, size: *size,
            },
            Self::RuntimeArena { lease } => SelectorBackingIdentity::RuntimeArena(lease.identity()),
        }
    }

    pub(super) fn module(&self) -> Option<u16> {
        match self {
            Self::GlobalHeap { module, .. } => *module,
            Self::Dos { .. } | Self::FirmwareRom { .. } => None,
            Self::ModuleImage { module, .. } => Some(*module),
            Self::RuntimeArena { .. } => None,
        }
    }

    pub(super) fn global_heap_allocation(&self) -> Option<GlobalHandle> {
        match self { Self::GlobalHeap { allocation, .. } => Some(*allocation), _ => None }
    }
}

#[derive(Debug)]
pub(super) struct SelectorBackingEntry {
    /// The descriptor generation is part of the owner key; raw selector reuse
    /// cannot inherit an earlier allocation's lifetime.
    pub(super) reference: SelectorRef,
    /// The first lease backs the current descriptor. Later leases are retained
    /// only while a failed transactional retarget still needs rollback owners.
    pub(super) leases: Vec<SelectorBackingLease>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MapLsEntry {
    pub(super) reference: SelectorRef,
    pub(super) base: u32,
    pub(super) references: u32,
}

impl Win16State {
    /// Preflight every cached main-image lease before automatic-data growth.
    /// The selector generation, base, and flags stay fixed; only the lease's
    /// extent snapshot may advance from the exact current size.
    pub(super) fn preflight_module_image_extent_change(
        &self,
        module: u16,
        primary: SelectorRef,
        base: PhysAddr,
        segment_flags: u16,
        old_size: u32,
        new_size: u32,
    ) -> Result<(), RuntimeError> {
        if old_size == 0 || new_size == 0 || new_size == old_size {
            return Err(RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "invalid checked module-image extent transition"));
        }
        for entry in self.selector_backing_leases.values() {
            for lease in &entry.leases {
                if let SelectorBackingLease::ModuleImage {
                    module: owner_module, primary: owner_primary, base: owner_base,
                    size: owner_size, segment_flags: owner_flags,
                } = lease
                    && *owner_primary == primary && *owner_base == base
                    && (*owner_module != module || *owner_size != old_size
                        || *owner_flags != segment_flags)
                {
                    return Err(RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                        "cached module-image lease does not match the current automatic-data extent"));
                }
            }
        }
        Ok(())
    }

    /// Advance only the exact primary image leases preflighted above. This is
    /// infallible and allocation-free after the selector extent commits.
    pub(super) fn commit_module_image_extent_change(
        &mut self,
        module: u16,
        primary: SelectorRef,
        base: PhysAddr,
        segment_flags: u16,
        old_size: u32,
        new_size: u32,
    ) {
        for entry in self.selector_backing_leases.values_mut() {
            for lease in &mut entry.leases {
                if let SelectorBackingLease::ModuleImage {
                    module: owner_module, primary: owner_primary, base: owner_base,
                    size: owner_size, segment_flags: owner_flags,
                } = lease
                    && *owner_module == module && *owner_primary == primary
                    && *owner_base == base && *owner_flags == segment_flags
                {
                    debug_assert_eq!(*owner_size, old_size);
                    *owner_size = new_size;
                }
            }
        }
    }

    pub(super) fn selector_backing_lease(
        &mut self,
        selector: SelectorRef,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<Option<SelectorBackingIdentity>, RuntimeError> {
        let descriptor = self.selectors.describe(selector).map_err(crate::runtime_error)?;
        if !descriptor.present { return Ok(None); }
        let size = descriptor.limit.checked_add(1).ok_or_else(|| {
            RuntimeError::new(crate::DiagnosticKind::InvalidInput,
                "selector backing range overflowed")
        })?;
        if let Some(entry) = self.selector_backing_leases.get(&selector.raw().0) {
            if entry.reference != selector || entry.leases.is_empty() {
                return Err(RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                    "selector backing record has a stale generation or no retained owner"));
            }
            let identity = entry.leases[0].identity();
            if !self.backing_identity_covers(identity, descriptor.base, size, dos, memory)? {
                return Err(RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                    "selector backing lease no longer covers its descriptor"));
            }
            return Ok(Some(identity));
        }
        let firmware = SelectorBackingIdentity::FirmwareRom { primary: selector, base: descriptor.base, size };
        if self.firmware_rom_identity_is_live(firmware, memory) { return Ok(Some(firmware)); }
        self.selector_backing_lease_for_range(descriptor.base, size, dos, memory)
    }

    /// Only an exact registered real-mode vector alias owns a firmware byte.
    /// ROM addresses alone never grant generic alias or MapLS ownership.
    pub(super) fn firmware_rom_identity_is_live(
        &self,
        identity: SelectorBackingIdentity,
        memory: &Memory,
    ) -> bool {
        let SelectorBackingIdentity::FirmwareRom { primary, base, size } = identity
        else { return false; };
        if size != 1 || !(ROM_START..ROM_END).contains(&base.0) { return false; }
        let registered = self.real_mode_vector_aliases.iter().any(|(&(segment, offset), &reference)| {
            reference == primary && guest_core::real_address(segment, offset) == base
        });
        if !registered { return false; }
        let Ok(descriptor) = self.selectors.describe(primary) else { return false; };
        descriptor.present && descriptor.base == base && descriptor.limit == 0
            && descriptor.rights == AccessRights::code()
            && self.selectors.translate(SegmentedPointer::new(primary, 0), Access::Execute, 1, memory).is_ok()
    }

    pub(super) fn selector_backing_lease_for_range(
        &mut self,
        base: PhysAddr,
        size: u32,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<Option<SelectorBackingIdentity>, RuntimeError> {
        if size == 0 { return Ok(None); }
        let start = u64::from(base.0);
        let end = start.checked_add(u64::from(size)).ok_or_else(|| {
            RuntimeError::new(crate::DiagnosticKind::InvalidInput,
                "selector backing range overflowed")
        })?;
        let mut identity = None;

        for region in self.heap.snapshot_regions().map_err(crate::runtime_error)? {
            let win16_abi::GlobalHeapRegion::Allocated { identity: allocation, info, .. } = region
            else { continue; };
            let module = self.resources.module_for_identity(allocation).or_else(||
                self.modules.records.iter().find_map(|(&module, record)|
                    record.allocations.iter().any(|entry| entry.handle == allocation)
                        .then_some(module)));
            let ne_segment_flags = module.and_then(|module|
                self.module_segment_flags_for_allocation(module, allocation));
            self.consider_heap_backing(
                allocation, module, ne_segment_flags, info, start, end, &mut identity,
            )?;
        }

        if let Some(extent) = dos.owned_block_containing_range(
            memory, base, usize::try_from(size).unwrap_or(usize::MAX),
        ).map_err(crate::runtime_error)? {
            let primary = self.dos_global_blocks.iter().find_map(|(&handle, block)| {
                (block.extent == extent).then(|| self.global_selectors.get(&handle).copied()).flatten()
            });
            Self::consider_extent_backing(
                SelectorBackingIdentity::Dos { extent, primary },
                extent.guest_base().map(|address| address.0),
                extent.byte_length().and_then(|bytes| u32::try_from(bytes).ok()),
                start, end, &mut identity,
            )?;
        }

        // The main EXE image is loader-owned outside GlobalHeap. Keep its
        // checked primary selector, complete SelectorTable extent, and HMODULE
        // together so DDESHARE aliases cannot outlive the process arena.
        for segment in &self.loaded.segments {
            let Ok(primary) = self.selectors.reference(Selector(segment.selector.0)) else {
                continue;
            };
            let Ok((head, segment_base, segment_size)) = self.selectors.allocation_range(primary)
            else { continue; };
            if head != primary { continue; }
            let Some(flags) = self.modules.records.get(&self.modules.main)
                .and_then(|record| record.definition.as_ref())
                .and_then(|definition| definition.segments.iter()
                    .find(|definition| definition.number == segment.number))
                .map(|definition| definition.flags)
            else { continue; };
            Self::consider_extent_backing(
                SelectorBackingIdentity::ModuleImage {
                    module: self.modules.main, primary, base: segment_base,
                    size: segment_size, segment_flags: flags,
                },
                Some(segment_base.0), Some(segment_size), start, end, &mut identity,
            )?;
        }

        // The reservation itself is not an owner. Only exact selector chunks
        // registered by bootstrap can back bytes inside the Win16 arena.
        for arena_identity in self.runtime_arena_backing.identities() {
            if !self.runtime_arena_backing.identity_is_live(
                arena_identity, &self.selectors, memory,
            )? {
                return Err(RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                    "registered runtime arena backing no longer matches its selector generation"));
            }
            Self::consider_extent_backing(
                SelectorBackingIdentity::RuntimeArena(arena_identity),
                Some(arena_identity.base.0), Some(arena_identity.size),
                start, end, &mut identity,
            )?;
        }
        Ok(identity)
    }

    fn consider_heap_backing(
        &self,
        allocation: GlobalHandle,
        module: Option<u16>,
        ne_segment_flags: Option<u16>,
        info: win16_abi::GlobalBlockInfo,
        start: u64,
        end: u64,
        found: &mut Option<SelectorBackingIdentity>,
    ) -> Result<(), RuntimeError> {
        if info.discarded || info.size == 0 { return Ok(()); }
        Self::consider_extent_backing(
            SelectorBackingIdentity::GlobalHeap { allocation, module, ne_segment_flags },
            Some(info.base.0), Some(info.size), start, end, found,
        )
    }

    fn module_segment_flags_for_allocation(
        &self,
        module: u16,
        allocation: GlobalHandle,
    ) -> Option<u16> {
        let record = self.modules.records.get(&module)?;
        let owned = record.allocations.iter().find(|entry| entry.handle == allocation)?;
        let loaded = record.loaded.as_ref()?;
        let number = loaded.segments.iter()
            .find(|segment| segment.selector == guest_core::Selector(owned.selector.raw().0))?
            .number;
        record.definition.as_ref()?.segments.iter()
            .find(|segment| segment.number == number)
            .map(|segment| segment.flags)
    }

    fn consider_extent_backing(
        candidate: SelectorBackingIdentity,
        base: Option<u32>,
        size: Option<u32>,
        start: u64,
        end: u64,
        found: &mut Option<SelectorBackingIdentity>,
    ) -> Result<(), RuntimeError> {
        let (Some(base), Some(size)) = (base, size) else { return Ok(()); };
        let block_start = u64::from(base);
        let block_end = block_start.checked_add(u64::from(size)).ok_or_else(|| {
            RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "selector backing extent overflowed")
        })?;
        if start >= block_end || block_start >= end { return Ok(()); }
        if start < block_start || end > block_end {
            return Err(RuntimeError::new(crate::DiagnosticKind::InvalidInput,
                "selector range crosses a guest allocation boundary"));
        }
        if let Some(previous) = *found {
            if previous != candidate {
                return Err(RuntimeError::new(crate::DiagnosticKind::InvalidInput,
                    "selector range overlaps more than one guest backing owner"));
            }
        } else {
            *found = Some(candidate);
        }
        Ok(())
    }

    fn backing_identity_covers(
        &self,
        identity: SelectorBackingIdentity,
        base: PhysAddr,
        size: u32,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        match identity {
            SelectorBackingIdentity::FirmwareRom { base: expected_base, size: expected_size, .. } =>
                Ok(base == expected_base && size == expected_size
                    && self.firmware_rom_identity_is_live(identity, memory)),
            SelectorBackingIdentity::GlobalHeap { allocation, .. } =>
                self.range_is_in_allocation(allocation, base, size),
            SelectorBackingIdentity::Dos { extent, .. } => Ok(
                dos.owned_block_containing_range(memory, base, usize::try_from(size)
                    .unwrap_or(usize::MAX)).map_err(crate::runtime_error)? == Some(extent)),
            SelectorBackingIdentity::ModuleImage { primary, base: image_base,
                size: image_size, module, .. } => {
                let Ok(current) = self.selectors.describe(primary) else { return Ok(false); };
                let Ok((head, current_base, current_size)) = self.selectors.allocation_range(primary)
                else { return Ok(false); };
                let module_live = self.modules.records.get(&module)
                    .is_some_and(|record| record.state != super::module_registry::ModuleState::Retired);
                let start = u64::from(base.0);
                let end = start.checked_add(u64::from(size)).unwrap_or(u64::MAX);
                let image_start = u64::from(image_base.0);
                let image_end = image_start.checked_add(u64::from(image_size)).unwrap_or(u64::MAX);
                Ok(module_live && current.present && head == primary
                    && current_base == image_base && current_size == image_size
                    && current.base == image_base
                    && start >= image_start && end <= image_end)
            }
            SelectorBackingIdentity::RuntimeArena(arena) => {
                let arena_start = u64::from(arena.base.0);
                let arena_end = arena_start.checked_add(u64::from(arena.size))
                    .ok_or_else(|| RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                        "runtime arena chunk extent overflowed"))?;
                let start = u64::from(base.0);
                let end = start.checked_add(u64::from(size)).unwrap_or(u64::MAX);
                Ok(self.runtime_arena_backing.identity_is_live(
                    arena, &self.selectors, memory,
                )? && start >= arena_start && end <= arena_end)
            }
        }
    }

    pub(super) fn range_is_in_allocation(
        &self,
        allocation: GlobalHandle,
        base: PhysAddr,
        size: u32,
    ) -> Result<bool, RuntimeError> {
        if size == 0 { return Ok(false); }
        let info = self.heap.info(allocation).map_err(crate::runtime_error)?;
        if info.discarded || info.size == 0 { return Ok(false); }
        let start = u64::from(base.0);
        let end = start.checked_add(u64::from(size)).ok_or_else(|| {
            RuntimeError::new(crate::DiagnosticKind::InvalidInput,
                "selector backing range overflowed")
        })?;
        let block_start = u64::from(info.base.0);
        let block_end = block_start.checked_add(u64::from(info.size)).ok_or_else(|| {
            RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "GlobalHeap selector backing extent overflowed")
        })?;
        Ok(start >= block_start && end <= block_end)
    }

    pub(super) fn retain_selector_backing(
        &mut self,
        reference: SelectorRef,
        identity: SelectorBackingIdentity,
        base: PhysAddr,
        size: u32,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<Option<SelectorBackingLease>, RuntimeError> {
        if size == 0 { return Ok(None); }
        if self.selectors.reference_including_unbacked(reference.raw()).ok() != Some(reference) {
            return Ok(None);
        }
        match identity {
            SelectorBackingIdentity::FirmwareRom { .. } => Ok(None),
            SelectorBackingIdentity::GlobalHeap { allocation, module, ne_segment_flags } => {
                if !self.range_is_in_allocation(allocation, base, size)? { return Ok(None); }
                // Preflight both counters before the first mutation. Keep the
                // exact module record borrowed until the heap alias succeeds,
                // then commit its root count; failed retains leave neither
                // counter changed and need no compensating release.
                let module_root = if let Some(module) = module {
                    let record = self.modules.records.get_mut(&module).ok_or_else(||
                        RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                            "selector backing names a missing module owner"))?;
                    let next = record.continuation_owner_refs.checked_add(1).ok_or_else(||
                        RuntimeError::new(crate::DiagnosticKind::ResourceExhausted,
                            "module continuation owner reference count is exhausted"))?;
                    Some((record, next))
                } else { None };
                match self.heap.retain_selector_alias(allocation) {
                    Ok(()) => {
                        if let Some((record, next)) = module_root {
                            record.continuation_owner_refs = next;
                        }
                        Ok(Some(SelectorBackingLease::GlobalHeap {
                            allocation, module, ne_segment_flags,
                        }))
                    }
                    Err(error) => {
                        match error {
                            win16_abi::Win16Error::LockCountOverflow
                            | win16_abi::Win16Error::InvalidHandle
                            | win16_abi::Win16Error::StaleHandle => Ok(None),
                            other => Err(crate::runtime_error(other)
                                .with_context("retaining a GlobalHeap selector alias")),
                        }
                    }
                }
            }
            SelectorBackingIdentity::Dos { extent, primary } => {
                if dos.owned_block_containing_range(memory, base, usize::try_from(size)
                    .unwrap_or(usize::MAX)).map_err(crate::runtime_error)? != Some(extent)
                { return Ok(None); }
                let lease = if let Some(primary) = primary {
                    let (handle, block) = self.dos_global_blocks.iter()
                        .find(|(_, block)| block.extent == extent)
                        .ok_or_else(|| RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                            "DOS selector owner lost its GlobalDOSAlloc primary lease"))?;
                    if self.global_selectors.get(handle) != Some(&primary)
                        || self.selectors.reference_including_unbacked(primary.raw()).ok()
                            != Some(primary)
                        || block.lease.extent() != extent
                    {
                        return Err(RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                            "DOS alias owner no longer matches its exact GlobalDOSAlloc primary generation"));
                    }
                    if block.mcb_released { return Ok(None); }
                    dos.retain_block_lease(memory, &block.lease).map_err(crate::runtime_error)?
                } else {
                    let Some(lease) = dos.pin_block_for_range(memory, base,
                        usize::try_from(size).unwrap_or(usize::MAX)).map_err(crate::runtime_error)?
                    else { return Ok(None); };
                    if lease.extent() != extent {
                        return Err(RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                            "DOS selector pin resolved to a different MCB generation"));
                    }
                    lease
                };
                Ok(Some(SelectorBackingLease::Dos { lease, extent, primary }))
            }
            SelectorBackingIdentity::ModuleImage {
                module, primary, base: expected_base, size: expected_size, segment_flags,
            } => {
                if self.modules.records.get(&module).is_none_or(|record|
                    record.state == super::module_registry::ModuleState::Retired)
                { return Ok(None); }
                let descriptor = self.selectors.describe(primary).map_err(crate::runtime_error)?;
                let (head, image_base, image_size) = self.selectors.allocation_range(primary)
                    .map_err(crate::runtime_error)?;
                if !descriptor.present || head != primary || descriptor.base != image_base
                    || image_base != expected_base || image_size != expected_size
                    || !self.range_is_in_allocation_image(image_base, image_size, base, size)?
                { return Ok(None); }
                let record = self.modules.records.get_mut(&module).ok_or_else(||
                    RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                        "module-image owner disappeared before its continuation root was retained"))?;
                let next = record.continuation_owner_refs.checked_add(1).ok_or_else(||
                    RuntimeError::new(crate::DiagnosticKind::ResourceExhausted,
                        "module continuation owner reference count is exhausted"))?;
                record.continuation_owner_refs = next;
                Ok(Some(SelectorBackingLease::ModuleImage {
                    module, primary, base: image_base, size: image_size, segment_flags,
                }))
            }
            SelectorBackingIdentity::RuntimeArena(arena) => {
                if !self.backing_identity_covers(
                    SelectorBackingIdentity::RuntimeArena(arena), base, size, dos, memory,
                )? {
                    return Ok(None);
                }
                let Some(lease) = self.runtime_arena_backing.retain(
                    arena, reference, base, size, &self.selectors, memory,
                )? else { return Ok(None); };
                Ok(Some(SelectorBackingLease::RuntimeArena { lease }))
            }
        }
    }

    /// CPU frames own a distinct token from aliases in the selector map so
    /// selector mutation and arena teardown can see the live architectural root.
    pub(super) fn retain_legacy_cpu_selector_backing(
        &mut self,
        reference: SelectorRef,
        identity: SelectorBackingIdentity,
        base: PhysAddr,
        size: u32,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<Option<SelectorBackingLease>, RuntimeError> {
        if let SelectorBackingIdentity::FirmwareRom { primary, base: rom_base, size: rom_size } = identity {
            return Ok((reference == primary && base == rom_base && size == rom_size
                && self.firmware_rom_identity_is_live(identity, memory))
                .then_some(SelectorBackingLease::FirmwareRom { primary, base, size }));
        }
        let SelectorBackingIdentity::RuntimeArena(arena) = identity else {
            return self.retain_selector_backing(reference, identity, base, size, dos, memory);
        };
        if size == 0
            || self.selectors.reference_including_unbacked(reference.raw()).ok() != Some(reference)
            || !self.backing_identity_covers(
                SelectorBackingIdentity::RuntimeArena(arena), base, size, dos, memory,
            )?
        {
            return Ok(None);
        }
        let Some(lease) = self.runtime_arena_backing.retain_frame_root(
            arena, reference, base, size, &self.selectors, memory,
        )? else { return Ok(None); };
        Ok(Some(SelectorBackingLease::RuntimeArena { lease }))
    }

    fn range_is_in_allocation_image(
        &self,
        image_base: PhysAddr,
        image_size: u32,
        base: PhysAddr,
        size: u32,
    ) -> Result<bool, RuntimeError> {
        let start = u64::from(base.0);
        let end = start.checked_add(u64::from(size)).ok_or_else(|| RuntimeError::new(
            crate::DiagnosticKind::InvalidInput, "module-image selector range overflowed"))?;
        let image_start = u64::from(image_base.0);
        let image_end = image_start.checked_add(u64::from(image_size)).ok_or_else(||
            RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "module-image allocation extent overflowed"))?;
        Ok(start >= image_start && end <= image_end)
    }

    pub(super) fn release_selector_lease(
        &mut self,
        lease: &SelectorBackingLease,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let module = lease.module();
        match lease {
            SelectorBackingLease::GlobalHeap { allocation, module, .. } => {
                let module_id = *module;
                // Preflight the module decrement and keep its exact record
                // borrowed while releasing the matching alias. The stored
                // lease remains retryable when the heap release fails.
                let module_root = if let Some(module) = module_id {
                    let record = self.modules.records.get_mut(&module).ok_or_else(||
                        RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                            "GlobalHeap selector lease lost its module owner before release"))?;
                    let next = record.continuation_owner_refs.checked_sub(1).ok_or_else(||
                        RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                            "module continuation owner reference count underflowed"))?;
                    Some((record, next))
                } else { None };
                self.heap.release_selector_alias(*allocation).map_err(crate::runtime_error)?;
                if let Some((record, next)) = module_root {
                    record.continuation_owner_refs = next;
                }
            }
            SelectorBackingLease::Dos { lease, .. } => {
                dos.release_block_lease(memory, lease, false).map_err(crate::runtime_error)?;
            }
            SelectorBackingLease::ModuleImage { module, .. } => {
                let record = self.modules.records.get_mut(module).ok_or_else(||
                    RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                        "module-image continuation owner lost its module record before release"))?;
                let next = record.continuation_owner_refs.checked_sub(1).ok_or_else(||
                    RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                        "module continuation owner reference count underflowed"))?;
                record.continuation_owner_refs = next;
            }
            // ROM belongs to the machine Memory for its entire lifetime. No
            // allocator pin is released. Privileged initialize_rom may still
            // change bytes; this contract preserves ownership, not byte identity.
            SelectorBackingLease::FirmwareRom { .. } => {}
            SelectorBackingLease::RuntimeArena { lease } => {
                self.runtime_arena_backing.release(lease)?;
            }
        }
        if module.is_some() { self.module_reap_pending = true; }
        Ok(())
    }

    pub(super) fn release_selector_backing(
        &mut self,
        reference: SelectorRef,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let raw = reference.raw().0;
        let Some(mut entry) = self.selector_backing_leases.remove(&raw) else { return Ok(()); };
        if entry.reference != reference {
            self.selector_backing_leases.insert(raw, entry);
            return Err(RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "selector release did not match its retained generation"));
        }
        while let Some(lease) = entry.leases.pop() {
            if let Err(error) = self.release_selector_lease(&lease, dos, memory) {
                entry.leases.push(lease);
                self.selector_backing_leases.insert(raw, entry);
                return Err(error);
            }
        }
        self.forget_mapls_selector(reference);
        Ok(())
    }

    pub(super) fn release_all_selector_backing(
        &mut self,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let mut references = Vec::new();
        references.try_reserve_exact(self.selector_backing_leases.len()).map_err(|error| {
            RuntimeError::with_source(crate::DiagnosticKind::ResourceExhausted,
                "reserve process selector-backing release snapshot", error)
        })?;
        references.extend(self.selector_backing_leases.values().map(|entry| entry.reference));
        for reference in references { self.retire_selector_with_backing(reference, dos, memory)?; }
        Ok(())
    }

    fn retire_selector_with_backing(
        &mut self,
        reference: SelectorRef,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let raw = reference.raw().0;
        if self.selectors.reference_including_unbacked(Selector(raw)).ok() == Some(reference) {
            let result = if self.api_allocated_selectors.get(&raw) == Some(&reference) {
                self.selectors.free_block(reference)
            } else {
                self.selectors.free_selector(reference)
            };
            match result {
                Ok(()) | Err(win16_abi::Win16Error::StaleSelector) => {}
                Err(error) => return Err(crate::runtime_error(error)
                    .with_context("retiring a selector whose guest backing is ending")),
            }
        }
        if self.api_allocated_selectors.get(&raw) == Some(&reference) {
            self.api_allocated_selectors.remove(&raw);
        }
        if self.allocated_selector_aliases.get(&raw) == Some(&reference) {
            self.allocated_selector_aliases.remove(&raw);
        }
        self.forget_mapls_selector(reference);
        self.release_selector_backing(reference, dos, memory)
    }
}
