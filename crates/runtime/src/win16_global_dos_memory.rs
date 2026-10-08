//! KERNEL GlobalDOSAlloc storage lifecycle over the guest DOS MCB arena.

use guest_core::memory::Memory;
use win16_abi::{AccessRights, GuestMemoryOwner, SelectorAllocationView, SelectorRef, Win16Error};

use super::{Win16DosGlobalBlock, Win16State, selector_ownership::{SelectorBackingIdentity, SelectorBackingLease}};
use crate::{DiagnosticKind as Kind, RuntimeError};

impl Win16State {
    /// Allocate conventional-memory paragraphs and expose a protected selector
    /// in the Win16 GlobalDOSAlloc DWORD result.
    pub(super) fn kernel_global_dos_alloc(
        &mut self,
        requested_size: u32,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        if requested_size == 0 { return Ok(0); }
        let Some(size) = requested_size.checked_add(31).map(|value| value & !31)
            .filter(|size| *size != 0) else { return Ok(0); };
        let paragraphs = match u16::try_from(size / 16) {
            Ok(value) if value != 0 => value,
            _ => return Ok(0),
        };
        let dos_owner_psp = dos.psp_segment();
        if dos_owner_psp == 0 { return Ok(0); }
        self.orphaned_dos_leases.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(crate::DiagnosticKind::ResourceExhausted,
                "reserve Win16 DOS lease rollback storage", error)
        })?;
        let lease = match dos.allocate_pinned_block(memory, dos_owner_psp, paragraphs) {
            Ok(lease) => lease,
            Err(dos_kernel::DosError::HostOperation(error))
                if error.code == dos_kernel::DosErrorCode::InsufficientMemory => return Ok(0),
            Err(error) => return Err(crate::runtime_error(error)
                .with_context("allocating Win16 GlobalDOSAlloc conventional memory")),
        };
        let extent = lease.extent();
        let paragraph_segment = extent.data_segment();
        let exact_size = extent.byte_length().and_then(|bytes| u32::try_from(bytes).ok());
        let Some(size) = exact_size.filter(|actual_size| *actual_size >= size) else {
            self.rollback_dos_global_allocation(dos, memory, lease)?;
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 GlobalDOSAlloc MCB extent is smaller than its requested backing"));
        };
        let Some(base) = extent.guest_base() else {
            self.rollback_dos_global_allocation(dos, memory, lease)?;
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 GlobalDOSAlloc MCB extent has no linear guest base"));
        };
        let selector = match self.selectors.alloc_block(
            base, size, AccessRights::read_write(), memory,
        ) {
            Ok(selector) => selector,
            Err(Win16Error::SelectorTableFull | Win16Error::OutOfMemory) => {
                self.rollback_dos_global_allocation(dos, memory, lease)?;
                return Ok(0);
            }
            Err(error) => {
                self.rollback_dos_global_allocation(dos, memory, lease)?;
                return Err(crate::runtime_error(error)
                    .with_context("creating Win16 GlobalDOSAlloc selector"));
            }
        };
        let guest_handle = selector.raw().0;
        if guest_handle == 0 || self.global_handles.contains_key(&guest_handle)
            || self.dos_global_blocks.contains_key(&guest_handle)
            || self.global_selectors.contains_key(&guest_handle)
        {
            if let Err(error) = self.selectors.free_block(selector) {
                self.orphaned_dos_leases.push(lease);
                return Err(crate::runtime_error(error)
                    .with_context("retiring collided Win16 GlobalDOSAlloc selector"));
            }
            self.rollback_dos_global_allocation(dos, memory, lease)?;
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 GlobalDOSAlloc selector collided with an existing HGLOBAL"));
        }
        let Some(kernel_module) = self.modules.by_name(b"KERNEL") else {
            if let Err(error) = self.selectors.free_block(selector) {
                self.orphaned_dos_leases.push(lease);
                return Err(crate::runtime_error(error)
                    .with_context("retiring Win16 GlobalDOSAlloc selector without KERNEL owner"));
            }
            self.rollback_dos_global_allocation(dos, memory, lease)?;
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 GlobalDOSAlloc cannot resolve the KERNEL module owner"));
        };
        self.global_selectors.insert(guest_handle, selector);
        self.dos_global_blocks.insert(guest_handle, Win16DosGlobalBlock {
            lease,
            extent,
            size,
            guest_owner: GuestMemoryOwner::from_raw(kernel_module),
            page_lock_count: 0,
            fix_count: 0,
            wire_count: 0,
            suspended_views: None,
            alias_release_started: false,
            mcb_released: false,
            mcb_release_uncertain: false,
        });
        Ok(u32::from(guest_handle) | (u32::from(paragraph_segment) << 16))
    }

    fn rollback_dos_global_allocation(
        &mut self,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        lease: dos_kernel::DosBlockLease,
    ) -> Result<(), RuntimeError> {
        match dos.release_block_lease(memory, &lease, true) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.orphaned_dos_leases.push(lease);
                Err(crate::runtime_error(error)
                    .with_context("rolling back Win16 GlobalDOSAlloc MCB lease"))
            }
        }
    }

    /// Suspend every exact selector-generation view before releasing the MCB.
    /// Only creation-time alias tokens may be released; a missing or unknown
    /// view leaves the primary allocation intact for Root composition.
    pub(super) fn kernel_global_dos_free(
        &mut self,
        selector_word: u16,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Some(block) = self.dos_global_blocks.get(&selector_word) else {
            return Ok(selector_word);
        };
        let extent = block.extent;
        let size = block.size;
        let mcb_released = block.mcb_released;
        let alias_release_started = block.alias_release_started;
        if block.mcb_release_uncertain {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 GlobalDOSAlloc MCB release rollback left backing state uncertain; selector views remain suspended"));
        }
        if !mcb_released
            && (block.page_lock_count != 0 || block.fix_count != 0 || block.wire_count != 0)
        { return Ok(selector_word); }
        let Some(selector) = self.global_selectors.get(&selector_word).copied() else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 GlobalDOSAlloc selector mapping is missing"));
        };
        self.selectors.describe(selector).map_err(crate::runtime_error)?;
        let Some(views) = self.suspend_or_resume_dos_views(selector_word, extent, size)? else {
            return Ok(selector_word);
        };
        self.selectors.validate_suspended_allocation_views(&views)
            .map_err(crate::runtime_error)?;
        if !views.iter().any(|view| view.reference() == selector) {
            if !mcb_released && !alias_release_started {
                self.resume_dos_global_views(selector_word, &views)?;
            }
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 GlobalDOSAlloc primary selector is absent from its suspended view set"));
        }
        if !mcb_released {
            if !alias_release_started
                && !self.release_detached_dos_alias_leases(extent, &views, dos, memory)?
            {
                self.resume_dos_global_views(selector_word, &views)?;
                return Ok(selector_word);
            }
            if !alias_release_started
                && !self.preflight_dos_global_views(selector, extent, &views, dos, memory)?
            {
                self.resume_dos_global_views(selector_word, &views)?;
                return Ok(selector_word);
            }
            // From this point until backing release or pin restoration, views
            // stay suspended. A retry can distinguish tokens already consumed
            // from the exact captured generation set without resuming aliases
            // whose MCB pin was dropped.
            self.dos_global_blocks.get_mut(&selector_word)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "Win16 DOS global block disappeared before alias retirement"))?
                .alias_release_started = true;
            self.release_dos_alias_leases(extent, dos, memory)?;
            if !self.release_dos_primary_lease(selector_word, selector, &views, dos, memory)? {
                return Ok(selector_word);
            }
        }
        self.retire_released_dos_views(selector_word, selector, &views, dos, memory)?;
        Ok(0)
    }

    fn suspend_or_resume_dos_views(
        &mut self,
        selector_word: u16,
        extent: dos_kernel::DosBlockExtent,
        size: u32,
    ) -> Result<Option<Vec<SelectorAllocationView>>, RuntimeError> {
        if let Some(views) = self.dos_global_blocks.get(&selector_word)
            .and_then(|block| block.suspended_views.as_ref())
        {
            return Ok(Some(views.clone()));
        }
        let base = extent.guest_base().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 DOS global MCB extent has no guest base",
        ))?;
        let views = match self.selectors.suspend_allocation_views(base, size) {
            Ok(views) => views,
            Err(Win16Error::SelectorBlockInterior | Win16Error::OutOfMemory
                | Win16Error::InvalidRange) => return Ok(None),
            Err(error) => return Err(crate::runtime_error(error)
                .with_context("suspending Win16 GlobalDOSAlloc selector views")),
        };
        self.dos_global_blocks.get_mut(&selector_word)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "Win16 DOS global block disappeared after view suspension"))?
            .suspended_views = Some(views.clone());
        Ok(Some(views))
    }

    fn preflight_dos_global_views(
        &self,
        primary: SelectorRef,
        extent: dos_kernel::DosBlockExtent,
        views: &[SelectorAllocationView],
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        for view in views {
            let reference = view.reference();
            let descriptor = self.selectors.describe(reference).map_err(crate::runtime_error)?;
            let view_size = self.selectors.allocation_size(reference)
                .map_err(crate::runtime_error)?;
            let contained = dos.owned_block_containing_range(
                memory, descriptor.base, usize::try_from(view_size).unwrap_or(usize::MAX),
            ).map_err(crate::runtime_error)? == Some(extent);
            if !contained { return Ok(false); }
            if reference == primary { continue; }
            let raw = reference.raw().0;
            if self.allocated_selector_aliases.get(&raw) != Some(&reference)
                && self.api_allocated_selectors.get(&raw) != Some(&reference)
            { return Ok(false); }
            let Some(entry) = self.selector_backing_leases.get(&raw)
                .filter(|entry| entry.reference == reference && entry.leases.len() == 1)
            else { return Ok(false); };
            let Some(SelectorBackingLease::Dos { lease: pin, extent: owner_extent,
                primary: Some(owner_primary) }) = entry.leases.first()
            else { return Ok(false); };
            if *owner_extent != extent || *owner_primary != primary || pin.extent() != extent {
                return Ok(false);
            }
            if dos.block_lease_is_last_pin(memory, pin).map_err(crate::runtime_error)? {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 DOS alias lease is not accompanied by its primary lease"));
            }
        }
        let has_live_alias_view = views.iter().any(|view| view.reference() != primary);
        let has_uncaptured_lease = self.selector_backing_leases.values().any(|entry| {
            entry.leases.iter().any(|lease| matches!(lease,
                SelectorBackingLease::Dos { extent: owner_extent, .. } if *owner_extent == extent))
                && !views.iter().any(|view| view.reference() == entry.reference)
        });
        // A live alias remains guest-visible even while temporarily suspended
        // for inspection. GlobalDOSFree is retryably busy until that exact
        // alias generation is explicitly unmapped/freed by its owner.
        Ok(!has_live_alias_view && !has_uncaptured_lease)
    }

    /// Release only DOS tokens whose exact selector generation no longer
    /// overlaps this MCB. A live untracked overlap stays busy; extent overlap
    /// is only a conservative safety test, never selector provenance.
    fn release_detached_dos_alias_leases(
        &mut self,
        extent: dos_kernel::DosBlockExtent,
        views: &[SelectorAllocationView],
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        let extent_start = u64::from(extent.guest_base().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 DOS global MCB extent has no linear base",
        ))?.0);
        let extent_size = extent.byte_length().and_then(|size| u64::try_from(size).ok())
            .ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 DOS global MCB extent length overflows",
        ))?;
        let extent_end = extent_start.checked_add(extent_size).ok_or_else(||
            RuntimeError::new(Kind::InternalInvariant,
                "Win16 DOS global MCB end address overflows"))?;
        let count = self.selector_backing_leases.values().filter(|entry|
            entry.leases.iter().any(|lease| matches!(lease,
                SelectorBackingLease::Dos { extent: candidate, .. } if *candidate == extent)))
            .count();
        let mut references = Vec::new();
        references.try_reserve_exact(count).map_err(|error| RuntimeError::with_source(
            crate::DiagnosticKind::ResourceExhausted,
            "reserve detached DOS selector lease scan", error,
        ))?;
        for entry in self.selector_backing_leases.values() {
            if entry.leases.iter().any(|lease| matches!(lease,
                SelectorBackingLease::Dos { extent: candidate, .. } if *candidate == extent))
            {
                references.push(entry.reference);
            }
        }
        for reference in references {
            if views.iter().any(|view| view.reference() == reference) { continue; }
            let current_generation = self.selectors.reference_including_unbacked(
                reference.raw(),
            ).ok() == Some(reference);
            let still_maps_extent = match self.selectors.describe(reference) {
                Ok(descriptor) if descriptor.present => {
                    let (_, base, size) = self.selectors.allocation_range(reference)
                        .map_err(crate::runtime_error)?;
                    let start = u64::from(base.0);
                    let Some(end) = start.checked_add(u64::from(size)) else { return Ok(false); };
                    start < extent_end && extent_start < end
                }
                Ok(_) | Err(Win16Error::InvalidSelector | Win16Error::StaleSelector
                    | Win16Error::ForeignSelector) => false,
                Err(error) => return Err(crate::runtime_error(error)),
            };
            if still_maps_extent { return Ok(false); }
            let raw = reference.raw().0;
            let Some(mut entry) = self.selector_backing_leases.remove(&raw) else { continue; };
            if entry.reference != reference {
                self.selector_backing_leases.insert(raw, entry);
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "detached DOS lease belongs to a stale selector generation"));
            }
            let mut index = 0;
            while index < entry.leases.len() {
                if !matches!(&entry.leases[index], SelectorBackingLease::Dos {
                    extent: candidate, ..
                } if *candidate == extent) {
                    index += 1;
                    continue;
                }
                let lease = entry.leases.remove(index);
                if let Err(error) = self.release_selector_lease(&lease, dos, memory) {
                    entry.leases.insert(index, lease);
                    self.selector_backing_leases.insert(raw, entry);
                    return Err(error.with_context(
                        "releasing a detached Win16 DOS selector alias lease"));
                }
            }
            if !entry.leases.is_empty() {
                self.selector_backing_leases.insert(raw, entry);
            } else if !current_generation {
                if self.allocated_selector_aliases.get(&raw) == Some(&reference) {
                    self.allocated_selector_aliases.remove(&raw);
                }
                if self.api_allocated_selectors.get(&raw) == Some(&reference) {
                    self.api_allocated_selectors.remove(&raw);
                }
                self.forget_mapls_selector(reference);
            }
        }
        Ok(true)
    }

    fn release_dos_alias_leases(
        &mut self,
        extent: dos_kernel::DosBlockExtent,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let count = self.selector_backing_leases.values().filter(|entry|
            entry.leases.iter().any(|lease| matches!(lease,
                SelectorBackingLease::Dos { extent: candidate, .. } if *candidate == extent)))
            .count();
        let mut references = Vec::new();
        references.try_reserve_exact(count).map_err(|error| RuntimeError::with_source(
            crate::DiagnosticKind::ResourceExhausted,
            "reserve DOS alias lease release snapshot", error,
        ))?;
        for entry in self.selector_backing_leases.values() {
            if entry.leases.iter().any(|lease| matches!(lease,
                SelectorBackingLease::Dos { extent: candidate, .. } if *candidate == extent))
            {
                references.push(entry.reference);
            }
        }
        for reference in references {
            let raw = reference.raw().0;
            let Some(mut entry) = self.selector_backing_leases.remove(&raw) else { continue; };
            if entry.reference != reference {
                self.selector_backing_leases.insert(raw, entry);
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "DOS alias retirement found a stale selector generation"));
            }
            // This exact view is suspended and its active owner was validated
            // against the MCB extent. Any remaining leases belong to its
            // earlier retarget phase; release them under the same canonical
            // selector record before the MCB can be freed.
            while let Some(lease) = entry.leases.pop() {
                if let Err(error) = self.release_selector_lease(&lease, dos, memory) {
                    entry.leases.push(lease);
                    self.selector_backing_leases.insert(raw, entry);
                    return Err(error.with_context(
                        "releasing a DOS selector alias lease while its views are suspended"));
                }
            }
        }
        Ok(())
    }

    fn release_dos_primary_lease(
        &mut self,
        selector_word: u16,
        selector: SelectorRef,
        views: &[SelectorAllocationView],
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        let primary_is_last = {
            let block = self.dos_global_blocks.get(&selector_word).ok_or_else(||
                RuntimeError::new(Kind::InternalInvariant,
                    "Win16 DOS global block disappeared during free preflight"))?;
            dos.block_lease_is_last_pin(memory, &block.lease).map_err(crate::runtime_error)?
        };
        if !primary_is_last {
            self.restore_dos_selector_alias_leases(selector_word, selector, views, dos, memory)?;
            self.dos_global_blocks.get_mut(&selector_word)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "Win16 DOS global block disappeared after alias pin restoration"))?
                .alias_release_started = false;
            self.resume_dos_global_views(selector_word, views)?;
            return Ok(false);
        }
        let release = {
            let block = self.dos_global_blocks.get(&selector_word).ok_or_else(||
                RuntimeError::new(Kind::InternalInvariant,
                    "Win16 DOS global block disappeared before MCB free"))?;
            dos.release_block_lease(memory, &block.lease, true)
        };
        if let Err(error) = release {
            if matches!(&error, dos_kernel::DosError::RollbackFailure { .. }) {
                self.dos_global_blocks.get_mut(&selector_word)
                    .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                        "Win16 DOS global block disappeared after uncertain MCB rollback"))?
                    .mcb_release_uncertain = true;
                return Err(crate::runtime_error(error).with_context(
                    "GlobalDOSAlloc MCB rollback failed; exact selector views remain suspended"));
            }
            if let Err(restore_error) = self.restore_dos_selector_alias_leases(
                selector_word, selector, views, dos, memory,
            ) {
                let primary = crate::runtime_error(error)
                    .with_context("freeing Win16 GlobalDOSAlloc MCB lease");
                return Err(primary.with_cleanup(
                    "restoring exact DOS selector alias pins after the primary MCB release failed",
                    restore_error,
                ));
            }
            self.dos_global_blocks.get_mut(&selector_word)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "Win16 DOS global block disappeared after alias pin restoration"))?
                .alias_release_started = false;
            self.resume_dos_global_views(selector_word, views)?;
            return Err(crate::runtime_error(error)
                .with_context("freeing Win16 GlobalDOSAlloc MCB lease"));
        }
        self.dos_global_blocks.get_mut(&selector_word)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "Win16 DOS global block disappeared after MCB free"))?
            .mcb_released = true;
        Ok(true)
    }

    fn retire_released_dos_views(
        &mut self,
        selector_word: u16,
        primary: SelectorRef,
        views: &[SelectorAllocationView],
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let mut owned_blocks = Vec::new();
        owned_blocks.try_reserve_exact(views.len()).map_err(|error| {
            RuntimeError::with_source(crate::DiagnosticKind::ResourceExhausted,
                "reserve Win16 DOS selector retirement set", error)
        })?;
        owned_blocks.push(primary);
        for view in views {
            let reference = view.reference();
            let raw = reference.raw().0;
            if reference != primary && (self.allocated_selector_aliases.get(&raw) == Some(&reference)
                || self.api_allocated_selectors.get(&raw) == Some(&reference))
            { owned_blocks.push(reference); }
        }
        // Suspended views are inaccessible to the guest. Release their
        // canonical owner records only after the MCB release has succeeded,
        // and before discarding the generation snapshots needed below.
        for reference in owned_blocks.iter().skip(1).copied() {
            self.release_selector_backing(reference, dos, memory)?;
        }
        let updates = self.selectors.retire_suspended_allocation_views(views, &owned_blocks)
            .map_err(crate::runtime_error)?;
        self.apply_selector_updates(&updates);
        for reference in owned_blocks.iter().skip(1) {
            let raw = reference.raw().0;
            if self.allocated_selector_aliases.get(&raw) == Some(reference) {
                self.allocated_selector_aliases.remove(&raw);
            }
            if self.api_allocated_selectors.get(&raw) == Some(reference) {
                self.api_allocated_selectors.remove(&raw);
            }
            self.forget_mapls_selector(*reference);
        }
        self.global_selectors.remove(&selector_word);
        self.dos_global_blocks.remove(&selector_word);
        Ok(())
    }

    fn restore_dos_selector_alias_leases(
        &mut self,
        selector_word: u16,
        primary: SelectorRef,
        views: &[SelectorAllocationView],
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let extent = self.dos_global_blocks.get(&selector_word)
            .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                "Win16 DOS global block disappeared before alias pin restoration"))?
            .extent;
        for view in views {
            let reference = view.reference();
            if reference == primary { continue; }
            let raw = reference.raw().0;
            if self.allocated_selector_aliases.get(&raw) != Some(&reference)
                && self.api_allocated_selectors.get(&raw) != Some(&reference)
            {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "captured DOS selector view lost its KERNEL allocation owner"));
            }
            let Some(entry) = self.selector_backing_leases.get(&raw) else {
                // The DOS alias tokens were deliberately released before
                // testing whether a third-party lease still owns the MCB.
                // Reacquire through the one canonical selector map.
                let identity = SelectorBackingIdentity::Dos { extent, primary: Some(primary) };
                let descriptor = self.selectors.describe(reference).map_err(crate::runtime_error)?;
                let Some(size) = descriptor.limit.checked_add(1) else {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "suspended DOS selector range overflowed during owner restoration"));
                };
                let mut leases = Vec::new();
                leases.try_reserve_exact(1).map_err(|error| RuntimeError::with_source(
                    crate::DiagnosticKind::ResourceExhausted,
                    "reserve canonical DOS selector alias lease", error,
                ))?;
                let Some(lease) = self.retain_selector_backing(
                    reference, identity, descriptor.base, size, dos, memory,
                )?
                else { return Err(RuntimeError::new(Kind::ResourceExhausted,
                    "Win16 DOS selector alias could not restore its MCB owner pin")); };
                leases.push(lease);
                self.selector_backing_leases.insert(raw,
                    super::selector_ownership::SelectorBackingEntry { reference, leases });
                continue;
            };
            if entry.reference != reference {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "suspended DOS selector view has a stale canonical generation"));
            }
            if entry.leases.iter().any(|lease| matches!(lease,
                SelectorBackingLease::Dos { extent: candidate, primary: Some(owner), .. }
                    if *candidate == extent && *owner == primary))
            { continue; }
            self.selector_backing_leases.get_mut(&raw)
                .ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
                    "DOS alias backing record disappeared before pin reservation"))?
                .leases.try_reserve(1).map_err(|error| RuntimeError::with_source(
                    crate::DiagnosticKind::ResourceExhausted,
                    "reserve canonical DOS selector alias lease", error,
                ))?;
            let identity = SelectorBackingIdentity::Dos { extent, primary: Some(primary) };
            let descriptor = self.selectors.describe(reference).map_err(crate::runtime_error)?;
            let Some(size) = descriptor.limit.checked_add(1) else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "suspended DOS selector range overflowed during owner restoration"));
            };
            let Some(lease) = self.retain_selector_backing(
                reference, identity, descriptor.base, size, dos, memory,
            )?
            else { return Err(RuntimeError::new(Kind::ResourceExhausted,
                "Win16 DOS selector alias could not restore its MCB owner pin")); };
            let Some(entry) = self.selector_backing_leases.get_mut(&raw) else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "DOS alias backing record disappeared during pin restoration"));
            };
            entry.leases.insert(0, lease);
        }
        Ok(())
    }

    fn resume_dos_global_views(
        &mut self,
        selector_word: u16,
        views: &[SelectorAllocationView],
    ) -> Result<(), RuntimeError> {
        self.selectors.resume_allocation_views(views).map_err(crate::runtime_error)?;
        if let Some(block) = self.dos_global_blocks.get_mut(&selector_word) {
            block.suspended_views = None;
        }
        Ok(())
    }
}
