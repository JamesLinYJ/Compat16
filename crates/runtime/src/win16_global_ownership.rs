//! Guest-owner operations and module provenance for global memory.

use guest_core::{memory::Memory, Selector};
use win16_abi::GuestMemoryOwner;

use super::{module_registry::ModuleState, Win16State};
use crate::RuntimeError;

impl Win16State {
    /// Apply GlobalFreeAll to blocks with the supplied Win16 guest owner.
    /// Guest owner words remain separate from internal allocator OwnerIds.
    pub(super) fn kernel_global_free_all(
        &mut self,
        owner_handle: u16,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let mut handles = Vec::new();
        handles.try_reserve_exact(self.global_handles.len()).map_err(|error| {
            RuntimeError::with_source(crate::DiagnosticKind::ResourceExhausted,
                "allocate Win16 GlobalFreeAll handle snapshot", error)
        })?;
        for (&guest_handle, &identity) in &self.global_handles {
            let info = self.heap.info(identity).map_err(crate::runtime_error)?;
            if info.guest_owner.is_some_and(|owner| owner.raw() == owner_handle) {
                handles.push(guest_handle);
            }
        }
        for guest_handle in handles {
            let _ = self.global_free(guest_handle)?;
        }

        let mut dos_handles = Vec::new();
        dos_handles.try_reserve_exact(self.dos_global_blocks.len()).map_err(|error| {
            RuntimeError::with_source(crate::DiagnosticKind::ResourceExhausted,
                "allocate Win16 GlobalFreeAll DOS handle snapshot", error)
        })?;
        for (&selector, block) in &self.dos_global_blocks {
            if block.guest_owner.raw() == owner_handle { dos_handles.push(selector); }
        }
        for selector in dos_handles {
            let _ = self.kernel_global_dos_free(selector, dos, memory)?;
        }
        Ok(())
    }

    pub(super) fn kernel_far_set_owner(
        &mut self,
        guest_handle: u16,
        owner_handle: u16,
    ) -> Result<(), RuntimeError> {
        if let Some(block) = self.dos_global_blocks.get_mut(&guest_handle) {
            block.guest_owner = GuestMemoryOwner::from_raw(owner_handle);
            return Ok(());
        }
        let Some(identity) = self.global_handles.get(&guest_handle).copied() else {
            return Ok(());
        };
        self.heap.set_guest_owner(identity, GuestMemoryOwner::from_raw(owner_handle))
            .map_err(crate::runtime_error)
    }

    pub(super) fn kernel_far_get_owner(&self, guest_handle: u16) -> u16 {
        if let Some(block) = self.dos_global_blocks.get(&guest_handle) {
            return block.guest_owner.raw();
        }
        self.global_handles.get(&guest_handle).copied()
            .and_then(|identity| self.heap.guest_owner(identity).ok().flatten())
            .map_or(0, GuestMemoryOwner::raw)
    }

    pub(super) fn kernel_global_change_lock_count(
        &mut self,
        guest_handle: u16,
        delta: i16,
        memory: &Memory,
    ) -> Result<(), RuntimeError> {
        match delta {
            1 => { let _ = self.global_lock(guest_handle, memory)?; }
            -1 => { let _ = self.global_unlock(guest_handle)?; }
            _ => {}
        }
        Ok(())
    }

    /// Resolve DDESHARE ownership from a current executable descriptor and an
    /// exact loaded module segment. Main-image code is loader-arena-owned and
    /// does not acquire a fabricated GlobalHeap handle or pin.
    pub(super) fn live_code_module_owner(&self, code_selector: u16) -> Option<u16> {
        if code_selector == 0 { return None; }
        let current_ref = self.selectors.reference(Selector(code_selector)).ok()?;
        let current = self.selectors.describe(current_ref).ok()?;
        if !current.present || !current.rights.executable() { return None; }
        let current_start = u64::from(current.base.0);
        let current_end = current_start.checked_add(u64::from(current.limit) + 1)?;

        for (&owner, record) in &self.modules.records {
            if record.state == ModuleState::Retired || record.external_application.is_some() {
                continue;
            }
            let Some(definition) = record.definition.as_ref() else { continue; };
            let segments = if owner == self.modules.main {
                &self.loaded.segments
            } else if let Some(loaded) = record.loaded.as_ref() {
                &loaded.segments
            } else {
                continue;
            };
            for segment in segments {
                let Some(segment_definition) = definition.segments.iter()
                    .find(|candidate| candidate.number == segment.number)
                else { continue; };
                // NE_SEGFLAGS_DATA: code-sharing ownership only comes from a
                // code segment, even if guest selector rights were retagged.
                if segment_definition.flags & 0x0001 != 0 { continue; }
                let Some(primary) = (if owner == self.modules.main {
                    self.selectors.reference(Selector(segment.selector.0)).ok()
                } else {
                    record.allocations.iter()
                        .find(|allocation| allocation.selector.raw().0 == segment.selector.0)
                        .map(|allocation| allocation.selector)
                }) else { continue; };
                let Ok(descriptor) = self.selectors.describe(primary) else { continue; };
                if !descriptor.present || !descriptor.rights.executable() { continue; }
                let start = u64::from(descriptor.base.0);
                let end = start.checked_add(u64::from(descriptor.limit) + 1)?;
                if current_start < start || current_end > end { continue; }

                let owner_matches_backing = self.selector_backing_leases
                    .get(&current_ref.raw().0)
                    .filter(|entry| entry.reference == current_ref)
                    .is_some_and(|entry| entry.leases.iter().any(|lease| {
                        if lease.module() != Some(owner) { return false; }
                        match lease {
                            super::selector_ownership::SelectorBackingLease::GlobalHeap {
                                allocation, ..
                            } => self.heap.info(*allocation).is_ok_and(|info| {
                                if info.discarded || info.size == 0 { return false; }
                                let base = u64::from(info.base.0);
                                let end = base + u64::from(info.size);
                                current_start >= base && current_end <= end
                            }),
                            super::selector_ownership::SelectorBackingLease::ModuleImage {
                                module, primary: source, base, size, ..
                            } => *module == owner && *source == primary
                                && current_start >= u64::from(base.0)
                                && current_end <= u64::from(base.0) + u64::from(*size),
                            super::selector_ownership::SelectorBackingLease::Dos { .. } => false,
                            super::selector_ownership::SelectorBackingLease::RuntimeArena { .. } => false,
                        }
                    }));
                if current_ref == primary || owner_matches_backing { return Some(owner); }
            }
        }
        None
    }
}
