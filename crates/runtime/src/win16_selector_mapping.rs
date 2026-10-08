//! MapSL/MapLS selector views and their reference-counted guest mappings.

use guest_core::{PhysAddr, Selector};
use guest_core::memory::Memory;
use win16_abi::{AccessRights, Win16Error};

use super::selector::MAX_SELECTOR_BYTES;
use super::selector_errors::{canonical_selector, selector_allocation_failure};
use super::{Win16State, selector_ownership};
use crate::RuntimeError;

impl Win16State {
    pub(super) fn is_shared_selector(&self, selector: u16) -> u16 {
        let canonical = canonical_selector(selector);
        // A selector alias keeps its owning module identity when it is made.
        // Resolve DDESHARE from that HMODULE instead of inferring ownership
        // from a raw CS word after the descriptor has been copied.
        let current = self.selectors.reference(Selector(selector)).ok();
        let alias_owner = current.and_then(|reference| self.selector_backing_leases
            .get(&canonical)
            .filter(|entry| entry.reference == reference)
            .and_then(|entry| entry.leases.first())
            .and_then(selector_ownership::SelectorBackingLease::module));
        let owner = alias_owner.or_else(|| self.modules.retained_owner(canonical, &self.selectors));
        let Some(owner) = owner else {
            return 0;
        };
        u16::from(self.modules.records.get(&owner)
            .and_then(|record| record.definition.as_ref())
            .is_some_and(|definition| definition.header.flags & 0x8000 != 0))
    }

    pub(super) fn map_sl(
        &mut self,
        far_pointer: u32,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        let selector = (far_pointer >> 16) as u16;
        let offset = (far_pointer & 0xffff) as u16;
        // The compared selector helper treats a clear TI bit as an already-linear
        // selector form and returns its offset without consulting the table.
        if selector & 0x0004 == 0 {
            return Ok(u32::from(offset));
        }
        let Ok(reference) = self.selectors.reference(Selector(selector)) else {
            return Ok(0);
        };
        let Ok(descriptor) = self.selectors.describe(reference) else {
            return Ok(0);
        };
        if !descriptor.present || u32::from(offset) > descriptor.limit {
            return Ok(0);
        }
        // Any valid guest LDT descriptor can map back to a guest-linear view;
        // no host address leaves this checked GuestMemory translation.
        if self.selector_backing_lease(reference, dos, memory)?.is_none() {
            return Ok(0);
        }
        Ok(descriptor.base.0.checked_add(u32::from(offset)).unwrap_or(0))
    }

    pub(super) fn map_ls(
        &mut self,
        guest_linear: u32,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        // The historical helper preserves small pointer values as selector
        // zero plus the same offset; they do not acquire a descriptor owner.
        if guest_linear <= 0xffff {
            return Ok(guest_linear);
        }
        let pointer_base = PhysAddr(guest_linear);
        let pointer_backing = match self.selector_backing_lease_for_range(pointer_base, 1, dos, memory) {
            Ok(Some(lease)) => lease,
            Ok(None) => return Ok(0),
            Err(error) if error.kind() == crate::DiagnosticKind::InvalidInput => return Ok(0),
            Err(error) => return Err(error),
        };
        // Match the pinned selector helper's 32-KiB alignment when the whole
        // view stays in this allocation. At an allocation boundary use the
        // exact pointer instead of exposing bytes owned by a neighbor.
        let aligned_base = guest_linear & !0x7fff;
        let (owner_base, owner_size) = match pointer_backing {
            selector_ownership::SelectorBackingIdentity::GlobalHeap { allocation, .. } => {
                let info = match self.heap.info(allocation) {
                    Ok(info) => info,
                    Err(Win16Error::InvalidHandle | Win16Error::StaleHandle) => return Ok(0),
                    Err(error) => return Err(crate::runtime_error(error)),
                };
                (info.base, info.size)
            }
            selector_ownership::SelectorBackingIdentity::Dos { extent, .. } => (
                extent.guest_base().ok_or_else(|| RuntimeError::new(
                    crate::DiagnosticKind::InternalInvariant, "MapLS DOS extent has no guest base"))?,
                u32::try_from(extent.byte_length().unwrap_or(0)).unwrap_or(0),
            ),
            selector_ownership::SelectorBackingIdentity::ModuleImage { base, size, .. } => (base, size),
            selector_ownership::SelectorBackingIdentity::RuntimeArena(arena) => (arena.base, arena.size),
        };
        let aligned = u64::from(aligned_base) >= u64::from(owner_base.0)
            && u64::from(aligned_base) < u64::from(owner_base.0).saturating_add(u64::from(owner_size));
        let base = if aligned {
            PhysAddr(aligned_base)
        } else {
            pointer_base
        };
        let block_end = u64::from(owner_base.0).checked_add(u64::from(owner_size))
            .ok_or_else(|| RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "MapLS backing extent overflowed"))?;
        let mapping_available = block_end.checked_sub(u64::from(base.0)).unwrap_or(0);
        let size = u32::try_from(mapping_available.min(u64::from(MAX_SELECTOR_BYTES)))
            .unwrap_or(MAX_SELECTOR_BYTES);
        let offset = guest_linear.checked_sub(base.0).unwrap_or(u32::MAX);
        if size == 0 || offset >= size {
            return Ok(0);
        }
        if let Some(&raw) = self.mapls_bases.get(&base.0) {
            let current = self.selectors.reference_including_unbacked(Selector(raw)).ok();
            let reusable = current.is_some_and(|reference| {
                self.mapls_selectors.get(&raw).is_some_and(|entry|
                    entry.reference == reference && entry.base == base.0
                ) && self.selectors.describe(reference).ok().is_some_and(|descriptor| {
                    descriptor.present
                        && descriptor.base == base
                        && u64::from(offset) <= u64::from(descriptor.limit)
                })
            }) && current.is_some_and(|reference| self.selector_backing_leases.get(&raw)
                .is_some_and(|entry| entry.reference == reference
                    && entry.leases.first().is_some_and(|lease| lease.identity() == pointer_backing)));
            if reusable {
                let Some(entry) = self.mapls_selectors.get_mut(&raw) else {
                    return Err(RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                        "MapLS base index has no selector record"));
                };
                if entry.base != base.0 {
                    return Err(RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                        "MapLS base index disagrees with its selector record"));
                }
                let Some(next_references) = entry.references.checked_add(1) else {
                    return Ok(0);
                };
                entry.references = next_references;
                return Ok((u32::from(raw | 0x0004) << 16) | offset);
            }
            if let Some(stale) = self.mapls_selectors.get(&raw)
                .map(|entry| entry.reference)
                .filter(|reference| current != Some(*reference))
            {
                self.forget_mapls_selector(stale);
                self.release_selector_backing(stale, dos, memory)?;
            }
            // Selector APIs may retarget a live MapLS descriptor. Keep that
            // mapping valid for its existing far pointers, but stop using a
            // stale reverse-index entry for this original flat address.
            self.mapls_bases.remove(&base.0);
        }
        let reference = match self.selectors.alloc_fixed_selector_descriptor(
            base, size, AccessRights::read_write(), memory,
        ) {
            Ok(reference) => reference,
            Err(error) => return selector_allocation_failure(error).map(u32::from),
        };
        match self.register_new_selector(reference, false, Some(pointer_backing), dos, memory) {
            Ok(true) => {}
            Ok(false) => {
                self.discard_new_selectors(&[reference], dos, memory)?;
                return Ok(0);
            }
            Err(error) => {
                return Err(self.rollback_selector_registration(&[reference], error, dos, memory));
            }
        }
        let raw = reference.raw().0;
        self.mapls_selectors.insert(raw, selector_ownership::MapLsEntry {
            reference,
            base: base.0,
            references: 1,
        });
        self.mapls_bases.insert(base.0, raw);
        // The SelectorTable stores canonical descriptor identities. The
        // Win16 far value marks this MapLS mapping as an LDT-backed flat view.
        Ok((u32::from(raw | 0x0004) << 16) | offset)
    }

    pub(super) fn unmap_ls(
        &mut self,
        far_pointer: u32,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let raw = canonical_selector((far_pointer >> 16) as u16);
        let Some(reference) = self.mapls_selectors.get(&raw).map(|entry| entry.reference) else {
            return Ok(());
        };
        if self.selectors.reference_including_unbacked(Selector(raw)).ok() != Some(reference) {
            self.forget_mapls_selector(reference);
            return Ok(());
        }
        let Some(entry) = self.mapls_selectors.get_mut(&raw) else {
            return Ok(());
        };
        if entry.references > 1 {
            entry.references -= 1;
            return Ok(());
        }
        let _ = self.free_selector(raw, dos, memory)?;
        Ok(())
    }

    pub(super) fn forget_mapls_selector(&mut self, reference: win16_abi::SelectorRef) {
        let raw = reference.raw().0;
        if self.mapls_selectors.get(&raw).is_some_and(|entry| entry.reference == reference)
            && let Some(entry) = self.mapls_selectors.remove(&raw)
            && self.mapls_bases.get(&entry.base) == Some(&raw)
        {
            self.mapls_bases.remove(&entry.base);
        }
    }
}
