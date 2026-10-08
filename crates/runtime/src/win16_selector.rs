//! KERNEL selector allocation, aliases, descriptor queries and conversion.

use guest_core::{PhysAddr, Selector};
use guest_core::memory::Memory;
use win16_abi::{SelectorRef, Win16Error};

use super::selector_errors::{canonical_selector, selector_allocation_failure, selector_change_failure};
use super::selector_ownership;
use super::Win16State;
use crate::RuntimeError;

pub(super) const MAX_SELECTOR_BYTES: u32 = 0x1_0000;
const NE_SEGMENT_MOVEABLE: u16 = 0x0010;
const NE_SEGMENT_DISCARDABLE: u16 = 0x1000;

impl Win16State {
    pub(super) fn alloc_selector(
        &mut self,
        source_selector: u16,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let (source, backing) = if source_selector == 0 {
            (None, None)
        } else {
            let Ok(source) = self.selectors.reference_including_unbacked(Selector(source_selector)) else {
                return Ok(0);
            };
            let canonical_source = source.raw().0;
            if self.is_protected_selector(canonical_source) {
                return Ok(0);
            }
            let descriptor = self.selectors.describe(source).map_err(crate::runtime_error)?;
            let backing = if descriptor.present {
                match self.selector_backing_lease(source, dos, memory) {
                    Ok(Some(lease)) => Some(lease),
                    Ok(None) if self.api_allocated_selectors.contains_key(&canonical_source)
                        && descriptor.base == PhysAddr(0) && descriptor.limit <= 1 => None,
                    Ok(None) => return Ok(0),
                    Err(error) if error.kind() == crate::DiagnosticKind::InvalidInput => {
                        return Ok(0);
                    }
                    Err(error) => return Err(error),
                }
            } else if self.api_allocated_selectors.contains_key(&canonical_source) {
                None
            } else {
                return Ok(0);
            };
            (Some(source), backing)
        };

        let allocations = match source {
            Some(source) => self.selectors.alloc_selector_copy(source, memory),
            None => self.selectors.reserve_fixed_selector_descriptor().map(|reference| vec![reference]),
        };
        let allocations = match allocations {
            Ok(references) => references,
            Err(error) => return selector_allocation_failure(error),
        };
        let Some(first) = allocations.first().copied() else {
            return Err(RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "AllocSelector produced no descriptor"));
        };
        for reference in &allocations {
            match self.register_new_selector(*reference, true, backing, dos, memory) {
                Ok(true) => {}
                Ok(false) => {
                    self.discard_new_selectors(&allocations, dos, memory)?;
                    return Ok(0);
                }
                Err(error) => {
                    return Err(self.rollback_selector_registration(&allocations, error, dos, memory));
                }
            }
        }
        Ok(first.raw().0)
    }

    pub(super) fn alloc_cs_to_ds_alias(
        &mut self,
        source_selector: u16,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Ok(source) = self.selectors.reference(Selector(source_selector)) else {
            return Ok(0);
        };
        let canonical_source = source.raw().0;
        if self.is_protected_selector(canonical_source) {
            return Ok(0);
        }
        let backing = match self.selector_backing_lease(source, dos, memory) {
            Ok(Some(lease)) => Some(lease),
            Ok(None) => return Ok(0),
            Err(error) if error.kind() == crate::DiagnosticKind::InvalidInput => return Ok(0),
            Err(error) => return Err(error),
        };
        let alias = match self.selectors.alloc_cs_to_ds_alias(source, memory) {
            Ok(alias) => alias,
            Err(error) => return selector_allocation_failure(error),
        };
        match self.register_new_selector(alias, false, backing, dos, memory) {
            Ok(true) => {}
            Ok(false) => {
                self.discard_new_selectors(&[alias], dos, memory)?;
                return Ok(0);
            }
            Err(error) => {
                return Err(self.rollback_selector_registration(&[alias], error, dos, memory));
            }
        }
        Ok(alias.raw().0)
    }

    pub(super) fn alloc_ds_to_cs_alias(
        &mut self,
        source_selector: u16,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Ok(source) = self.selectors.reference(Selector(source_selector)) else {
            return Ok(0);
        };
        let canonical_source = source.raw().0;
        if self.is_protected_selector(canonical_source) {
            return Ok(0);
        }
        let Ok(descriptor) = self.selectors.describe(source) else {
            return Ok(0);
        };
        if descriptor.rights.executable() {
            return Ok(0);
        }
        let backing = match self.selector_backing_lease(source, dos, memory) {
            Ok(Some(lease)) => lease,
            Ok(None) => return Ok(0),
            Err(error) if error.kind() == crate::DiagnosticKind::InvalidInput => return Ok(0),
            Err(error) => return Err(error),
        };
        // SDK 3.1 specifies a fixed, nondiscardable data source. Keep that
        // source contract while pinning its exact GlobalHeap generation.
        match backing {
            selector_ownership::SelectorBackingIdentity::GlobalHeap {
                allocation, ne_segment_flags, ..
            } => {
                if let Some(flags) = ne_segment_flags {
                    if flags & (NE_SEGMENT_MOVEABLE | NE_SEGMENT_DISCARDABLE) != 0 {
                        return Ok(0);
                    }
                } else {
                    let info = match self.heap.info(allocation) {
                        Ok(info) => info,
                        Err(Win16Error::InvalidHandle | Win16Error::StaleHandle) => return Ok(0),
                        Err(error) => return Err(crate::runtime_error(error)),
                    };
                    if info.movable || info.discardable || info.discarded { return Ok(0); }
                }
            }
            selector_ownership::SelectorBackingIdentity::ModuleImage { segment_flags, .. }
                if segment_flags & (NE_SEGMENT_MOVEABLE | NE_SEGMENT_DISCARDABLE) != 0 => {
                    return Ok(0);
                }
            _ => {}
        }
        let alias = match self.selectors.alloc_ds_to_cs_alias(source, memory) {
            Ok(alias) => alias,
            Err(error) => return selector_allocation_failure(error),
        };
        match self.register_new_selector(alias, false, Some(backing), dos, memory) {
            Ok(true) => {}
            Ok(false) => {
                self.discard_new_selectors(&[alias], dos, memory)?;
                return Ok(0);
            }
            Err(error) => {
                return Err(self.rollback_selector_registration(&[alias], error, dos, memory));
            }
        }
        Ok(alias.raw().0)
    }

    pub(super) fn alloc_selector_array(
        &mut self,
        count: u16,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let references = match self.selectors.alloc_selector_array(count, memory) {
            Ok(references) => references,
            Err(error) => return selector_allocation_failure(error),
        };
        let first = references.first().copied().ok_or_else(|| {
            RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "AllocSelectorArray produced no descriptor for a nonzero count")
        })?;
        for reference in &references {
            match self.register_new_selector(*reference, true, None, dos, memory) {
                Ok(true) => {}
                Ok(false) => {
                    self.discard_new_selectors(&references, dos, memory)?;
                    return Ok(0);
                }
                Err(error) => {
                    return Err(self.rollback_selector_registration(&references, error, dos, memory));
                }
            }
        }
        Ok(first.raw().0)
    }

    pub(super) fn register_new_selector(
        &mut self,
        reference: SelectorRef,
        api_allocated: bool,
        backing: Option<selector_ownership::SelectorBackingIdentity>,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<bool, RuntimeError> {
        let raw = reference.raw().0;
        if self.selector_backing_leases.get(&raw)
            .is_some_and(|entry| entry.reference != reference)
            || self.api_allocated_selectors.get(&raw)
                .is_some_and(|existing| *existing != reference)
            || self.allocated_selector_aliases.get(&raw)
                .is_some_and(|existing| *existing != reference)
        {
            // A prior generation may still own a failed-release lease. Never
            // overwrite that exact owner when the guest-visible word is reused.
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "new selector generation collides with a retained prior-generation owner",
            ));
        }
        if self.selector_backing_leases.get(&raw)
            .is_some_and(|entry| entry.reference == reference)
            || self.api_allocated_selectors.get(&raw) == Some(&reference)
            || self.allocated_selector_aliases.get(&raw) == Some(&reference)
        {
            return Err(RuntimeError::new(
                crate::DiagnosticKind::InternalInvariant,
                "selector generation was registered more than once",
            ));
        }
        if let Some(identity) = backing {
            let mut leases = Vec::new();
            leases.try_reserve_exact(1).map_err(|error| RuntimeError::with_source(
                crate::DiagnosticKind::ResourceExhausted,
                "reserve canonical selector backing lease", error,
            ))?;
            let descriptor = self.selectors.describe(reference).map_err(crate::runtime_error)?;
            let Some(size) = descriptor.limit.checked_add(1) else { return Ok(false); };
            let Some(lease) = self.retain_selector_backing(
                reference, identity, descriptor.base, size, dos, memory,
            )?
            else { return Ok(false); };
            leases.push(lease);
            self.selector_backing_leases.insert(raw, selector_ownership::SelectorBackingEntry {
                reference, leases,
            });
        }
        if api_allocated {
            self.api_allocated_selectors.insert(raw, reference);
        } else {
            self.allocated_selector_aliases.insert(raw, reference);
        }
        Ok(true)
    }

    pub(super) fn discard_new_selectors(
        &mut self,
        references: &[SelectorRef],
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let mut cleanup_error: Option<RuntimeError> = None;
        for reference in references {
            let raw = reference.raw().0;
            let freed = match self.selectors.free_selector(*reference) {
                Ok(()) | Err(Win16Error::StaleSelector) => true,
                Err(error) => {
                    let cleanup = crate::runtime_error(error)
                        .with_context("freeing a partially registered selector allocation");
                    cleanup_error = Some(match cleanup_error {
                        Some(existing) => existing.with_cleanup(
                            "rolling back selector allocation registration", cleanup),
                        None => cleanup,
                    });
                    false
                }
            };
            if !freed {
                continue;
            }
            if self.api_allocated_selectors.get(&raw) == Some(reference) {
                self.api_allocated_selectors.remove(&raw);
            }
            if self.allocated_selector_aliases.get(&raw) == Some(reference) {
                self.allocated_selector_aliases.remove(&raw);
            }
            self.forget_mapls_selector(*reference);
            if let Err(cleanup) = self.release_selector_backing(*reference, dos, memory) {
                cleanup_error = Some(match cleanup_error {
                    Some(existing) => existing.with_cleanup(
                        "rolling back selector allocation registration", cleanup),
                    None => cleanup,
                });
            }
        }
        match cleanup_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub(super) fn rollback_selector_registration(
        &mut self,
        references: &[SelectorRef],
        operation: RuntimeError,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> RuntimeError {
        match self.discard_new_selectors(references, dos, memory) {
            Ok(()) => operation,
            Err(cleanup) => operation.with_cleanup(
                "rolling back selector allocation after owner registration failed",
                cleanup,
            ),
        }
    }

    pub(super) fn free_selector(
        &mut self, selector: u16, dos: &mut dos_kernel::DosKernel, memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let raw = canonical_selector(selector);
        let live_reference = self.selectors.reference_including_unbacked(Selector(raw)).ok();
        if self.is_protected_selector(raw)
            || live_reference.is_some_and(|reference|
                self.legacy_cpu_frame_owns_selector(reference))
        {
            return Ok(selector);
        }
        let api_allocated = self.api_allocated_selectors.get(&raw).copied();
        let alias = self.allocated_selector_aliases.get(&raw).copied();
        let Some(reference) = api_allocated.or(alias) else {
            return Ok(selector);
        };

        let current = self.selectors.reference_including_unbacked(Selector(raw));
        if current.is_err() || current.ok() != Some(reference) {
            if self.api_allocated_selectors.get(&raw) == Some(&reference) {
                self.api_allocated_selectors.remove(&raw);
            }
            if self.allocated_selector_aliases.get(&raw) == Some(&reference) {
                self.allocated_selector_aliases.remove(&raw);
            }
            self.forget_mapls_selector(reference);
            self.release_selector_backing(reference, dos, memory)?;
            return Ok(selector);
        }

        let result = self.selectors.free_selector(reference);
        match result {
            Ok(()) => {
                if self.api_allocated_selectors.get(&raw) == Some(&reference) {
                    self.api_allocated_selectors.remove(&raw);
                }
                if self.allocated_selector_aliases.get(&raw) == Some(&reference) {
                    self.allocated_selector_aliases.remove(&raw);
                }
                self.forget_mapls_selector(reference);
                self.release_selector_backing(reference, dos, memory)?;
                Ok(0)
            }
            Err(Win16Error::StaleSelector) => {
                if self.api_allocated_selectors.get(&raw) == Some(&reference) {
                    self.api_allocated_selectors.remove(&raw);
                }
                if self.allocated_selector_aliases.get(&raw) == Some(&reference) {
                    self.allocated_selector_aliases.remove(&raw);
                }
                self.forget_mapls_selector(reference);
                self.release_selector_backing(reference, dos, memory)?;
                Ok(selector)
            }
            Err(Win16Error::SelectorBlockInterior) => Ok(selector),
            Err(error) => Err(crate::runtime_error(error)),
        }
    }

    pub(super) fn presto_chango_selector(
        &mut self,
        source_selector: u16,
        destination_selector: u16,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Ok(source) = self.selectors.reference(Selector(source_selector)) else {
            return Ok(0);
        };
        let canonical_source = source.raw().0;
        if self.is_protected_selector(canonical_source)
            || self.real_mode_vector_aliases.values().any(|reference| *reference == source)
        {
            return Ok(0);
        }
        let _backing = match self.selector_backing_lease(source, dos, memory) {
            Ok(Some(lease)) => lease,
            Ok(None) => return Ok(0),
            Err(error) if error.kind() == crate::DiagnosticKind::InvalidInput => return Ok(0),
            Err(error) => return Err(error),
        };

        let Ok(destination) = self.selectors.reference_including_unbacked(
            Selector(destination_selector),
        ) else {
            return Ok(0);
        };
        let canonical_destination = destination.raw().0;
        let self_conversion = canonical_source == canonical_destination;
        if self.is_protected_selector(canonical_destination)
            || self.real_mode_vector_aliases.values().any(|reference| *reference == destination)
        {
            return Ok(0);
        }
        if !self_conversion
            && self.api_allocated_selectors.get(&canonical_destination).copied()
                != Some(destination)
        {
            return Ok(0);
        }

        // The SDK 3.1 contract allocates a distinct destination with
        // AllocSelector. The pinned historical selector implementation also
        // accepts source==destination and rewrites that same descriptor;
        // permit that compatibility path only for tracked guest backing.
        let source_descriptor = match self.selectors.describe(source) {
            Ok(descriptor) => descriptor,
            Err(_) => return Ok(0),
        };
        let size = match source_descriptor.limit.checked_add(1) {
            Some(size) => size,
            None => return Ok(0),
        };
        let converted = if self_conversion {
            // Keep the primary descriptor's existing owner model intact. In
            // particular, self-conversion must not turn a GlobalHeap primary
            // selector into a separately retained alias pin.
            match self.selectors.presto_chango_selector(source, destination, memory) {
                Ok(()) => true,
                Err(error) => return match selector_change_failure(error) {
                    Ok(_) => Ok(0),
                    Err(error) => Err(error),
                },
            }
        } else {
            self.retarget_selector_range(
                destination,
                source_descriptor.base,
                size,
                dos,
                memory,
                |selectors, memory| selectors.presto_chango_selector(source, destination, memory),
            )?
        };
        if !converted {
            return Ok(0);
        }
        self.real_mode_vector_aliases.retain(|_, identity| *identity != destination);
        Ok(destination_selector)
    }

    pub(super) fn get_selector_base(&self, selector: u16) -> u32 {
        self.selectors.reference_including_unbacked(Selector(selector)).ok()
            .and_then(|reference| self.selectors.describe(reference).ok())
            .map_or(0, |descriptor| descriptor.base.0)
    }

    pub(super) fn set_selector_base(
        &mut self,
        selector: u16,
        base: u32,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Ok(reference) = self.selectors.reference_including_unbacked(Selector(selector)) else {
            return Ok(0);
        };
        if !self.is_mutable_guest_selector(reference) {
            return Ok(0);
        }
        let Ok(descriptor) = self.selectors.describe(reference) else {
            return Ok(0);
        };
        let size = match descriptor.limit.checked_add(1) {
            Some(size) => size,
            None => return Ok(0),
        };
        let base = PhysAddr(base);
        let result = self.retarget_selector_range(reference, base, size, dos, memory, |selectors, memory| {
            selectors.set_selector_base(reference, base, memory)
        })?;
        Ok(if result { selector } else { 0 })
    }

    pub(super) fn get_selector_limit(&self, selector: u16) -> u32 {
        self.selectors.reference_including_unbacked(Selector(selector)).ok()
            .and_then(|reference| self.selectors.describe(reference).ok())
            .map_or(0, |descriptor| descriptor.limit)
    }

    pub(super) fn set_selector_limit(
        &mut self,
        selector: u16,
        limit: u32,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Ok(reference) = self.selectors.reference_including_unbacked(Selector(selector)) else {
            return Ok(0);
        };
        if !self.is_mutable_guest_selector(reference) {
            return Ok(0);
        }
        let Ok(descriptor) = self.selectors.describe(reference) else {
            return Ok(0);
        };
        let size = match limit.checked_add(1) {
            Some(size) => size,
            None => return Ok(0),
        };
        let base = descriptor.base;
        let result = self.retarget_selector_range(reference, base, size, dos, memory, |selectors, memory| {
            selectors.set_selector_limit(reference, limit, memory)
        })?;
        if !result {
            return Ok(0);
        }
        // The Win3.1 SDK header declares UINT but does not define the success
        // value. The pinned Win16 implementation returns the selector on
        // success and zero when the descriptor update fails.
        Ok(selector)
    }

    pub(super) fn selector_access_rights(
        &mut self,
        selector: u16,
        operation: u16,
        access: u16,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<u16, RuntimeError> {
        let Ok(reference) = self.selectors.reference_including_unbacked(Selector(selector)) else {
            return Ok(0);
        };
        if operation == 0 {
            return Ok(self.selectors.selector_access_rights(reference).unwrap_or(0));
        }
        if !self.is_mutable_guest_selector(reference) {
            return Ok(0);
        }
        let Ok(descriptor) = self.selectors.describe(reference) else { return Ok(0); };
        let size = match descriptor.limit.checked_add(1) {
            Some(size) => size,
            None => return Ok(0),
        };
        let _ = self.retarget_selector_range(
            reference, descriptor.base, size, dos, memory,
            |selectors, memory| selectors.set_selector_access_rights(reference, access, memory),
        )?;
        // The historical setter returns zero whether the requested flags are
        // accepted or rejected; descriptor state and typed runtime failures
        // carry the actual result.
        Ok(0)
    }

    pub(super) fn long_ptr_add(
        &mut self,
        far_pointer: u32,
        amount: u32,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        let selector = (far_pointer >> 16) as u16;
        let Ok(reference) = self.selectors.reference(Selector(selector)) else {
            return Ok(0);
        };
        if !self.is_mutable_guest_selector(reference) {
            return Ok(0);
        }
        let Ok(descriptor) = self.selectors.describe(reference) else {
            return Ok(0);
        };
        let Some(base) = descriptor.base.0.checked_add(amount) else {
            return Ok(0);
        };
        let size = match descriptor.limit.checked_add(1) {
            Some(size) => size,
            None => return Ok(0),
        };
        let base = PhysAddr(base);
        let result = self.retarget_selector_range(reference, base, size, dos, memory, |selectors, memory| {
            selectors.set_selector_base(reference, base, memory)
        })?;
        Ok(if result { far_pointer } else { 0 })
    }

    fn is_protected_selector(&self, selector: u16) -> bool {
        self.owns_native_procedure_selector(selector)
            || self.is_service_gate(selector)
            || self.is_callback_gate(selector)
            || self.runtime_arena_backing.owns_selector(selector)
            || self.runtime_selector_aliases.owns_selector(selector)
            || self.selectors.reference_including_unbacked(Selector(selector)).ok()
                .is_some_and(|reference| self.legacy_cpu_frame_owns_selector(reference))
    }

    fn is_mutable_guest_selector(&self, reference: SelectorRef) -> bool {
        let raw = reference.raw().0;
        !self.runtime_arena_backing.owns_selector(raw)
            && !self.legacy_cpu_frame_owns_selector(reference)
            && (self.api_allocated_selectors.get(&raw).copied() == Some(reference)
                || self.allocated_selector_aliases.get(&raw).copied() == Some(reference)
            )
    }

    fn retarget_selector_range(
        &mut self,
        reference: SelectorRef,
        base: PhysAddr,
        size: u32,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        change: impl FnOnce(&mut win16_abi::SelectorTable, &Memory) -> Result<(), Win16Error>,
    ) -> Result<bool, RuntimeError> {
        if size == 0 || self.legacy_cpu_frame_owns_selector(reference) {
            return Ok(false);
        }
        let replacement = match self.selector_backing_lease_for_range(base, size, dos, memory) {
            Ok(Some(lease)) => Some(lease),
            Ok(None) => return Ok(false),
            Err(error) if error.kind() == crate::DiagnosticKind::InvalidInput => return Ok(false),
            Err(error) => return Err(error),
        };
        let replacement = match replacement {
            Some(identity) => identity,
            None => return Ok(false),
        };
        let raw = reference.raw().0;
        let mut previous_record = self.selector_backing_leases.remove(&raw);
        if previous_record.as_ref().is_some_and(|entry| entry.reference != reference) {
            if let Some(entry) = previous_record.take() {
                self.selector_backing_leases.insert(raw, entry);
            }
            return Err(RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "selector retarget found a backing record for another generation"));
        }
        let existing_identity = previous_record.as_ref().and_then(|entry| entry.leases.first())
            .map(selector_ownership::SelectorBackingLease::identity);
        let mut pending_leases = Vec::new();
        if existing_identity != Some(replacement) {
            let reserve = if let Some(entry) = previous_record.as_mut() {
                entry.leases.try_reserve(1)
            } else {
                pending_leases.try_reserve_exact(1)
            };
            if let Err(error) = reserve {
                if let Some(entry) = previous_record.take() {
                    self.selector_backing_leases.insert(raw, entry);
                }
                return Err(RuntimeError::with_source(
                    crate::DiagnosticKind::ResourceExhausted,
                    "reserve selector backing retarget owner storage", error,
                ));
            }
        }
        let acquired = if existing_identity == Some(replacement) {
            None
        } else {
            let lease = match self.retain_selector_backing(
                reference, replacement, base, size, dos, memory,
            ) {
                Ok(Some(lease)) => lease,
                Ok(None) => {
                    if let Some(entry) = previous_record.take()
                        && !entry.leases.is_empty()
                    {
                        self.selector_backing_leases.insert(raw, entry);
                    }
                    return Ok(false);
                }
                Err(error) => {
                    if let Some(entry) = previous_record.take()
                        && !entry.leases.is_empty()
                    {
                        self.selector_backing_leases.insert(raw, entry);
                    }
                    return Err(error);
                }
            };
            Some(lease)
        };

        if let Err(error) = change(&mut self.selectors, memory) {
            if let Some(lease) = acquired {
                if let Err(cleanup) = self.release_selector_lease(&lease, dos, memory) {
                    let mut entry = match previous_record.take() {
                        Some(entry) => entry,
                        None => selector_ownership::SelectorBackingEntry {
                            reference, leases: pending_leases,
                        },
                    };
                    entry.leases.push(lease);
                    self.selector_backing_leases.insert(raw, entry);
                    return Err(crate::runtime_error(error).with_cleanup(
                        "releasing a speculative selector retarget lease", cleanup));
                }
            }
            if let Some(entry) = previous_record.take()
                && !entry.leases.is_empty()
            {
                self.selector_backing_leases.insert(raw, entry);
            }
            return match selector_change_failure(error) {
                Ok(_) => Ok(false),
                Err(error) => Err(error),
            };
        }

        if let Some(lease) = acquired {
            let entry = previous_record.get_or_insert_with(||
                selector_ownership::SelectorBackingEntry {
                    reference, leases: pending_leases,
                });
            if entry.reference != reference {
                entry.leases.push(lease);
                if let Some(entry) = previous_record.take() {
                    self.selector_backing_leases.insert(raw, entry);
                }
                return Err(RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                    "selector generation changed while committing a backing retarget"));
            }
            entry.leases.insert(0, lease);
            while entry.leases.len() > 1 {
                let Some(old_lease) = entry.leases.pop() else {
                    if let Some(entry) = previous_record.take() {
                        self.selector_backing_leases.insert(raw, entry);
                    }
                    return Err(RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                        "selector retarget lost its previous backing lease"));
                };
                if let Err(error) = self.release_selector_lease(&old_lease, dos, memory) {
                    entry.leases.push(old_lease);
                    if let Some(entry) = previous_record.take() {
                        self.selector_backing_leases.insert(raw, entry);
                    }
                    return Err(error.with_context("releasing a previous selector backing after retarget"));
                }
            }
        }
        if let Some(entry) = previous_record.take()
            && !entry.leases.is_empty()
        {
            self.selector_backing_leases.insert(raw, entry);
        }
        // Keep MapLS's base-to-selector reuse index coherent when the guest
        // retargets a live mapping through SetSelectorBase or LongPtrAdd.
        if let Some(entry) = self.mapls_selectors.get_mut(&raw)
            && entry.reference == reference
            && entry.base != base.0
        {
            if self.mapls_bases.get(&entry.base) == Some(&raw) {
                self.mapls_bases.remove(&entry.base);
            }
            entry.base = base.0;
            if !self.mapls_bases.contains_key(&entry.base) {
                self.mapls_bases.insert(entry.base, raw);
            }
        }
        Ok(true)
    }

}
