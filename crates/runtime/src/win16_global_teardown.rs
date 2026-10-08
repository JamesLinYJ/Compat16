//! Shared GlobalHeap teardown over a narrow, disjoint mutable borrow.

use std::collections::{BTreeMap, BTreeSet};

use win16_abi::{GlobalHandle, GlobalHeap, SelectorRef, SelectorTable, Win16Error};

use super::{global_memory::GlobalTeardownResult, selector_ownership, Win16State};
use super::module_registry::ModuleRecord;
use crate::{DiagnosticKind as Kind, RuntimeError};

/// Borrow only the canonical heap and selector owners needed by runtime
/// teardown. DDE and callback completions can compose this view beside their
/// own continuation borrow without cloning or taking the whole Win16State.
pub(super) struct GlobalMemoryTeardownAccess<'a> {
    heap: &'a mut GlobalHeap,
    selectors: &'a mut SelectorTable,
    selector_backing_leases: &'a mut BTreeMap<u16, selector_ownership::SelectorBackingEntry>,
    modules: &'a mut BTreeMap<u16, ModuleRecord>,
    global_handles: &'a mut BTreeMap<u16, GlobalHandle>,
    global_selectors: &'a mut BTreeMap<u16, SelectorRef>,
    discarded_handles: &'a mut BTreeSet<u16>,
    allocated_selector_aliases: &'a mut BTreeMap<u16, SelectorRef>,
    api_allocated_selectors: &'a mut BTreeMap<u16, SelectorRef>,
    mapls_selectors: &'a mut BTreeMap<u16, selector_ownership::MapLsEntry>,
    mapls_bases: &'a mut BTreeMap<u32, u16>,
    module_reap_pending: &'a mut bool,
}

impl<'a> GlobalMemoryTeardownAccess<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_parts(
        heap: &'a mut GlobalHeap,
        selectors: &'a mut SelectorTable,
        selector_backing_leases: &'a mut BTreeMap<u16, selector_ownership::SelectorBackingEntry>,
        modules: &'a mut BTreeMap<u16, ModuleRecord>,
        global_handles: &'a mut BTreeMap<u16, GlobalHandle>,
        global_selectors: &'a mut BTreeMap<u16, SelectorRef>,
        discarded_handles: &'a mut BTreeSet<u16>,
        allocated_selector_aliases: &'a mut BTreeMap<u16, SelectorRef>,
        api_allocated_selectors: &'a mut BTreeMap<u16, SelectorRef>,
        mapls_selectors: &'a mut BTreeMap<u16, selector_ownership::MapLsEntry>,
        mapls_bases: &'a mut BTreeMap<u32, u16>,
        module_reap_pending: &'a mut bool,
    ) -> Self {
        Self {
            heap,
            selectors,
            selector_backing_leases,
            modules,
            global_handles,
            global_selectors,
            discarded_handles,
            allocated_selector_aliases,
            api_allocated_selectors,
            mapls_selectors,
            mapls_bases,
            module_reap_pending,
        }
    }

    /// Reborrow selector metadata for a sequential checked guest-memory step.
    pub(super) fn selectors(&self) -> &SelectorTable { self.selectors }

    /// Borrow the two disjoint allocator components for one scoped lock step.
    /// Callers must use the canonical teardown method instead of freeing the
    /// returned heap directly.
    pub(super) fn heap_and_selectors_mut(&mut self) -> (&mut GlobalHeap, &mut SelectorTable) {
        (self.heap, self.selectors)
    }

    /// Free only the exact GlobalHeap generation retained by the caller.
    /// A live selector alias, page lock, or loader pin is a normal deferred
    /// result; identities and mappings stay owned until a later retry.
    pub(super) fn free_runtime_global_on_teardown(
        &mut self,
        expected: GlobalHandle,
    ) -> Result<GlobalTeardownResult, RuntimeError> {
        match self.heap.info(expected) {
            Ok(_) => {}
            Err(Win16Error::InvalidHandle | Win16Error::StaleHandle)
                if self.heap.is_retired_identity(expected) =>
            {
                if self.selector_backing_leases.values().any(|entry|
                    entry.leases.iter().any(|lease|
                        lease.global_heap_allocation() == Some(expected)))
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "retired GlobalHandle still has a canonical selector lease"));
                }
                for (&raw, &identity) in self.global_handles.iter() {
                    if identity != expected { continue; }
                    if let Some(selector) = self.global_selectors.get(&raw) {
                        match self.selectors.reference_including_unbacked(selector.raw()) {
                            Ok(current) if current == *selector => return Err(RuntimeError::new(
                                Kind::InternalInvariant,
                                "retired GlobalHandle still has its live primary selector")),
                            Ok(_) => return Err(RuntimeError::new(Kind::InternalInvariant,
                                "retired HGLOBAL mapping now names a reused selector generation")),
                            Err(_) => {}
                        }
                    }
                }
                self.global_selectors.retain(|raw, _|
                    self.global_handles.get(raw) != Some(&expected));
                self.discarded_handles.retain(|raw|
                    self.global_handles.get(raw) != Some(&expected));
                self.global_handles.retain(|_, identity| *identity != expected);
                return Ok(GlobalTeardownResult::Freed);
            }
            Err(error) => return Err(crate::runtime_error(error)
                .with_context("validating exact GlobalHeap teardown identity")),
        }
        self.validate_runtime_primary(expected)?;

        // This retires only runtime-owned descriptors proven detached from
        // their exact SelectorRef generation. Live aliases stay with callers.
        let tracked_aliases = self.retire_detached_heap_alias_leases(expected)?;
        let selector_aliases = self.heap.selector_alias_count(expected)
            .map_err(crate::runtime_error)?;
        if tracked_aliases > selector_aliases {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "canonical selector lease count exceeds the GlobalHeap alias owner count"));
        }
        // The only leases outside this map come from the non-cloneable owner
        // returned by capture_legacy_cpu_binding_owner; its paired release
        // consumes those pins explicitly. Callback/UI callsites are still
        // pending, so this difference can only be a live owner when wired.
        // Any such heap alias remains busy and is returned as Retained below.
        let page_locks = self.heap.page_lock_count(expected).map_err(crate::runtime_error)?;
        let internal_pins = self.heap.internal_pin_count(expected).map_err(crate::runtime_error)?;
        if selector_aliases != 0 || page_locks != 0 || internal_pins != 0 {
            return Ok(GlobalTeardownResult::Retained {
                selector_aliases,
                page_locks,
                internal_pins,
            });
        }

        self.heap.free_on_teardown(expected, self.selectors)
            .map_err(crate::runtime_error)?;
        self.global_selectors.retain(|raw, _|
            self.global_handles.get(raw) != Some(&expected));
        self.discarded_handles.retain(|raw|
            self.global_handles.get(raw) != Some(&expected));
        self.global_handles.retain(|_, identity| *identity != expected);
        Ok(GlobalTeardownResult::Freed)
    }

    fn validate_runtime_primary(&self, allocation: GlobalHandle) -> Result<(), RuntimeError> {
        let primary = self.heap.runtime_primary_selector(allocation)
            .map_err(crate::runtime_error)?;
        let mut mapped_handle = None;
        for (&raw, &identity) in self.global_handles.iter() {
            if identity != allocation { continue; }
            if mapped_handle.replace(raw).is_some() {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "one GlobalHeap generation is mapped by multiple Win16 HGLOBAL values"));
            }
        }
        match (primary, mapped_handle) {
            (Some(primary), Some(raw)) => {
                if self.global_selectors.get(&raw) != Some(&primary)
                    || self.selectors.reference_including_unbacked(primary.raw()).ok()
                        != Some(primary)
                    || self.global_selectors.values().filter(|selector| **selector == primary).count() != 1
                {
                    return Err(RuntimeError::new(Kind::InternalInvariant,
                        "GlobalHeap primary selector generation disagrees with its exact HGLOBAL map"));
                }
            }
            (None, None) => {}
            _ => return Err(RuntimeError::new(Kind::InternalInvariant,
                "GlobalHeap primary selector and Win16 HGLOBAL owner map disagree")),
        }
        Ok(())
    }

    /// Remove detached alias leases only after checking their stored selector
    /// generation. A live descriptor remains a caller-owned pin.
    fn retire_detached_heap_alias_leases(
        &mut self,
        allocation: GlobalHandle,
    ) -> Result<u16, RuntimeError> {
        let mut references = Vec::new();
        references.try_reserve_exact(self.selector_backing_leases.len()).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve exact-generation GlobalHeap alias scan", error)
        })?;
        for entry in self.selector_backing_leases.values() {
            if entry.leases.iter().any(|lease|
                lease.global_heap_allocation() == Some(allocation))
            {
                references.push(entry.reference);
            }
        }

        let mut active = 0_u16;
        for reference in references {
            let raw = reference.raw().0;
            let Some(mut entry) = self.selector_backing_leases.remove(&raw) else { continue; };
            if entry.reference != reference {
                self.selector_backing_leases.insert(raw, entry);
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "GlobalHeap alias scan found a different selector generation"));
            }
            let live = self.selectors.reference_including_unbacked(reference.raw()).ok()
                == Some(reference);
            let mut index = 0;
            while index < entry.leases.len() {
                if entry.leases[index].global_heap_allocation() != Some(allocation) {
                    index += 1;
                    continue;
                }
                if live && index == 0 {
                    let Some(next_active) = active.checked_add(1) else {
                        self.selector_backing_leases.insert(raw, entry);
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "GlobalHeap live alias count overflowed during owner scan"));
                    };
                    active = next_active;
                    index += 1;
                    continue;
                }
                let lease = entry.leases.remove(index);
                let (owner, module) = match &lease {
                    selector_ownership::SelectorBackingLease::GlobalHeap {
                        allocation, module, ..
                    } => (*allocation, *module),
                    _ => {
                        entry.leases.insert(index, lease);
                        self.selector_backing_leases.insert(raw, entry);
                        return Err(RuntimeError::new(Kind::InternalInvariant,
                            "GlobalHeap alias identity disagrees with its retained lease"));
                    }
                };
                let mut module_record = if let Some(module) = module {
                    match self.modules.get_mut(&module) {
                        Some(record) => Some(record),
                        None => {
                            entry.leases.insert(index, lease);
                            self.selector_backing_leases.insert(raw, entry);
                            return Err(RuntimeError::new(Kind::InternalInvariant,
                                "GlobalHeap selector lease lost its module owner record"));
                        }
                    }
                } else { None };
                let next_module_refs = match module_record.as_ref() {
                    Some(record) => match record.continuation_owner_refs.checked_sub(1) {
                        Some(next) => Some(next),
                        None => {
                            entry.leases.insert(index, lease);
                            self.selector_backing_leases.insert(raw, entry);
                            return Err(RuntimeError::new(Kind::InternalInvariant,
                                "module continuation owner reference count underflowed"));
                        }
                    },
                    None => None,
                };
                if let Err(error) = self.heap.release_selector_alias(owner) {
                    entry.leases.insert(index, lease);
                    self.selector_backing_leases.insert(raw, entry);
                    return Err(crate::runtime_error(error)
                        .with_context("releasing a detached GlobalHeap selector lease"));
                }
                if let (Some(record), Some(next)) = (module_record.as_mut(), next_module_refs) {
                    record.continuation_owner_refs = next;
                    *self.module_reap_pending = true;
                }
            }
            if entry.leases.is_empty() {
                if self.api_allocated_selectors.get(&raw) == Some(&reference) {
                    self.api_allocated_selectors.remove(&raw);
                }
                if self.allocated_selector_aliases.get(&raw) == Some(&reference) {
                    self.allocated_selector_aliases.remove(&raw);
                }
                self.forget_mapls_selector(reference);
            } else {
                self.selector_backing_leases.insert(raw, entry);
            }
        }
        Ok(active)
    }

    fn forget_mapls_selector(&mut self, reference: SelectorRef) {
        let raw = reference.raw().0;
        if self.mapls_selectors.get(&raw).is_some_and(|entry| entry.reference == reference)
            && let Some(entry) = self.mapls_selectors.remove(&raw)
            && self.mapls_bases.get(&entry.base) == Some(&raw)
        {
            self.mapls_bases.remove(&entry.base);
        }
    }
}

impl Win16State {
    pub(super) fn global_memory_teardown_access(&mut self) -> GlobalMemoryTeardownAccess<'_> {
        GlobalMemoryTeardownAccess::from_parts(
            &mut self.heap,
            &mut self.selectors,
            &mut self.selector_backing_leases,
            &mut self.modules.records,
            &mut self.global_handles,
            &mut self.global_selectors,
            &mut self.discarded_handles,
            &mut self.allocated_selector_aliases,
            &mut self.api_allocated_selectors,
            &mut self.mapls_selectors,
            &mut self.mapls_bases,
            &mut self.module_reap_pending,
        )
    }
}
