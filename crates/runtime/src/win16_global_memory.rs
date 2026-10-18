//! Win16 KERNEL global-memory exports backed by the shared guest GlobalHeap.
//!
//! Guest HGLOBAL words remain distinct from allocator slots and selector
//! references. Compaction and reallocation return selector-generation changes
//! so the runtime can refresh the mappings it owns.

use guest_core::{memory::Memory, Selector};
use win16_abi::global::{
    GMEM_DDESHARE, GMEM_DISCARDABLE, GMEM_INVALID_HANDLE, GMEM_LOCKCOUNT_MASK, GMEM_MODIFY,
    GMEM_MOVEABLE, GMEM_NOCOMPACT, GMEM_NODISCARD, GMEM_NOTIFY, GMEM_ZEROINIT,
};
use win16_abi::{
    AccessRights, AllocationFlags, GlobalHandle, GuestMemoryOwner, SelectorRef, Win16Error,
};

use super::{module_registry::ModuleState, Win16State, TASK_DATABASE_PREFIX_SIZE};
use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GlobalTeardownResult {
    Freed,
    Retained { selector_aliases: u16, page_locks: u16, internal_pins: u16 },
}

/// Caller provenance for shared global-memory ownership.
/// Builtin services have module identities but no guest code selectors.
#[derive(Clone, Copy)]
pub(super) enum GlobalMemoryCaller {
    GuestCode(u16),
    BuiltinModule(u16),
}

impl GlobalTeardownResult {
    pub(super) fn retained_error(self, owner: &'static str) -> Option<RuntimeError> {
        match self {
            Self::Freed => None,
            Self::Retained { selector_aliases, page_locks, internal_pins } => Some(RuntimeError::new(
                Kind::ResourceExhausted,
                format!("Win16 {owner} teardown is deferred by {selector_aliases} live selector aliases, {page_locks} page locks and {internal_pins} internal pins"),
            )),
        }
    }
}

impl Win16State {
    fn global_memory_caller_owner(
        &self, caller: Option<GlobalMemoryCaller>,
    ) -> Option<GuestMemoryOwner> {
        let owner = match caller? {
            GlobalMemoryCaller::GuestCode(selector) => self.live_code_module_owner(selector),
            GlobalMemoryCaller::BuiltinModule(module) => self.modules.records.get(&module)
                .filter(|record| record.builtin
                    && record.handle == module
                    && record.state == ModuleState::Ready
                    && record.external_application.is_none())
                .map(|record| record.handle),
        }?;
        Some(GuestMemoryOwner::from_raw(owner))
    }

    /// Reallocate one live Win16 HGLOBAL. Invalid handles and allocator pressure
    /// are ordinary NULL results. Heap and selector state change together.
    pub(super) fn kernel_global_realloc(
        &mut self,
        guest_handle: u16,
        size: u32,
        flags: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        self.kernel_global_realloc_with_caller(guest_handle, size, flags, None, memory, host)
    }

    pub(super) fn kernel_global_realloc_with_caller(
        &mut self,
        guest_handle: u16,
        size: u32,
        flags: u16,
        caller: Option<GlobalMemoryCaller>,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        const MODELED_REALLOC_FLAGS: u16 = GMEM_MOVEABLE | GMEM_NOCOMPACT | GMEM_NODISCARD
            | GMEM_ZEROINIT | GMEM_MODIFY | GMEM_DISCARDABLE | GMEM_DDESHARE | GMEM_NOTIFY;
        let unmodeled = flags & !MODELED_REALLOC_FLAGS;
        if unmodeled != 0 && self.reported_global_realloc_flags.insert(unmodeled) {
            host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                format!("Win16 GlobalReAlloc flags 0x{unmodeled:04X} include unmodeled bits")));
        }
        if self.clipboard_state.owns_identity(
            guest_handle, self.global_handles.get(&guest_handle).copied(),
        ) {
            return Ok(0);
        }
        let Some(identity) = self.global_handles.get(&guest_handle).copied() else {
            return Ok(0);
        };
        let discarded_zero_realloc = size == 0
            && self.heap.info(identity).is_ok_and(|block| block.discarded);
        if self.queued_drop_files.iter().any(|entry|
            entry.guest_handle == guest_handle
                && entry.allocation == identity
                && entry.native_pending)
        {
            // The native queue still publishes this exact HGLOBAL on repeated
            // PM_NOREMOVE peeks; do not let guest reallocation invalidate or
            // recycle the stable MSG token before PM_REMOVE retires its lease.
            return Ok(0);
        }
        let primary = self.global_selectors.get(&guest_handle).copied();
        if primary.is_some_and(|selector| self.toolhelp_interrupt_owns_selector(selector)) {
            return Ok(0);
        }
        let shared_owner = if flags & (GMEM_MODIFY | GMEM_DDESHARE)
            == (GMEM_MODIFY | GMEM_DDESHARE) && !discarded_zero_realloc
        {
            // GMEM_DDESHARE takes the owner of the calling code. Resolve it
            // before changing flags or handles, including internal builtin
            // callers whose code does not live in a guest NE segment.
            let Some(owner) = self.global_memory_caller_owner(caller) else { return Ok(0); };
            Some(owner)
        } else {
            None
        };
        let modified_handle = if flags & (GMEM_MODIFY | GMEM_MOVEABLE)
            == (GMEM_MODIFY | GMEM_MOVEABLE) && !discarded_zero_realloc
        {
            let Some(selector) = primary else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 GlobalReAlloc has no primary selector"));
            };
            // Absence of GMEM_MOVEABLE never converts a movable allocation
            // back to a fixed selector or replaces its existing HGLOBAL.
            let Some(next) = selector.raw().0.checked_sub(1) else { return Ok(0); };
            if next == 0 || (next != guest_handle && (
                self.global_handles.contains_key(&next)
                    || self.dos_global_blocks.contains_key(&next)
                    || self.task_handles.values().any(|handle| *handle == next)
                    || self.module_memory_info(next).is_some()
            )) {
                return Ok(0);
            }
            Some(next)
        } else {
            None
        };
        let mut selector_updates = Vec::new();
        let result = self.heap.realloc_global(
            identity, size, flags, primary, memory, &mut self.selectors,
            &mut selector_updates,
        );
        self.apply_selector_updates(&selector_updates);
        self.sync_discarded_global_handles();
        match result {
            Ok(_) => {
                if let Some(owner) = shared_owner {
                    self.heap.set_guest_owner(identity, owner).map_err(crate::runtime_error)?;
                }
                let next = if let Some(next) = modified_handle {
                    if next != guest_handle {
                        self.global_handles.remove(&guest_handle);
                        self.global_handles.insert(next, identity);
                        if let Some(selector) = self.global_selectors.remove(&guest_handle) {
                            self.global_selectors.insert(next, selector);
                        }
                        if self.discarded_handles.remove(&guest_handle) {
                            self.discarded_handles.insert(next);
                        }
                    }
                    next
                } else {
                    guest_handle
                };
                for entry in &mut self.queued_drop_files {
                    if entry.guest_handle == guest_handle && entry.allocation == identity {
                        entry.guest_handle = next;
                    }
                }
                Ok(next)
            }
            Err(Win16Error::OutOfMemory | Win16Error::HandleTableFull
                | Win16Error::SelectorTableFull | Win16Error::Locked
                | Win16Error::SelectorBlockInterior | Win16Error::InvalidHandle
                | Win16Error::InvalidSize) => Ok(0),
            Err(error) => Err(crate::runtime_error(error)
                .with_context(format!("Win16 GlobalReAlloc for HGLOBAL 0x{guest_handle:04X}"))),
        }
    }

    /// Returns the stored Win16 memory attributes plus the live lock/discard
    /// state. The historical invalid-handle result is GMEM_INVALID_HANDLE.
    pub(super) fn kernel_global_flags(&self, guest_handle: u16) -> u32 {
        if let Some(block) = self.dos_global_blocks.get(&guest_handle) {
            return u32::from(block.fix_count.saturating_add(block.wire_count)
                .min(GMEM_LOCKCOUNT_MASK));
        }
        let Some(identity) = self.global_handles.get(&guest_handle).copied() else {
            return u32::from(GMEM_INVALID_HANDLE);
        };
        self.heap.global_flags(identity)
            .map(u32::from)
            .unwrap_or(u32::from(GMEM_INVALID_HANDLE))
    }

    /// Compact actual guest heap allocations, refresh moved selector
    /// generations, and report the largest range that remains allocatable.
    pub(super) fn kernel_global_compact(
        &mut self,
        minimum_free: u32,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        let mut selector_updates = Vec::new();
        let result = self.heap.compact(
            minimum_free, memory, &mut self.selectors, &mut selector_updates,
        );
        self.apply_selector_updates(&selector_updates);
        self.sync_discarded_global_handles();
        match result {
            Ok(largest) => Ok(largest),
            Err(Win16Error::OutOfMemory | Win16Error::SelectorTableFull) => {
                // Compaction may already have moved earlier eligible blocks.
                // Return the allocator's current measured maximum, not a
                // synthetic estimate, while preserving all committed rebinds.
                self.heap.maximum_available().map_err(crate::runtime_error)
            }
            Err(error) => Err(crate::runtime_error(error)
                .with_context("compacting the Win16 global heap")),
        }
    }

    pub(super) fn kernel_global_lru(
        &mut self,
        guest_handle: u16,
        oldest: bool,
    ) -> Result<u16, RuntimeError> {
        let Some(identity) = self.global_handles.get(&guest_handle).copied() else {
            return Ok(0);
        };
        let result = if oldest {
            self.heap.move_lru_oldest(identity)
        } else {
            self.heap.move_lru_newest(identity)
        };
        match result {
            Ok(()) => Ok(guest_handle),
            Err(Win16Error::InvalidHandle | Win16Error::OutOfMemory) => Ok(0),
            Err(error) => Err(crate::runtime_error(error)
                .with_context(format!("moving Win16 HGLOBAL 0x{guest_handle:04X} in LRU order"))),
        }
    }

    /// Move movable allocations toward the low end of the guest global heap,
    /// then retain a guest-visible lock and return the stable FAR selector.
    /// GlobalWire pins even nondiscardable blocks; this differs from Win3.1
    /// protected-mode GlobalLock, which does not pin those blocks.
    pub(super) fn kernel_global_wire(
        &mut self,
        guest_handle: u16,
        memory: &mut Memory,
    ) -> Result<u32, RuntimeError> {
        if let Some(block) = self.dos_global_blocks.get_mut(&guest_handle) {
            if block.wire_count == u16::MAX { return Ok(0); }
            let Some(selector) = self.global_selectors.get(&guest_handle).copied() else {
                return Err(RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                    "Win16 GlobalDOSAlloc selector mapping is missing"));
            };
            let descriptor = self.selectors.describe(selector).map_err(crate::runtime_error)?;
            if !descriptor.present { return Ok(0); }
            block.wire_count += 1;
            return Ok(u32::from(selector.raw().0) << 16);
        }
        let Some(identity) = self.global_handles.get(&guest_handle).copied() else {
            return Ok(0);
        };
        if self.heap.info(identity).map_err(crate::runtime_error)?.discarded {
            return Ok(0);
        }
        if !self.global_selectors.contains_key(&guest_handle) {
            return Err(RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "Win16 GlobalWire has no stable selector"));
        }
        let mut selector_updates = Vec::new();
        let compacted = self.heap.compact(
            0, memory, &mut self.selectors, &mut selector_updates,
        );
        self.apply_selector_updates(&selector_updates);
        self.sync_discarded_global_handles();
        match compacted {
            Ok(_) => {}
            Err(Win16Error::OutOfMemory | Win16Error::SelectorTableFull
                | Win16Error::SelectorBlockInterior | Win16Error::Locked) => return Ok(0),
            Err(error) => return Err(crate::runtime_error(error)
                .with_context("compacting the Win16 global heap for GlobalWire")),
        }
        match self.heap.fix(identity) {
            Ok(()) => {}
            Err(Win16Error::InvalidHandle | Win16Error::Locked
                | Win16Error::LockCountOverflow) => return Ok(0),
            Err(error) => return Err(crate::runtime_error(error)
                .with_context(format!("Win16 GlobalWire for HGLOBAL 0x{guest_handle:04X}"))),
        }
        let Some(selector) = self.global_selectors.get(&guest_handle).copied() else {
            self.heap.unfix(identity).map_err(crate::runtime_error)?;
            return Err(RuntimeError::new(crate::DiagnosticKind::InternalInvariant,
                "Win16 GlobalWire lost its stable selector"));
        };
        let descriptor = match self.selectors.describe(selector) {
            Ok(descriptor) => descriptor,
            Err(error) => {
                self.heap.unfix(identity).map_err(crate::runtime_error)?;
                return Err(crate::runtime_error(error)
                    .with_context("validating the Win16 GlobalWire selector"));
            }
        };
        if !descriptor.present {
            self.heap.unfix(identity).map_err(crate::runtime_error)?;
            return Ok(0);
        }
        Ok(u32::from(selector.raw().0) << 16)
    }

    /// Release one GlobalWire lock. Win16 returns TRUE when the shared guest
    /// lock count reaches zero, and FALSE while another guest lock remains.
    pub(super) fn kernel_global_unwire(
        &mut self,
        guest_handle: u16,
    ) -> Result<u16, RuntimeError> {
        if let Some(block) = self.dos_global_blocks.get_mut(&guest_handle) {
            if block.wire_count == 0 { return Ok(0); }
            block.wire_count -= 1;
            return Ok(u16::from(block.wire_count == 0));
        }
        let Some(identity) = self.global_handles.get(&guest_handle).copied() else {
            return Ok(0);
        };
        match self.heap.unfix(identity) {
            Ok(_) => {
                let info = self.heap.info(identity).map_err(crate::runtime_error)?;
                Ok(u16::from(info.lock_count == 0))
            }
            Err(Win16Error::InvalidHandle | Win16Error::LockUnderflow) => Ok(0),
            Err(error) => Err(crate::runtime_error(error)
                .with_context(format!("Win16 GlobalUnWire for HGLOBAL 0x{guest_handle:04X}"))),
        }
    }

    /// GlobalFix adds an independent fix reference. The Win3.1 SDK declares
    /// void; the catalog applies the project's AX/DX-preserving Void policy.
    /// The internal zero is not a guest success or lock-count result.
    pub(super) fn kernel_global_fix(
        &mut self,
        guest_handle: u16,
        _memory: &Memory,
    ) -> Result<u16, RuntimeError> {
        if let Some(block) = self.dos_global_blocks.get_mut(&guest_handle) {
            if block.fix_count == u16::MAX { return Ok(0); }
            block.fix_count += 1;
            return Ok(0);
        }
        let Some(identity) = self.global_handles.get(&guest_handle).copied() else {
            return Ok(0);
        };
        match self.heap.fix(identity) {
            Ok(_) => Ok(0),
            Err(Win16Error::InvalidHandle | Win16Error::Locked
                | Win16Error::LockCountOverflow) => Ok(0),
            Err(error) => Err(crate::runtime_error(error)
                .with_context(format!("Win16 GlobalFix for HGLOBAL 0x{guest_handle:04X}"))),
        }
    }

    /// GlobalUnfix releases one GlobalFix reference. Its internal remaining
    /// count is exposed through the existing CX compatibility behavior, not
    /// AX/DX: the SDK declaration is void and the catalog uses Void.
    pub(super) fn kernel_global_unfix(
        &mut self,
        guest_handle: u16,
    ) -> Result<u16, RuntimeError> {
        if let Some(block) = self.dos_global_blocks.get_mut(&guest_handle) {
            if block.fix_count != 0 { block.fix_count -= 1; }
            return Ok(block.fix_count);
        }
        let Some(identity) = self.global_handles.get(&guest_handle).copied() else {
            return Ok(0);
        };
        match self.heap.unfix(identity) {
            Ok(remaining) => Ok(remaining),
            Err(Win16Error::InvalidHandle | Win16Error::LockUnderflow) => Ok(0),
            Err(error) => Err(crate::runtime_error(error)
                .with_context(format!("Win16 GlobalUnfix for HGLOBAL 0x{guest_handle:04X}"))),
        }
    }

    /// Lock a loaded NE segment by its segment selector or Win16 segment
    /// handle. Main-image segments live in the reserved guest arena and are
    /// fixed for their lifetime; locking them requires no heap transition.
    pub(super) fn kernel_lock_segment(
        &mut self,
        segment: u16,
        memory: &Memory,
    ) -> Result<u16, RuntimeError> {
        let Some((selector, allocation)) = self.module_segment(segment, false)? else { return Ok(0); };
        if let Some(identity) = allocation {
            match self.heap.lock_segment(identity, &mut self.selectors, memory) {
                Ok(_) => return Ok(segment),
                Err(Win16Error::SelectorTableFull | Win16Error::OutOfMemory
                    | Win16Error::LockCountOverflow | Win16Error::InvalidHandle) => return Ok(0),
                Err(error) => return Err(crate::runtime_error(error)
                    .with_context(format!("locking Win16 segment 0x{segment:04X}"))),
            }
        }
        if self.selectors.reference(Selector(selector)).is_ok() {
            Ok(segment)
        } else {
            Ok(0)
        }
    }

    /// Unlock one caller-acquired module segment lock. The module loader's
    /// retained baseline lock is never consumed by this API.
    pub(super) fn kernel_unlock_segment(
        &mut self,
        segment: u16,
    ) -> Result<u16, RuntimeError> {
        let Some((_selector, allocation)) = self.module_segment(segment, true)? else { return Ok(0); };
        let Some(identity) = allocation else { return Ok(0); };
        match self.heap.unlock_segment(identity, &mut self.selectors) {
            Ok(_) => {
                // The Win16 API's remaining-lock result is returned in CX.
                // The loader pin is separate and must not leak into that count.
                self.module_reap_pending = true;
                let remaining = self.heap.info(identity).map_err(crate::runtime_error)?.lock_count;
                Ok(remaining)
            }
            Err(Win16Error::LockUnderflow | Win16Error::InvalidHandle) => Ok(0),
            Err(error) => Err(crate::runtime_error(error)
                .with_context(format!("unlocking Win16 segment 0x{segment:04X}"))),
        }
    }

    /// The Win16 flags argument is retained in the ABI but the current guest
    /// heap has one ownership domain, so report its actual aggregate free size.
    pub(super) fn kernel_get_free_space(&self, _flags: u16) -> Result<u32, RuntimeError> {
        let available = self.heap.total_available().map_err(crate::runtime_error)?;
        Ok(u32::try_from(available).unwrap_or(u32::MAX))
    }

    fn module_segment(
        &self,
        input: u16,
        for_unlock: bool,
    ) -> Result<Option<(u16, Option<GlobalHandle>)>, RuntimeError> {
        let Some((&selector, _)) = self.loaded_segment_handles.iter().find(|(selector, handle)| {
            **selector == input || **handle == input
        }) else { return Ok(None); };
        for record in self.modules.records.values() {
            if record.state == ModuleState::Retired && !for_unlock {
                continue;
            }
            if !record.loaded.as_ref().is_some_and(|loaded| {
                    loaded.segments.iter().any(|segment| segment.selector.0 == selector)
                }) {
                continue;
            }
            if let Some(allocation) = record.allocations.iter()
                .find(|allocation| allocation.selector.raw().0 == selector)
            {
                if record.state == ModuleState::Retired
                    && self.heap.info(allocation.handle).map_err(crate::runtime_error)?.lock_count == 0
                {
                    continue;
                }
                return Ok(Some((selector, Some(allocation.handle))));
            }
            if record.handle == self.modules.main {
                return Ok(Some((selector, None)));
            }
        }
        Ok(None)
    }

    pub(super) fn apply_selector_updates(&mut self, updates: &[(SelectorRef, SelectorRef)]) {
        for &(old, replacement) in updates {
            for reference in self.global_selectors.values_mut() {
                if *reference == old { *reference = replacement; }
            }
            for reference in self.allocated_selector_aliases.values_mut() {
                if *reference == old { *reference = replacement; }
            }
            for reference in self.api_allocated_selectors.values_mut() {
                if *reference == old { *reference = replacement; }
            }
            for reference in self.real_mode_vector_aliases.values_mut() {
                if *reference == old { *reference = replacement; }
            }
            for entry in self.selector_backing_leases.values_mut() {
                if entry.reference == old { entry.reference = replacement; }
                for lease in &mut entry.leases {
                    match lease {
                        super::selector_ownership::SelectorBackingLease::Dos {
                            primary: Some(primary), ..
                        }
                        | super::selector_ownership::SelectorBackingLease::ModuleImage {
                            primary, ..
                        } if *primary == old => *primary = replacement,
                        _ => {}
                    }
                }
            }
            if let Some(entry) = self.mapls_selectors.get_mut(&old.raw().0)
                && entry.reference == old
            {
                entry.reference = replacement;
            }
            for pointer in self.protected_dos_vectors.values_mut().flatten()
                .chain(self.win87em_exception_handler.iter_mut()) {
                if pointer.selector() == old {
                    *pointer = win16_abi::SegmentedPointer::new(replacement, pointer.offset());
                }
            }
            self.global_notify.update_selector(old, replacement);
            for pointer in self.interrupt_callbacks.values_mut() {
                if pointer.selector() == old {
                    *pointer = win16_abi::SegmentedPointer::new(replacement, pointer.offset());
                }
            }
            for registration in self.toolhelp_interrupt_handles.values_mut() {
                if registration.callback_selector == old {
                    registration.callback_selector = replacement;
                }
            }
            for frame in &mut self.toolhelp_interrupt_frames {
                if frame.callback.selector() == old {
                    frame.callback = win16_abi::SegmentedPointer::new(
                        replacement,
                        frame.callback.offset(),
                    );
                }
                if let Some(stack) = frame.private_stack.as_mut()
                    && stack.selector == old
                {
                    stack.selector = replacement;
                }
            }
            for retained in &mut self.toolhelp_interrupt_retained_stacks {
                if retained.allocation.selector == old {
                    retained.allocation.selector = replacement;
                }
            }
            for frame in &mut self.interrupt_returns {
                if frame.code == old { frame.code = replacement; }
                if frame.stack == old { frame.stack = replacement; }
            }
            for record in self.modules.records.values_mut() {
                for allocation in &mut record.allocations {
                    if allocation.selector == old { allocation.selector = replacement; }
                }
            }
        }
    }

    pub(super) fn sync_discarded_global_handles(&mut self) {
        self.discarded_handles.clear();
        for (&guest_handle, &identity) in &self.global_handles {
            if self.heap.info(identity).is_ok_and(|info| info.discarded) {
                self.discarded_handles.insert(guest_handle);
            }
        }
    }

    pub(super) fn global_alloc(
        &mut self,
        raw_flags: u16,
        size: u32,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        self.global_alloc_with_caller(raw_flags, size, 0, memory, host)
    }

    pub(super) fn global_alloc_with_caller(
        &mut self,
        raw_flags: u16,
        size: u32,
        caller_code_selector: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        self.global_alloc_with_context(
            raw_flags, size, Some(GlobalMemoryCaller::GuestCode(caller_code_selector)), memory, host,
        )
    }

    pub(super) fn global_alloc_with_context(
        &mut self,
        raw_flags: u16,
        size: u32,
        caller: Option<GlobalMemoryCaller>,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        self.global_alloc_with_context_at_slot(
            raw_flags, size, caller, None, memory, host,
        )
    }

    pub(super) fn global_alloc_at_selector(
        &mut self,
        raw_flags: u16,
        size: u32,
        selector: u16,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        if selector & 0x04 == 0 || selector >> 3 == 0 {
            return Ok(0);
        }
        self.global_alloc_with_context_at_slot(
            raw_flags,
            size,
            None,
            Some(usize::from(selector >> 3)),
            memory,
            host,
        )
    }

    fn global_alloc_with_context_at_slot(
        &mut self,
        raw_flags: u16,
        size: u32,
        caller: Option<GlobalMemoryCaller>,
        selector_slot: Option<usize>,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        let movable = raw_flags & GMEM_MOVEABLE != 0;
        if size == 0 && !movable { return Ok(0); }
        if selector_slot.is_some() && movable { return Ok(0); }
        // A zero-sized movable HGLOBAL retains a selector identity but has no
        // guest-memory backing. It must not consume an unrelated byte in the
        // shared heap as a stand-in for a discarded object.
        let discarded = size == 0;
        let owner = self.tasks.current().ok_or_else(|| RuntimeError::new(
            Kind::InternalInvariant, "Win16 GlobalAlloc has no current task owner"))?;
        let task_handle = self.current_task_handle()?;
        let guest_owner = if raw_flags & GMEM_DDESHARE != 0 {
            let Some(owner) = self.global_memory_caller_owner(caller) else {
                return Ok(0);
            };
            owner
        } else {
            GuestMemoryOwner::from_raw(task_handle)
        };
        let flags = AllocationFlags {
            movable,
            zero_init: raw_flags & GMEM_ZEROINIT != 0,
            executable: false,
        };
        let allocation = if discarded {
            self.heap.alloc_discarded_with_guest_owner(
                owner, Some(guest_owner), flags, raw_flags,
            )
        } else {
            self.heap.alloc_with_guest_owner(memory, owner, guest_owner, size, flags, raw_flags)
        };
        let handle = match allocation {
            Ok(handle) => handle,
            Err(Win16Error::OutOfMemory | Win16Error::HandleTableFull
                | Win16Error::InvalidSize) => return Ok(0),
            Err(error) => return Err(crate::runtime_error(error)),
        };
        let selector_result = if discarded {
            self.selectors.reserve_unbacked()
        } else {
            let base = self.heap.info(handle).map_err(crate::runtime_error)?.base;
            match selector_slot {
                Some(slot) => self.selectors.alloc_block_at_slot(
                    slot, base, size, AccessRights::read_write(), memory,
                ),
                None => self.selectors.alloc_block(
                    base, size, AccessRights::read_write(), memory,
                ),
            }
        };
        let selector = match selector_result {
            Ok(selector) => selector,
            Err(Win16Error::SelectorTableFull | Win16Error::OutOfMemory) => {
                self.heap.free(handle, &mut self.selectors).map_err(crate::runtime_error)?;
                return Ok(0);
            }
            Err(error) => {
                self.heap.free(handle, &mut self.selectors).map_err(crate::runtime_error)?;
                return Err(crate::runtime_error(error));
            }
        };
        if let Err(error) = self.heap.bind_runtime_primary(handle, selector) {
            self.selectors.free_block(selector).map_err(crate::runtime_error)?;
            self.heap.free(handle, &mut self.selectors).map_err(crate::runtime_error)?;
            return Err(crate::runtime_error(error)
                .with_context("binding the Win16 HGLOBAL primary selector"));
        }
        // Windows 3.x identifies a fixed HGLOBAL by its selector and a
        // movable HGLOBAL by the selector minus one. Both stay stable while
        // the object is allocated, even across GlobalUnlock.
        let guest_handle = if movable {
            selector.raw().0.checked_sub(1).ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant, "Win16 movable selector has no handle value",
            ))?
        } else {
            selector.raw().0
        };
        if guest_handle == 0 || self.global_handles.contains_key(&guest_handle)
            || self.dos_global_blocks.contains_key(&guest_handle)
        {
            self.heap.free(handle, &mut self.selectors).map_err(crate::runtime_error)?;
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 global selector collided with another handle"));
        }
        self.global_handles.insert(guest_handle, handle);
        self.global_selectors.insert(guest_handle, selector);
        if discarded { self.discarded_handles.insert(guest_handle); }
        let modeled_flags = GMEM_MOVEABLE | GMEM_NOCOMPACT | GMEM_NODISCARD
            | GMEM_ZEROINIT | GMEM_DISCARDABLE | GMEM_DDESHARE | GMEM_NOTIFY;
        if raw_flags & !modeled_flags != 0
            && self.reported_global_flags.insert(raw_flags)
        {
            host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                format!("Win16 GlobalAlloc flags 0x{raw_flags:04X} include unmodeled bits")));
        }
        Ok(guest_handle)
    }

    pub(super) fn global_free(&mut self, guest_handle: u16) -> Result<u16, RuntimeError> {
        // USER owns both transferred blocks and aliases returned by
        // GetClipboardData until their format is retired. Native clipboard
        // memory is a separate copy; freeing the guest identity here would
        // invalidate an observable USER handle while it remains live.
        if self.clipboard_state.owns_identity(
            guest_handle, self.global_handles.get(&guest_handle).copied(),
        ) {
            return Ok(guest_handle);
        }
        if self.task_handles.values().any(|handle| *handle == guest_handle) {
            return Ok(guest_handle);
        }
        let Some(&handle) = self.global_handles.get(&guest_handle) else { return Ok(guest_handle); };
        let queued_drop = self.queued_drop_files.iter().position(|entry|
            entry.guest_handle == guest_handle
                && entry.allocation == handle
        );
        if let Some(index) = queued_drop {
            self.queued_drop_files[index].finish_requested = true;
            if self.queued_drop_files[index].native_pending {
                // PM_NOREMOVE still owns the native queue record. Keep the same
                // guest HGLOBAL identity live so a repeated PeekMessage returns
                // the same MSG lease rather than a stale/recycled handle.
                return Ok(guest_handle);
            }
        }
        if self.global_selectors.get(&guest_handle).copied()
            .is_some_and(|selector| self.toolhelp_interrupt_owns_selector(selector))
        {
            return Ok(guest_handle);
        }
        if self.heap.runtime_primary_selector(handle).map_err(crate::runtime_error)?
            != self.global_selectors.get(&guest_handle).copied()
        {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "Win16 HGLOBAL primary does not match its GlobalHeap owner"));
        }
        let info = match self.heap.info(handle) {
            Ok(info) => info,
            Err(Win16Error::InvalidHandle | Win16Error::StaleHandle) => return Ok(guest_handle),
            Err(error) => return Err(crate::runtime_error(error)),
        };
        let internal_pins = self.heap.internal_pin_count(handle).map_err(crate::runtime_error)?;
        // GlobalFree remains a guest-visible busy result while any guest lock,
        // loader pin, or page pin is active. Alias retirement and exact map
        // removal use the same canonical owner path as runtime allocations.
        if info.lock_count != 0 || info.page_lock_count != 0 || internal_pins != 0 {
            return Ok(guest_handle);
        }
        match self.free_runtime_global_on_teardown(handle)? {
            GlobalTeardownResult::Freed => {
                self.queued_drop_files.retain(|entry|
                    entry.guest_handle != guest_handle || entry.allocation != handle);
                Ok(0)
            }
            GlobalTeardownResult::Retained { .. } => Ok(guest_handle),
        }
    }

    pub(super) fn free_global_on_teardown(&mut self, guest_handle: u16,
        expected: GlobalHandle) -> Result<GlobalTeardownResult, RuntimeError> {
        let _ = guest_handle;
        self.free_runtime_global_on_teardown(expected)
    }

    pub(super) fn free_global_on_teardown_without_primary(
        &mut self,
        guest_handle: u16,
        expected: GlobalHandle,
    ) -> Result<GlobalTeardownResult, RuntimeError> {
        let _ = guest_handle;
        self.free_runtime_global_on_teardown(expected)
    }

    /// Release one runtime-owned GlobalHeap generation, whether or not the
    /// caller ever published a Win16 HGLOBAL mapping for it.
    pub(super) fn free_runtime_global_on_teardown(
        &mut self,
        expected: GlobalHandle,
    ) -> Result<GlobalTeardownResult, RuntimeError> {
        self.global_memory_teardown_access().free_runtime_global_on_teardown(expected)
    }

    pub(super) fn global_lock(&mut self, guest_handle: u16, _memory: &Memory) -> Result<u32, RuntimeError> {
        if self.task_handles.values().any(|handle| *handle == guest_handle) {
            return Ok(u32::from(guest_handle) << 16);
        }
        if let Some((selector, _)) = self.module_memory_info(guest_handle) {
            return Ok(u32::from(selector) << 16);
        }
        if self.dos_global_blocks.contains_key(&guest_handle) {
            let Some(selector) = self.global_selectors.get(&guest_handle).copied() else {
                return Err(RuntimeError::new(Kind::InternalInvariant,
                    "Win16 GlobalDOSAlloc selector mapping is missing"));
            };
            let descriptor = self.selectors.describe(selector).map_err(crate::runtime_error)?;
            return Ok(if descriptor.present { u32::from(selector.raw().0) << 16 } else { 0 });
        }
        let Some(&handle) = self.global_handles.get(&guest_handle) else { return Ok(0); };
        // Validate the complete returned selector before the heap can add a
        // lock. An invariant/presence failure must leave no partial lock that
        // a retried LockResource result would acquire a second time.
        let selector = self.global_selectors.get(&guest_handle).copied().ok_or_else(||
            RuntimeError::new(Kind::InternalInvariant, "Win16 global selector is missing"))?;
        let descriptor = self.selectors.describe(selector).map_err(crate::runtime_error)?;
        if !descriptor.present {
            return Ok(0);
        }
        match self.heap.global_lock(handle) {
            Ok(()) => {
                // GlobalLock does not pin nondiscardable movable blocks in
                // Win3.1 protected mode. Their stable guest selector is
                // rebound by GlobalHeap whenever the allocation moves.
                Ok(u32::from(selector.raw().0) << 16)
            }
            Err(Win16Error::InvalidHandle | Win16Error::SelectorTableFull
                | Win16Error::OutOfMemory | Win16Error::LockCountOverflow) => Ok(0),
            Err(error) => Err(crate::runtime_error(error)),
        }
    }

    pub(super) fn global_unlock(&mut self, guest_handle: u16) -> Result<u16, RuntimeError> {
        if self.dos_global_blocks.contains_key(&guest_handle) { return Ok(0); }
        let Some(&handle) = self.global_handles.get(&guest_handle) else { return Ok(0); };
        match self.heap.global_unlock(handle) {
            Ok(remaining) => {
                if !remaining {
                    self.retry_finished_queued_drop_file(guest_handle)?;
                }
                Ok(u16::from(remaining))
            }
            Err(Win16Error::InvalidHandle | Win16Error::LockUnderflow) => Ok(0),
            Err(error) => Err(crate::runtime_error(error)),
        }
    }

    pub(super) fn global_size(&self, guest_handle: u16) -> Result<u32, RuntimeError> {
        if self.task_handles.values().any(|handle| *handle == guest_handle) {
            return Ok(TASK_DATABASE_PREFIX_SIZE as u32);
        }
        if let Some((_, size)) = self.module_memory_info(guest_handle) { return Ok(size); }
        if let Some(block) = self.dos_global_blocks.get(&guest_handle) { return Ok(block.size); }
        let Some(&handle) = self.global_handles.get(&guest_handle) else { return Ok(0); };
        match self.heap.info(handle) {
            Ok(info) => Ok(info.size),
            Err(Win16Error::InvalidHandle) => Ok(0),
            Err(error) => Err(crate::runtime_error(error)),
        }
    }
}

#[cfg(test)]
#[path = "win16_global_fix_void_tests.rs"]
mod fix_void_tests;
