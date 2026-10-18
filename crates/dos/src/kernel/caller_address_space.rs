//! DOS caller-owned addresses retained between INT 21h calls.

use crate::{DosError, DosHost};
use guest_core::MemoryError;

use super::super::caller_address_space::{
    DosCallAddressSpace, DosCallerId, DosFarPointer, DosPersistentFarPointer, DosPointerAccess,
};
use super::state::DosKernel;

const DTA_BYTES: usize = 43;
const PSP_PREFIX_BYTES: usize = 0x100;
const DEFAULT_PSP_DTA_OFFSET: u16 = 0x80;

impl DosKernel {
    pub(super) fn set_caller_dta(
        &mut self,
        memory: &mut impl DosCallAddressSpace,
        segment_or_selector: u16,
        offset: u16,
    ) -> Result<(), DosError> {
        let caller = memory.caller_id();
        if caller == DosCallerId::REAL_MODE {
            self.dta_segment = segment_or_selector;
            self.dta_offset = offset;
            return Ok(());
        }

        let far = memory.resolve_caller_pointer(segment_or_selector, offset)?;
        self.retained_dta_by_caller
            .entry(caller)
            .or_default()
            .try_reserve(1)
            .map_err(|_| DosError::Memory(MemoryError::AllocationFailed))?;
        // Retaining before comparing is deliberate: raw selector words do not
        // identify a descriptor generation, while the opaque token does.
        let retained = memory.retain_caller_pointer(far)?;
        {
            let pointers = self.retained_dta_by_caller.entry(caller).or_default();
            if !pointers.contains(&retained) {
                pointers.push(retained);
            }
        }
        let previous = self.dta_by_caller.insert(caller, retained);
        if previous != Some(retained) {
            self.prune_caller_dta_leases(caller, memory)?;
        }
        Ok(())
    }

    pub(super) fn caller_dta(
        &mut self,
        memory: &mut impl DosCallAddressSpace,
    ) -> Result<DosPersistentFarPointer, DosError> {
        let caller = memory.caller_id();
        if caller == DosCallerId::REAL_MODE {
            let pointer =
                DosFarPointer::real_mode(DosCallerId::REAL_MODE, self.dta_segment, self.dta_offset);
            return memory.retain_caller_pointer(pointer);
        }
        if let Some(pointer) = self.dta_by_caller.get(&caller).copied() {
            return Ok(pointer);
        }

        // The default DTA is an address into PSP:80h. DOS writes a 43-byte
        // record, while the protected selector must keep the complete backing
        // range alive for as long as the runtime-owned alias remains valid.
        // Explicit protected AH=1Ah pointers use the retained-pointer path.
        let canonical_default = self.dta_segment == self.psp_segment
            && self.dta_offset == DEFAULT_PSP_DTA_OFFSET
            && self.mcb_head.is_some();
        let has_backing_lease = self.block_leases.has_caller_range_lease(
            caller,
            self.psp_segment,
            self.psp_segment,
            0,
            PSP_PREFIX_BYTES,
        )?;
        let mut new_backing_lease = None;
        let default_psp_view_is_proven = if canonical_default && has_backing_lease {
            self.owned_block_extent(memory, self.psp_segment, self.psp_segment)?
                .is_some_and(|extent| {
                    extent.data_segment() == self.psp_segment
                        && extent.owner_psp_segment() == self.psp_segment
                        && extent
                            .byte_length()
                            .is_some_and(|bytes| bytes >= PSP_PREFIX_BYTES)
                })
        } else if canonical_default {
            new_backing_lease = self.pin_owned_block_range_for_caller(
                memory,
                self.psp_segment,
                self.psp_segment,
                0,
                PSP_PREFIX_BYTES,
                caller,
            )?;
            new_backing_lease.is_some()
        } else {
            false
        };
        let view = if default_psp_view_is_proven {
            let psp_view = match memory.expose_dos_pointer(
                self.psp_segment,
                0,
                PSP_PREFIX_BYTES,
                DosPointerAccess::Write,
            ) {
                Ok(view) => view,
                Err(cause) => {
                    if let Some(lease) = new_backing_lease.take() {
                        if let Err(rollback) = self.release_block_lease(memory, &lease, false) {
                            // The shared registry keeps the caller association
                            // reachable for teardown retry despite this local
                            // handle leaving scope.
                            return Err(DosError::RollbackFailure {
                                operation: "expose default PSP DTA alias",
                                cause: Box::new(cause),
                                rollback: Box::new(rollback),
                            });
                        }
                    }
                    return Err(cause);
                }
            };
            // The registry owns the caller association before this selector
            // becomes visible; dropping this local token cannot release it.
            drop(new_backing_lease.take());
            match psp_view {
                DosFarPointer::Protected {
                    caller, selector, ..
                } => DosFarPointer::protected(caller, selector, DEFAULT_PSP_DTA_OFFSET),
                DosFarPointer::RealMode { .. } => {
                    return Err(DosError::HostContractViolation(
                        "protected DOS caller received a real-mode PSP alias",
                    ));
                }
            }
        } else {
            memory.expose_dos_pointer(
                self.dta_segment,
                self.dta_offset,
                DTA_BYTES,
                DosPointerAccess::Write,
            )?
        };
        self.retained_dta_by_caller
            .entry(caller)
            .or_default()
            .try_reserve(1)
            .map_err(|_| DosError::Memory(MemoryError::AllocationFailed))?;
        let retained = memory.retain_caller_pointer(view)?;
        {
            let pointers = self.retained_dta_by_caller.entry(caller).or_default();
            if !pointers.contains(&retained) {
                pointers.push(retained);
            }
        }
        self.dta_by_caller.insert(caller, retained);
        Ok(retained)
    }

    fn prune_caller_dta_leases(
        &mut self,
        caller: DosCallerId,
        memory: &mut impl DosCallAddressSpace,
    ) -> Result<(), DosError> {
        let current = self.dta_by_caller.get(&caller).copied();
        let searches = &self.searches;
        let empty = {
            let Some(pointers) = self.retained_dta_by_caller.get_mut(&caller) else {
                return Ok(());
            };
            let mut index = 0;
            while index < pointers.len() {
                let pointer = pointers[index];
                let (segment_or_selector, offset) = pointer.pointer().words();
                let has_search = searches.keys().any(|key| {
                    key.kind == super::state::SearchKind::Dta && key.caller == caller
                        && key.dta_segment == segment_or_selector
                        && key.dta_offset == offset
                        && key.dta_lease == pointer.lease()
                });
                if Some(pointer) == current || has_search {
                    index += 1;
                } else {
                    memory.release_caller_pointer(pointer)?;
                    pointers.remove(index);
                }
            }
            pointers.is_empty()
        };
        if empty {
            self.retained_dta_by_caller.remove(&caller);
        }
        Ok(())
    }

    pub(super) fn caller_dta_words(
        &mut self,
        memory: &mut impl DosCallAddressSpace,
    ) -> Result<(u16, u16), DosError> {
        if memory.caller_id() == DosCallerId::REAL_MODE {
            // AH=2Fh returns the words stored by AH=1Ah; it does not access
            // the DTA. Consumers such as Find First still validate its range.
            return Ok((self.dta_segment, self.dta_offset));
        }
        let pointer = self.caller_dta(memory)?;
        memory.validate_persistent_range(pointer, 0, 0, DosPointerAccess::Read)?;
        Ok(pointer.pointer().words())
    }

    /// Release selector-backing range pins after the runtime has successfully
    /// retired every protected alias owned by this caller. On failure the
    /// shared lease registry retains each unfreed token for teardown retry.
    pub fn release_caller_dta_backing_leases(
        &mut self,
        memory: &mut impl guest_core::GuestMemory,
        caller: DosCallerId,
    ) -> Result<(), DosError> {
        while let Some(lease) = self.block_leases.first_caller_range_lease(caller)? {
            // The registry association is removed only after the checked
            // release succeeds. A failure leaves the token available to retry
            // even when a different child DosKernel owns this call frame.
            self.release_block_lease(memory, &lease, false)?;
        }
        Ok(())
    }

    /// Release address-space leases retained for one DOS caller during task
    /// teardown. DOS process exit is not proof that the caller task ended: the
    /// runtime must call this explicitly before retiring that caller's selector
    /// table, including after synchronous DOS child execution returns.
    pub fn release_caller_address_space(
        &mut self,
        memory: &mut impl DosCallAddressSpace,
        host: &mut impl DosHost,
    ) -> Result<(), DosError> {
        let caller = memory.caller_id();
        // Copy one owned identity at a time, so teardown needs no allocation
        // and a failed host close leaves that search available for retry.
        while let Some((key, search)) = self
            .searches
            .iter()
            .find(|(key, _)| key.caller == caller)
            .map(|(key, search)| (*key, *search))
        {
            host.directory_search_close(search.host_search)
                .map_err(DosError::HostOperation)?;
            self.searches.remove(&key);
        }

        self.fcb_searches.release_caller(caller);
        self.dta_by_caller.remove(&caller);
        if let Some(pointers) = self.retained_dta_by_caller.get_mut(&caller) {
            while let Some(pointer) = pointers.last().copied() {
                memory.release_caller_pointer(pointer)?;
                pointers.pop();
            }
            self.retained_dta_by_caller.remove(&caller);
        }
        Ok(())
    }
}

/// Build a deterministic key for DOS FindFirst/FindNext state. The lease
/// distinguishes selector generations even when a guest reuses the same raw
/// selector and offset.
pub(super) fn search_address_key(
    caller: DosCallerId,
    pointer: DosPersistentFarPointer,
) -> (DosCallerId, u16, u16, u64) {
    let (segment_or_selector, offset) = pointer.pointer().words();
    (caller, segment_or_selector, offset, pointer.lease())
}

pub(super) fn validate_dta_write(
    memory: &mut impl DosCallAddressSpace,
    pointer: DosPersistentFarPointer,
) -> Result<(), DosError> {
    memory.validate_persistent_range(pointer, 0, DTA_BYTES, DosPointerAccess::Write)
}

pub(super) fn validate_dta_read(
    memory: &mut impl DosCallAddressSpace,
    pointer: DosPersistentFarPointer,
    length: usize,
) -> Result<(), DosError> {
    memory.validate_persistent_range(pointer, 0, length, DosPointerAccess::Read)
}

pub(super) fn read_dta_prefix(
    memory: &mut impl DosCallAddressSpace,
    pointer: DosPersistentFarPointer,
    output: &mut [u8],
) -> Result<(), DosError> {
    memory.read_persistent_range(pointer, 0, output)
}

pub(super) fn write_dta(
    memory: &mut impl DosCallAddressSpace,
    pointer: DosPersistentFarPointer,
    input: &[u8],
) -> Result<(), DosError> {
    memory.write_persistent_range(pointer, 0, input)
}
