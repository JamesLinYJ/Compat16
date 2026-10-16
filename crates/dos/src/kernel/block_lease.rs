//! Explicit leases protecting DOS MCB allocations used by host-backed views.
//!
//! A lease records DOS allocation provenance, not a Win16 selector. Its weak
//! registry identity and monotonic token distinguish allocations independently
//! of guest segment numbers; cloned DOS child contexts share the same registry.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::{Rc, Weak};

use crate::{DosError, DosErrorCode, DosHostError};
use guest_core::{GuestMemory, MemoryError, PhysAddr};

use super::super::caller_address_space::DosCallerId;
use super::DosBlockExtent;
use super::memory::{
    allocate_block_for_owner, coalesce_free_mcb_chain, write_mcb, write_mcb_batch,
};
use super::state::{DosKernel, Mcb};

#[derive(Clone, Debug)]
pub(super) struct DosBlockLeases {
    inner: Rc<RefCell<LeaseRegistry>>,
}

#[derive(Debug)]
struct LeaseRegistry {
    next_token: Option<u64>,
    leases: BTreeMap<u64, LeaseRecord>,
    /// A partial MCB/publication transfer cannot be rolled back or retried.
    /// This barrier is shared by every DOS context using the allocation arena.
    storage_faulted: bool,
    /// Record the owner and requested extent before any allocation MCB write.
    /// On uncertain failure this is retained as intent, not a proven live block.
    allocation_intent: Option<(u16, u16)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeaseRange {
    Exact,
    /// The allocation may resize while this byte-prefix remains allocated.
    Prefix {
        minimum_paragraphs: u16,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LeaseRecord {
    extent: DosBlockExtent,
    range: LeaseRange,
    /// Protected selector aliases outlive a DOS call and may be retired
    /// through a child `DosKernel` sharing this registry.
    caller: Option<DosCallerId>,
}

/// An explicit pin on one DOS-owned MCB allocation.
///
/// There is intentionally no `Drop` implementation: releasing a guest MCB
/// needs `GuestMemory` and is safe only after its host selectors are invalidated.
#[derive(Debug)]
pub struct DosBlockLease {
    registry_identity: Weak<RefCell<LeaseRegistry>>,
    token: u64,
    record: LeaseRecord,
}

impl DosBlockLease {
    /// DOS allocation provenance observed when this lease was acquired.
    /// Prefix-range leases may permit later resizing while keeping their range.
    pub fn extent(&self) -> DosBlockExtent {
        self.record.extent
    }
}

impl DosBlockLeases {
    pub(super) fn new() -> Self {
        Self {
            inner: Rc::new(RefCell::new(LeaseRegistry {
                next_token: Some(1),
                leases: BTreeMap::new(),
                storage_faulted: false,
                allocation_intent: None,
            })),
        }
    }

    pub(super) fn check_storage_state(&self) -> Result<(), DosError> {
        let registry = self.inner.try_borrow().map_err(|_| {
            DosError::HostContractViolation("DOS block lease registry is already borrowed")
        })?;
        if registry.storage_faulted {
            return Err(DosError::HostContractViolation(
                "DOS allocation arena has an uncertain storage mutation; execution and cleanup are stopped",
            ));
        }
        Ok(())
    }

    pub(super) fn poison_on_storage_failure(&self, error: &DosError) -> Result<(), DosError> {
        if uncertain_storage_failure(error) {
            let mut registry = self.inner.try_borrow_mut().map_err(|_| {
                DosError::HostContractViolation("DOS block lease registry is already borrowed")
            })?;
            registry.storage_faulted = true;
        }
        Ok(())
    }

    fn reserve_token(&self) -> Result<(Weak<RefCell<LeaseRegistry>>, u64), DosError> {
        let mut registry = self.inner.try_borrow_mut().map_err(|_| {
            DosError::HostContractViolation("DOS block lease registry is already borrowed")
        })?;
        let token = registry.next_token.ok_or(DosError::HostContractViolation(
            "DOS block lease token space is exhausted",
        ))?;
        registry.next_token = token.checked_add(1);
        Ok((Rc::downgrade(&self.inner), token))
    }

    fn insert_reserved(&self, token: u64, record: LeaseRecord) -> Result<(), DosError> {
        let mut registry = self.inner.try_borrow_mut().map_err(|_| {
            DosError::HostContractViolation("DOS block lease registry is already borrowed")
        })?;
        if registry.leases.contains_key(&token) {
            return Err(DosError::HostContractViolation(
                "DOS block lease token was reused",
            ));
        }
        registry.leases.insert(token, record);
        Ok(())
    }

    fn recorded_lease(&self, lease: &DosBlockLease) -> Result<LeaseRecord, DosError> {
        let expected_registry = Rc::downgrade(&self.inner);
        if !Weak::ptr_eq(&lease.registry_identity, &expected_registry) {
            return Err(DosError::HostContractViolation(
                "DOS block lease belongs to a different allocation arena",
            ));
        }
        let registry = self.inner.try_borrow().map_err(|_| {
            DosError::HostContractViolation("DOS block lease registry is already borrowed")
        })?;
        let recorded = registry.leases.get(&lease.token).copied().ok_or(
            DosError::HostContractViolation("DOS block lease token is no longer active"),
        )?;
        if recorded != lease.record {
            return Err(DosError::HostContractViolation(
                "DOS block lease range does not match its registry record",
            ));
        }
        Ok(recorded)
    }

    /// Validate every pin against the just-read complete MCB chain.
    pub(super) fn validate(&self, chain: &[Mcb]) -> Result<(), DosError> {
        let registry = self.inner.try_borrow().map_err(|_| {
            DosError::HostContractViolation("DOS block lease registry is already borrowed")
        })?;
        for record in registry.leases.values() {
            let extent = record.extent;
            let header_segment = extent.data_segment().checked_sub(1).ok_or(
                DosError::MalformedGuestInput("pinned DOS data segment has no MCB header"),
            )?;
            let Some(mcb) = chain.iter().find(|mcb| mcb.segment == header_segment) else {
                return Err(DosError::MalformedGuestInput(
                    "pinned DOS allocation is missing from the MCB chain",
                ));
            };
            let range_is_live = match record.range {
                LeaseRange::Exact => mcb.size() == extent.paragraphs(),
                LeaseRange::Prefix { minimum_paragraphs } => {
                    mcb.size() >= minimum_paragraphs
                        && minimum_paragraphs <= extent.paragraphs()
                }
            };
            if mcb.segment.checked_add(1) != Some(extent.data_segment())
                || mcb.owner() == 0
                || mcb.owner() != extent.owner_psp_segment()
                || !range_is_live
            {
                return Err(DosError::MalformedGuestInput(
                    "pinned DOS MCB no longer contains the recorded owner and live range",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn is_pinned(
        &self,
        data_segment: u16,
        owner_psp_segment: u16,
    ) -> Result<bool, DosError> {
        let registry = self.inner.try_borrow().map_err(|_| {
            DosError::HostContractViolation("DOS block lease registry is already borrowed")
        })?;
        Ok(registry.leases.values().any(|record| {
            record.extent.data_segment() == data_segment
                && record.extent.owner_psp_segment() == owner_psp_segment
        }))
    }

    pub(super) fn has_caller_range_lease(
        &self,
        caller: DosCallerId,
        data_segment: u16,
        owner_psp_segment: u16,
        byte_offset: usize,
        byte_length: usize,
    ) -> Result<bool, DosError> {
        let Some(end) = byte_offset.checked_add(byte_length) else {
            return Ok(false);
        };
        let Some(minimum_paragraphs) = end
            .checked_add(15)
            .and_then(|rounded| u16::try_from(rounded / 16).ok())
        else {
            return Ok(false);
        };
        let registry = self.inner.try_borrow().map_err(|_| {
            DosError::HostContractViolation("DOS block lease registry is already borrowed")
        })?;
        Ok(registry.leases.values().any(|record| {
            record.caller == Some(caller)
                && record.extent.data_segment() == data_segment
                && record.extent.owner_psp_segment() == owner_psp_segment
                && matches!(
                    record.range,
                    LeaseRange::Prefix { minimum_paragraphs: pinned }
                        if pinned >= minimum_paragraphs
                )
        }))
    }

    pub(super) fn first_caller_range_lease(
        &self,
        caller: DosCallerId,
    ) -> Result<Option<DosBlockLease>, DosError> {
        let registry = self.inner.try_borrow().map_err(|_| {
            DosError::HostContractViolation("DOS block lease registry is already borrowed")
        })?;
        Ok(registry.leases.iter().find_map(|(token, record)| {
            (record.caller == Some(caller)).then(|| DosBlockLease {
                registry_identity: Rc::downgrade(&self.inner),
                token: *token,
                record: *record,
            })
        }))
    }

    pub(super) fn allows_resize(
        &self,
        data_segment: u16,
        owner_psp_segment: u16,
        current_paragraphs: u16,
        requested_paragraphs: u16,
    ) -> Result<bool, DosError> {
        let registry = self.inner.try_borrow().map_err(|_| {
            DosError::HostContractViolation("DOS block lease registry is already borrowed")
        })?;
        let mut allowed = true;
        for record in registry.leases.values().filter(|record| {
            record.extent.data_segment() == data_segment
                && record.extent.owner_psp_segment() == owner_psp_segment
        }) {
            match record.range {
                LeaseRange::Exact => {
                    allowed &= requested_paragraphs == current_paragraphs;
                }
                LeaseRange::Prefix { minimum_paragraphs }
                    if requested_paragraphs < minimum_paragraphs =>
                {
                    return Ok(false);
                }
                LeaseRange::Prefix { .. } => {}
            }
        }
        Ok(allowed)
    }
}

/// Observe completed MCB writes so a non-mutating preflight failure does not
/// provoke unnecessary snapshot writes (which could themselves be read-only).
struct LeaseMutationMemory<'a, M> {
    memory: &'a mut M,
    changed: bool,
}

impl<M: GuestMemory> GuestMemory for LeaseMutationMemory<'_, M> {
    fn len(&self) -> u32 { self.memory.len() }
    fn validate_read(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.memory.validate_read(address, length)
    }
    fn validate_write(&self, address: PhysAddr, length: usize) -> Result<(), MemoryError> {
        self.memory.validate_write(address, length)
    }
    fn read(&self, address: PhysAddr, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.memory.read(address, bytes)
    }
    fn write(&mut self, address: PhysAddr, bytes: &[u8]) -> Result<(), MemoryError> {
        self.memory.write(address, bytes)?;
        self.changed = true;
        Ok(())
    }
}

fn uncertain_storage_failure(error: &DosError) -> bool {
    matches!(error,
        DosError::Memory(MemoryError::StorageAccess { .. })
        | DosError::HostMemoryContractViolation { source: MemoryError::StorageAccess { .. }, .. }
        | DosError::RollbackFailure { .. }
    )
}

fn rollback_mcb_chain(
    memory: &mut impl GuestMemory,
    original_chain: &[Mcb],
    operation: &'static str,
    cause: DosError,
) -> DosError {
    if uncertain_storage_failure(&cause) {
        return cause;
    }
    match write_mcb_batch(memory, original_chain) {
        Ok(()) => cause,
        Err(rollback) => DosError::RollbackFailure {
            operation,
            cause: Box::new(cause),
            rollback: Box::new(rollback),
        },
    }
}

impl DosKernel {
    /// Pin the complete range using its actual DOS MCB owner and extent.
    /// Returns `None` for a range that has no single live DOS allocation.
    pub fn pin_block_for_range(
        &mut self,
        memory: &mut impl GuestMemory,
        base: PhysAddr,
        byte_length: usize,
    ) -> Result<Option<DosBlockLease>, DosError> {
        let Some(extent) = self.owned_block_containing_range(memory, base, byte_length)? else {
            return Ok(None);
        };
        self.pin_owned_block(memory, extent.data_segment(), extent.owner_psp_segment())
    }

    /// Retain one independently releasable pin on an already leased DOS block.
    ///
    /// This uses the existing registry and a fresh, non-reusable token rather
    /// than cloning a segment/owner pair. A guest MCB needs explicit pins;
    /// ordinary Rust ownership cannot prevent guest INT 21h from resizing it.
    pub fn retain_block_lease(
        &mut self,
        memory: &mut impl GuestMemory,
        lease: &DosBlockLease,
    ) -> Result<DosBlockLease, DosError> {
        let record = self.block_leases.recorded_lease(lease)?;
        let _ = self.mcb_chain(memory)?;
        let (registry_identity, token) = self.block_leases.reserve_token()?;
        self.block_leases.insert_reserved(token, record)?;
        Ok(DosBlockLease {
            registry_identity,
            token,
            record,
        })
    }

    /// Whether releasing this exact live lease could also free its DOS block.
    ///
    /// Other pins are an ordinary busy result. A foreign, expired or corrupted
    /// lease remains a typed error. Callers retain their lease on either result;
    /// the actual release rechecks the registry before changing guest memory.
    pub fn block_lease_is_last_pin(
        &mut self,
        memory: &mut impl GuestMemory,
        lease: &DosBlockLease,
    ) -> Result<bool, DosError> {
        let record = self.block_leases.recorded_lease(lease)?;
        let _ = self.mcb_chain(memory)?;
        if !matches!(record.range, LeaseRange::Exact) {
            return Ok(false);
        }
        let registry = self.block_leases.inner.try_borrow().map_err(|_| {
            DosError::HostContractViolation("DOS block lease registry is already borrowed")
        })?;
        Ok(registry
            .leases
            .values()
            .filter(|other| {
                other.extent.data_segment() == record.extent.data_segment()
                    && other.extent.owner_psp_segment() == record.extent.owner_psp_segment()
            })
            .count() == 1)
    }

    /// Pin a matching live DOS allocation, returning `None` if it is absent.
    pub fn pin_owned_block(
        &mut self,
        memory: &mut impl GuestMemory,
        data_segment: u16,
        owner_psp_segment: u16,
    ) -> Result<Option<DosBlockLease>, DosError> {
        let Some(extent) = self.owned_block_extent(memory, data_segment, owner_psp_segment)? else {
            return Ok(None);
        };
        let record = LeaseRecord {
            extent,
            range: LeaseRange::Exact,
            caller: None,
        };
        let (registry_identity, token) = self.block_leases.reserve_token()?;
        self.block_leases.insert_reserved(token, record)?;
        Ok(Some(DosBlockLease {
            registry_identity,
            token,
            record,
        }))
    }

    /// Pin only the byte range retained by a DOS-backed selector alias.
    ///
    /// Resizing may shrink the MCB as long as the complete range remains inside
    /// the allocation. Freeing the allocation remains blocked until release.
    pub fn pin_owned_block_range(
        &mut self,
        memory: &mut impl GuestMemory,
        data_segment: u16,
        owner_psp_segment: u16,
        byte_offset: usize,
        byte_length: usize,
    ) -> Result<Option<DosBlockLease>, DosError> {
        self.pin_owned_block_range_for_caller_inner(
            memory,
            data_segment,
            owner_psp_segment,
            byte_offset,
            byte_length,
            None,
        )
    }

    /// Pin an exposed range and associate release with its protected caller.
    /// The association lives in the shared lease registry, so any cloned child
    /// `DosKernel` can release it after the runtime retires the caller aliases.
    pub(super) fn pin_owned_block_range_for_caller(
        &mut self,
        memory: &mut impl GuestMemory,
        data_segment: u16,
        owner_psp_segment: u16,
        byte_offset: usize,
        byte_length: usize,
        caller: DosCallerId,
    ) -> Result<Option<DosBlockLease>, DosError> {
        self.pin_owned_block_range_for_caller_inner(
            memory,
            data_segment,
            owner_psp_segment,
            byte_offset,
            byte_length,
            Some(caller),
        )
    }

    fn pin_owned_block_range_for_caller_inner(
        &mut self,
        memory: &mut impl GuestMemory,
        data_segment: u16,
        owner_psp_segment: u16,
        byte_offset: usize,
        byte_length: usize,
        caller: Option<DosCallerId>,
    ) -> Result<Option<DosBlockLease>, DosError> {
        if byte_length == 0 {
            return Ok(None);
        }
        let Some(range_end) = byte_offset.checked_add(byte_length) else {
            return Ok(None);
        };
        let Some(extent) = self.owned_block_extent(memory, data_segment, owner_psp_segment)? else {
            return Ok(None);
        };
        let Some(allocation_length) = extent.byte_length() else {
            return Ok(None);
        };
        if range_end > allocation_length {
            return Ok(None);
        }
        let Some(minimum_paragraphs) = range_end
            .checked_add(15)
            .and_then(|rounded| u16::try_from(rounded / 16).ok())
        else {
            return Ok(None);
        };
        if minimum_paragraphs == 0 || minimum_paragraphs > extent.paragraphs() {
            return Ok(None);
        }
        let record = LeaseRecord {
            extent,
            range: LeaseRange::Prefix { minimum_paragraphs },
            caller,
        };
        let (registry_identity, token) = self.block_leases.reserve_token()?;
        self.block_leases.insert_reserved(token, record)?;
        Ok(Some(DosBlockLease {
            registry_identity,
            token,
            record,
        }))
    }

    /// Allocate a DOS block for `owner_psp_segment` and pin its resulting extent.
    pub fn allocate_pinned_block(
        &mut self,
        memory: &mut impl GuestMemory,
        owner_psp_segment: u16,
        paragraphs: u16,
    ) -> Result<DosBlockLease, DosError> {
        if self.mcb_head.is_none() {
            return Err(DosError::HostContractViolation(
                "DOS MCB chain has not been initialized",
            ));
        }
        if owner_psp_segment == 0 || paragraphs == 0 {
            return Err(DosError::HostContractViolation(
                "pinned DOS allocation requires a nonzero owner and size",
            ));
        }

        let original_chain = self.mcb_chain(memory)?;
        let (registry_identity, token) = self.block_leases.reserve_token()?;
        {
            let mut registry = self.block_leases.inner.try_borrow_mut().map_err(|_| {
                DosError::HostContractViolation("DOS block lease registry is already borrowed")
            })?;
            if registry.allocation_intent.is_some() {
                return Err(DosError::HostContractViolation("DOS allocation already has a pending intent"));
            }
            registry.allocation_intent = Some((owner_psp_segment, paragraphs));
        }
        let mut mutation = LeaseMutationMemory { memory, changed: false };
        let allocation = (|| {
            let chain = coalesce_free_mcb_chain(&mut mutation, original_chain.clone())?;
            let data_segment = allocate_block_for_owner(
                &mut mutation,
                &chain,
                Some(owner_psp_segment),
                paragraphs,
            )?
            .ok_or_else(|| {
                DosError::HostOperation(DosHostError::new(DosErrorCode::InsufficientMemory))
            })?;
            let extent = self
                .owned_block_extent(&mut mutation, data_segment, owner_psp_segment)?
                .ok_or(DosError::HostContractViolation(
                    "newly allocated DOS block is absent from its MCB chain",
                ))?;
            let record = LeaseRecord {
                extent,
                range: LeaseRange::Exact,
                caller: None,
            };
            self.block_leases.insert_reserved(token, record)?;
            Ok(DosBlockLease {
                registry_identity,
                token,
                record,
            })
        })();

        let result = match allocation {
            Ok(lease) => Ok(lease),
            Err(error) if !mutation.changed => Err(error),
            Err(error) => Err(rollback_mcb_chain(
                &mut mutation, &original_chain, "pinned DOS block allocation", error,
            )),
        };
        let mut registry = self.block_leases.inner.try_borrow_mut().map_err(|_| {
            DosError::HostContractViolation("DOS block lease registry is already borrowed")
        })?;
        if result.as_ref().is_err_and(uncertain_storage_failure) {
            registry.storage_faulted = true;
        } else {
            registry.allocation_intent = None;
        }
        result
    }

    /// Explicitly unpin a block, optionally freeing it when this is its last pin.
    pub fn release_block_lease(
        &mut self,
        memory: &mut impl GuestMemory,
        lease: &DosBlockLease,
        free_block: bool,
    ) -> Result<(), DosError> {
        let recorded = self.block_leases.recorded_lease(lease)?;
        let chain = self.mcb_chain(memory)?;
        let mut registry = self.block_leases.inner.try_borrow_mut().map_err(|_| {
            DosError::HostContractViolation("DOS block lease registry is already borrowed")
        })?;

        if free_block {
            if !matches!(recorded.range, LeaseRange::Exact) {
                return Err(DosError::HostContractViolation(
                    "a retained-range DOS lease cannot free its backing allocation",
                ));
            }
            let pin_count = registry
                .leases
                .values()
                .filter(|other| {
                    other.extent.data_segment() == recorded.extent.data_segment()
                        && other.extent.owner_psp_segment()
                            == recorded.extent.owner_psp_segment()
                })
                .count();
            if pin_count != 1 {
                return Err(DosError::HostContractViolation(
                    "cannot free a DOS block while other leases still pin it",
                ));
            }
            let header_segment = recorded.extent.data_segment().checked_sub(1).ok_or(
                DosError::HostContractViolation("pinned DOS data segment has no MCB header"),
            )?;
            let Some(index) = chain.iter().position(|mcb| mcb.segment == header_segment) else {
                return Err(DosError::HostContractViolation(
                    "pinned DOS allocation is missing from the MCB chain",
                ));
            };
            let mut released = chain[index];
            released.set_owner(0);
            if let Err(error) = write_mcb(memory, released) {
                // No completed MCB write precedes this operation. Ordinary
                // preflight errors are retryable; partial transfers are not.
                registry.storage_faulted |= uncertain_storage_failure(&error);
                return Err(error);
            }
            let mut released_chain = chain.clone();
            released_chain[index] = released;
            if let Err(error) = coalesce_free_mcb_chain(memory, released_chain) {
                let error = rollback_mcb_chain(memory, &chain, "DOS block lease release", error);
                registry.storage_faulted |= uncertain_storage_failure(&error);
                return Err(error);
            }
        }

        registry.leases.remove(&lease.token);
        Ok(())
    }
}
