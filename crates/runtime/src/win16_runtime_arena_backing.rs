//! Exact owner records for fixed chunks inside the Win16 physical reservation.
//!
//! `ReservedRegion` is only metadata; the machine's `PhysicalArenaMap` keeps
//! the reservation alive. This registry records the runtime-created selector
//! chunks inside that exact reservation and issues non-cloneable frame leases.

use std::collections::BTreeMap;
use std::fmt;

use guest_core::{GuestMemory, PhysAddr, arena::{ArenaRegionId, RegionKind, ReservedRegion}, memory::{Memory, MemoryDomainSnapshot}};
use win16_abi::{DescriptorInfo, SelectorRef, SelectorTable};

use crate::{DiagnosticKind, RuntimeError};

use super::{WIN16_ARENA_BASE, WIN16_MEMORY_END};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RuntimeArenaChunkKind {
    ServiceGate,
    CallbackReturnGate,
    BuiltinData(&'static str),
    TaskDatabase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RuntimeArenaBackingIdentity {
    pub(super) region: ArenaRegionId,
    pub(super) chunk_id: u64,
    pub(super) kind: RuntimeArenaChunkKind,
    pub(super) primary: SelectorRef,
    pub(super) base: PhysAddr,
    pub(super) size: u32,
}

pub(super) struct RuntimeArenaBackingLease {
    identity: RuntimeArenaBackingIdentity,
    selector: SelectorRef,
    token_id: u64,
    domain: MemoryDomainSnapshot,
    owner: RuntimeArenaLeaseOwner,
}

impl fmt::Debug for RuntimeArenaBackingLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RuntimeArenaBackingLease")
            .field("identity", &self.identity)
            .field("selector", &self.selector)
            .field("token_id", &self.token_id)
            .field("owner", &self.owner)
            .finish()
    }
}

impl RuntimeArenaBackingLease {
    pub(super) fn identity(&self) -> RuntimeArenaBackingIdentity {
        self.identity
    }
}

#[derive(Debug)]
struct ChunkRecord {
    identity: RuntimeArenaBackingIdentity,
    descriptor: DescriptorInfo,
    active_leases: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveLease {
    identity: RuntimeArenaBackingIdentity,
    selector: SelectorRef,
    owner: RuntimeArenaLeaseOwner,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RuntimeArenaChunkRetirement {
    NotRegistered,
    Deferred,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeArenaLeaseOwner {
    SelectorView,
    LegacyCpuFrame,
}

#[derive(Debug)]
pub(super) struct RuntimeArenaBackingRegistry {
    region: ReservedRegion,
    chunks: BTreeMap<u64, ChunkRecord>,
    active_leases: BTreeMap<u64, ActiveLease>,
    next_chunk_id: u64,
    next_lease_id: u64,
    retired: bool,
}

impl RuntimeArenaBackingRegistry {
    pub(super) fn new(
        region: ReservedRegion,
        memory: &Memory,
    ) -> Result<Self, RuntimeError> {
        let expected_length = WIN16_MEMORY_END.checked_sub(WIN16_ARENA_BASE)
            .ok_or_else(|| invariant("Win16 arena bounds are reversed"))?;
        if region.kind() != RegionKind::Win16
            || region.base() != PhysAddr(WIN16_ARENA_BASE)
            || region.length() != expected_length
            || region.end_exclusive().0 > memory.len()
        {
            return Err(invariant("runtime arena registry received a different Win16 reservation"));
        }
        Ok(Self {
            region,
            chunks: BTreeMap::new(),
            active_leases: BTreeMap::new(),
            next_chunk_id: 1,
            next_lease_id: 1,
            retired: false,
        })
    }

    pub(super) fn register_chunk(
        &mut self,
        kind: RuntimeArenaChunkKind,
        primary: SelectorRef,
        selectors: &SelectorTable,
        memory: &Memory,
    ) -> Result<RuntimeArenaBackingIdentity, RuntimeError> {
        self.ensure_live()?;
        if self.region.end_exclusive().0 > memory.len() {
            return Err(invariant("Win16 arena reservation exceeds current guest memory"));
        }
        let descriptor = selectors.describe(primary).map_err(crate::runtime_error)?;
        let (head, base, size) = selectors.allocation_range(primary).map_err(crate::runtime_error)?;
        let region_start = u64::from(self.region.base().0);
        let region_end = u64::from(self.region.end_exclusive().0);
        let start = u64::from(base.0);
        let end = start.checked_add(u64::from(size))
            .ok_or_else(|| invariant("runtime arena chunk extent overflowed"))?;
        let descriptor_size = descriptor.limit.checked_add(1)
            .ok_or_else(|| invariant("runtime arena selector descriptor extent overflowed"))?;
        if !descriptor.present || head != primary || descriptor.base != base || size == 0
            || descriptor_size > size || start < region_start || end > region_end
        {
            return Err(invariant("runtime arena selector does not describe a complete registered chunk"));
        }
        for previous in self.chunks.values() {
            let old_start = u64::from(previous.identity.base.0);
            let old_end = old_start.checked_add(u64::from(previous.identity.size))
                .ok_or_else(|| invariant("registered runtime arena chunk extent overflowed"))?;
            if start < old_end && old_start < end {
                return Err(invariant("runtime arena selector chunks overlap"));
            }
        }
        let chunk_id = take_id(&mut self.next_chunk_id, "runtime arena chunk identities are exhausted")?;
        let identity = RuntimeArenaBackingIdentity {
            region: self.region.id(), chunk_id, kind, primary, base, size,
        };
        self.chunks.insert(chunk_id, ChunkRecord { identity, descriptor, active_leases: 0 });
        Ok(identity)
    }

    pub(super) fn identities(&self) -> impl Iterator<Item = RuntimeArenaBackingIdentity> + '_ {
        self.chunks.values().map(|chunk| chunk.identity)
    }

    pub(super) fn owns_selector(&self, raw: u16) -> bool {
        !self.retired && (self.chunks.values().any(|chunk| chunk.identity.primary.raw().0 == raw)
            || self.active_leases.values().any(|lease|
                lease.owner == RuntimeArenaLeaseOwner::LegacyCpuFrame
                    && lease.selector.raw().0 == raw))
    }

    pub(super) fn identity_is_live(
        &self,
        identity: RuntimeArenaBackingIdentity,
        selectors: &SelectorTable,
        memory: &Memory,
    ) -> Result<bool, RuntimeError> {
        self.ensure_live()?;
        if self.region.end_exclusive().0 > memory.len() {
            return Err(invariant("Win16 arena reservation exceeds current guest memory"));
        }
        self.selector_identity_is_live(identity, selectors)
    }

    fn selector_identity_is_live(
        &self,
        identity: RuntimeArenaBackingIdentity,
        selectors: &SelectorTable,
    ) -> Result<bool, RuntimeError> {
        self.ensure_live()?;
        let Some(chunk) = self.chunks.get(&identity.chunk_id) else { return Ok(false); };
        if chunk.identity != identity || identity.region != self.region.id() { return Ok(false); }
        let Ok(reference) = selectors.reference_including_unbacked(identity.primary.raw()) else {
            return Ok(false);
        };
        if reference != identity.primary { return Ok(false); }
        let Ok(descriptor) = selectors.describe(reference) else { return Ok(false); };
        let Ok((head, base, size)) = selectors.allocation_range(reference) else { return Ok(false); };
        Ok(descriptor == chunk.descriptor && descriptor.present && head == reference
            && base == identity.base && size == identity.size)
    }

    /// Defer builtin-data unload while an alias or legacy CPU frame uses it.
    pub(super) fn primary_has_active_leases(
        &self,
        primary: SelectorRef,
    ) -> Result<bool, RuntimeError> {
        self.ensure_live()?;
        let Some(chunk) = self.chunks.values().find(|chunk| chunk.identity.primary == primary)
        else { return Ok(false); };
        Ok(self.active_lease_count(chunk.identity)? != 0)
    }

    /// Retire one exact registered selector only after SelectorTable frees it.
    pub(super) fn retire_registered_chunk(
        &mut self,
        primary: SelectorRef,
        selectors: &mut SelectorTable,
    ) -> Result<RuntimeArenaChunkRetirement, RuntimeError> {
        self.ensure_live()?;
        let Some(identity) = self.chunks.values()
            .find(|chunk| chunk.identity.primary == primary)
            .map(|chunk| chunk.identity)
        else { return Ok(RuntimeArenaChunkRetirement::NotRegistered); };
        if self.active_lease_count(identity)? != 0 {
            return Ok(RuntimeArenaChunkRetirement::Deferred);
        }
        if !self.selector_identity_is_live(identity, selectors)? {
            return Err(invariant("registered runtime arena chunk changed before module retirement"));
        }
        selectors.free_block(primary).map_err(crate::runtime_error)
            .map_err(|error| error.with_context("freeing a registered runtime arena chunk"))?;
        self.chunks.remove(&identity.chunk_id)
            .ok_or_else(|| invariant("retired runtime arena chunk lost its owner record"))?;
        Ok(RuntimeArenaChunkRetirement::Retired)
    }

    pub(super) fn retain(
        &mut self,
        identity: RuntimeArenaBackingIdentity,
        selector: SelectorRef,
        base: PhysAddr,
        size: u32,
        selectors: &SelectorTable,
        memory: &Memory,
    ) -> Result<Option<RuntimeArenaBackingLease>, RuntimeError> {
        self.retain_with_owner(identity, selector, base, size, selectors, memory,
            RuntimeArenaLeaseOwner::SelectorView)
    }

    pub(super) fn retain_frame_root(
        &mut self,
        identity: RuntimeArenaBackingIdentity,
        selector: SelectorRef,
        base: PhysAddr,
        size: u32,
        selectors: &SelectorTable,
        memory: &Memory,
    ) -> Result<Option<RuntimeArenaBackingLease>, RuntimeError> {
        self.retain_with_owner(identity, selector, base, size, selectors, memory,
            RuntimeArenaLeaseOwner::LegacyCpuFrame)
    }

    fn retain_with_owner(
        &mut self,
        identity: RuntimeArenaBackingIdentity,
        selector: SelectorRef,
        base: PhysAddr,
        size: u32,
        selectors: &SelectorTable,
        memory: &Memory,
        owner: RuntimeArenaLeaseOwner,
    ) -> Result<Option<RuntimeArenaBackingLease>, RuntimeError> {
        self.ensure_live()?;
        let Some(chunk) = self.chunks.get(&identity.chunk_id) else { return Ok(None); };
        if chunk.identity != identity || identity.region != self.region.id() || size == 0 {
            return Ok(None);
        }
        if !self.identity_is_live(identity, selectors, memory)? { return Ok(None); }
        let Some(request_end) = u64::from(base.0).checked_add(u64::from(size)) else {
            return Err(RuntimeError::new(DiagnosticKind::InvalidInput,
                "runtime arena backing request range overflowed"));
        };
        let chunk_start = u64::from(identity.base.0);
        let chunk_end = chunk_start.checked_add(u64::from(identity.size))
            .ok_or_else(|| invariant("registered runtime arena chunk extent overflowed"))?;
        if u64::from(base.0) < chunk_start || request_end > chunk_end { return Ok(None); }
        if selectors.reference_including_unbacked(selector.raw()).ok() != Some(selector) {
            return Ok(None);
        }
        let descriptor = selectors.describe(selector).map_err(crate::runtime_error)?;
        let descriptor_size = descriptor.limit.checked_add(1)
            .ok_or_else(|| invariant("selector descriptor extent overflowed"))?;
        if !descriptor.present || descriptor.base != base || descriptor_size < size {
            return Ok(None);
        }
        let next_count = chunk.active_leases.checked_add(1).ok_or_else(|| {
            RuntimeError::new(DiagnosticKind::ResourceExhausted,
                "runtime arena chunk lease count is exhausted")
        })?;
        let token_id = take_id(&mut self.next_lease_id,
            "runtime arena lease identities are exhausted")?;
        if self.active_leases.contains_key(&token_id) {
            return Err(invariant("runtime arena lease identity was already active"));
        }
        let chunk = self.chunks.get_mut(&identity.chunk_id)
            .ok_or_else(|| invariant("runtime arena chunk disappeared during retain"))?;
        chunk.active_leases = next_count;
        self.active_leases.insert(token_id, ActiveLease { identity, selector, owner });
        Ok(Some(RuntimeArenaBackingLease {
            identity, selector, token_id, domain: memory.domain_snapshot(), owner,
        }))
    }

    pub(super) fn release(
        &mut self,
        lease: &RuntimeArenaBackingLease,
    ) -> Result<(), RuntimeError> {
        let expected = ActiveLease {
            identity: lease.identity, selector: lease.selector, owner: lease.owner,
        };
        if self.active_leases.get(&lease.token_id) != Some(&expected) {
            return Err(invariant("runtime arena lease is stale or was already released"));
        }
        let chunk = self.chunks.get_mut(&lease.identity.chunk_id)
            .ok_or_else(|| invariant("runtime arena lease lost its registered chunk"))?;
        let next_count = chunk.active_leases.checked_sub(1)
            .ok_or_else(|| invariant("runtime arena chunk lease count underflowed"))?;
        chunk.active_leases = next_count;
        self.active_leases.remove(&lease.token_id);
        Ok(())
    }

    pub(super) fn lease_is_live(
        &self,
        lease: &RuntimeArenaBackingLease,
        selector: SelectorRef,
        selectors: &SelectorTable,
        memory: &Memory,
    ) -> Result<bool, RuntimeError> {
        self.ensure_live()?;
        if !memory.domain_matches(&lease.domain) { return Ok(false); }
        let expected = ActiveLease {
            identity: lease.identity, selector: lease.selector, owner: lease.owner,
        };
        if lease.selector != selector || self.active_leases.get(&lease.token_id) != Some(&expected) {
            return Ok(false);
        }
        let Some(chunk) = self.chunks.get(&lease.identity.chunk_id) else { return Ok(false); };
        if chunk.active_leases == 0 || chunk.identity != lease.identity
            || !self.identity_is_live(lease.identity, selectors, memory)?
        {
            return Ok(false);
        }
        let Ok(current) = selectors.reference_including_unbacked(selector.raw()) else {
            return Ok(false);
        };
        if current != selector { return Ok(false); }
        let Ok(descriptor) = selectors.describe(selector) else { return Ok(false); };
        let size = descriptor.limit.checked_add(1)
            .ok_or_else(|| invariant("runtime arena lease descriptor extent overflowed"))?;
        let start = u64::from(descriptor.base.0);
        let end = start.checked_add(u64::from(size))
            .ok_or_else(|| invariant("runtime arena lease descriptor end overflowed"))?;
        let chunk_start = u64::from(lease.identity.base.0);
        let chunk_end = chunk_start.checked_add(u64::from(lease.identity.size))
            .ok_or_else(|| invariant("runtime arena chunk extent overflowed"))?;
        Ok(descriptor.present && start >= chunk_start && end <= chunk_end)
    }

    pub(super) fn retire_before_selector_teardown(
        &mut self,
        selectors: &SelectorTable,
        memory: &Memory,
    ) -> Result<(), RuntimeError> {
        if self.retired { return Ok(()); }
        self.ensure_live()?;
        if self.region.end_exclusive().0 > memory.len() {
            return Err(invariant("Win16 arena reservation exceeds current guest memory"));
        }
        if !self.active_leases.is_empty()
            || self.chunks.values().any(|chunk| chunk.active_leases != 0)
        {
            return Err(RuntimeError::new(DiagnosticKind::ResourceExhausted,
                "Win16 runtime arena teardown is deferred while a frame retains a chunk"));
        }
        for chunk in self.chunks.values() {
            if !self.identity_is_live(chunk.identity, selectors, memory)? {
                return Err(invariant("registered runtime arena selector changed before teardown"));
            }
        }
        self.retired = true;
        self.chunks.clear();
        Ok(())
    }

    pub(super) fn ensure_no_frame_leases(&self) -> Result<(), RuntimeError> {
        if self.active_leases.values().any(|lease|
            lease.owner == RuntimeArenaLeaseOwner::LegacyCpuFrame)
        {
            return Err(RuntimeError::new(DiagnosticKind::ResourceExhausted,
                "Win16 selector teardown is deferred while a legacy CPU frame retains a runtime chunk"));
        }
        Ok(())
    }

    fn active_lease_count(
        &self,
        identity: RuntimeArenaBackingIdentity,
    ) -> Result<u64, RuntimeError> {
        let chunk = self.chunks.get(&identity.chunk_id)
            .filter(|chunk| chunk.identity == identity)
            .ok_or_else(|| invariant("runtime arena lease names an unknown chunk generation"))?;
        let observed = self.active_leases.values()
            .filter(|lease| lease.identity == identity)
            .count();
        let observed = u64::try_from(observed)
            .map_err(|_| invariant("runtime arena active lease count exceeds its counter"))?;
        if observed != chunk.active_leases {
            return Err(invariant("runtime arena active lease index disagrees with its chunk counter"));
        }
        Ok(observed)
    }

    fn ensure_live(&self) -> Result<(), RuntimeError> {
        if self.retired { return Err(invariant("runtime arena backing registry has retired")); }
        Ok(())
    }
}

fn take_id(next: &mut u64, exhausted: &'static str) -> Result<u64, RuntimeError> {
    let value = *next;
    let following = value.checked_add(1)
        .ok_or_else(|| RuntimeError::new(DiagnosticKind::ResourceExhausted, exhausted))?;
    *next = following;
    Ok(value)
}

fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(DiagnosticKind::InternalInvariant, message)
}
