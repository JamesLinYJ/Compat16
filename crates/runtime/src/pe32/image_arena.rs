//! Reusable suballocator confined to the runtime's dedicated PE32 RAM region.

use std::sync::atomic::{AtomicU64, Ordering};

use guest_core::arena::{RegionKind, ReservedRegion};

use crate::{DiagnosticKind as Kind, RuntimeError};

use super::{Pe32GuestAddress, Pe32GuestImage, Pe32ModuleIdentity};

static NEXT_IMAGE_ARENA: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AllocationState {
    Reserved,
    Quarantined,
    Releasing,
}

#[derive(Debug)]
struct Allocation {
    id: u64,
    generation: u64,
    base: u32,
    size: u32,
    module: Option<Pe32ModuleIdentity>,
    state: AllocationState,
}

/// Exact, non-cloneable ownership token for one image allocation.
#[must_use = "a PE32 image lease must stay with its module until retirement"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Pe32ImageLease {
    arena_id: u64,
    id: u64,
    generation: u64,
    base: u32,
    size: u32,
}

impl Pe32ImageLease {
    pub(crate) const fn base(&self) -> u32 {
        self.base
    }
    pub(crate) const fn size(&self) -> u32 {
        self.size
    }
}

/// Allocation state inside one `ReservedRegion`; it never expands or borrows
/// neighboring Win16/XMS ranges. The root selects and owns the region layout.
pub(crate) struct Pe32ImageArena {
    arena_id: u64,
    region: ReservedRegion,
    free: Vec<(u32, u32)>,
    allocations: Vec<Allocation>,
    next_id: Option<u64>,
    next_generation: Option<u64>,
}

impl Pe32ImageArena {
    pub(crate) fn new(region: ReservedRegion) -> Result<Self, RuntimeError> {
        if region.kind() != RegionKind::Pe32
            || region.length() == 0
            || u64::from(region.base().0) + u64::from(region.length()) > u64::from(u32::MAX)
        {
            return Err(loader_failure(
                "PE32 image arena requires a dedicated reservation with a u32 exclusive end",
            ));
        }
        let arena_id = NEXT_IMAGE_ARENA
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| {
                RuntimeError::new(Kind::ResourceExhausted, "PE32 arena identities exhausted")
            })?;
        let mut free = Vec::new();
        free.try_reserve_exact(1).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted, "reserve PE32 arena extent", error)
        })?;
        free.push((region.base().0, region.length()));
        Ok(Self {
            arena_id,
            region,
            free,
            allocations: Vec::new(),
            next_id: Some(1),
            next_generation: Some(1),
        })
    }

    pub(crate) const fn region(&self) -> ReservedRegion {
        self.region
    }

    /// Prefer the PE image's base when it is free; otherwise first-fit in the
    /// caller-reserved RAM region and let the PE relocation planner validate it.
    pub(crate) fn reserve(
        &mut self,
        size: u32,
        alignment: u32,
        preferred_base: u32,
    ) -> Result<Pe32ImageLease, RuntimeError> {
        if size == 0 || alignment == 0 {
            return Err(loader_failure("invalid PE32 image size or alignment"));
        }
        let selected = self
            .preferred_extent(preferred_base, size, alignment)
            .or_else(|| self.first_fit(size, alignment))
            .ok_or_else(|| {
                RuntimeError::new(Kind::ResourceExhausted, "PE32 image arena is full")
            })?;

        let id = self.next_id.ok_or_else(identity_exhausted)?;
        let generation = self.next_generation.ok_or_else(identity_exhausted)?;
        let next_id = id.checked_add(1);
        let next_generation = generation.checked_add(1);
        self.allocations.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve PE32 allocation record",
                error,
            )
        })?;
        self.free.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(Kind::ResourceExhausted, "split PE32 free extent", error)
        })?;
        self.claim_extent(selected.0, size)?;
        self.allocations.push(Allocation {
            id,
            generation,
            base: selected.0,
            size,
            module: None,
            state: AllocationState::Reserved,
        });
        self.next_id = next_id;
        self.next_generation = next_generation;
        Ok(Pe32ImageLease {
            arena_id: self.arena_id,
            id,
            generation,
            base: selected.0,
            size,
        })
    }

    pub(crate) fn guest_image(
        &self,
        lease: &Pe32ImageLease,
    ) -> Result<Pe32GuestImage, RuntimeError> {
        self.record(lease)?;
        Ok(Pe32GuestImage {
            arena_id: lease.arena_id,
            base: Pe32GuestAddress(lease.base),
            size: lease.size,
            allocation_id: lease.id,
            generation: lease.generation,
        })
    }

    pub(crate) fn bind_module(
        &mut self,
        lease: &Pe32ImageLease,
        module: Pe32ModuleIdentity,
    ) -> Result<(), RuntimeError> {
        let record = self.record_mut(lease)?;
        if record.state != AllocationState::Reserved || record.module.is_some() {
            return Err(invariant("PE32 allocation was already bound to a module"));
        }
        record.module = Some(module);
        Ok(())
    }

    /// Preserve a possibly partially written image until its registry record
    /// is safely retired. A quarantined extent is never returned to first-fit.
    pub(crate) fn quarantine(
        &mut self,
        lease: &Pe32ImageLease,
        module: Option<Pe32ModuleIdentity>,
    ) -> Result<(), RuntimeError> {
        let record = self.record_mut(lease)?;
        if record.module != module || record.state == AllocationState::Releasing {
            return Err(invariant("PE32 quarantine owner does not match allocation"));
        }
        record.state = AllocationState::Quarantined;
        Ok(())
    }

    /// Begin exact release. The free range remains unavailable until registry
    /// retirement succeeds; retries of this same lease are harmless.
    pub(crate) fn begin_release(
        &mut self,
        lease: &Pe32ImageLease,
        module: Option<Pe32ModuleIdentity>,
    ) -> Result<(), RuntimeError> {
        let index = self.record_index(lease)?;
        let record = &self.allocations[index];
        if record.module != module {
            return Err(invariant(
                "PE32 release module identity does not match allocation",
            ));
        }
        match record.state {
            AllocationState::Reserved | AllocationState::Quarantined => {
                self.free.try_reserve(1).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "prepare PE32 range release",
                        error,
                    )
                })?;
                self.allocations[index].state = AllocationState::Releasing;
                Ok(())
            }
            AllocationState::Releasing => Ok(()),
        }
    }

    /// Make a previously retiring range reusable. If bookkeeping allocation
    /// fails, the allocation record remains Releasing and therefore reserved.
    pub(crate) fn finish_release(&mut self, lease: &Pe32ImageLease) -> Result<(), RuntimeError> {
        let index = self.record_index(lease)?;
        if self.allocations[index].state != AllocationState::Releasing {
            return Err(invariant("PE32 range was freed without begin_release"));
        }
        self.insert_free_extent(lease.base, lease.size)?;
        self.allocations.remove(index);
        Ok(())
    }

    pub(crate) fn release_unbound(&mut self, lease: &Pe32ImageLease) -> Result<(), RuntimeError> {
        self.begin_release(lease, None)?;
        self.finish_release(lease)
    }

    fn preferred_extent(&self, base: u32, size: u32, alignment: u32) -> Option<(u32, usize)> {
        if base == 0 || base % alignment != 0 || !self.contains_range(base, size) {
            return None;
        }
        self.free
            .iter()
            .enumerate()
            .find_map(|(index, &(start, length))| {
                let end = u64::from(base).checked_add(u64::from(size))?;
                let free_end = u64::from(start).checked_add(u64::from(length))?;
                (base >= start && end <= free_end).then_some((base, index))
            })
    }

    fn first_fit(&self, size: u32, alignment: u32) -> Option<(u32, usize)> {
        self.free
            .iter()
            .enumerate()
            .find_map(|(index, &(start, length))| {
                let aligned = align_up(start, alignment)?;
                let end = u64::from(aligned).checked_add(u64::from(size))?;
                let free_end = u64::from(start).checked_add(u64::from(length))?;
                (end <= free_end).then_some((aligned, index))
            })
    }

    fn claim_extent(&mut self, base: u32, size: u32) -> Result<(), RuntimeError> {
        let index = self
            .free
            .iter()
            .position(|(start, length)| {
                let end = u64::from(base) + u64::from(size);
                base >= *start && end <= u64::from(*start) + u64::from(*length)
            })
            .ok_or_else(|| invariant("selected PE32 extent is no longer free"))?;
        let end = base
            .checked_add(size)
            .ok_or_else(|| loader_failure("PE32 allocation crosses 4 GiB"))?;
        let (start, length) = self.free[index];
        let old_end = start
            .checked_add(length)
            .ok_or_else(|| invariant("PE32 arena extent overflowed"))?;
        self.free.remove(index);
        if start < base {
            self.free.insert(index, (start, base - start));
        }
        let suffix_index = index + usize::from(start < base);
        if end < old_end {
            self.free.insert(suffix_index, (end, old_end - end));
        }
        Ok(())
    }

    fn insert_free_extent(&mut self, base: u32, size: u32) -> Result<(), RuntimeError> {
        let end = base
            .checked_add(size)
            .ok_or_else(|| invariant("released PE32 extent overflowed"))?;
        let index = self.free.partition_point(|(start, _)| *start < base);
        let previous = index.checked_sub(1).and_then(|i| self.free.get(i)).copied();
        let next = self.free.get(index).copied();
        let previous_end = previous
            .map(|(start, length)| {
                start
                    .checked_add(length)
                    .ok_or_else(|| invariant("preceding PE32 free extent overflowed"))
            })
            .transpose()?;
        if previous_end.is_some_and(|previous_end| previous_end > base) {
            return Err(invariant("released PE32 range overlaps a free extent"));
        }
        if next.is_some_and(|(next_start, _)| end > next_start) {
            return Err(invariant("released PE32 range overlaps a following extent"));
        }
        let joins_previous = previous_end == Some(base);
        let joins_next = next.is_some_and(|(next_start, _)| next_start == end);
        match (joins_previous, joins_next) {
            (true, true) => {
                let (_, previous_len) = self.free[index - 1];
                let next_len = self.free[index].1;
                let merged = previous_len
                    .checked_add(size)
                    .and_then(|length| length.checked_add(next_len))
                    .ok_or_else(|| invariant("merged PE32 free extent overflowed"))?;
                self.free.remove(index);
                self.free[index - 1].1 = merged;
            }
            (true, false) => {
                self.free[index - 1].1 = self.free[index - 1]
                    .1
                    .checked_add(size)
                    .ok_or_else(|| invariant("merged PE32 free extent overflowed"))?;
            }
            (false, true) => {
                let merged = size
                    .checked_add(self.free[index].1)
                    .ok_or_else(|| invariant("merged PE32 free extent overflowed"))?;
                self.free[index] = (base, merged);
            }
            (false, false) => {
                self.free.try_reserve(1).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve PE32 free-list entry during release",
                        error,
                    )
                })?;
                self.free.insert(index, (base, size));
            }
        }
        Ok(())
    }

    fn contains_range(&self, base: u32, size: u32) -> bool {
        let start = u64::from(self.region.base().0);
        let end = start + u64::from(self.region.length());
        u64::from(base) >= start && u64::from(base) + u64::from(size) <= end
    }

    fn record(&self, lease: &Pe32ImageLease) -> Result<&Allocation, RuntimeError> {
        let index = self.record_index(lease)?;
        Ok(&self.allocations[index])
    }

    fn record_mut(&mut self, lease: &Pe32ImageLease) -> Result<&mut Allocation, RuntimeError> {
        let index = self.record_index(lease)?;
        Ok(&mut self.allocations[index])
    }

    fn record_index(&self, lease: &Pe32ImageLease) -> Result<usize, RuntimeError> {
        if lease.arena_id != self.arena_id {
            return Err(invariant("PE32 allocation lease belongs to another arena"));
        }
        self.allocations
            .iter()
            .position(|record| {
                record.id == lease.id
                    && record.generation == lease.generation
                    && record.base == lease.base
                    && record.size == lease.size
            })
            .ok_or_else(|| invariant("PE32 allocation lease is stale or altered"))
    }
}

fn align_up(value: u32, alignment: u32) -> Option<u32> {
    let remainder = value % alignment;
    if remainder == 0 {
        Some(value)
    } else {
        value.checked_add(alignment - remainder)
    }
}

fn identity_exhausted() -> RuntimeError {
    RuntimeError::new(
        Kind::ResourceExhausted,
        "PE32 allocation identities exhausted",
    )
}

fn loader_failure(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::CompatibilityGap, message)
}

fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
