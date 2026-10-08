//! Metadata-only reservations for disjoint guest physical-memory regions.
//!
//! The runtime creates one map for its selected [`crate::memory::Memory`]
//! length, reserves each machine/service range, and passes the validated base
//! and length to the corresponding allocator. The map owns no guest bytes and
//! exposes no host pointers. Reservations last for the lifetime of the map;
//! there is intentionally no release or reuse operation.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::PhysAddr;

static NEXT_MAP_ID: AtomicU64 = AtomicU64::new(1);

/// The machine component assigned to a reserved physical range.
///
/// These names describe reservation purpose only. The caller selects the
/// actual addresses from its physical-memory layout; this module does not
/// impose fixed hardware partitions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RegionKind {
    BiosRom,
    VideoMemory,
    ConventionalMemory,
    DosSystem,
    Hma,
    Xms,
    Win16,
    /// Process-owned guest RAM reserved for PE32 images and loader storage.
    /// Image allocations cannot borrow an XMS or Win16 allocator's range.
    Pe32,
    Dpmi,
}

/// Stable identifier for one reservation in one [`PhysicalArenaMap`].
///
/// The identifier is metadata, not ownership of memory. It is intentionally
/// opaque and includes its originating map identity so identifiers cannot be
/// accidentally looked up in another machine's map.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ArenaRegionId {
    map_id: u64,
    sequence: u64,
}

/// Read-only description of an accepted reservation.
///
/// Copying this description does not create another reservation. Only the
/// map tracks and validates allocated ranges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReservedRegion {
    id: ArenaRegionId,
    kind: RegionKind,
    base: PhysAddr,
    length: u32,
}

impl ReservedRegion {
    pub const fn id(self) -> ArenaRegionId {
        self.id
    }

    pub const fn kind(self) -> RegionKind {
        self.kind
    }

    pub const fn base(self) -> PhysAddr {
        self.base
    }

    pub const fn length(self) -> u32 {
        self.length
    }

    /// Exclusive end, checked when the region was reserved.
    pub const fn end_exclusive(self) -> PhysAddr {
        PhysAddr(self.base.0 + self.length)
    }
}

/// Errors from physical-region map construction, reservation, or lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArenaError {
    InvalidMemorySize,
    InvalidLength,
    InvalidAlignment { alignment: u32 },
    MisalignedRange {
        base: PhysAddr,
        length: u32,
        alignment: u32,
    },
    AddressOverflow { base: PhysAddr, length: u32 },
    OutOfBounds {
        base: PhysAddr,
        length: u32,
        memory_size: u32,
    },
    Overlap {
        requested_kind: RegionKind,
        requested_base: PhysAddr,
        requested_length: u32,
        existing: ArenaRegionId,
        existing_kind: RegionKind,
        existing_base: PhysAddr,
        existing_length: u32,
    },
    ForeignMapId,
    UnknownRegionId,
    IdentityExhausted,
    RegionIdExhausted,
}

impl std::fmt::Display for ArenaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMemorySize => {
                f.write_str("physical arena map requires a nonzero guest memory size")
            }
            Self::InvalidLength => {
                f.write_str("physical reservation length must be greater than zero")
            }
            Self::InvalidAlignment { alignment } => write!(
                f,
                "reservation alignment 0x{alignment:08X} is invalid; alignment must be nonzero"
            ),
            Self::MisalignedRange {
                base,
                length,
                alignment,
            } => write!(
                f,
                "physical range at 0x{:08X} with length {length} bytes (0x{length:08X}) is not aligned to 0x{alignment:08X}",
                base.0
            ),
            Self::AddressOverflow { base, length } => write!(
                f,
                "physical range at 0x{:08X} with length {length} bytes (0x{length:08X}) overflows the 32-bit address space",
                base.0
            ),
            Self::OutOfBounds {
                base,
                length,
                memory_size,
            } => write!(
                f,
                "physical range at 0x{:08X} with length {length} bytes (0x{length:08X}) exceeds guest memory size 0x{memory_size:08X}",
                base.0
            ),
            Self::Overlap {
                requested_kind,
                requested_base,
                requested_length,
                existing_kind,
                existing_base,
                existing_length,
                ..
            } => write!(
                f,
                "cannot reserve {} at 0x{:08X} with length {} bytes (0x{:08X}); it overlaps {} at 0x{:08X} with length {} bytes (0x{:08X})",
                region_kind_name(*requested_kind),
                requested_base.0,
                requested_length,
                requested_length,
                region_kind_name(*existing_kind),
                existing_base.0,
                existing_length,
                existing_length
            ),
            Self::ForeignMapId => {
                f.write_str("physical region identifier belongs to a different arena map")
            }
            Self::UnknownRegionId => {
                f.write_str("physical region identifier does not name a reserved region")
            }
            Self::IdentityExhausted => {
                f.write_str("no more physical arena map identities are available")
            }
            Self::RegionIdExhausted => {
                f.write_str("no more reservation identifiers are available in this arena map")
            }
        }
    }
}

fn region_kind_name(kind: RegionKind) -> &'static str {
    match kind {
        RegionKind::BiosRom => "BIOS ROM",
        RegionKind::VideoMemory => "video memory",
        RegionKind::ConventionalMemory => "conventional memory",
        RegionKind::DosSystem => "DOS system memory",
        RegionKind::Hma => "high-memory area",
        RegionKind::Xms => "extended memory",
        RegionKind::Win16 => "Win16 memory",
        RegionKind::Pe32 => "PE32 guest memory",
        RegionKind::Dpmi => "DPMI memory",
    }
}

impl std::error::Error for ArenaError {}

/// Tracks non-overlapping physical ranges for one guest machine.
///
/// This manager is deliberately not `Clone`: copying allocator state could
/// make two managers appear to own the same ranges. Create one map using the
/// physical memory size selected by the runtime, then reserve the service
/// arenas for the machine's lifetime.
#[derive(Debug)]
pub struct PhysicalArenaMap {
    memory_size: u32,
    map_id: u64,
    next_sequence: u64,
    regions: Vec<ReservedRegion>,
}

impl PhysicalArenaMap {
    /// Create an empty map bounded by the guest's configured physical size.
    pub fn new(memory_size: u32) -> Result<Self, ArenaError> {
        if memory_size == 0 {
            return Err(ArenaError::InvalidMemorySize);
        }

        let map_id = NEXT_MAP_ID
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| ArenaError::IdentityExhausted)?;

        Ok(Self {
            memory_size,
            map_id,
            next_sequence: 1,
            regions: Vec::new(),
        })
    }

    pub const fn memory_size(&self) -> u32 {
        self.memory_size
    }

    pub fn len(&self) -> usize {
        self.regions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Reserve `[base, base + length)` if it is aligned, backed by this
    /// machine's physical memory, and disjoint from every existing range.
    ///
    /// Both `base` and `length` must be multiples of `alignment`. A zero
    /// alignment or empty range is invalid. Adjacent half-open ranges are
    /// allowed.
    pub fn reserve(
        &mut self,
        kind: RegionKind,
        base: PhysAddr,
        length: u32,
        alignment: u32,
    ) -> Result<ArenaRegionId, ArenaError> {
        if length == 0 {
            return Err(ArenaError::InvalidLength);
        }
        if alignment == 0 {
            return Err(ArenaError::InvalidAlignment { alignment });
        }
        if base.0 % alignment != 0 || length % alignment != 0 {
            return Err(ArenaError::MisalignedRange {
                base,
                length,
                alignment,
            });
        }

        let end = base
            .0
            .checked_add(length)
            .ok_or(ArenaError::AddressOverflow { base, length })?;
        if end > self.memory_size {
            return Err(ArenaError::OutOfBounds {
                base,
                length,
                memory_size: self.memory_size,
            });
        }

        for existing in &self.regions {
            let existing_end = existing.end_exclusive().0;
            if base.0 < existing_end && existing.base.0 < end {
                return Err(ArenaError::Overlap {
                    requested_kind: kind,
                    requested_base: base,
                    requested_length: length,
                    existing: existing.id,
                    existing_kind: existing.kind,
                    existing_base: existing.base,
                    existing_length: existing.length,
                });
            }
        }

        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(ArenaError::RegionIdExhausted)?;
        let id = ArenaRegionId {
            map_id: self.map_id,
            sequence: self.next_sequence,
        };
        self.regions.push(ReservedRegion {
            id,
            kind,
            base,
            length,
        });
        self.next_sequence = next_sequence;
        Ok(id)
    }

    /// Resolve an identifier issued by this map to its validated range.
    pub fn get(&self, id: ArenaRegionId) -> Result<ReservedRegion, ArenaError> {
        if id.map_id != self.map_id {
            return Err(ArenaError::ForeignMapId);
        }
        let index = id
            .sequence
            .checked_sub(1)
            .and_then(|sequence| usize::try_from(sequence).ok())
            .ok_or(ArenaError::UnknownRegionId)?;
        match self.regions.get(index).copied() {
            Some(region) if region.id == id => Ok(region),
            _ => Err(ArenaError::UnknownRegionId),
        }
    }

    /// Iterate over the currently reserved ranges in insertion order.
    pub fn regions(&self) -> impl Iterator<Item = ReservedRegion> + '_ {
        self.regions.iter().copied()
    }
}

#[cfg(test)]
mod tests;
