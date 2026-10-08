//! Runtime-owned legacy CPU roots. Proofs copy identities; leases remain here.

use std::{error::Error, fmt};

use dos_kernel::DosKernel;
use guest_core::{Registers, Selector};
use guest_core::memory::{Memory, MemoryDomainSnapshot};
use win16_abi::{DescriptorInfo, SelectorRef, SelectorTable, Win16Error};
use x86_cpu::{
    LegacyBindingTransfer, LegacyCpuBinding, LegacyStackPointerTarget,
};

use super::{Win16State, selector_ownership::{SelectorBackingIdentity, SelectorBackingLease}};
use crate::{DiagnosticKind, RuntimeError};

#[path = "win16_legacy_cpu_growth.rs"]
mod growth;
pub(super) use growth::{AutomaticDataOwner, LegacyCpuDataGrowthPlan};
use growth::{
    AutomaticDataGrowthReceipt, root_history_is_current, root_snapshot_is_authorized,
};

#[derive(Debug)]
pub(super) enum Win16LegacyCpuBindingError {
    Selector { segment: u8, source: Win16Error },
    Runtime(RuntimeError),
    MissingBacking { segment: u8 },
    RootNotOwned { segment: u8, selector: u16 },
    DescriptorChanged {
        segment: u8, reference: SelectorRef,
        saved: DescriptorInfo, current: DescriptorInfo,
    },
    UnmappedDataChanged { segment: u8 },
    BackingChanged { segment: u8 },
    MemoryDomainChanged,
    InvalidSegmentAccess { segment: u8 },
    InvalidTransfer,
}

impl fmt::Display for Win16LegacyCpuBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selector { segment, source } => {
                let name = ["CS", "SS", "DS", "ES", "FS", "GS"]
                    .get(usize::from(*segment)).copied().unwrap_or("unknown");
                write!(f, "legacy CPU {name} selector cannot be retained: {source}")
            }
            Self::Runtime(error) => fmt::Display::fmt(error, f),
            Self::MissingBacking { segment } => write!(f, "legacy CPU segment {segment} has no retained backing"),
            Self::RootNotOwned { segment, selector } => {
                let name = ["CS", "SS", "DS", "ES", "FS", "GS"]
                    .get(usize::from(*segment)).copied().unwrap_or("unknown");
                write!(f, "legacy CPU {name} selector 0x{selector:04X} has no frame-owned lease")
            },
            Self::DescriptorChanged { segment, reference, saved, current } => {
                write!(f, "legacy CPU segment {segment} descriptor changed: selector={:04X}, generation={}, ",
                    reference.raw().0, reference.generation())?;
                write_descriptor(f, "saved", saved)?;
                f.write_str("; ")?;
                write_descriptor(f, "current", current)
            },
            Self::UnmappedDataChanged { segment } => write!(f, "legacy CPU data segment {segment} changed after it was saved as unmapped"),
            Self::BackingChanged { segment } => write!(f, "legacy CPU segment {segment} backing changed"),
            Self::MemoryDomainChanged => f.write_str("legacy CPU guest memory domain changed"),
            Self::InvalidSegmentAccess { segment } => write!(f, "legacy CPU segment {segment} cannot satisfy its code or stack role"),
            Self::InvalidTransfer => f.write_str("legacy CPU register transfer proof is inconsistent"),
        }
    }
}

impl Error for Win16LegacyCpuBindingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Selector { source, .. } => Some(source),
            Self::Runtime(error) => Some(error),
            _ => None,
        }
    }
}

fn write_descriptor(f: &mut fmt::Formatter<'_>, label: &str, descriptor: &DescriptorInfo) -> fmt::Result {
    write!(f, "{label} base={:08X}, limit={:08X}, rights={}{}{}, segment={}/{}, present={}",
        descriptor.base.0, descriptor.limit,
        if descriptor.rights.readable() { 'R' } else { '-' },
        if descriptor.rights.writable() { 'W' } else { '-' },
        if descriptor.rights.executable() { 'X' } else { '-' },
        descriptor.segment_index, descriptor.segment_count, descriptor.present)
}

#[derive(Clone, Eq, PartialEq)]
struct SegmentRootProof {
    reference: SelectorRef,
    descriptor: DescriptorInfo,
    backing: SelectorBackingIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnmappedDataSnapshot {
    Absent,
    InstalledUnbacked {
        reference: SelectorRef,
        descriptor: DescriptorInfo,
    },
}

#[derive(Clone, Eq, PartialEq)]
enum SegmentProof {
    Live(SegmentRootProof),
    /// Win16 CPU save/restore preserves these bits without making the raw
    /// selector a capability. Any later access still goes through the checked
    /// selector resolver, and a later descriptor cannot revive this proof.
    UnmappedData {
        raw: u16,
        slot: u8,
        snapshot: UnmappedDataSnapshot,
    },
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct Win16LegacyCpuBindingProof {
    registers: Registers,
    domain: MemoryDomainSnapshot,
    segments: [Option<SegmentProof>; 6],
}

struct OwnedSelectorRoot {
    reference: SelectorRef,
    descriptor: DescriptorInfo,
    backing: SelectorBackingIdentity,
    lease: SelectorBackingLease,
    growths: Vec<AutomaticDataGrowthReceipt>,
}

/// Non-cloneable frame owner. Callers must retain it until explicit release.
pub(super) struct Win16LegacyCpuBindingOwner {
    domain: MemoryDomainSnapshot,
    roots: Vec<OwnedSelectorRoot>,
}

pub(super) struct Win16LegacyCpuBindingOwnerBuildError {
    pub(super) cause: Win16LegacyCpuBindingError,
    /// Partial pins remain here so a caller can retry cleanup without losing them.
    pub(super) owner: Win16LegacyCpuBindingOwner,
}

pub(super) struct Win16LegacyCpuBinding<'a> {
    state: &'a Win16State,
    memory: &'a Memory,
    owner: &'a Win16LegacyCpuBindingOwner,
}

impl Win16LegacyCpuBindingOwner {
    pub(super) fn owns_selector(&self, reference: SelectorRef) -> bool {
        self.roots.iter().any(|root| {
            root.reference.raw().0 & 0xfff8 == reference.raw().0 & 0xfff8
                && root.reference.generation() == reference.generation()
        })
    }
}

impl Win16State {
    /// Capture all six visible segment roots and retain their real backing leases.
    pub(super) fn capture_legacy_cpu_binding_owner(
        &mut self,
        registers: &Registers,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<Win16LegacyCpuBindingOwner, Win16LegacyCpuBindingOwnerBuildError> {
        self.capture_legacy_cpu_binding_owner_with_faulting_stack(registers, dos, memory, false)
    }

    /// Observer capture retains the source stack selector and backing, but
    /// allows its current SP to be the fault that produced the deferred event.
    pub(super) fn capture_legacy_cpu_binding_owner_for_event_observer(
        &mut self,
        registers: &Registers,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<Win16LegacyCpuBindingOwner, Win16LegacyCpuBindingOwnerBuildError> {
        self.capture_legacy_cpu_binding_owner_with_faulting_stack(registers, dos, memory, true)
    }

    fn capture_legacy_cpu_binding_owner_with_faulting_stack(
        &mut self,
        registers: &Registers,
        dos: &mut DosKernel,
        memory: &mut Memory,
        allow_faulting_stack: bool,
    ) -> Result<Win16LegacyCpuBindingOwner, Win16LegacyCpuBindingOwnerBuildError> {
        let mut owner = Win16LegacyCpuBindingOwner {
            domain: memory.domain_snapshot(),
            roots: Vec::new(),
        };
        if let Err(cause) = self.retain_legacy_cpu_binding_roots_with_faulting_stack(
            &mut owner,
            registers,
            dos,
            memory,
            allow_faulting_stack,
        ) {
            return Err(Win16LegacyCpuBindingOwnerBuildError { cause, owner });
        }
        Ok(owner)
    }

    /// Add callback or target registers to the same frame owner before prepare.
    pub(super) fn retain_legacy_cpu_binding_roots(
        &mut self,
        owner: &mut Win16LegacyCpuBindingOwner,
        registers: &Registers,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), Win16LegacyCpuBindingError> {
        self.retain_legacy_cpu_binding_roots_with_faulting_stack(
            owner, registers, dos, memory, false,
        )
    }

    fn retain_legacy_cpu_binding_roots_with_faulting_stack(
        &mut self,
        owner: &mut Win16LegacyCpuBindingOwner,
        registers: &Registers,
        dos: &mut DosKernel,
        memory: &mut Memory,
        allow_faulting_stack: bool,
    ) -> Result<(), Win16LegacyCpuBindingError> {
        if !memory.domain_matches(&owner.domain) {
            return Err(Win16LegacyCpuBindingError::MemoryDomainChanged);
        }
        for (slot, raw) in visible_segments(registers).into_iter().enumerate() {
            let selector = Selector(raw);
            let reference = match self.selectors.reference(selector) {
                Ok(reference) => reference,
                Err(Win16Error::InvalidSelector) if (2..=5).contains(&slot) => {
                    // These raw words are saved in the register frame but do
                    // not acquire selector or backing ownership.
                    capture_unmapped_data_snapshot(&self.selectors, raw)
                        .map_err(|source| Win16LegacyCpuBindingError::Selector { segment: slot as u8, source })?;
                    continue;
                }
                Err(source) => return Err(Win16LegacyCpuBindingError::Selector { segment: slot as u8, source }),
            };
            let descriptor = self.selectors.describe(reference)
                .map_err(|source| Win16LegacyCpuBindingError::Selector { segment: slot as u8, source })?;
            if allow_faulting_stack && slot == 1 {
                if !descriptor.present || !descriptor.rights.writable() {
                    return Err(Win16LegacyCpuBindingError::InvalidSegmentAccess {
                        segment: slot as u8,
                    });
                }
            } else {
                validate_segment(slot, descriptor, registers)?;
            }
            if let Some(existing) = owner.roots.iter().find(|root| root.reference == reference) {
                if existing.descriptor != descriptor {
                    return Err(Win16LegacyCpuBindingError::DescriptorChanged {
                        segment: slot as u8, reference, saved: existing.descriptor, current: descriptor,
                    });
                }
                if !root_history_is_current(existing) {
                    return Err(Win16LegacyCpuBindingError::BackingChanged { segment: slot as u8 });
                }
                continue;
            }
            let backing = self.selector_backing_lease(reference, dos, memory)
                .map_err(Win16LegacyCpuBindingError::Runtime)?
                .ok_or(Win16LegacyCpuBindingError::MissingBacking { segment: slot as u8 })?;
            owner.roots.try_reserve(1).map_err(|source| Win16LegacyCpuBindingError::Runtime(
                RuntimeError::with_source(DiagnosticKind::ResourceExhausted,
                    "reserve legacy CPU segment owner", source)))?;
            let lease = self.retain_legacy_cpu_selector_backing(
                reference, backing, descriptor.base,
                descriptor.limit.checked_add(1).ok_or_else(|| Win16LegacyCpuBindingError::InvalidSegmentAccess { segment: slot as u8 })?,
                dos, memory,
            ).map_err(Win16LegacyCpuBindingError::Runtime)?
                .ok_or(Win16LegacyCpuBindingError::MissingBacking { segment: slot as u8 })?;
            let retained_identity = lease.identity();
            owner.roots.push(OwnedSelectorRoot {
                reference, descriptor, backing: retained_identity, lease,
                growths: Vec::new(),
            });
            if retained_identity != backing {
                return Err(Win16LegacyCpuBindingError::BackingChanged { segment: slot as u8 });
            }
        }
        Ok(())
    }

    /// Prebuild exact saved-proof transitions before the checked allocator
    /// transaction changes guest bytes or selector metadata.
    pub(super) fn prepare_legacy_cpu_data_growth(
        &mut self,
        owner: AutomaticDataOwner,
        old_size: u32,
        new_size: u32,
        targets: &[(SelectorRef, DescriptorInfo)],
        memory: &Memory,
    ) -> Result<LegacyCpuDataGrowthPlan, Win16LegacyCpuBindingError> {
        growth::prepare(self, owner, old_size, new_size, targets, memory)
    }

    /// Applies only preallocated receipts after selector/heap commit.
    pub(super) fn commit_legacy_cpu_data_growth(
        &mut self,
        plan: LegacyCpuDataGrowthPlan,
    ) {
        growth::commit(self, plan)
    }

    /// Release pins one at a time; a failed release leaves that owner in place.
    pub(super) fn release_legacy_cpu_binding_owner(
        &mut self,
        owner: &mut Win16LegacyCpuBindingOwner,
        dos: &mut DosKernel,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        while let Some(root) = owner.roots.last() {
            self.release_selector_lease(&root.lease, dos, memory)?;
            owner.roots.pop();
        }
        Ok(())
    }
}

impl<'a> Win16LegacyCpuBinding<'a> {
    pub(super) fn new(
        state: &'a Win16State,
        memory: &'a Memory,
        owner: &'a Win16LegacyCpuBindingOwner,
    ) -> Self {
        Self { state, memory, owner }
    }

    fn capture_proof(&self, registers: &Registers) -> Result<Win16LegacyCpuBindingProof, Win16LegacyCpuBindingError> {
        if !self.memory.domain_matches(&self.owner.domain) {
            return Err(Win16LegacyCpuBindingError::MemoryDomainChanged);
        }
        let mut segments: [Option<SegmentProof>; 6] = std::array::from_fn(|_| None);
        for (slot, raw) in visible_segments(registers).into_iter().enumerate() {
            let reference = match self.state.selectors.reference(Selector(raw)) {
                Ok(reference) => reference,
                Err(Win16Error::InvalidSelector) if (2..=5).contains(&slot) => {
                    let segment = capture_unmapped_data_proof(&self.state.selectors, slot, raw)
                        .map_err(|source| Win16LegacyCpuBindingError::Selector { segment: slot as u8, source })?;
                    segments[slot] = Some(segment);
                    continue;
                }
                Err(source) => return Err(Win16LegacyCpuBindingError::Selector { segment: slot as u8, source }),
            };
            let descriptor = self.state.selectors.describe(reference)
                .map_err(|source| Win16LegacyCpuBindingError::Selector { segment: slot as u8, source })?;
            validate_segment(slot, descriptor, registers)?;
            let root = self.owner.roots.iter().find(|root| root.reference == reference)
                .ok_or(Win16LegacyCpuBindingError::RootNotOwned { segment: slot as u8, selector: raw })?;
            if root.descriptor != descriptor {
                return Err(Win16LegacyCpuBindingError::DescriptorChanged {
                    segment: slot as u8, reference, saved: root.descriptor, current: descriptor,
                });
            }
            if !root_history_is_current(root) {
                return Err(Win16LegacyCpuBindingError::BackingChanged { segment: slot as u8 });
            }
            self.validate_backing(slot, root)?;
            segments[slot] = Some(SegmentProof::Live(SegmentRootProof {
                reference, descriptor, backing: root.backing,
            }));
        }
        Ok(Win16LegacyCpuBindingProof {
            registers: registers.clone(), domain: self.owner.domain.clone(), segments,
        })
    }

    fn validate_backing(&self, slot: usize, root: &OwnedSelectorRoot) -> Result<(), Win16LegacyCpuBindingError> {
        if root.lease.identity() != root.backing {
            return Err(Win16LegacyCpuBindingError::BackingChanged { segment: slot as u8 });
        }
        let size = root.descriptor.limit.checked_add(1)
            .ok_or(Win16LegacyCpuBindingError::BackingChanged { segment: slot as u8 })?;
        let start = u64::from(root.descriptor.base.0);
        let end = start.checked_add(u64::from(size))
            .ok_or(Win16LegacyCpuBindingError::BackingChanged { segment: slot as u8 })?;
        let live = match (&root.backing, &root.lease) {
            (SelectorBackingIdentity::GlobalHeap { allocation, module, .. }, SelectorBackingLease::GlobalHeap { allocation: held, module: held_module, .. }) if allocation == held && module == held_module => {
                let info = self.state.heap.info(*allocation).map_err(|e| Win16LegacyCpuBindingError::Runtime(crate::runtime_error(e)))?;
                let count = self.state.heap.selector_alias_count(*allocation).map_err(|e| Win16LegacyCpuBindingError::Runtime(crate::runtime_error(e)))?;
                let block_start = u64::from(info.base.0);
                let block_end = block_start.checked_add(u64::from(info.size)).unwrap_or(0);
                let module_root_live = (*module).is_none_or(|module| self.state.modules.records
                    .get(&module).is_some_and(|record| record.continuation_owner_refs != 0));
                !info.discarded && count != 0 && module_root_live
                    && start >= block_start && end <= block_end
            }
            (SelectorBackingIdentity::Dos { extent, primary }, SelectorBackingLease::Dos { lease, extent: held, primary: held_primary }) if extent == held && primary == held_primary && lease.extent() == *extent => {
                primary.is_none_or(|primary| self.state.selectors.reference_including_unbacked(primary.raw()).ok() == Some(primary))
            }
            (SelectorBackingIdentity::ModuleImage { module, primary, base, size: image_size, .. }, SelectorBackingLease::ModuleImage { module: held_module, primary: held_primary, base: held_base, size: held_size, .. }) if module == held_module && primary == held_primary && base == held_base && image_size == held_size => {
                let Some(record) = self.state.modules.records.get(module) else {
                    return Err(Win16LegacyCpuBindingError::BackingChanged { segment: slot as u8 });
                };
                let (head, live_base, live_size) = self.state.selectors.allocation_range(*primary)
                    .map_err(|e| Win16LegacyCpuBindingError::Selector { segment: slot as u8, source: e })?;
                // Retired modules remain physically present while this exact
                // frame lease contributes a continuation owner root.
                record.continuation_owner_refs != 0
                    && head == *primary && live_base == *base && live_size == *image_size
                    && start >= u64::from(base.0)
                    && u64::from(base.0).checked_add(u64::from(*image_size)).is_some_and(|image_end| end <= image_end)
            }
            (SelectorBackingIdentity::RuntimeArena(arena), SelectorBackingLease::RuntimeArena { lease }) if *arena == lease.identity() => {
                self.state.runtime_arena_backing.lease_is_live(
                    lease, root.reference, &self.state.selectors, self.memory,
                ).map_err(Win16LegacyCpuBindingError::Runtime)?
            }
            _ => false,
        };
        if live { Ok(()) } else { Err(Win16LegacyCpuBindingError::BackingChanged { segment: slot as u8 }) }
    }

    fn validate_proof(&self, proof: &Win16LegacyCpuBindingProof) -> Result<(), Win16LegacyCpuBindingError> {
        if proof.domain != self.owner.domain || !self.memory.domain_matches(&proof.domain) {
            return Err(Win16LegacyCpuBindingError::MemoryDomainChanged);
        }
        for (slot, segment) in proof.segments.iter().enumerate() {
            let Some(segment) = segment else {
                return Err(Win16LegacyCpuBindingError::InvalidTransfer);
            };
            let raw = visible_segments(&proof.registers)[slot];
            match segment {
                SegmentProof::Live(root) => {
                    // Visible selector bits retain the caller's low-bit alias;
                    // SelectorTable owns canonicalization and generation checks.
                    let live_reference = self.state.selectors.reference_including_unbacked(Selector(raw))
                        .map_err(|source| Win16LegacyCpuBindingError::Selector { segment: slot as u8, source })?;
                    if live_reference != root.reference {
                        return Err(Win16LegacyCpuBindingError::Selector { segment: slot as u8, source: Win16Error::StaleSelector });
                    }
                    let held = self.owner.roots.iter().find(|held| held.reference == root.reference)
                        .ok_or(Win16LegacyCpuBindingError::RootNotOwned { segment: slot as u8, selector: root.reference.raw().0 })?;
                    let descriptor = self.state.selectors.describe(root.reference)
                        .map_err(|source| Win16LegacyCpuBindingError::Selector { segment: slot as u8, source })?;
                    if descriptor != held.descriptor {
                        return Err(Win16LegacyCpuBindingError::DescriptorChanged {
                            segment: slot as u8, reference: root.reference,
                            saved: held.descriptor, current: descriptor,
                        });
                    }
                    if !root_snapshot_is_authorized(
                        held, root.descriptor, root.backing,
                    ) {
                        if root.descriptor != held.descriptor {
                            return Err(Win16LegacyCpuBindingError::DescriptorChanged {
                                segment: slot as u8, reference: root.reference,
                                saved: root.descriptor, current: held.descriptor,
                            });
                        }
                        return Err(Win16LegacyCpuBindingError::BackingChanged { segment: slot as u8 });
                    }
                    self.validate_backing(slot, held)?;
                }
                SegmentProof::UnmappedData { raw: saved_raw, slot: saved_slot, snapshot } => {
                    if !(2..=5).contains(&slot) || *saved_slot as usize != slot || *saved_raw != raw {
                        return Err(Win16LegacyCpuBindingError::InvalidTransfer);
                    }
                    validate_unmapped_data_snapshot(&self.state.selectors, *saved_raw, slot, *snapshot)?;
                }
            }
        }
        Ok(())
    }
}

impl LegacyCpuBinding for Win16LegacyCpuBinding<'_> {
    type Proof = Win16LegacyCpuBindingProof;
    type Error = Win16LegacyCpuBindingError;

    fn capture(&self, registers: &Registers) -> Result<Self::Proof, Self::Error> {
        self.capture_proof(registers)
    }

    fn revalidate(
        &self,
        saved: &Self::Proof,
        observed: &Self::Proof,
        transfer: &LegacyBindingTransfer<'_, Self::Proof>,
    ) -> Result<(), Self::Error> {
        if transfer.current.registers != *transfer.current_registers
            || transfer.target.registers != *transfer.target_registers
            || (observed.registers != saved.registers
                && observed.registers != *transfer.current_registers
                && observed.registers != *transfer.target_registers)
        {
            return Err(Win16LegacyCpuBindingError::InvalidTransfer);
        }
        self.validate_proof(saved)?;
        self.validate_proof(observed)?;
        self.validate_proof(transfer.current)?;
        self.validate_proof(transfer.target)?;
        if transfer.stack_pointer == LegacyStackPointerTarget::OnePast16BitSegment {
            let Some(SegmentProof::Live(stack)) = transfer.target.segments[1].as_ref() else {
                return Err(Win16LegacyCpuBindingError::InvalidTransfer);
            };
            if transfer.target_registers.sp() != 0
                || stack.descriptor.limit != u32::from(u16::MAX)
                || !stack.descriptor.rights.writable()
            {
                return Err(Win16LegacyCpuBindingError::InvalidTransfer);
            }
        }
        Ok(())
    }
}

fn capture_unmapped_data_snapshot(
    selectors: &SelectorTable,
    raw: u16,
) -> Result<UnmappedDataSnapshot, Win16Error> {
    match selectors.reference(Selector(raw)) {
        Ok(_) => return Err(Win16Error::StaleSelector),
        Err(Win16Error::InvalidSelector) => {}
        Err(error) => return Err(error),
    }
    match selectors.reference_including_unbacked(Selector(raw)) {
        Ok(reference) => {
            let descriptor = selectors.describe(reference)?;
            if descriptor.present {
                // A present identity after `reference` rejected the raw value
                // means the selector changed between the two observations.
                return Err(Win16Error::StaleSelector);
            }
            Ok(UnmappedDataSnapshot::InstalledUnbacked { reference, descriptor })
        }
        Err(Win16Error::InvalidSelector) => Ok(UnmappedDataSnapshot::Absent),
        Err(error) => Err(error),
    }
}

fn capture_unmapped_data_proof(
    selectors: &SelectorTable,
    slot: usize,
    raw: u16,
) -> Result<SegmentProof, Win16Error> {
    if !(2..=5).contains(&slot) {
        return Err(Win16Error::InvalidSelector);
    }
    let snapshot = capture_unmapped_data_snapshot(selectors, raw)?;
    Ok(SegmentProof::UnmappedData { raw, slot: slot as u8, snapshot })
}

fn validate_unmapped_data_snapshot(
    selectors: &SelectorTable,
    raw: u16,
    slot: usize,
    expected: UnmappedDataSnapshot,
) -> Result<(), Win16LegacyCpuBindingError> {
    let current = capture_unmapped_data_snapshot(selectors, raw)
        .map_err(|_| Win16LegacyCpuBindingError::UnmappedDataChanged { segment: slot as u8 })?;
    if current == expected {
        Ok(())
    } else {
        Err(Win16LegacyCpuBindingError::UnmappedDataChanged { segment: slot as u8 })
    }
}

fn visible_segments(registers: &Registers) -> [u16; 6] {
    [registers.cs, registers.ss, registers.ds, registers.es, registers.fs, registers.gs]
}

fn validate_segment(slot: usize, descriptor: DescriptorInfo, registers: &Registers) -> Result<(), Win16LegacyCpuBindingError> {
    let valid = match slot {
        0 => descriptor.present && descriptor.rights.executable()
            && u32::from(registers.ip()) <= descriptor.limit,
        1 => descriptor.present && descriptor.rights.writable()
            && u32::from(registers.sp()) <= descriptor.limit,
        _ => descriptor.present,
    };
    if valid { Ok(()) } else { Err(Win16LegacyCpuBindingError::InvalidSegmentAccess { segment: slot as u8 }) }
}

#[cfg(test)]
#[path = "win16_legacy_cpu_binding_tests.rs"]
mod tests;
