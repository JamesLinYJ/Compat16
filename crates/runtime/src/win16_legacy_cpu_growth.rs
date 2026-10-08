//! Exact committed automatic-data extent transitions for saved CPU roots.

use guest_core::memory::Memory;
use win16_abi::{DescriptorInfo, GlobalHandle, SelectorRef};

use super::{OwnedSelectorRoot, Win16LegacyCpuBinding, Win16LegacyCpuBindingError};
use super::super::{
    Win16State,
    selector_ownership::{SelectorBackingIdentity, SelectorBackingLease},
};
use crate::{DiagnosticKind, RuntimeError};

/// Exact runtime provenance for an automatic-data segment that owns reserved
/// adjacent capacity. Selector and heap handles preserve allocation generations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::win16_runtime) enum AutomaticDataOwner {
    Main {
        module: u16,
        selector: SelectorRef,
        segment: u16,
        segment_flags: u16,
        base: guest_core::PhysAddr,
        capacity: u32,
    },
    Library {
        module: u16,
        allocation: GlobalHandle,
        selector: SelectorRef,
        segment: u16,
        segment_flags: u16,
        base: guest_core::PhysAddr,
        capacity: u32,
    },
}

impl AutomaticDataOwner {
    pub(super) fn selector(self) -> SelectorRef {
        match self {
            Self::Main { selector, .. } | Self::Library { selector, .. } => selector,
        }
    }

    pub(super) fn base(self) -> guest_core::PhysAddr {
        match self {
            Self::Main { base, .. } | Self::Library { base, .. } => base,
        }
    }

    pub(in crate::win16_runtime) fn capacity(self) -> u32 {
        match self {
            Self::Main { capacity, .. } | Self::Library { capacity, .. } => capacity,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AutomaticDataGrowthReceipt {
    owner: AutomaticDataOwner,
    reference: SelectorRef,
    extent_before: u32,
    extent_after: u32,
    before: DescriptorInfo,
    after: DescriptorInfo,
    backing_before: SelectorBackingIdentity,
    backing_after: SelectorBackingIdentity,
}

struct LegacyCpuGrowthUpdate {
    frame_index: usize,
    root_index: usize,
    receipt: AutomaticDataGrowthReceipt,
}

/// All allocations and owner checks complete before the allocator mutates
/// guest bytes or selector metadata.
pub(in crate::win16_runtime) struct LegacyCpuDataGrowthPlan {
    updates: Vec<LegacyCpuGrowthUpdate>,
}

pub(super) fn prepare(
    state: &mut Win16State,
    owner: AutomaticDataOwner,
    old_size: u32,
    new_size: u32,
    targets: &[(SelectorRef, DescriptorInfo)],
    memory: &Memory,
) -> Result<LegacyCpuDataGrowthPlan, Win16LegacyCpuBindingError> {
    if old_size == 0 || new_size <= old_size || new_size > owner.capacity() {
        return Err(Win16LegacyCpuBindingError::BackingChanged { segment: 1 });
    }
    let primary = owner.selector();
    if state.selectors.reference_including_unbacked(primary.raw()).ok() != Some(primary) {
        return Err(Win16LegacyCpuBindingError::BackingChanged { segment: 1 });
    }
    let primary_target = targets.iter().find(|(reference, _)| *reference == primary)
        .ok_or(Win16LegacyCpuBindingError::BackingChanged { segment: 1 })?;
    if primary_target.1.selector != primary.raw()
        || primary_target.1.base != owner.base()
        || primary_target.1.limit.checked_add(1) != Some(old_size)
        || !primary_target.1.present
        || primary_target.1.segment_index != 0
        || primary_target.1.segment_count != 1
    {
        return Err(Win16LegacyCpuBindingError::BackingChanged { segment: 1 });
    }
    for (reference, descriptor) in targets {
        if descriptor.selector != reference.raw()
            || descriptor.base != owner.base()
            || descriptor.limit.checked_add(1) != Some(old_size)
            || !descriptor.present
            || descriptor.segment_index != 0
            || descriptor.segment_count != 1
        {
            return Err(Win16LegacyCpuBindingError::BackingChanged { segment: 1 });
        }
    }

    // Validate current backing ranges before taking mutable frame borrows or
    // reserving proof history. The later commit step relies on this live
    // allocation state remaining unchanged during the synchronous growth.
    for frame in &state.legacy_cpu_frames {
        for root in &frame.owner.roots {
            let target = targets.iter()
                .find(|(reference, _)| *reference == root.reference);
            let backing_after = grow_backing_identity(
                owner, owner.base(), root.backing, old_size, new_size,
            );
            if target.is_none()
                && !backing_after.is_some_and(|next| next != root.backing)
            {
                continue;
            }
            if !memory.domain_matches(&frame.owner.domain)
                || root.lease.identity() != root.backing
                || !growth_history_ends_at(root, owner)
            {
                return Err(Win16LegacyCpuBindingError::BackingChanged { segment: 1 });
            }
            let before = if let Some((_, before)) = target {
                *before
            } else {
                state.selectors.describe(root.reference).map_err(|source|
                    Win16LegacyCpuBindingError::Selector { segment: 1, source })?
            };
            if root.descriptor != before {
                return Err(Win16LegacyCpuBindingError::DescriptorChanged {
                    segment: 1, reference: root.reference,
                    saved: root.descriptor, current: before,
                });
            }
            let binding = Win16LegacyCpuBinding::new(state, memory, &frame.owner);
            binding.validate_backing(1, root)?;
        }
    }

    let mut plan = LegacyCpuDataGrowthPlan { updates: Vec::new() };
    for (frame_index, frame) in state.legacy_cpu_frames.iter_mut().enumerate() {
        for (root_index, root) in frame.owner.roots.iter_mut().enumerate() {
            let target = targets.iter()
                .find(|(reference, _)| *reference == root.reference);
            let backing_after = grow_backing_identity(
                owner, owner.base(), root.backing, old_size, new_size,
            );
            let advances_image_extent = backing_after.is_some_and(|next| next != root.backing);
            if target.is_none() && !advances_image_extent { continue; }
            if !memory.domain_matches(&frame.owner.domain) {
                return Err(Win16LegacyCpuBindingError::MemoryDomainChanged);
            }
            if root.lease.identity() != root.backing {
                return Err(Win16LegacyCpuBindingError::BackingChanged { segment: 1 });
            }
            if !growth_history_ends_at(root, owner) {
                return Err(Win16LegacyCpuBindingError::BackingChanged { segment: 1 });
            }
            let before = if let Some((_, before)) = target {
                *before
            } else {
                state.selectors.describe(root.reference).map_err(|source|
                    Win16LegacyCpuBindingError::Selector { segment: 1, source })?
            };
            if root.descriptor != before {
                return Err(Win16LegacyCpuBindingError::DescriptorChanged {
                    segment: 1, reference: root.reference,
                    saved: root.descriptor, current: before,
                });
            }
            let backing_after = backing_after
                .ok_or(Win16LegacyCpuBindingError::BackingChanged { segment: 1 })?;
            let mut after = before;
            if target.is_some() { after.limit = new_size - 1; }
            let receipt = AutomaticDataGrowthReceipt {
                owner,
                reference: root.reference,
                extent_before: old_size,
                extent_after: new_size,
                before,
                after,
                backing_before: root.backing,
                backing_after,
            };
            if !valid_growth_receipt(root.reference, receipt) {
                return Err(Win16LegacyCpuBindingError::BackingChanged { segment: 1 });
            }
            root.growths.try_reserve(1).map_err(|source|
                Win16LegacyCpuBindingError::Runtime(RuntimeError::with_source(
                    DiagnosticKind::ResourceExhausted,
                    "reserve a checked automatic-data growth receipt",
                    source,
                )))?;
            plan.updates.try_reserve(1).map_err(|source|
                Win16LegacyCpuBindingError::Runtime(RuntimeError::with_source(
                    DiagnosticKind::ResourceExhausted,
                    "reserve legacy CPU automatic-data growth updates",
                    source,
                )))?;
            plan.updates.push(LegacyCpuGrowthUpdate { frame_index, root_index, receipt });
        }
    }
    Ok(plan)
}

/// Appends only preallocated receipts after selector and allocator commit.
pub(super) fn commit(state: &mut Win16State, plan: LegacyCpuDataGrowthPlan) {
    for update in plan.updates {
        let frame = &mut state.legacy_cpu_frames[update.frame_index];
        let root = &mut frame.owner.roots[update.root_index];
        let receipt = update.receipt;
        debug_assert_eq!(root.reference, receipt.reference);
        debug_assert_eq!(root.descriptor, receipt.before);
        debug_assert_eq!(root.backing, receipt.backing_before);
        debug_assert_eq!(root.lease.identity(), receipt.backing_before);
        root.growths.push(receipt);
        root.descriptor = receipt.after;
        root.backing = receipt.backing_after;
        match (&mut root.lease, receipt.backing_after) {
            (
                SelectorBackingLease::ModuleImage { module, primary, base, size, segment_flags },
                SelectorBackingIdentity::ModuleImage {
                    module: next_module, primary: next_primary, base: next_base,
                    size: next_size, segment_flags: next_flags,
                },
            ) if *module == next_module && *primary == next_primary
                && *base == next_base && *segment_flags == next_flags => {
                    *size = next_size;
                }
            (SelectorBackingLease::GlobalHeap { allocation, module, ne_segment_flags },
                SelectorBackingIdentity::GlobalHeap {
                    allocation: next_allocation, module: next_module,
                    ne_segment_flags: next_flags,
                }) if *allocation == next_allocation && *module == next_module
                    && *ne_segment_flags == next_flags => {}
            _ => unreachable!("prepared automatic-data receipt changed backing kind"),
        }
    }
}

fn growth_history_ends_at(root: &OwnedSelectorRoot, owner: AutomaticDataOwner) -> bool {
    root_history_is_current(root)
        && root.growths.last().is_none_or(|receipt| receipt.owner == owner)
}

pub(super) fn root_history_is_current(root: &OwnedSelectorRoot) -> bool {
    if root.growths.is_empty() { return root.lease.identity() == root.backing; }
    let mut previous: Option<AutomaticDataGrowthReceipt> = None;
    for receipt in &root.growths {
        if !valid_growth_receipt(root.reference, *receipt)
            || previous.is_some_and(|prior|
                prior.extent_after != receipt.extent_before
                    || prior.owner != receipt.owner
                    || prior.after != receipt.before
                    || prior.backing_after != receipt.backing_before)
        {
            return false;
        }
        previous = Some(*receipt);
    }
    previous.is_some_and(|last|
        last.after == root.descriptor
            && last.backing_after == root.backing
            && root.lease.identity() == root.backing)
}

pub(super) fn root_snapshot_is_authorized(
    root: &OwnedSelectorRoot,
    descriptor: DescriptorInfo,
    backing: SelectorBackingIdentity,
) -> bool {
    if !root_history_is_current(root) { return false; }
    if root.growths.is_empty() {
        return descriptor == root.descriptor && backing == root.backing;
    }
    let mut previous: Option<AutomaticDataGrowthReceipt> = None;
    let mut found = false;
    for receipt in &root.growths {
        if !valid_growth_receipt(root.reference, *receipt)
            || previous.is_some_and(|prior|
                prior.owner != receipt.owner
                    || prior.extent_after != receipt.extent_before
                    || prior.after != receipt.before
                    || prior.backing_after != receipt.backing_before)
        {
            return false;
        }
        if (descriptor == receipt.before && backing == receipt.backing_before)
            || (descriptor == receipt.after && backing == receipt.backing_after)
        {
            found = true;
        }
        previous = Some(*receipt);
    }
    previous.is_some_and(|last|
        found
            && last.after == root.descriptor
            && last.backing_after == root.backing
            && root.lease.identity() == root.backing)
}

fn valid_growth_receipt(
    reference: SelectorRef,
    receipt: AutomaticDataGrowthReceipt,
) -> bool {
    if receipt.reference != reference
        || receipt.before.selector != reference.raw()
        || receipt.after.selector != reference.raw()
        || !receipt.before.present || !receipt.after.present
        || receipt.before.segment_index != receipt.after.segment_index
        || receipt.before.segment_count != receipt.after.segment_count
        || receipt.before.rights != receipt.after.rights
        || receipt.before.present != receipt.after.present
    {
        return false;
    }
    if receipt.extent_before == 0
        || receipt.extent_after <= receipt.extent_before
        || receipt.extent_after > receipt.owner.capacity()
        || grow_backing_identity(
            receipt.owner, receipt.owner.base(), receipt.backing_before,
            receipt.extent_before, receipt.extent_after,
        ) != Some(receipt.backing_after)
    {
        return false;
    }
    if receipt.before != receipt.after {
        receipt.before.base == receipt.owner.base()
            && receipt.after.base == receipt.owner.base()
            && receipt.before.segment_index == 0
            && receipt.before.segment_count == 1
            && receipt.before.limit.checked_add(1) == Some(receipt.extent_before)
            && receipt.after.limit.checked_add(1) == Some(receipt.extent_after)
    } else {
        let (AutomaticDataOwner::Main { .. },
            SelectorBackingIdentity::ModuleImage { base, size, .. }) =
            (receipt.owner, receipt.backing_before)
        else { return false; };
        let start = u64::from(receipt.before.base.0);
        let end = start.checked_add(u64::from(receipt.before.limit) + 1);
        let image_start = u64::from(base.0);
        let image_end = image_start.checked_add(u64::from(size));
        start >= image_start && end.is_some_and(|end| image_end.is_some_and(|image_end| end <= image_end))
    }
}

fn grow_backing_identity(
    owner: AutomaticDataOwner,
    base: guest_core::PhysAddr,
    backing: SelectorBackingIdentity,
    old_size: u32,
    new_size: u32,
) -> Option<SelectorBackingIdentity> {
    if owner.base() != base { return None; }
    match (owner, backing) {
        (
            AutomaticDataOwner::Main {
                module, selector, segment_flags, base, capacity, ..
            },
            SelectorBackingIdentity::ModuleImage {
                module: backing_module, primary, base: backing_base,
                size, segment_flags: backing_flags,
            },
        ) if old_size < new_size && module == backing_module && selector == primary && base == backing_base
            && segment_flags == backing_flags && size == old_size
            && new_size <= capacity => Some(SelectorBackingIdentity::ModuleImage {
                module: backing_module, primary, base: backing_base,
                size: new_size, segment_flags: backing_flags,
            }),
        (
            AutomaticDataOwner::Library {
                module, allocation, segment_flags, capacity, ..
            },
            SelectorBackingIdentity::GlobalHeap {
                allocation: backing_allocation, module: Some(backing_module),
                ne_segment_flags: Some(backing_flags),
            },
        ) if module == backing_module && allocation == backing_allocation
            && segment_flags == backing_flags && new_size <= capacity
            && old_size < new_size => Some(SelectorBackingIdentity::GlobalHeap {
                allocation: backing_allocation, module: Some(backing_module),
                ne_segment_flags: Some(backing_flags),
            }),
        _ => None,
    }
}
