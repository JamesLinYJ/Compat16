//! Descriptor view metadata and allocation resize contracts.

use guest_core::{PhysAddr, Selector};

use super::AccessRights;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorInfo {
    pub selector: Selector,
    pub base: PhysAddr,
    pub limit: u32,
    pub rights: AccessRights,
    pub segment_index: usize,
    pub segment_count: usize,
    /// False for a reserved selector identity that currently has no guest
    /// memory backing (for example a discarded movable HGLOBAL).
    pub present: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Descriptor {
    pub(super) base: PhysAddr,
    pub(super) limit: u32,
    pub(super) rights: AccessRights,
    /// The modeled 16-bit LDT access/flag bytes exposed by the historical
    /// KERNEL.196 helper. Keeping this beside the capability rights lets
    /// Presto and heap rebind preserve descriptor identity without fabricating
    /// access bits from a lossy host permission enum.
    pub(super) access_flags: u16,
    pub(super) resize_policy: AllocationResizePolicy,
    pub(super) generation: u64,
    pub(super) block_index: usize,
    pub(super) segment_index: usize,
    pub(super) segment_count: usize,
    pub(super) block_size: u32,
    pub(super) present: bool,
}

/// Describes how a selector view tracks its backing allocation. Ordinary heap
/// heads and complete heap aliases follow the allocation's resized extent;
/// an AllocSelector descriptor copy keeps the exact copied limit while its
/// base follows moves of the backing bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AllocationResizePolicy {
    FollowAllocationExtent,
    PreserveDescriptorShape,
}
