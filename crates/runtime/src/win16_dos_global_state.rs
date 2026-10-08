//! Exact runtime metadata for one Win16 GlobalDOSAlloc handle.

use dos_kernel::{DosBlockExtent, DosBlockLease};
use win16_abi::{GuestMemoryOwner, SelectorAllocationView};

#[derive(Debug)]
pub(super) struct Win16DosGlobalBlock {
    /// Registry token plus full MCB extent identifies this exact allocation;
    /// owner and segment words alone become ambiguous after DOS reuses them.
    pub(super) lease: DosBlockLease,
    pub(super) extent: DosBlockExtent,
    pub(super) size: u32,
    pub(super) guest_owner: GuestMemoryOwner,
    pub(super) page_lock_count: u16,
    pub(super) fix_count: u16,
    pub(super) wire_count: u16,
    /// Retained across retryable cleanup while the exact selector generations
    /// are suspended; MCB release may already have succeeded on a later phase.
    pub(super) suspended_views: Option<Vec<SelectorAllocationView>>,
    /// Alias tokens have been checked and at least one may have been consumed.
    /// Retries keep the selector generations suspended until pins are restored
    /// or the primary MCB lease is safely retired.
    pub(super) alias_release_started: bool,
    pub(super) mcb_released: bool,
    /// A failed DOS rollback means the MCB contents are not known to be live.
    /// Keep the exact views suspended and never retry the uncertain token.
    pub(super) mcb_release_uncertain: bool,
}
