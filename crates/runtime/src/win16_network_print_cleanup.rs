//! Retryable cleanup identities for WNet printer jobs, watches, and snapshots.

use super::network_print_jobs::{Win16NetworkPrintJobs, Win16NetworkPrintQueueDataLease};
use crate::win16_host_spool::Win16HostNetworkQueueWatch;
use crate::{RuntimeError, Win16HostWindow};

#[derive(Debug)]
pub(crate) struct Win16NetworkPrintCleanupPlan {
    pub(crate) watches: Vec<Win16HostNetworkQueueWatch>,
    pub(crate) queue_data: Vec<Win16NetworkPrintQueueDataLease>,
}

/// Snapshot task-owned identities without retiring them. The caller removes
/// each record only after the matching host cleanup succeeds, so a failed or
/// ambiguous host call remains available for retry.
pub(crate) fn plan(
    jobs: &Win16NetworkPrintJobs,
) -> Result<Win16NetworkPrintCleanupPlan, RuntimeError> {
    Ok(Win16NetworkPrintCleanupPlan {
        watches: jobs.watches_for_cleanup()?,
        queue_data: jobs.queue_data_leases_for_cleanup()?,
    })
}

pub(crate) fn retire_watch_after_host_unwatch(
    jobs: &mut Win16NetworkPrintJobs,
    watch: Win16HostNetworkQueueWatch,
) -> bool {
    jobs.retire_watch(watch)
}

pub(crate) fn retire_queue_data_after_global_release(
    jobs: &mut Win16NetworkPrintJobs,
    queue: &[u8],
    global_handle: u16,
) -> bool {
    jobs.retire_queue_data_lease(queue, global_handle)
}

pub(crate) fn watches_for_destroyed_window(
    jobs: &Win16NetworkPrintJobs,
    guest_hwnd: u16,
    window: Win16HostWindow,
) -> Result<Vec<Win16HostNetworkQueueWatch>, RuntimeError> {
    jobs.matching_watches_for_window(guest_hwnd, window)
}
