//! Validate transfer ownership before committing its local, non-fallible close.

use super::{DdeDataTransferGuard, invariant};
use crate::win16_dde::{Win16DdeDataOrigin as Origin, Win16DdeRetiredGuestBlock, Win16DdeState};
use crate::{
    DiagnosticKind as Kind, RuntimeError, Win16DdeNativeTransferGuardSource as Source,
    Win16HostDdeDataTransferOutcome as Outcome,
};

/// All fallible validation and queue allocation precede ownership mutation.
/// The caller journals success before attempting deferred guest-block cleanup.
/// A missing guard is never interpreted as an earlier successful settlement.
pub(super) fn settle_transfer_guard(
    dde: &mut Win16DdeState,
    guard: DdeDataTransferGuard,
    source: Source,
    retired_blocks: &mut Vec<Win16DdeRetiredGuestBlock>,
) -> Result<(), RuntimeError> {
    let (prior, freed, uninitialized, begun) = dde
        .data_transfer_guard_retirement_state(
            guard.guard_id,
            guard.guest_data,
            guard.host_data,
            guard.owner,
            guard.origin,
        )
        .ok_or_else(|| invariant("DDE transfer settlement lost its exact guard evidence"))?;
    if prior != guard.previously_transferred
        || dde.data_transfer_guard_matches(
            guard.guard_id,
            guard.guest_data,
            guard.host_data,
            guard.owner,
            guard.origin,
        ) != Some(true)
    {
        return Err(invariant(
            "DDE transfer settlement changed its captured source identity",
        ));
    }
    let outcome = match source {
        Source::NotEntered | Source::PreflightRejected => Some(Outcome::NotPassed),
        Source::NativeCompletion(outcome) => Some(outcome),
        Source::InstanceUninitialized if begun => None,
        Source::InstanceUninitialized => {
            return Err(invariant(
                "DDE uninitialize receipt names a transfer that never began",
            ));
        }
        Source::Retained => return Err(invariant("DDE native transfer remains retained")),
    };
    let live = !freed && !uninitialized;
    if !live
        && dde.host_data(guard.guest_data) == Some(guard.host_data)
        && dde.instance_for_data(guard.guest_data) == Some(guard.owner)
        && dde.data_origin(guard.guest_data) == Some(guard.origin)
    {
        return Err(invariant(
            "retired DDE transfer evidence conflicts with a visible source alias",
        ));
    }
    match outcome {
        Some(Outcome::Consumed) => {
            if freed
                || !matches!(
                    guard.origin,
                    Origin::Created {
                        retain_after_transfer: false
                    }
                )
                || !guard.transfer_marked
                || !begun
                || (live && dde.data_transfer_state(guard.guest_data) != Some(true))
            {
                return Err(invariant(
                    "DDE Consumed receipt conflicts with its exact input source",
                ));
            }
        }
        Some(Outcome::RetainedReadOnly) => {
            if !matches!(
                guard.origin,
                Origin::Created {
                    retain_after_transfer: true
                }
            ) || !guard.transfer_marked
                || !begun
                || (live
                    && (dde.data_transfer_state(guard.guest_data) != Some(true)
                        || dde.data_is_writable(guard.guest_data) != Some(false)))
            {
                return Err(invariant(
                    "DDE APPOWNED receipt changed its read-only source",
                ));
            }
        }
        Some(Outcome::CopiedInputRetained) => {
            if !matches!(
                guard.origin,
                Origin::CallbackBorrowed | Origin::ClientResult
            ) || guard.transfer_marked
                || !begun
                || (live && dde.data_transfer_state(guard.guest_data) != Some(prior))
            {
                return Err(invariant(
                    "DDE copied-input receipt changed its retained source",
                ));
            }
        }
        Some(Outcome::NotPassed) | None => {}
    }
    if outcome == Some(Outcome::Consumed) && live {
        retired_blocks.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve deferred DDE transfer block before committing local settlement",
                error,
            )
        })?;
        if let Some(block) = dde.access_block(guard.guest_data)
            && retired_blocks
                .iter()
                .any(|entry| entry.identity == block.identity)
        {
            return Err(invariant(
                "live DDE transfer block already has a retirement owner",
            ));
        }
    }

    // No host calls, allocation, or fallible resource cleanup occurs below.
    // The exact ledger facts checked above cannot change during this commit.
    if outcome == Some(Outcome::NotPassed) {
        dde.restore_data_transfer(
            guard.guard_id,
            guard.guest_data,
            guard.host_data,
            guard.owner,
            guard.origin,
        )
        .expect("validated exact DDE transfer restore");
    }
    if outcome == Some(Outcome::Consumed) && live {
        let removed = dde
            .consume_data_transfer(guard.guest_data)
            .expect("validated exact consumed DDE source");
        if let Some(block) = removed.and_then(|removed| removed.access_block) {
            retired_blocks.push(Win16DdeRetiredGuestBlock::pending(block.identity, true));
        }
    }
    // Global native uninitialization does not recreate or remove guest data;
    // final DDE storage teardown owns any remaining local mappings.
    if source == Source::InstanceUninitialized {
        dde.mark_transfer_guard_instance_uninitialized(
            guard.guard_id,
            guard.guest_data,
            guard.host_data,
            guard.owner,
            guard.origin,
        )
        .expect("validated exact DDE uninitialize guard");
    }
    let closed = dde
        .take_guest_free_evidence(
            guard.guard_id,
            guard.guest_data,
            guard.host_data,
            guard.owner,
            guard.origin,
        )
        .expect("validated exact DDE guard close");
    debug_assert_eq!(
        closed,
        (
            prior,
            freed,
            uninitialized || source == Source::InstanceUninitialized
        )
    );
    Ok(())
}

#[cfg(test)]
#[path = "win16_runtime_dde_transfer_tests.rs"]
mod tests;
