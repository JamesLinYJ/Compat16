//! Capacity planning and stable failure reconciliation for DDE shutdown.

use super::*;

pub(super) fn reserve_receipt_for_pending_owner(
    host: &Win16DdeHost,
    receipt: &mut Win16DdeAbortReceipt,
) -> Result<(), RuntimeError> {
    let operations = host
        .pending_operation_instances
        .len()
        .checked_add(host.pending_operations.len())
        .and_then(|count| count.checked_add(host.pending_callbacks.len()))
        .ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted,
            "DDE pending operation count overflowed while reserving shutdown evidence",
        ))?;
    let failures = operations
        .checked_add(host.pending_transfer_guards.len())
        .and_then(|count| count.checked_add(4))
        .ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted,
            "DDE cleanup evidence count overflowed while reserving shutdown receipt",
        ))?;
    receipt.cleanup_failures.try_reserve(failures).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve typed DDE cleanup failure receipt entries",
            error,
        )
    })?;
    receipt.cancelled_operations.try_reserve(operations).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve exact DDE operation cancellation receipt entries",
            error,
        )
    })?;
    receipt.cancelled_callbacks.try_reserve(host.pending_callbacks.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve exact DDE callback cancellation receipt entries",
            error,
        )
    })?;
    receipt.native_transfer_guards.try_reserve(host.pending_transfer_guards.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve exact DDE transfer guard receipt entries",
            error,
        )
    })?;
    Ok(())
}

pub(super) fn push_failure_once(receipt: &mut Win16DdeAbortReceipt, failure: Win16DdeCleanupFailure) {
    if let Some(current) = receipt.cleanup_failures.iter_mut().find(|current| {
        current.phase == failure.phase
            && current.frame == failure.frame
            && current.operation == failure.operation
            && current.instance == failure.instance
    }) {
        let was_unresolved = matches!(
            current.status,
            Win16DdeCleanupStatus::Retained | Win16DdeCleanupStatus::Unresolved
        );
        let now_resolved = matches!(
            failure.status,
            Win16DdeCleanupStatus::Released | Win16DdeCleanupStatus::RetriedAndReleased
        );
        if was_unresolved && now_resolved {
            current.status = Win16DdeCleanupStatus::RetriedAndReleased;
        }
    } else {
        receipt.cleanup_failures.push(failure);
    }
}
