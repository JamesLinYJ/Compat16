//! Capacity planning and stable failure reconciliation for DDE shutdown.

use super::*;
use runtime::Win16HostDdeValue;

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
    let transfer_guards = host.pending_transfer_guards.len()
        .checked_add(host.pending_operation_instances.values()
            .filter(|record| record.transfer_data.is_some()).count())
        .ok_or_else(|| RuntimeError::new(
            Kind::ResourceExhausted,
            "DDE completed transfer count overflowed while reserving shutdown evidence",
        ))?;
    receipt.native_transfer_guards.try_reserve(transfer_guards).map_err(|error| {
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

/// Recover the disposition already returned by DDEML, using the original
/// accepted input identity rather than the shutdown's global instance status.
pub(super) fn completed_transfer_receipt(
    operation: Win16HostDdeOperation,
    record: &PendingDdeOperationRecord,
) -> Result<Option<Win16DdeNativeTransferGuardReceipt>, RuntimeError> {
    let invalid = || RuntimeError::new(
        Kind::InternalInvariant,
        "DDE completed transfer does not match its exact original input and native result",
    );
    let result = record.completed_result.as_ref().ok_or_else(invalid)?;
    match (record.transfer_data, result.data_transfer.as_ref()) {
        (None, None) => Ok(None),
        (Some(data), Some(transfer)) if data == transfer.token => {
            let instance = record.instance.ok_or_else(invalid)?;
            if operation.0 == 0 || data.0 == 0 || instance.0 == 0 {
                return Err(invalid());
            }
            let source = match (&result.value, transfer.outcome) {
                (Win16HostDdeValue::ClientTransaction {
                    data: None, succeeded: false, entered_native: false,
                }, runtime::Win16HostDdeDataTransferOutcome::NotPassed)
                    if (0x4000..=0x4011).contains(&result.dde_error)
                        && result.transaction_result.is_none() => {
                    Win16DdeNativeTransferGuardSource::PreflightRejected
                }
                (Win16HostDdeValue::ClientTransaction { entered_native: true, .. },
                    outcome @ (runtime::Win16HostDdeDataTransferOutcome::Consumed
                        | runtime::Win16HostDdeDataTransferOutcome::RetainedReadOnly
                        | runtime::Win16HostDdeDataTransferOutcome::CopiedInputRetained)) => {
                    Win16DdeNativeTransferGuardSource::NativeCompletion(outcome)
                }
                _ => return Err(invalid()),
            };
            Ok(Some(Win16DdeNativeTransferGuardReceipt {
                operation, data, instance, source, failure: None,
            }))
        }
        _ => Err(invalid()),
    }
}

pub(super) fn seed_completed_transfer_receipt(
    operation: Win16HostDdeOperation,
    record: &PendingDdeOperationRecord,
    receipt: &mut Win16DdeAbortReceipt,
) -> Result<(), RuntimeError> {
    let expected = completed_transfer_receipt(operation, record)?;
    let mut matching = receipt.native_transfer_guards.iter()
        .filter(|entry| entry.operation == operation);
    match (expected, matching.next(), matching.next()) {
        (None, None, None) => Ok(()),
        (Some(expected), Some(actual), None) if same_transfer_guard(&expected, actual) => Ok(()),
        (Some(expected), None, None) => {
            receipt.native_transfer_guards.push(expected);
            Ok(())
        }
        _ => Err(RuntimeError::new(
            Kind::InternalInvariant,
            "DDE completed transfer conflicts with an existing exact shutdown disposition",
        )),
    }
}
