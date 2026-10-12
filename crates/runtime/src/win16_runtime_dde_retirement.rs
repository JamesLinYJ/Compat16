//! Exact per-operation DDE retirement after native-owner quiescence.

use std::sync::Arc;

use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16DdeAbortReceipt,
    Win16DdeNativeTransferGuardReceipt, Win16DdeNativeTransferGuardSource,
    Win16DdeOperationCancellationStatus, Win16DdeOperationRetirement,
    Win16DdeOperationRetirementProof, Win16HostDdeDataTransferOutcome,
};

use super::{DdeDataTransferGuard, Win16DdeContinuation};
use crate::win16_dde::{Win16DdeRetiredGuestBlock, Win16DdeState};
use super::source_lifecycle::{Win16DdeNormalShutdown, Win16DdeSourceRetirementRecord};

pub(in crate::win16_runtime) fn prepare_dde_window_operation_retirement(
    dde: &mut Win16DdeState,
    continuation: &mut Win16DdeContinuation,
    receipt: &Win16DdeAbortReceipt,
    host: &mut impl RuntimeHost,
    retired_guest_blocks: &mut Vec<Win16DdeRetiredGuestBlock>,
) -> Win16DdeOperationRetirement {
    let operation = continuation.host_operation();
    let Some(operation) = operation else {
        return retained(None, None, invariant("DDE continuation has no native operation identity"));
    };

    if let Err(error) = continuation.capture_native_input_identity(dde)
        .and_then(|()| continuation.validate_source_record_identities())
    {
        return retained(Some(operation), None, error);
    }
    if continuation.data_transfer_guard.is_some_and(|guard|
        continuation.guest_instance() != Some(guard.owner))
    {
        return retained(Some(operation), None, invariant(
            "DDE terminal transfer changed its exact guest instance owner"));
    }
    // Follow-ups inherit previous normal sources. Each has its own immutable
    // native input, result, transfer settlement, and shutdown ACK journal.
    for index in 0..continuation.normal_source_retirements.len() {
        let entry = &mut continuation.normal_source_retirements[index];
        if entry.consumed {
            continue;
        }
        if let Err(error) = retire_normal_record(dde, entry, receipt, host, retired_guest_blocks) {
            if entry.proof.operation == operation {
                continuation.operation_retirement_proof = entry.shutdown.as_ref()
                    .map(|shutdown| shutdown.proof.clone());
            }
            return retained(Some(operation), continuation.operation_retirement_proof.clone(), error);
        }
        if entry.proof.operation == operation {
            let shutdown = entry.shutdown.as_ref().expect("normal terminal proof was acknowledged");
            continuation.operation_retirement_proof = Some(shutdown.proof.clone());
            continuation.operation_retirement_acknowledged = shutdown.acknowledged;
            continuation.transfer_guard_retired = entry.transfer_settled;
        }
    }

    if let Some(proof) = continuation.operation_retirement_proof.clone() {
        if !proof_matches_receipt(&proof, receipt)
            || proof.cancellation.operation != operation
            || continuation
                .started_failure()
                .is_some_and(|failure| !proof.matches_started_failure(failure))
        {
            return retained(
                Some(operation),
                Some(proof),
                invariant("cached DDE operation retirement proof changed its exact receipt identity"),
            );
        }
        if continuation.operation_retirement_acknowledged {
            return Win16DdeOperationRetirement::Released(proof);
        }
    } else {
        let proof = match exact_operation_proof(
            operation,
            continuation.native_input_instance.expect("captured original DDE input"),
            continuation.data_transfer_guard,
            receipt,
        ) {
            Ok(proof) => proof,
            Err(error) => return retained(Some(operation), None, error),
        };
        if continuation.started_failure().is_some_and(|failure| !proof.matches_started_failure(failure)) {
            return retained(Some(operation), Some(proof), invariant(
                "DDE terminal proof differs from its retained started failure"));
        }
        if let Err(error) = continuation.bind_host_owner_identity(
            proof.owner,
            proof.worker_generation,
        ) {
            return retained(Some(operation), Some(proof), error);
        }
        continuation.operation_retirement_proof = Some(proof);
    }

    let Some(proof) = continuation.operation_retirement_proof.clone() else {
        return retained(
            Some(operation),
            None,
            invariant("DDE operation proof disappeared before local retirement"),
        );
    };
    if !continuation.transfer_guard_retired {
        if let Some(guard) = continuation.data_transfer_guard {
            let Some(native_guard) = proof.transfer_guard.as_ref() else {
                return retained(
                    Some(operation),
                    Some(proof),
                    invariant("DDE transfer guard retirement lacks its exact native receipt"),
                );
            };
            if let Err(error) = retire_local_transfer_guard(
                dde,
                guard,
                native_guard,
                receipt,
                retired_guest_blocks,
            ) {
                return retained(Some(operation), Some(proof), error);
            }
        } else if proof.transfer_guard.is_some() {
            return retained(
                Some(operation),
                Some(proof),
                invariant("DDE native shutdown receipt has an unowned transfer guard"),
            );
        }
        continuation.transfer_guard_retired = true;
    }

    if let Err(error) = host.win16_dde_operation_retired(&proof, receipt) {
        return retained(Some(operation), Some(proof), error);
    }
    continuation.operation_retirement_acknowledged = true;
    Win16DdeOperationRetirement::Released(proof)
}

fn exact_operation_proof(
    operation: crate::Win16HostDdeOperation,
    native_input: Option<crate::Win16HostDdeInstance>,
    local_guard: Option<DdeDataTransferGuard>,
    receipt: &Win16DdeAbortReceipt,
) -> Result<Win16DdeOperationRetirementProof, RuntimeError> {
    if !receipt.is_quiesced() {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "DDE operation receipt is not quiesced",
        ));
    }
    let owner = receipt
        .owner
        .ok_or_else(|| invariant("quiesced DDE receipt omitted its exact owner"))?;
    let worker_generation = receipt
        .worker_generation
        .ok_or_else(|| invariant("quiesced DDE receipt omitted its worker generation"))?;
    let request_id = receipt
        .request_id
        .ok_or_else(|| invariant("quiesced DDE receipt omitted its shutdown request"))?;
    let native_owner = receipt
        .native_owner_receipt
        .ok_or_else(|| invariant("quiesced DDE receipt omitted native owner evidence"))?;
    if owner.0 == 0
        || worker_generation == 0
        || native_owner.owner != owner
        || native_owner.worker_generation != worker_generation
        || native_owner.request_id != request_id
        || request_id == 0
    {
        return Err(invariant(
            "DDE owner, worker generation, and shutdown request do not form one identity",
        ));
    }
    let mut cancellations = receipt
        .cancelled_operations
        .iter()
        .filter(|entry| entry.operation == operation);
    let cancellation = cancellations
        .next()
        .ok_or_else(|| invariant("DDE abort receipt omitted the exact operation cancellation"))?;
    if cancellations.next().is_some()
        || !matches!(
            cancellation.status,
            Win16DdeOperationCancellationStatus::CompletedDuringAbort
                | Win16DdeOperationCancellationStatus::CancelledByOwnerShutdown
                | Win16DdeOperationCancellationStatus::NativeCompleteError
                | Win16DdeOperationCancellationStatus::NativeCompleteReturned
        )
    {
        return Err(invariant(
            "DDE operation cancellation is duplicated or lacks terminal proof",
        ));
    }
    if cancellation.instance != native_input {
        return Err(invariant("DDE cancellation changed its captured original native input"));
    }

    let mut transfer_guards = receipt
        .native_transfer_guards
        .iter()
        .filter(|entry| entry.operation == operation);
    let transfer_guard = transfer_guards.next();
    if transfer_guards.next().is_some() {
        return Err(invariant("DDE operation has duplicate native transfer receipts"));
    }
    match (local_guard, transfer_guard) {
        (Some(local), Some(native)) if native.operation == operation && native_input == Some(native.instance)
            && local.host_data == native.data
            && native.source != Win16DdeNativeTransferGuardSource::Retained => {}
        (None, None) => {}
        _ => {
            return Err(invariant(
                "DDE operation and native transfer receipt changed their exact owner identity",
            ));
        }
    }
    let proof = Win16DdeOperationRetirementProof {
        owner,
        worker_generation,
        request_id,
        cancellation: cancellation.clone(),
        callback_receipts: receipt
            .cancelled_callbacks
            .iter()
            .filter(|entry| entry.parent_operation == Some(operation))
            .cloned()
            .collect(),
        transfer_guard: transfer_guard.cloned(),
    };
    if !proof_matches_receipt(&proof, receipt) {
        return Err(invariant("DDE operation retirement proof does not match its receipt"));
    }
    Ok(proof)
}

fn retire_normal_record(
    dde: &mut Win16DdeState,
    entry: &mut Win16DdeSourceRetirementRecord,
    receipt: &Win16DdeAbortReceipt,
    host: &mut impl RuntimeHost,
    retired_guest_blocks: &mut Vec<Win16DdeRetiredGuestBlock>,
) -> Result<(), RuntimeError> {
    let native_input = entry.native_input_instance.ok_or_else(|| invariant(
        "normal DDE terminal settlement lost its captured original native input"))?;
    let expected = exact_operation_proof(entry.proof.operation, native_input, entry.transfer_guard, receipt)?;
    if !entry.proof.has_valid_identity() || expected.owner != entry.proof.owner
        || expected.worker_generation != entry.proof.worker_generation
        || expected.cancellation.status != Win16DdeOperationCancellationStatus::NativeCompleteReturned
        || expected.cancellation.failure.is_some()
    {
        return Err(invariant("normal DDE source conflicts with its exact native completion receipt"));
    }
    super::completion::receipt::validate_transfer_receipt(&entry.request, entry.instance,
        entry.transfer_guard, entry.transaction_output, &entry.result)?;
    match (entry.result.data_transfer, expected.transfer_guard.as_ref()) {
        (None, None) => {}
        (Some(result), Some(native)) if result.token == native.data && native.failure.is_none()
            && (native.source == Win16DdeNativeTransferGuardSource::NativeCompletion(result.outcome)
                || (result.outcome == Win16HostDdeDataTransferOutcome::NotPassed
                    && native.source == Win16DdeNativeTransferGuardSource::PreflightRejected)) => {}
        _ => return Err(invariant("normal DDE transfer result changed in the native shutdown receipt")),
    }
    match &entry.shutdown {
        Some(shutdown) if shutdown.proof != expected => return Err(invariant(
            "normal DDE shutdown proof changed across an exact retry")),
        Some(shutdown) if shutdown.acknowledged => return Ok(()),
        Some(_) => {}
        None => {
            if !host.win16_dde_source_retirement(&entry.proof)? {
                return Err(invariant("normal DDE shutdown settlement has no exact source tombstone"));
            }
            entry.shutdown = Some(Win16DdeNormalShutdown {
                proof: expected.clone(), acknowledged: false,
            });
        }
    }
    if !entry.transfer_settled {
        if let Some(guard) = entry.transfer_guard {
            let native = expected.transfer_guard.as_ref().expect("validated exact transfer receipt");
            retire_local_transfer_guard(dde, guard, native, receipt, retired_guest_blocks)?;
        }
        entry.transfer_settled = true;
    }
    host.win16_dde_operation_retired(&expected, receipt)?;
    entry.shutdown.as_mut().expect("cached exact shutdown proof").acknowledged = true;
    Ok(())
}

fn retire_local_transfer_guard(
    dde: &mut Win16DdeState,
    guard: DdeDataTransferGuard,
    native: &Win16DdeNativeTransferGuardReceipt,
    receipt: &Win16DdeAbortReceipt,
    retired_guest_blocks: &mut Vec<Win16DdeRetiredGuestBlock>,
) -> Result<(), RuntimeError> {
    if native.source == Win16DdeNativeTransferGuardSource::InstanceUninitialized
        && native_instance_retirement_count(native.instance, receipt) != 1
    {
        return Err(invariant("DDE transfer has no unique exact-instance uninitialize receipt"));
    }
    super::transfer::settle_transfer_guard(dde, guard, native.source, retired_guest_blocks)
}

fn native_instance_retirement_count(
    instance: crate::Win16HostDdeInstance,
    receipt: &Win16DdeAbortReceipt,
) -> usize {
    receipt
        .native_instances
        .iter()
        .filter(|entry| {
            entry.instance == instance
                && matches!(
                    entry.status,
                    crate::Win16DdeCleanupStatus::Released
                        | crate::Win16DdeCleanupStatus::RetriedAndReleased
                )
        })
        .count()
}

fn proof_matches_receipt(
    proof: &Win16DdeOperationRetirementProof,
    receipt: &Win16DdeAbortReceipt,
) -> bool {
    proof.matches_receipt(receipt)
}

fn retained(
    operation: Option<crate::Win16HostDdeOperation>,
    proof: Option<Win16DdeOperationRetirementProof>,
    error: RuntimeError,
) -> Win16DdeOperationRetirement {
    Win16DdeOperationRetirement::Retained {
        operation,
        proof,
        cause: Arc::new(error),
    }
}

fn invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
