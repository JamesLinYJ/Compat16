//! Exact per-operation DDE retirement after native-owner quiescence.

use std::sync::Arc;

use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16DdeAbortReceipt,
    Win16DdeNativeTransferGuardReceipt, Win16DdeNativeTransferGuardSource,
    Win16DdeOperationCancellationStatus, Win16DdeOperationRetirement,
    Win16DdeOperationRetirementProof, Win16HostDdeDataTransferOutcome,
};

use super::{DdeDataTransferGuard, Win16DdeContinuation};
use crate::win16_dde::{Win16DdeDataOrigin, Win16DdeRetiredGuestBlock, Win16DdeState};

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
        let proof = match exact_operation_proof(continuation, receipt, dde) {
            Ok(proof) => proof,
            Err(error) => return retained(Some(operation), None, error),
        };
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
    continuation: &Win16DdeContinuation,
    receipt: &Win16DdeAbortReceipt,
    dde: &Win16DdeState,
) -> Result<Win16DdeOperationRetirementProof, RuntimeError> {
    let operation = continuation
        .host_operation()
        .ok_or_else(|| invariant("DDE continuation has no native operation identity"))?;
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
    // Initialize's staged guest instance is an output owner, not the native
    // instance supplied to this operation. Match the original input even if
    // initialization has not yet projected its new instance into guest state.
    if let win16_abi::Win16DdeRequest::Initialize { initial_instance, callback, .. }
        = continuation.request
    {
        let candidate = continuation.callback_candidate.ok_or_else(|| {
            invariant("DDE initialization retirement lost its exact staged callback owner")
        })?;
        if continuation.guest_instance() != Some(candidate.guest_instance)
            || candidate.reinitializing != (initial_instance != 0)
            || (initial_instance != 0 && candidate.guest_instance != initial_instance)
            || candidate.callback != callback
            || dde.instance_for_route(candidate.route) != Some(candidate.guest_instance)
            || dde.callback_for_route(candidate.route) != Some(callback)
        {
            return Err(invariant(
                "DDE initialization retirement changed its staged callback or input owner",
            ));
        }
    }
    match continuation.native_input_guest_instance() {
        Some(guest_instance) => {
            let expected_instance = dde.host_instance(guest_instance).ok_or_else(|| {
                invariant("DDE continuation guest instance lost its exact host identity")
            })?;
            if cancellation.instance != Some(expected_instance) {
                return Err(invariant(
                    "DDE operation cancellation changed its exact host instance",
                ));
            }
        }
        None if cancellation.instance.is_some() => {
            return Err(invariant(
                "DDE operation receipt names an instance absent from its continuation",
            ));
        }
        None => {}
    }

    let mut transfer_guards = receipt
        .native_transfer_guards
        .iter()
        .filter(|entry| entry.operation == operation);
    let transfer_guard = transfer_guards.next();
    if transfer_guards.next().is_some() {
        return Err(invariant("DDE operation has duplicate native transfer receipts"));
    }
    match (continuation.data_transfer_guard, transfer_guard) {
        (Some(local), Some(native)) if transfer_guard_matches(local, native, continuation, dde) => {}
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
    if !proof_matches_receipt(&proof, receipt)
        || continuation
            .started_failure()
            .is_some_and(|failure| !proof.matches_started_failure(failure))
    {
        return Err(invariant("DDE operation retirement proof does not match its receipt"));
    }
    Ok(proof)
}

fn transfer_guard_matches(
    local: DdeDataTransferGuard,
    native: &Win16DdeNativeTransferGuardReceipt,
    continuation: &Win16DdeContinuation,
    dde: &Win16DdeState,
) -> bool {
    continuation.host_operation() == Some(native.operation)
        && continuation.guest_instance() == Some(local.owner)
        && dde.host_instance(local.owner) == Some(native.instance)
        && local.host_data == native.data
        && native.source != Win16DdeNativeTransferGuardSource::Retained
}

fn retire_local_transfer_guard(
    dde: &mut Win16DdeState,
    guard: DdeDataTransferGuard,
    native: &Win16DdeNativeTransferGuardReceipt,
    receipt: &Win16DdeAbortReceipt,
    retired_guest_blocks: &mut Vec<Win16DdeRetiredGuestBlock>,
) -> Result<(), RuntimeError> {
    if dde.data_transfer_guard_matches(
        guard.guard_id,
        guard.guest_data,
        guard.host_data,
        guard.owner,
        guard.origin,
    ) != Some(true)
    {
        if native.source != Win16DdeNativeTransferGuardSource::InstanceUninitialized {
            return Err(invariant(
                "DDE operation lost its exact local transfer source before retirement",
            ));
        }
    }
    let owner_uninitialized = native.source
        == Win16DdeNativeTransferGuardSource::InstanceUninitialized;
    let (previously_transferred, guest_free_seen, instance_uninitialized, _begun) = dde
        .data_transfer_guard_retirement_state(
            guard.guard_id,
            guard.guest_data,
            guard.host_data,
            guard.owner,
            guard.origin,
        )
        .ok_or_else(|| invariant("DDE local transfer guard lost its exact retirement evidence"))?;
    if previously_transferred != guard.previously_transferred {
        return Err(invariant("DDE transfer guard changed its saved prior state"));
    }
    if owner_uninitialized {
        let matching_instances = native_instance_retirement_count(native.instance, receipt);
        if matching_instances != 1 {
            return Err(invariant(
                "DDE transfer guard has no unique successful exact-instance uninitialize proof",
            ));
        }
        dde.mark_transfer_guard_instance_uninitialized(
            guard.guard_id,
            guard.guest_data,
            guard.host_data,
            guard.owner,
            guard.origin,
        )
        .ok_or_else(|| invariant("DDE uninitialize proof changed its local transfer guard"))?;
    }

    let transfer_outcome = match native.source {
        Win16DdeNativeTransferGuardSource::NotEntered
        | Win16DdeNativeTransferGuardSource::PreflightRejected => {
            dde.restore_data_transfer(
                guard.guard_id,
                guard.guest_data,
                guard.host_data,
                guard.owner,
                guard.origin,
            )
            .ok_or_else(|| invariant("DDE pre-entry receipt could not restore its exact token"))?;
            None
        }
        Win16DdeNativeTransferGuardSource::NativeCompletion(outcome) => {
            if outcome == Win16HostDdeDataTransferOutcome::NotPassed {
                dde.restore_data_transfer(
                    guard.guard_id,
                    guard.guest_data,
                    guard.host_data,
                    guard.owner,
                    guard.origin,
                )
                .ok_or_else(|| invariant("DDE NotPassed receipt could not restore its exact token"))?;
            }
            if outcome == Win16HostDdeDataTransferOutcome::Consumed {
                retired_guest_blocks.try_reserve(1).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve deferred AccessData block retirement before consuming DDE token",
                        error,
                    )
                })?;
            }
            Some(outcome)
        }
        Win16DdeNativeTransferGuardSource::InstanceUninitialized => None,
        Win16DdeNativeTransferGuardSource::Retained => {
            return Err(native.failure.as_ref().map_or_else(
                || RuntimeError::new(Kind::HostFailure, "DDE native transfer guard remains retained"),
                |cause| RuntimeError::with_source(
                    cause.kind(),
                    "DDE native transfer guard remains retained",
                    Arc::clone(cause),
                ),
            ));
        }
    };

    if !guest_free_seen && !instance_uninitialized {
        match transfer_outcome {
            Some(Win16HostDdeDataTransferOutcome::Consumed) => {
                if !matches!(
                    guard.origin,
                    Win16DdeDataOrigin::Created {
                        retain_after_transfer: false
                    }
                ) || !guard.transfer_marked
                {
                    return Err(invariant("DDE Consumed receipt conflicts with its source origin"));
                }
                let removed = dde.consume_data_transfer(guard.guest_data).map_err(|_| {
                    invariant("DDE Consumed receipt contradicted the guest data ledger")
                })?;
                if let Some(block) = removed.and_then(|data| data.access_block) {
                    retired_guest_blocks.push(Win16DdeRetiredGuestBlock::pending(
                        block.identity,
                        true,
                    ));
                }
            }
            Some(Win16HostDdeDataTransferOutcome::RetainedReadOnly) => {
                if !matches!(
                    guard.origin,
                    Win16DdeDataOrigin::Created {
                        retain_after_transfer: true
                    }
                ) || !guard.transfer_marked
                    || dde.data_transfer_state(guard.guest_data) != Some(true)
                    || dde.data_is_writable(guard.guest_data) != Some(false)
                {
                    return Err(invariant("DDE APPOWNED transfer receipt changed its read-only source"));
                }
            }
            Some(Win16HostDdeDataTransferOutcome::CopiedInputRetained) => {
                if !matches!(
                    guard.origin,
                    Win16DdeDataOrigin::CallbackBorrowed | Win16DdeDataOrigin::ClientResult
                ) || guard.transfer_marked
                    || dde.data_transfer_state(guard.guest_data)
                        != Some(guard.previously_transferred)
                {
                    return Err(invariant("DDE copied-input receipt changed its guest source"));
                }
            }
            Some(Win16HostDdeDataTransferOutcome::NotPassed) | None => {}
        }
    }
    let (actual_previously_transferred, actual_guest_free_seen, actual_instance_uninitialized) = dde
        .take_guest_free_evidence(
            guard.guard_id,
            guard.guest_data,
            guard.host_data,
            guard.owner,
            guard.origin,
        )
        .ok_or_else(|| invariant("DDE local transfer guard disappeared before retirement"))?;
    if actual_previously_transferred != previously_transferred
        || actual_guest_free_seen != guest_free_seen
        || actual_instance_uninitialized != instance_uninitialized
    {
        return Err(invariant("DDE transfer retirement evidence changed before its exact close"));
    }
    Ok(())
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
