//! Pure regression fixtures at the native Complete -> runtime carrier seam.

use super::*;
use runtime::{
    Win16DdeAbortOwnerStatus, Win16DdeAbortReceipt, Win16DdeAbortWorkerStatus,
    Win16DdeNativeOwnerShutdownReceipt, Win16DdeOperationCancellation,
    Win16DdeOperationCancellationStatus, Win16DdeOperationRequestPhase,
    Win16DdeOperationRetirementProof, Win16HostDdeInstance, Win16HostDdeResult, Win16HostDdeValue,
    Win16WindowResult,
};

const OPERATION: Win16HostDdeOperation = Win16HostDdeOperation(21);

fn result() -> Win16HostDdeResult {
    Win16HostDdeResult {
        value: Win16HostDdeValue::Instance(Some(Win16HostDdeInstance(31))),
        dde_error: 0,
        transaction_result: None,
        data_transfer: None,
    }
}

fn fixture() -> (Win16Windows, Win16HostDdeStep) {
    let (dde, step) = Win16DdeHost::completed_operation_fixture(OPERATION, result());
    (
        Win16Windows {
            worker: None,
            worker_start_error: None,
            pending: Vec::new(),
            dde_sources: DdeSourceLedger {
                pending: vec![PendingSource::Dde {
                    operation: OPERATION,
                }],
                ..DdeSourceLedger::default()
            },
            identity_source: Arc::new(AtomicU64::new(100)),
            dde: Some(dde),
            dde_start_error: None,
            aborted: false,
            terminal_abort: None,
            terminal_shutdown_retirement: None,
            terminal_acknowledgements: Vec::new(),
            source_retirements: Vec::new(),
            classic_dde_sources: Vec::new(),
            native_drop_retirements: super::super::NativeDropRetirementQueue::shared(),
        },
        step,
    )
}

#[test]
fn dde_completion_immediate_result_retires_exact_source_and_replays_tombstone() {
    let (mut host, native_step) = fixture();
    let step = host.dde_window_step(OPERATION, native_step).unwrap();
    let Win16WindowStep::DdeSourceRetired {
        proof,
        result: completed,
    } = step
    else {
        panic!("immediate native completion must have a DDE-owned source proof");
    };
    let Win16WindowStep::Complete(Win16WindowResult::Dde(completed)) = *completed else {
        panic!("DDE source proof must retain the exact native completion");
    };
    assert_eq!(completed, result());
    assert_eq!(proof.operation, OPERATION);
    assert!(host.dde_sources.pending.is_empty());
    assert_eq!(host.dde_sources.retired_operations.len(), 1);
    assert!(host.dde_source_retirement_inner(&proof).unwrap());
    assert_eq!(
        host.dde
            .as_ref()
            .unwrap()
            .normal_completion_result(OPERATION),
        Some(result())
    );

    // Neither replay resubmits or requires an already-popped live source.
    let replay = host
        .dde_window_step(OPERATION, Win16HostDdeStep::Complete(result()))
        .unwrap();
    let Win16WindowStep::DdeSourceRetired {
        proof: replay_proof,
        ..
    } = replay
    else {
        panic!("native result replay must preserve its exact tombstone");
    };
    assert!(Arc::ptr_eq(&proof, &replay_proof));
    host.dde_window_step(
        OPERATION,
        Win16HostDdeStep::SourceRetired {
            proof: Arc::clone(&proof),
            result: result(),
        },
    )
    .unwrap();
    assert_eq!(host.dde_sources.retired_operations.len(), 1);

    let mut foreign = (*proof).clone();
    foreign.worker_generation += 1;
    assert!(
        host.dde_window_step(
            OPERATION,
            Win16HostDdeStep::SourceRetired {
                proof: Arc::new(foreign),
                result: result(),
            }
        )
        .is_err()
    );
    assert_eq!(host.dde_sources.retired_operations.len(), 1);
    host.dde_sources.pending.push(PendingSource::Dde {
        operation: OPERATION,
    });
    assert!(
        host.dde_window_step(
            OPERATION,
            Win16HostDdeStep::SourceRetired {
                proof: Arc::clone(&proof),
                result: result(),
            }
        )
        .is_err()
    );
    assert_eq!(
        host.dde_sources.pending.pop(),
        Some(PendingSource::Dde {
            operation: OPERATION
        })
    );
    host.consume_dde_source_retirement_inner(&proof).unwrap();
    assert!(host.dde_sources.retired_operations.is_empty());
    assert!(
        host.dde
            .as_ref()
            .unwrap()
            .normal_completion_result(OPERATION)
            .is_none()
    );
    assert!(host.consume_dde_source_retirement_inner(&proof).is_err());
}

#[test]
fn dde_completion_live_transfer_guard_blocks_retirement_without_dropping_owner() {
    let (mut host, step) = fixture();
    host.dde
        .as_mut()
        .unwrap()
        .retain_transfer_guard_fixture(OPERATION);
    let Win16WindowStep::DdeStartedFailure(failure) =
        host.dde_window_step(OPERATION, step).unwrap()
    else {
        panic!("a retained native transfer guard must block source retirement");
    };
    assert_eq!(failure.operation, OPERATION);
    assert_eq!(
        failure.request_phase,
        Win16DdeOperationRequestPhase::NativeCompleteReturned
    );
    assert_eq!(
        host.dde_sources.pending,
        [PendingSource::Dde {
            operation: OPERATION
        }]
    );
    assert!(host.dde_sources.retired_operations.is_empty());
    assert_eq!(
        host.dde
            .as_ref()
            .unwrap()
            .normal_completion_result(OPERATION),
        Some(result())
    );
    let proof = runtime::Win16DdeSourceRetiredProof {
        operation: OPERATION,
        owner: failure.owner,
        worker_generation: failure.worker_generation,
    };
    assert!(!host.dde_source_retirement_inner(&proof).unwrap());
    assert!(host.consume_dde_source_retirement_inner(&proof).is_err());
    assert_eq!(host.dde_sources.pending.len(), 1);
}

#[test]
fn dde_completion_retirement_failure_keeps_first_owner_until_exact_shutdown_ack() {
    let (mut host, _) = fixture();
    let mut wrong_result = result();
    wrong_result.dde_error = 1;
    let Win16WindowStep::DdeStartedFailure(failure) = host
        .dde_window_step(OPERATION, Win16HostDdeStep::Complete(wrong_result.clone()))
        .unwrap()
    else {
        panic!("a failure after native Complete must retain the accepted operation");
    };
    assert_eq!(failure.operation, OPERATION);
    assert_eq!(
        failure.request_phase,
        Win16DdeOperationRequestPhase::NativeCompleteReturned
    );
    assert_eq!(
        host.dde_sources.pending,
        [PendingSource::Dde {
            operation: OPERATION
        }]
    );
    assert!(host.dde_sources.retired_operations.is_empty());
    assert_eq!(
        host.dde
            .as_ref()
            .unwrap()
            .normal_completion_result(OPERATION),
        Some(result())
    );
    let Win16WindowStep::DdeStartedFailure(replayed) = host
        .dde_window_step(OPERATION, Win16HostDdeStep::Complete(wrong_result))
        .unwrap()
    else {
        panic!("the first accepted failure must remain owned")
    };
    assert!(Arc::ptr_eq(&failure, &replayed));

    let cancellation = Win16DdeOperationCancellation {
        operation: OPERATION,
        instance: None,
        status: Win16DdeOperationCancellationStatus::NativeCompleteReturned,
        failure: None,
    };
    let receipt = Win16DdeAbortReceipt {
        owner: Some(failure.owner),
        worker_generation: Some(failure.worker_generation),
        request_id: Some(41),
        native_owner_receipt: Some(Win16DdeNativeOwnerShutdownReceipt {
            owner: failure.owner,
            worker_generation: failure.worker_generation,
            request_id: 41,
            all_native_callbacks_returned: true,
            all_active_operations_returned: true,
            all_native_replies_released_or_transferred: true,
            all_native_transfer_guards_retired: true,
            all_native_instances_uninitialized: true,
            control_window_destroyed: true,
        }),
        owner_status: Win16DdeAbortOwnerStatus::Quiesced,
        worker_status: Win16DdeAbortWorkerStatus::Joined,
        cancelled_callbacks: Vec::new(),
        cancelled_operations: vec![cancellation.clone()],
        native_instances: vec![runtime::Win16DdeNativeInstanceReceipt {
            instance: Win16HostDdeInstance(31),
            status: runtime::Win16DdeCleanupStatus::Released,
            failure: None,
        }],
        native_replies: Vec::new(),
        native_transfer_guards: Vec::new(),
        cleanup_failures: Vec::new(),
    };
    let proof = Win16DdeOperationRetirementProof {
        owner: failure.owner,
        worker_generation: failure.worker_generation,
        request_id: 41,
        cancellation,
        callback_receipts: Vec::new(),
        transfer_guard: None,
    };
    assert!(proof.matches_started_failure(&failure));
    host.dde
        .as_mut()
        .unwrap()
        .cache_abort_receipt_fixture(receipt.clone());
    let mut foreign = proof.clone();
    foreign.cancellation.operation.0 += 1;
    assert!(
        host.dde_operation_retired_inner(&foreign, &receipt)
            .is_err()
    );
    assert_eq!(host.dde_sources.pending.len(), 1);
    host.dde_operation_retired_inner(&proof, &receipt).unwrap();
    assert!(host.dde_sources.pending.is_empty());
    assert!(
        host.dde
            .as_ref()
            .unwrap()
            .normal_completion_result(OPERATION)
            .is_none()
    );
    host.dde_operation_retired_inner(&proof, &receipt).unwrap();
    host.dde_runtime_resources_retired_inner(&receipt).unwrap();
    assert!(host.dde_sources.retired_operations.is_empty());
}
