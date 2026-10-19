//! Completed native transfer evidence survives normal source retirement.

use super::*;
use runtime::{Win16HostDdeDataTransfer, Win16HostDdeDataTransferOutcome, Win16HostDdeValue};

const OPERATION: Win16HostDdeOperation = Win16HostDdeOperation(21);
const DATA: Win16HostDdeData = Win16HostDdeData(51);
const INSTANCE: Win16HostDdeInstance = Win16HostDdeInstance(31);

fn completed_result(outcome: Win16HostDdeDataTransferOutcome) -> Win16HostDdeResult {
    Win16HostDdeResult {
        value: Win16HostDdeValue::ClientTransaction {
            data: None,
            succeeded: outcome != Win16HostDdeDataTransferOutcome::NotPassed,
            entered_native: outcome != Win16HostDdeDataTransferOutcome::NotPassed,
        },
        dde_error: if outcome == Win16HostDdeDataTransferOutcome::NotPassed {
            compat_services::win16_dde::error::INVALIDPARAMETER
        } else {
            0
        },
        transaction_result: None,
        data_transfer: Some(Win16HostDdeDataTransfer {
            token: DATA,
            outcome,
        }),
    }
}

fn joined_receipt(host: &Win16DdeHost) -> Win16DdeAbortReceipt {
    Win16DdeAbortReceipt {
        owner: Some(host.owner),
        worker_generation: Some(host.worker_generation),
        request_id: Some(41),
        native_owner_receipt: Some(Win16DdeNativeOwnerShutdownReceipt {
            owner: host.owner,
            worker_generation: host.worker_generation,
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
        cancelled_operations: Vec::new(),
        native_instances: vec![Win16DdeNativeInstanceReceipt {
            instance: INSTANCE,
            status: Win16DdeCleanupStatus::Released,
            failure: None,
        }],
        native_replies: Vec::new(),
        native_transfer_guards: Vec::new(),
        cleanup_failures: Vec::new(),
    }
}

fn idle_host() -> Win16DdeHost {
    let (mut host, _) = Win16DdeHost::completed_operation_fixture(
        OPERATION, completed_result(Win16HostDdeDataTransferOutcome::NotPassed),
    );
    host.pending_operations.clear();
    host.pending_operation_instances.clear();
    host
}

#[test]
fn dde_shutdown_final_poll_publishes_queued_native_proof_after_worker_join() {
    let mut host = idle_host();
    let expected = joined_receipt(&host);
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    sender.send(WorkerShutdownReport {
        native_owner_receipt: expected.native_owner_receipt.unwrap(),
        native_instances: expected.native_instances.clone(),
        native_transfer_guards: Vec::new(), native_replies: Vec::new(),
        cleanup_failures: Vec::new(), terminal_error: None,
    }).unwrap();
    host.shutdown_receiver = Some(receiver);
    // No native worker or window: only a completed Rust thread and an owned
    // channel report. This deterministically exercises the final poll without
    // relying on a scheduler delay at the 250 ms deadline.
    let worker = thread::spawn(|| {});
    let deadline = Instant::now() + Duration::from_secs(5);
    while !worker.is_finished() {
        assert!(Instant::now() < deadline, "fixture thread did not finish");
        thread::yield_now();
    }
    host.worker = Some(worker);
    let mut receipt = expected.clone();
    receipt.native_owner_receipt = None;
    receipt.native_instances.clear();
    receipt.worker_status = Win16DdeAbortWorkerStatus::Running;
    receipt.owner_status = Win16DdeAbortOwnerStatus::Retained;
    assert!(!receipt.is_quiesced());
    assert!(host.poll_abort_completion(&mut receipt));
    assert!(host.worker.is_none());
    assert!(same_abort_receipt(&expected, &receipt));
    assert!(host.poll_abort_completion(&mut receipt));
    assert!(same_abort_receipt(&expected, &receipt));
    host.cache_abort_receipt_fixture(receipt.clone());
    host.verify_abort_receipt(&receipt).unwrap();
}

#[test]
fn dde_shutdown_final_poll_retains_missing_foreign_and_unresolved_proofs() {
    for case in 0..8 {
        let mut host = idle_host();
        let mut receipt = joined_receipt(&host);
        receipt.owner_status = Win16DdeAbortOwnerStatus::Active;
        match case {
            0 => receipt.native_owner_receipt = None,
            1 => receipt.worker_status = Win16DdeAbortWorkerStatus::Running,
            2 => receipt.native_owner_receipt.as_mut().unwrap().owner.0 += 1,
            3 => receipt.native_owner_receipt.as_mut().unwrap().worker_generation += 1,
            4 => receipt.native_owner_receipt.as_mut().unwrap().request_id += 1,
            5 => receipt.native_owner_receipt.as_mut().unwrap().all_native_callbacks_returned = false,
            6 => receipt.native_instances[0].status = Win16DdeCleanupStatus::Retained,
            _ => receipt.cleanup_failures.push(Win16DdeCleanupFailure {
                phase: Win16DdeAbortPhase::JoinWorker, frame: None, operation: None,
                instance: None, status: Win16DdeCleanupStatus::Unresolved,
                cause: Arc::new(RuntimeError::new(Kind::HostFailure, "unresolved fixture")),
            }),
        }
        assert!(!host.poll_abort_completion(&mut receipt), "case {case}");
        assert_eq!(receipt.owner_status, Win16DdeAbortOwnerStatus::Retained);
        assert!(!receipt.is_quiesced());
    }
}

#[test]
fn dde_shutdown_recovers_exact_completed_transfer_dispositions_and_ack() {
    for outcome in [
        Win16HostDdeDataTransferOutcome::NotPassed,
        Win16HostDdeDataTransferOutcome::Consumed,
        Win16HostDdeDataTransferOutcome::RetainedReadOnly,
        Win16HostDdeDataTransferOutcome::CopiedInputRetained,
    ] {
        let result = completed_result(outcome);
        let (mut host, _) = Win16DdeHost::completed_operation_with_transfer_fixture(
            OPERATION,
            result.clone(),
            Some((DATA, INSTANCE)),
        );
        assert!(host.pending_transfer_guards.is_empty());
        host.normal_source_retired_proof(OPERATION, &result)
            .unwrap();
        let mut receipt = joined_receipt(&host);
        reserve_receipt_for_pending_owner(&host, &mut receipt).unwrap();
        assert!(receipt.native_transfer_guards.capacity() >= 1);
        host.seed_pending_receipt(&mut receipt);
        assert!(receipt.is_quiesced());
        assert_eq!(receipt.native_transfer_guards.len(), 1);
        let guard = &receipt.native_transfer_guards[0];
        assert_eq!(guard.operation, OPERATION);
        assert_eq!(guard.data, DATA);
        assert_eq!(guard.instance, INSTANCE);
        assert_eq!(
            guard.source,
            if outcome == Win16HostDdeDataTransferOutcome::NotPassed {
                Win16DdeNativeTransferGuardSource::PreflightRejected
            } else {
                Win16DdeNativeTransferGuardSource::NativeCompletion(outcome)
            }
        );
        let original = receipt.clone();
        host.seed_pending_receipt(&mut receipt);
        assert!(same_abort_receipt(&original, &receipt));
        host.cache_abort_receipt_fixture(receipt.clone());
        let proof = runtime::Win16DdeOperationRetirementProof {
            owner: host.owner,
            worker_generation: host.worker_generation,
            request_id: 41,
            cancellation: receipt.cancelled_operations[0].clone(),
            callback_receipts: Vec::new(),
            transfer_guard: Some(receipt.native_transfer_guards[0].clone()),
        };
        let mut foreign = proof.clone();
        foreign.transfer_guard.as_mut().unwrap().data.0 += 1;
        assert!(host.operation_retired(&foreign, &receipt).is_err());
        assert!(host.pending_operation_instances.contains_key(&OPERATION));
        host.operation_retired(&proof, &receipt).unwrap();
        assert!(host.pending_operation_instances.is_empty());
    }
}

#[test]
fn dde_shutdown_rejects_missing_extra_wrong_or_contradictory_completed_transfer() {
    for case in 0..7 {
        let mut result = completed_result(Win16HostDdeDataTransferOutcome::Consumed);
        let mut input = Some((DATA, INSTANCE));
        match case {
            0 => result.data_transfer = None,
            1 => input = None,
            2 => result.data_transfer.as_mut().unwrap().token.0 += 1,
            3 => result.value = Win16HostDdeValue::Boolean(true),
            4 => {
                result.data_transfer.as_mut().unwrap().outcome =
                    Win16HostDdeDataTransferOutcome::NotPassed
            }
            5 => {
                result.value = Win16HostDdeValue::ClientTransaction {
                    data: None,
                    succeeded: false,
                    entered_native: false,
                }
            }
            _ => {
                result = completed_result(Win16HostDdeDataTransferOutcome::NotPassed);
                result.dde_error = 0;
            }
        }
        let (host, _) =
            Win16DdeHost::completed_operation_with_transfer_fixture(OPERATION, result, input);
        let mut receipt = joined_receipt(&host);
        reserve_receipt_for_pending_owner(&host, &mut receipt).unwrap();
        host.seed_pending_receipt(&mut receipt);
        assert!(
            !receipt.is_quiesced(),
            "malformed completed transfer case {case}"
        );
        assert!(receipt.native_transfer_guards.is_empty());
        assert_eq!(receipt.cleanup_failures.len(), 1);
        assert!(host.pending_operation_instances.contains_key(&OPERATION));
    }
}

#[test]
fn dde_shutdown_completed_transfer_retry_preserves_and_rejects_conflicting_receipt() {
    let (host, _) = Win16DdeHost::completed_operation_with_transfer_fixture(
        OPERATION,
        completed_result(Win16HostDdeDataTransferOutcome::Consumed),
        Some((DATA, INSTANCE)),
    );
    let mut receipt = joined_receipt(&host);
    reserve_receipt_for_pending_owner(&host, &mut receipt).unwrap();
    host.seed_pending_receipt(&mut receipt);
    let original = receipt.native_transfer_guards[0].clone();
    receipt.native_transfer_guards[0].source =
        Win16DdeNativeTransferGuardSource::InstanceUninitialized;
    host.seed_pending_receipt(&mut receipt);
    assert!(!receipt.is_quiesced());
    assert_eq!(receipt.native_transfer_guards.len(), 1);
    assert_eq!(
        receipt.native_transfer_guards[0].source,
        Win16DdeNativeTransferGuardSource::InstanceUninitialized
    );
    assert_ne!(receipt.native_transfer_guards[0].source, original.source);
    assert!(host.pending_operation_instances.contains_key(&OPERATION));
}

#[test]
fn dde_shutdown_retry_preserves_cancellation_before_native_entry() {
    let (host, _) = Win16DdeHost::completed_operation_with_transfer_fixture(
        OPERATION,
        completed_result(Win16HostDdeDataTransferOutcome::NotPassed),
        Some((DATA, INSTANCE)),
    );
    let mut receipt = joined_receipt(&host);
    receipt
        .cancelled_operations
        .push(Win16DdeOperationCancellation {
            operation: OPERATION,
            instance: Some(INSTANCE),
            status: Win16DdeOperationCancellationStatus::CancelledByOwnerShutdown,
            failure: None,
        });
    receipt
        .native_transfer_guards
        .push(Win16DdeNativeTransferGuardReceipt {
            operation: OPERATION,
            data: DATA,
            instance: INSTANCE,
            source: Win16DdeNativeTransferGuardSource::NotEntered,
            failure: None,
        });
    let original = receipt.clone();
    host.seed_pending_receipt(&mut receipt);
    assert!(receipt.is_quiesced());
    assert!(same_abort_receipt(&original, &receipt));
}
