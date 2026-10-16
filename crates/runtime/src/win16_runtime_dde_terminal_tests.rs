//! Terminal reconciliation of retained normal DDE completion owners.

use super::super::super as runtime_state;
use super::*;

pub(super) fn install_terminal_receipts(runtime: &mut Runtime, receipt: Win16DdeAbortReceipt) {
    let state = runtime.win16.as_mut().unwrap();
    state.dde_abort_receipt = Some(receipt);
    state.window_teardown_state = runtime_state::WindowTeardownState::NativeQuiescent;
    state.window_abort_receipt = Some(Win16WindowAbortReceipt {
        worker_generation: GENERATION,
        request_id: 21,
        active_operations: Vec::new(),
        cancelled_callbacks: Vec::new(),
        cancelled_modals: Vec::new(),
        active_operation_stack_empty: true,
        callback_stack_empty: true,
        modal_scope_stack_empty: true,
        resources: Win16NativeWindowResourceSnapshot {
            windows: Vec::new(),
            menus: Vec::new(),
            classes: Vec::new(),
        },
        resource_retirement: Win16NativeResourceRetirement::Deferred,
    });
}

pub(super) fn terminal_retire(
    runtime: &mut Runtime,
    host: &mut InitializationHost,
) -> Result<(), RuntimeError> {
    let step = runtime
        .win16
        .as_mut()
        .unwrap()
        .retire_window_operations_for_teardown(
            &Win16TaskExecutionEnded::for_test(),
            &mut runtime.cpu,
            &mut runtime.dos,
            &mut runtime.memory,
            host,
        )?;
    assert_eq!(
        step,
        runtime_state::windows::WindowTerminalRetirementStep::DdeFrameRetired
    );
    Ok(())
}

#[test]
fn initialize_caller_return_failure_aborts_without_reprojection_or_checked_return_retry() {
    let mut runtime = fixture();
    write_instance(&mut runtime, 0);
    let mut host = InitializationHost::default();
    let pointer = output(&runtime);
    begin(&mut runtime, &mut host, pointer).unwrap();
    runtime
        .win16
        .as_mut()
        .unwrap()
        .window_operations
        .last_mut()
        .unwrap()
        .return_to
        .0 = 0;
    let original = drive(&mut runtime, &mut host).unwrap_err();
    assert_ne!(read_instance(&runtime), 0);
    assert!(host.consumed.is_empty());
    // A write after the failed caller restore exposes any accidental replay
    // of DdeInitialize projection during terminal cleanup.
    write_instance(&mut runtime, 0xfeed_beef);
    install_terminal_receipts(&mut runtime, shutdown_receipt(None));
    host.fail_retirement_before_once = true;
    assert_eq!(
        terminal_retire(&mut runtime, &mut host).unwrap_err().kind(),
        original.kind()
    );
    terminal_retire(&mut runtime, &mut host).unwrap();
    assert_eq!(read_instance(&runtime), 0xfeed_beef);
    assert_eq!(host.calls.len(), 1);
    assert_eq!(host.retired.len(), 1);
    assert!(runtime.win16.as_ref().unwrap().legacy_cpu_frames.is_empty());
}

#[test]
fn initialize_normal_readback_failure_accepts_exact_shutdown_ack_reply_loss_retry() {
    let mut runtime = fixture();
    write_instance(&mut runtime, 0);
    let mut host = InitializationHost {
        fail_source_readback_once: true,
        ..Default::default()
    };
    let pointer = output(&runtime);
    let returned = begin(&mut runtime, &mut host, pointer).unwrap();
    assert!(drive(&mut runtime, &mut host).is_err());
    assert_caller(&runtime, returned);
    write_instance(&mut runtime, 0xfeed_beef);
    install_terminal_receipts(&mut runtime, shutdown_receipt(None));
    host.fail_retirement_reply_once = true;
    assert!(terminal_retire(&mut runtime, &mut host).is_err());
    assert_eq!(host.retired.len(), 1);
    let readbacks = host.source_readbacks;
    let proof = dde_continuation(&runtime)
        .operation_retirement_proof()
        .cloned()
        .unwrap();
    assert_eq!(proof, host.retired[0]);
    assert!(
        runtime.win16.as_ref().unwrap().window_operations[0]
            .cpu_call_owner
            .is_some()
    );
    terminal_retire(&mut runtime, &mut host).unwrap();
    assert_eq!(
        host.source_readbacks, readbacks,
        "retry uses the exact cached terminal proof"
    );
    assert_eq!(host.retired.len(), 1);
    assert_eq!(host.calls.len(), 1);
    assert_eq!(read_instance(&runtime), 0xfeed_beef);
    assert!(host.consumed.is_empty());
    assert!(runtime.win16.as_ref().unwrap().legacy_cpu_frames.is_empty());
}

#[test]
fn projected_uninitialize_retains_original_native_input_after_guest_mapping_is_removed() {
    let mut runtime = fixture();
    write_instance(&mut runtime, 0);
    let mut initial_host = InitializationHost {
        proof: Arc::new(Win16DdeSourceRetiredProof {
            operation: Win16HostDdeOperation(OPERATION.0 - 1),
            owner: OWNER,
            worker_generation: GENERATION,
        }),
        ..Default::default()
    };
    prepare_dispatch(&mut runtime);
    dispatch(&mut runtime, &mut initial_host).unwrap();
    let guest = read_instance(&runtime);
    let mut host = InitializationHost {
        result: Some(Win16HostDdeResult {
            value: Win16HostDdeValue::Boolean(true),
            dde_error: 0,
            transaction_result: None,
            data_transfer: None,
        }),
        fail_source_readback_once: true,
        ..Default::default()
    };
    begin_request(
        &mut runtime,
        &mut host,
        Win16DdeRequest::Uninitialize { instance: guest },
    )
    .unwrap();
    assert!(drive(&mut runtime, &mut host).is_err());
    assert_eq!(
        runtime.win16.as_ref().unwrap().dde.host_instance(guest),
        None
    );
    install_terminal_receipts(&mut runtime, shutdown_receipt(Some(INSTANCE)));
    terminal_retire(&mut runtime, &mut host).unwrap();
    assert_eq!(host.retired[0].cancellation.instance, Some(INSTANCE));
    assert_eq!(host.calls.len(), 1);
    assert!(runtime.win16.as_ref().unwrap().legacy_cpu_frames.is_empty());
}

#[test]
fn normal_dde_terminal_source_leaves_unrelated_source_and_respects_post_ordering() {
    let mut runtime = fixture();
    write_instance(&mut runtime, 0);
    let mut host = InitializationHost::default();
    let pointer = output(&runtime);
    begin(&mut runtime, &mut host, pointer).unwrap();
    install_terminal_receipts(&mut runtime, shutdown_receipt(None));
    let post = Win16WindowTerminalSourceTop::User {
        operation: Win16HostWindowOperationId(500),
        kind: Win16NativeWindowOperationKind::PostGuestNotification,
        state: Win16NativeWindowOperationState::Returned,
        worker_generation: GENERATION,
    };
    host.terminal_source = Some(post);
    let step = runtime
        .win16
        .as_mut()
        .unwrap()
        .retire_window_operations_for_teardown(
            &Win16TaskExecutionEnded::for_test(),
            &mut runtime.cpu,
            &mut runtime.dos,
            &mut runtime.memory,
            &mut host,
        )
        .unwrap();
    assert_eq!(
        step,
        runtime_state::windows::WindowTerminalRetirementStep::BlockedBySource(post)
    );
    assert!(host.retired.is_empty());
    assert_eq!(host.source_readbacks, 0);
    let unrelated = Win16WindowTerminalSourceTop::Dde {
        operation: Win16HostDdeOperation(500),
    };
    host.terminal_source = Some(unrelated);
    terminal_retire(&mut runtime, &mut host).unwrap();
    assert_eq!(host.terminal_source, Some(unrelated));
    assert_eq!(read_instance(&runtime), 0);
    assert_eq!(host.retired.len(), 1);
}

#[test]
fn inherited_normal_sources_reconcile_each_exact_operation_and_skip_consumed_prefix() {
    for consumed_prefix in [false, true] {
        let mut runtime = fixture();
        write_instance(&mut runtime, 0);
        let mut host = InitializationHost::default();
        let pointer = output(&runtime);
        begin(&mut runtime, &mut host, pointer).unwrap();
        let next_proof = Win16DdeSourceRetiredProof {
            operation: Win16HostDdeOperation(OPERATION.0 + 1),
            owner: OWNER,
            worker_generation: GENERATION,
        };
        host.additional_proofs.push(next_proof.clone());
        let state = runtime.win16.as_mut().unwrap();
        let Some(WindowReturn::Dde(continuation)) = state
            .window_operations
            .last_mut()
            .unwrap()
            .continuation_mut()
        else {
            panic!("missing continuation");
        };
        if consumed_prefix {
            host.win16_dde_source_retirement_consumed(&host.proof.clone())
                .unwrap();
            continuation
                .mark_source_retirement_consumed(&host.proof)
                .unwrap();
        }
        continuation.clear_completed_phase_for_followup().unwrap();
        continuation.host_operation = None;
        continuation.request = Win16DdeRequest::GetData {
            data: 1,
            output: Win16DdeBuffer {
                far_pointer: 0,
                capacity: 0,
            },
            offset: 0,
        };
        continuation.callback_candidate = None;
        // Handle-only GetData has no explicit native instance argument. Its
        // guest resource owner intentionally remains present on the record.
        continuation
            .capture_native_input_identity(&state.dde)
            .unwrap();
        assert_eq!(continuation.native_input_instance, Some(None));
        continuation.reserve_source_retirement_record().unwrap();
        continuation
            .cache_normal_source_retirement(
                Arc::new(next_proof.clone()),
                Win16HostDdeResult {
                    value: Win16HostDdeValue::GetData {
                        bytes: Vec::new(),
                        copied: 8,
                    },
                    dde_error: 0,
                    transaction_result: None,
                    data_transfer: None,
                },
            )
            .unwrap();
        let mut receipt = shutdown_receipt(None);
        if consumed_prefix {
            receipt.cancelled_operations.clear();
        }
        receipt
            .cancelled_operations
            .push(Win16DdeOperationCancellation {
                operation: next_proof.operation,
                instance: None,
                status: Win16DdeOperationCancellationStatus::NativeCompleteReturned,
                failure: None,
            });
        install_terminal_receipts(&mut runtime, receipt);
        terminal_retire(&mut runtime, &mut host).unwrap();
        assert_eq!(host.retired.len(), if consumed_prefix { 1 } else { 2 });
        assert_eq!(host.consumed.len(), usize::from(consumed_prefix));
        assert_eq!(
            host.retired.last().unwrap().cancellation.operation,
            next_proof.operation
        );
        assert_eq!(host.calls.len(), 1);
        assert!(runtime.win16.as_ref().unwrap().legacy_cpu_frames.is_empty());
    }
}

#[test]
fn normal_terminal_receipt_rejects_foreign_and_duplicate_identity_without_ack() {
    for mismatch in 0..7 {
        let mut runtime = fixture();
        write_instance(&mut runtime, 0);
        let mut host = InitializationHost::default();
        let pointer = output(&runtime);
        begin(&mut runtime, &mut host, pointer).unwrap();
        let mut receipt = shutdown_receipt(None);
        match mismatch {
            0 => {
                receipt.owner = Some(Win16HostDdeOwner(OWNER.0 + 1));
                receipt.native_owner_receipt.as_mut().unwrap().owner = receipt.owner.unwrap();
            }
            1 => {
                receipt.worker_generation = Some(GENERATION + 1);
                receipt
                    .native_owner_receipt
                    .as_mut()
                    .unwrap()
                    .worker_generation = GENERATION + 1;
            }
            2 => receipt.cancelled_operations[0].operation = Win16HostDdeOperation(OPERATION.0 + 1),
            3 => receipt
                .cancelled_operations
                .push(receipt.cancelled_operations[0].clone()),
            4 => receipt.cancelled_operations[0].instance = Some(INSTANCE),
            5 => {
                receipt.cancelled_operations[0].status =
                    Win16DdeOperationCancellationStatus::CompletedDuringAbort
            }
            6 => receipt.worker_status = Win16DdeAbortWorkerStatus::Panicked,
            _ => unreachable!(),
        }
        install_terminal_receipts(&mut runtime, receipt);
        assert!(terminal_retire(&mut runtime, &mut host).is_err());
        assert!(host.retired.is_empty());
        assert!(host.consumed.is_empty());
        assert_eq!(runtime.win16.as_ref().unwrap().window_operations.len(), 1);
        assert_eq!(host.calls.len(), 1);
    }
}

#[test]
fn cached_normal_shutdown_proof_rejects_changed_request_on_retry() {
    let mut runtime = fixture();
    write_instance(&mut runtime, 0);
    let mut host = InitializationHost {
        fail_retirement_before_once: true,
        ..Default::default()
    };
    let pointer = output(&runtime);
    begin(&mut runtime, &mut host, pointer).unwrap();
    install_terminal_receipts(&mut runtime, shutdown_receipt(None));
    assert!(terminal_retire(&mut runtime, &mut host).is_err());
    let proof = dde_continuation(&runtime)
        .operation_retirement_proof()
        .cloned()
        .unwrap();
    let mut foreign = shutdown_receipt(None);
    foreign.request_id = Some(20);
    foreign.native_owner_receipt.as_mut().unwrap().request_id = 20;
    runtime.win16.as_mut().unwrap().dde_abort_receipt = Some(foreign);
    assert!(terminal_retire(&mut runtime, &mut host).is_err());
    assert_eq!(
        dde_continuation(&runtime).operation_retirement_proof(),
        Some(&proof)
    );
    assert!(host.retired.is_empty());
    runtime.win16.as_mut().unwrap().dde_abort_receipt = Some(shutdown_receipt(None));
    terminal_retire(&mut runtime, &mut host).unwrap();
    assert_eq!(host.retired, [proof]);
}

#[test]
fn normally_consumed_dde_frame_releases_cpu_without_fabricated_shutdown_cancellation() {
    let mut runtime = fixture();
    write_instance(&mut runtime, 0);
    let mut host = InitializationHost {
        fail_source_readback_once: true,
        ..Default::default()
    };
    let pointer = output(&runtime);
    begin(&mut runtime, &mut host, pointer).unwrap();
    assert!(drive(&mut runtime, &mut host).is_err());
    // Exercise the exact ownership state retained after normal source ACK and
    // before fallible CPU-owner release. No native operation remains to abort.
    let state = runtime.win16.as_mut().unwrap();
    let frame = state.window_operations.last_mut().unwrap();
    let Some(WindowReturn::Dde(continuation)) = frame.continuation_mut() else {
        panic!("missing continuation");
    };
    host.win16_dde_source_retirement_consumed(&host.proof.clone())
        .unwrap();
    continuation
        .mark_source_retirement_consumed(&host.proof)
        .unwrap();
    frame.source_retirement_consumed = true;
    let mut receipt = shutdown_receipt(None);
    receipt.cancelled_operations.clear();
    install_terminal_receipts(&mut runtime, receipt);
    terminal_retire(&mut runtime, &mut host).unwrap();
    assert!(host.retired.is_empty());
    assert_eq!(host.consumed.len(), 1);
    assert_eq!(host.source_readbacks, 1);
    assert!(runtime.win16.as_ref().unwrap().legacy_cpu_frames.is_empty());
}

#[test]
fn normal_transfer_journals_exact_guard_close_before_deferred_block_cleanup_retry() {
    let mut runtime = fixture();
    write_instance(&mut runtime, 0);
    let mut initial_host = InitializationHost {
        proof: Arc::new(Win16DdeSourceRetiredProof {
            operation: Win16HostDdeOperation(OPERATION.0 - 1),
            owner: OWNER,
            worker_generation: GENERATION,
        }),
        ..Default::default()
    };
    prepare_dispatch(&mut runtime);
    dispatch(&mut runtime, &mut initial_host).unwrap();
    let guest = read_instance(&runtime);
    let state = runtime.win16.as_mut().unwrap();
    let conversation = state
        .dde
        .add_conversation(guest, Win16HostDdeConversation(97))
        .unwrap();
    let input = Win16HostDdeData(98);
    let data = state.dde.add_created_data(guest, input, false).unwrap();
    let deferred = state
        .heap
        .alloc(
            &mut runtime.memory,
            guest_core::OwnerId(1),
            16,
            win16_abi::AllocationFlags::fixed(),
        )
        .unwrap();
    // Inject a real allocator lock-underflow at the deferred cleanup boundary.
    // Ownership settlement must be journaled before this fallible operation.
    state
        .dde_retired_guest_blocks
        .push(crate::win16_dde::Win16DdeRetiredGuestBlock::pending(
            deferred, true,
        ));
    let mut host = InitializationHost {
        result: Some(Win16HostDdeResult {
            value: Win16HostDdeValue::ClientTransaction {
                data: None,
                succeeded: true,
                entered_native: true,
            },
            dde_error: 0,
            transaction_result: None,
            data_transfer: Some(Win16HostDdeDataTransfer {
                token: input,
                outcome: Win16HostDdeDataTransferOutcome::Consumed,
            }),
        }),
        ..Default::default()
    };
    begin_request(
        &mut runtime,
        &mut host,
        Win16DdeRequest::ClientTransaction {
            data: win16_abi::Win16DdeTransactionData::DataHandle(data),
            conversation,
            item: 0,
            format: 1,
            transaction_type: 0x4090, // XTYP_POKE: 0x0090 | XCLASS_FLAGS
            timeout: 1000,
            result_output: 0,
        },
    )
    .unwrap();
    assert!(drive(&mut runtime, &mut host).is_err());
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.dde.pending_data_transfer_guard_count(), 0);
    assert_eq!(state.dde.host_data(data), None);
    assert_eq!(state.dde_retired_guest_blocks.len(), 1);
    assert_eq!(state.dde_retired_guest_blocks[0].identity, deferred);
    assert!(dde_continuation(&runtime).transfer_guard_retired);
    assert!(dde_continuation(&runtime).normal_source_retirements()[0].transfer_settled);
    assert!(host.consumed.is_empty());
    let state = runtime.win16.as_mut().unwrap();
    let Some(WindowReturn::Dde(continuation)) = state
        .window_operations
        .last_mut()
        .unwrap()
        .continuation_mut()
    else {
        panic!("missing continuation");
    };
    // A missing settlement journal cannot be replaced by source-consumption
    // flags, even when the underlying guard is no longer in the live map.
    continuation.normal_source_retirements[0].transfer_settled = false;
    assert!(consume_source_retirements(continuation, &mut host).is_err());
    assert!(host.consumed.is_empty());
    continuation.normal_source_retirements[0].consumed = true;
    assert!(!continuation.all_normal_sources_consumed());
    continuation.normal_source_retirements[0].consumed = false;
    continuation.normal_source_retirements[0].transfer_settled = true;
    state
        .heap
        .lock(deferred, &mut state.selectors, &runtime.memory)
        .unwrap();
    drive(&mut runtime, &mut host).unwrap();
    let state = runtime.win16.as_ref().unwrap();
    assert_eq!(state.dde.pending_data_transfer_guard_count(), 0);
    assert!(state.dde_retired_guest_blocks.is_empty());
    assert!(state.window_operations.is_empty());
    assert_eq!(host.calls.len(), 1);
    assert_eq!(host.consumed.len(), 1);
}

#[test]
fn duplicate_runtime_normal_records_reject_before_any_source_is_consumed() {
    let mut runtime = fixture();
    write_instance(&mut runtime, 0);
    let mut host = InitializationHost::default();
    let pointer = output(&runtime);
    begin(&mut runtime, &mut host, pointer).unwrap();
    let state = runtime.win16.as_mut().unwrap();
    let Some(WindowReturn::Dde(continuation)) = state
        .window_operations
        .last_mut()
        .unwrap()
        .continuation_mut()
    else {
        panic!("missing continuation");
    };
    let duplicate = continuation.normal_source_retirements[0].clone();
    continuation.normal_source_retirements.push(duplicate);
    assert!(consume_source_retirements(continuation, &mut host).is_err());
    assert_eq!(host.source_readbacks, 0);
    assert!(host.consumed.is_empty());
    install_terminal_receipts(&mut runtime, shutdown_receipt(None));
    assert!(terminal_retire(&mut runtime, &mut host).is_err());
    assert!(host.retired.is_empty());
    assert!(host.consumed.is_empty());
    assert_eq!(host.source_readbacks, 0);
    assert_eq!(runtime.win16.as_ref().unwrap().window_operations.len(), 1);
}
