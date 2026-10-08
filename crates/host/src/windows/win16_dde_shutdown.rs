//! Typed DDE shutdown receipts and bounded owner-thread polling.

use std::thread;
use std::time::{Duration, Instant};

use super::*;

#[path = "win16_dde_shutdown_events.rs"]
mod events;
#[path = "win16_dde_shutdown_receipts.rs"]
mod receipts;
use receipts::{push_failure_once, reserve_receipt_for_pending_owner};

const ABORT_POLL_WINDOW: Duration = Duration::from_millis(250);

impl Win16DdeHost {
    /// Request native callback cancellation, then retain every unresolved
    /// owner until the worker supplies exact release and join evidence.
    pub fn abort(&mut self) -> Win16DdeAbortReceipt {
        if let Some(receipt) = self.abort_receipt.as_ref()
            && receipt.is_quiesced()
        {
            return receipt.clone();
        }
        let mut receipt = self.abort_receipt.take().unwrap_or_else(|| {
            Win16DdeAbortReceipt {
                owner: Some(self.owner),
                worker_generation: Some(self.worker_generation),
                request_id: self.abort_request_id,
                native_owner_receipt: None,
                owner_status: Win16DdeAbortOwnerStatus::Active,
                worker_status: Win16DdeAbortWorkerStatus::Running,
                cancelled_callbacks: Vec::new(),
                cancelled_operations: Vec::new(),
                native_instances: Vec::new(),
                native_replies: Vec::new(),
                native_transfer_guards: Vec::new(),
                cleanup_failures: Vec::new(),
            }
        });
        receipt.owner = Some(self.owner);
        receipt.owner_status = Win16DdeAbortOwnerStatus::Active;
        if let Err(error) = reserve_receipt_for_pending_owner(self, &mut receipt) {
            record_failure(
                &mut receipt,
                Win16DdeAbortPhase::ReconcileRuntimeLedger,
                None,
                None,
                None,
                Win16DdeCleanupStatus::Retained,
                error,
            );
            receipt.owner_status = Win16DdeAbortOwnerStatus::Retained;
            self.abort_receipt = Some(receipt.clone());
            return receipt;
        }
        self.seed_pending_receipt(&mut receipt);

        let request_id = match self.abort_request_id {
            Some(request_id) => request_id,
            None => match allocate_id(&self.identity_source) {
                Ok(request_id) => {
                    self.abort_request_id = Some(request_id);
                    request_id
                }
                Err(error) => {
                    record_failure(
                        &mut receipt,
                        Win16DdeAbortPhase::StartOwner,
                        None,
                        None,
                        None,
                        Win16DdeCleanupStatus::Unresolved,
                        error,
                    );
                    receipt.owner_status = Win16DdeAbortOwnerStatus::Retained;
                    self.abort_receipt = Some(receipt.clone());
                    return receipt;
                }
            },
        };
        receipt.request_id = Some(request_id);

        self.cancel_pending_callbacks(&mut receipt);
        if !self.shutdown_requested {
            self.shutdown_requested = true;
            if let Err(error) = self.command_sender.send(WorkerCommand::Shutdown { request_id }) {
                record_failure(
                    &mut receipt,
                    Win16DdeAbortPhase::ReceiveReceipt,
                    None,
                    None,
                    None,
                    Win16DdeCleanupStatus::Unresolved,
                    disconnected("send the exact DDE owner shutdown request"),
                );
                let _ = error;
            }
        }
        if let Err(error) = self.wake_worker() {
            record_failure(
                &mut receipt,
                Win16DdeAbortPhase::ReceiveReceipt,
                None,
                None,
                None,
                Win16DdeCleanupStatus::Retained,
                error,
            );
        }

        let deadline = Instant::now() + ABORT_POLL_WINDOW;
        loop {
            self.poll_abort_events(&mut receipt);
            self.poll_shutdown_report(&mut receipt);
            self.join_completed_worker(&mut receipt);
            if receipt.quiescence_evidence_ready() {
                receipt.owner_status = Win16DdeAbortOwnerStatus::Quiesced;
                if receipt.is_quiesced() {
                    self.abort_receipt = Some(receipt.clone());
                    return receipt;
                }
            }
            if Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }

        self.poll_abort_events(&mut receipt);
        self.poll_shutdown_report(&mut receipt);
        self.join_completed_worker(&mut receipt);
        receipt.owner_status = Win16DdeAbortOwnerStatus::Retained;
        self.abort_receipt = Some(receipt.clone());
        receipt
    }

    pub fn shutdown(&mut self) -> Result<(), RuntimeError> {
        let receipt = self.abort();
        if receipt.is_quiesced() {
            Ok(())
        } else {
            Err(receipt.as_error())
        }
    }

    pub fn verify_runtime_retirement(&self, receipt: &Win16DdeAbortReceipt) -> Result<(), RuntimeError> {
        self.verify_abort_receipt(receipt)?;
        if self.worker.is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE runtime retirement does not match the joined owner's exact cached receipt",
            ));
        }
        if !self.pending_callbacks.is_empty()
            || !self.pending_operations.is_empty()
            || !self.pending_operation_instances.is_empty()
            || !self.pending_transfer_guards.is_empty()
        {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "DDE runtime retirement still has native callback or operation tombstones",
            ));
        }
        Ok(())
    }

    pub fn verify_abort_receipt(&self, receipt: &Win16DdeAbortReceipt) -> Result<(), RuntimeError> {
        let exact = self.abort_receipt.as_ref().is_some_and(|cached| {
            cached.is_quiesced()
                && receipt.is_quiesced()
                && same_abort_receipt(cached, receipt)
        });
        if !exact || self.worker.is_some() {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE operation receipt does not match the joined owner's exact cached abort receipt",
            ));
        }
        Ok(())
    }

    /// Consume one operation source only after its exact native shutdown and
    /// transfer-guard identities have been acknowledged by the runtime.
    pub fn operation_retired(
        &mut self,
        proof: &runtime::Win16DdeOperationRetirementProof,
        receipt: &Win16DdeAbortReceipt,
    ) -> Result<(), RuntimeError> {
        self.verify_abort_receipt(receipt)?;
        let operation = proof.cancellation.operation;
        if proof.owner != self.owner
            || proof.request_id == 0
            || receipt.owner != Some(proof.owner)
            || receipt.request_id != Some(proof.request_id)
            || !proof.matches_receipt(receipt)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE operation retirement proof changed its owner, request, or exact cancellation record",
            ));
        }
        let mut matching_operations = receipt
            .cancelled_operations
            .iter()
            .filter(|entry| entry.operation == operation);
        let Some(actual_operation) = matching_operations.next() else {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE operation retirement proof names no exact cancellation record",
            ));
        };
        if matching_operations.next().is_some()
            || !same_operation_cancellation(actual_operation, &proof.cancellation)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE operation retirement proof changed or duplicated its exact cancellation record",
            ));
        }
        let matching_guards: Vec<_> = receipt
            .native_transfer_guards
            .iter()
            .filter(|entry| entry.operation == operation)
            .collect();
        match (matching_guards.as_slice(), proof.transfer_guard.as_ref()) {
            ([], None) => {}
            ([actual], Some(expected)) if same_transfer_guard(actual, expected) => {}
            _ => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "DDE operation retirement proof omitted or changed its exact transfer guard receipt",
                ));
            }
        }
        let operation_record = self.pending_operation_instances.get(&operation).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "DDE operation retirement does not name a retained host operation record",
            )
        })?;
        if operation_record.instance != proof.cancellation.instance {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE operation retirement changed its exact host instance identity",
            ));
        }
        let operation_phase_matches = match proof.cancellation.status {
            Win16DdeOperationCancellationStatus::NativeCompleteError => {
                operation_record.request_phase
                    == Some(runtime::Win16DdeOperationRequestPhase::NativeCompleteError)
                    && operation_record.completed_result.is_none()
                    && operation_record.failure.is_some()
            }
            Win16DdeOperationCancellationStatus::NativeCompleteReturned
            | Win16DdeOperationCancellationStatus::CompletedDuringAbort => {
                operation_record.request_phase
                    == Some(runtime::Win16DdeOperationRequestPhase::NativeCompleteReturned)
                    && operation_record.completed_result.is_some()
                    && operation_record.failure.is_none()
            }
            Win16DdeOperationCancellationStatus::CancelledByOwnerShutdown => {
                match operation_record.request_phase {
                    Some(runtime::Win16DdeOperationRequestPhase::NativeCompleteError) => {
                        operation_record.failure.is_some()
                            && operation_record.completed_result.is_none()
                    }
                    Some(runtime::Win16DdeOperationRequestPhase::NativeCompleteReturned) => {
                        operation_record.failure.is_none()
                            && operation_record.completed_result.is_some()
                    }
                    Some(runtime::Win16DdeOperationRequestPhase::SubmittedPending) | None => false,
                }
            }
            Win16DdeOperationCancellationStatus::Requested
            | Win16DdeOperationCancellationStatus::Retained => false,
        };
        if !operation_phase_matches
            || self.pending_operations.contains(&operation)
            || self.pending_transfer_guards.contains_key(&operation)
            || !same_optional_error(&operation_record.failure, &proof.cancellation.failure)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE operation retirement is not backed by its exact terminal owner record",
            ));
        }
        if self.operation_has_pending_callback(operation) {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "DDE operation source cannot retire while an exact callback frame remains live",
            ));
        }
        self.pending_operation_instances.remove(&operation);
        Ok(())
    }

    pub fn callback_retirement_is_pending(
        &self,
        frame: Win16HostDdeCallbackFrame,
        parent: Option<Win16HostDdeOperation>,
        instance: Win16HostDdeInstance,
        owner: runtime::Win16HostDdeOwner,
        worker_generation: u64,
    ) -> Result<bool, RuntimeError> {
        if owner != self.owner || worker_generation != self.worker_generation {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE callback retirement query changed its native owner or worker generation",
            ));
        }
        if let Some(pending) = self.pending_callbacks.get(&frame) {
            if pending.parent == parent && pending.instance == instance && pending.acknowledged {
                return Ok(true);
            }
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE callback retirement identity or acknowledgement does not match its owner ledger",
            ));
        }
        let cached_ack = self.abort_receipt.as_ref().is_some_and(|receipt| {
            receipt.is_quiesced()
                && receipt.owner == Some(self.owner)
                && receipt.worker_generation == Some(worker_generation)
                && receipt.request_id == self.abort_request_id
                && receipt.cancelled_callbacks.iter().any(|entry| {
                    entry.frame == frame
                        && entry.parent_operation == parent
                        && entry.instance == Some(instance)
                        && entry.status == Win16DdeCallbackCancellationStatus::FrameAcknowledged
                        && matches!(
                            entry.source,
                            Win16DdeCancellationSource::GuestReply
                                | Win16DdeCancellationSource::OwnerShutdown
                        )
                })
        });
        if cached_ack {
            Ok(false)
        } else {
            Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE callback retirement has no live tombstone or exact cached native acknowledgement",
            ))
        }
    }

    fn seed_pending_receipt(&self, receipt: &mut Win16DdeAbortReceipt) {
        for operation in &self.pending_operations {
            if !receipt.cancelled_operations.iter().any(|entry| entry.operation == *operation) {
                let record = self.pending_operation_instances.get(operation);
                receipt.cancelled_operations.push(Win16DdeOperationCancellation {
                    operation: *operation,
                    instance: record.and_then(|record| record.instance),
                    status: Win16DdeOperationCancellationStatus::Requested,
                    failure: record.and_then(|record| record.failure.clone()),
                });
            }
        }
        for (frame, pending) in &self.pending_callbacks {
            upsert_callback(
                receipt,
                *frame,
                pending.parent,
                Some(pending.instance),
                if pending.acknowledged {
                    Win16DdeCallbackCancellationStatus::FrameAcknowledged
                } else if pending.reply_sent {
                    Win16DdeCallbackCancellationStatus::NativeCallbackReturned
                } else {
                    Win16DdeCallbackCancellationStatus::Requested
                },
                if pending.abort_reply_sent || !pending.reply_sent {
                    Win16DdeCancellationSource::OwnerShutdown
                } else {
                    Win16DdeCancellationSource::GuestReply
                },
                pending.acknowledgement_failure.clone(),
            );
            if let Some(operation) = pending.parent {
                upsert_operation(
                    receipt,
                    operation,
                    Some(pending.instance),
                    Win16DdeOperationCancellationStatus::Requested,
                    None,
                );
            }
        }
        for (operation, (_, instance)) in &self.pending_transfer_guards {
            upsert_operation(
                receipt,
                *operation,
                Some(*instance),
                Win16DdeOperationCancellationStatus::Requested,
                None,
            );
        }
        for (operation, record) in &self.pending_operation_instances {
            if self.pending_operations.contains(operation) {
                continue;
            }
            match record.request_phase {
                Some(runtime::Win16DdeOperationRequestPhase::NativeCompleteError) => {
                    upsert_operation(
                        receipt,
                        *operation,
                        record.instance,
                        Win16DdeOperationCancellationStatus::NativeCompleteError,
                        record.failure.clone(),
                    );
                }
                Some(runtime::Win16DdeOperationRequestPhase::NativeCompleteReturned)
                    if record.completed_result.is_some() =>
                {
                    upsert_operation(
                        receipt,
                        *operation,
                        record.instance,
                        Win16DdeOperationCancellationStatus::NativeCompleteReturned,
                        None,
                    );
                }
                Some(runtime::Win16DdeOperationRequestPhase::NativeCompleteReturned) => {
                    let error = Arc::new(RuntimeError::new(
                        Kind::InternalInvariant,
                        "DDE operation was marked returned without its exact cached result",
                    ));
                    upsert_operation(
                        receipt,
                        *operation,
                        record.instance,
                        Win16DdeOperationCancellationStatus::Retained,
                        Some(Arc::clone(&error)),
                    );
                    record_failure(
                        receipt,
                        Win16DdeAbortPhase::ReconcileRuntimeLedger,
                        None,
                        Some(*operation),
                        record.instance,
                        Win16DdeCleanupStatus::Unresolved,
                        super::shared_runtime_error(
                            error,
                            "DDE operation was marked returned without its exact cached result",
                        ),
                    );
                }
                Some(runtime::Win16DdeOperationRequestPhase::SubmittedPending) => {
                    upsert_operation(
                        receipt,
                        *operation,
                        record.instance,
                        Win16DdeOperationCancellationStatus::Retained,
                        record.failure.clone(),
                    );
                }
                None => {}
            }
        }
    }

    fn join_completed_worker(&mut self, receipt: &mut Win16DdeAbortReceipt) {
        let worker_finished = self.worker.as_ref().is_some_and(|worker| worker.is_finished());
        if worker_finished {
            if let Some(worker) = self.worker.take() {
                match worker.join() {
                    Ok(()) => receipt.worker_status = Win16DdeAbortWorkerStatus::Joined,
                    Err(_) => {
                        receipt.worker_status = Win16DdeAbortWorkerStatus::Panicked;
                        record_failure(
                            receipt,
                            Win16DdeAbortPhase::JoinWorker,
                            None,
                            None,
                            None,
                            Win16DdeCleanupStatus::Unresolved,
                            RuntimeError::new(Kind::HostFailure, "DDE owner thread panicked before joining"),
                        );
                    }
                }
            }
        }
        if matches!(
            receipt.worker_status,
            Win16DdeAbortWorkerStatus::Joined | Win16DdeAbortWorkerStatus::Panicked
        ) && let Some(report) = self.shutdown_report.take()
        {
            receipt.native_owner_receipt = Some(report.native_owner_receipt);
            receipt.native_instances = report.native_instances;
            receipt.native_replies = report.native_replies;
            if let Err(error) = self.reconcile_native_transfer_guard_report(
                receipt,
                &report.native_transfer_guards,
            ) {
                record_failure(
                    receipt,
                    Win16DdeAbortPhase::ReconcileRuntimeLedger,
                    None,
                    None,
                    None,
                    Win16DdeCleanupStatus::Retained,
                    error,
                );
            }
            let unresolved_operations: Vec<_> = self.pending_operations.iter().copied().collect();
            for operation in unresolved_operations {
                let instance = self
                    .pending_operation_instances
                    .get(&operation)
                    .and_then(|record| record.instance);
                let error = Arc::new(RuntimeError::new(
                    Kind::HostFailure,
                    "DDE owner joined without publishing the exact operation terminal receipt",
                ));
                upsert_operation(
                    receipt,
                    operation,
                    instance,
                    Win16DdeOperationCancellationStatus::Retained,
                    Some(Arc::clone(&error)),
                );
                record_failure(
                    receipt,
                    Win16DdeAbortPhase::ReconcileRuntimeLedger,
                    None,
                    Some(operation),
                    instance,
                    Win16DdeCleanupStatus::Retained,
                    super::shared_runtime_error(
                        error,
                        "DDE owner joined without publishing the exact operation terminal receipt",
                    ),
                );
            }
            for failure in report.cleanup_failures {
                push_failure_once(receipt, failure);
            }
            if let Some(error) = report.terminal_error {
                let native_done = report.native_owner_receipt.all_native_callbacks_returned
                    && report.native_owner_receipt.all_active_operations_returned
                    && report.native_owner_receipt.all_native_replies_released_or_transferred
                    && report.native_owner_receipt.all_native_transfer_guards_retired
                    && report.native_owner_receipt.all_native_instances_uninitialized
                    && report.native_owner_receipt.control_window_destroyed;
                record_failure(
                    receipt,
                    Win16DdeAbortPhase::ReconcileRuntimeLedger,
                    None,
                    None,
                    None,
                    if native_done {
                        Win16DdeCleanupStatus::RetriedAndReleased
                    } else {
                        Win16DdeCleanupStatus::Unresolved
                    },
                    RuntimeError::with_source(
                        error.kind(),
                        "DDE shutdown preserved its typed cleanup cause",
                        error,
                    ),
                );
            }
            self.shutdown_receiver.take();
        }
    }
}

fn same_abort_receipt(left: &Win16DdeAbortReceipt, right: &Win16DdeAbortReceipt) -> bool {
        left.owner == right.owner
        && left.worker_generation == right.worker_generation
        && left.request_id == right.request_id
        && left.owner_status == right.owner_status
        && left.worker_status == right.worker_status
        && left.native_owner_receipt == right.native_owner_receipt
        && same_callbacks(left, right)
        && same_operations(left, right)
        && same_native_instances(left, right)
        && same_native_replies(left, right)
        && same_native_transfer_guards(left, right)
        && same_cleanup_failures(left, right)
}

fn same_callbacks(left: &Win16DdeAbortReceipt, right: &Win16DdeAbortReceipt) -> bool {
    same_records(&left.cancelled_callbacks, &right.cancelled_callbacks, |a, b| {
            a.frame == b.frame
                && a.parent_operation == b.parent_operation
                && a.instance == b.instance
                && a.source == b.source
                && a.status == b.status
                && same_optional_error(&a.failure, &b.failure)
        })
}

fn same_operations(left: &Win16DdeAbortReceipt, right: &Win16DdeAbortReceipt) -> bool {
    same_records(&left.cancelled_operations, &right.cancelled_operations, |a, b| {
            a.operation == b.operation
                && a.instance == b.instance
                && a.status == b.status
                && same_optional_error(&a.failure, &b.failure)
        })
}

fn same_operation_cancellation(
    left: &runtime::Win16DdeOperationCancellation,
    right: &runtime::Win16DdeOperationCancellation,
) -> bool {
    left.operation == right.operation
        && left.instance == right.instance
        && left.status == right.status
        && same_optional_error(&left.failure, &right.failure)
}

fn same_native_instances(left: &Win16DdeAbortReceipt, right: &Win16DdeAbortReceipt) -> bool {
    same_records(&left.native_instances, &right.native_instances, |a, b| {
            a.instance == b.instance
                && a.status == b.status
                && same_optional_error(&a.failure, &b.failure)
        })
}

fn same_native_replies(left: &Win16DdeAbortReceipt, right: &Win16DdeAbortReceipt) -> bool {
    same_records(&left.native_replies, &right.native_replies, |a, b| {
            a.frame == b.frame
                && a.operation == b.operation
                && a.instance == b.instance
                && a.role == b.role
                && a.status == b.status
                && same_optional_error(&a.failure, &b.failure)
        })
}

fn same_native_transfer_guards(
    left: &Win16DdeAbortReceipt,
    right: &Win16DdeAbortReceipt,
) -> bool {
    same_records(&left.native_transfer_guards, &right.native_transfer_guards, |a, b| {
        a.operation == b.operation
            && a.data == b.data
            && a.instance == b.instance
            && a.source == b.source
            && same_optional_error(&a.failure, &b.failure)
    })
}

pub(super) fn upsert_native_transfer_guard(
    receipt: &mut Win16DdeAbortReceipt,
    operation: Win16HostDdeOperation,
    data: Win16HostDdeData,
    instance: Win16HostDdeInstance,
    source: Win16DdeNativeTransferGuardSource,
    failure: Option<Arc<RuntimeError>>,
) {
    if let Some(current) = receipt.native_transfer_guards.iter_mut().find(|entry| {
        entry.operation == operation && entry.data == data && entry.instance == instance
    }) {
        current.source = source;
        if current.failure.is_none() {
            current.failure = failure;
        }
    } else {
        receipt.native_transfer_guards.push(Win16DdeNativeTransferGuardReceipt {
            operation,
            data,
            instance,
            source,
            failure,
        });
    }
}

fn same_transfer_guard(
    left: &runtime::Win16DdeNativeTransferGuardReceipt,
    right: &runtime::Win16DdeNativeTransferGuardReceipt,
) -> bool {
    left.operation == right.operation
        && left.data == right.data
        && left.instance == right.instance
        && left.source == right.source
        && same_optional_error(&left.failure, &right.failure)
}

fn same_cleanup_failures(left: &Win16DdeAbortReceipt, right: &Win16DdeAbortReceipt) -> bool {
    same_records(&left.cleanup_failures, &right.cleanup_failures, |a, b| {
            a.phase == b.phase
                && a.frame == b.frame
                && a.operation == b.operation
                && a.instance == b.instance
                && a.status == b.status
                && Arc::ptr_eq(&a.cause, &b.cause)
        })
}

fn same_records<T>(left: &[T], right: &[T], matches: impl Fn(&T, &T) -> bool) -> bool {
    left.len() == right.len()
        && left.iter().all(|a| right.iter().filter(|b| matches(a, *b)).count() == 1)
        && right.iter().all(|b| left.iter().filter(|a| matches(*a, b)).count() == 1)
}

fn same_optional_error(left: &Option<Arc<RuntimeError>>, right: &Option<Arc<RuntimeError>>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
        (None, None) => true,
        _ => false,
    }
}

impl Drop for Win16DdeHost {
    fn drop(&mut self) {
        let _ = self.abort();
    }
}

pub(super) fn upsert_callback(
    receipt: &mut Win16DdeAbortReceipt,
    frame: Win16HostDdeCallbackFrame,
    parent_operation: Option<Win16HostDdeOperation>,
    instance: Option<Win16HostDdeInstance>,
    status: Win16DdeCallbackCancellationStatus,
    source: Win16DdeCancellationSource,
    failure: Option<Arc<RuntimeError>>,
) {
    if let Some(callback) = receipt.cancelled_callbacks.iter_mut().find(|entry| entry.frame == frame) {
        callback.parent_operation = parent_operation;
        callback.instance = instance;
        callback.source = source;
        callback.status = status;
        if failure.is_some() { callback.failure = failure; }
    } else {
        receipt.cancelled_callbacks.push(Win16DdeCallbackCancellation {
            frame,
            parent_operation,
            instance,
            source,
            status,
            failure,
        });
    }
}

pub(super) fn upsert_operation(
    receipt: &mut Win16DdeAbortReceipt,
    operation: Win16HostDdeOperation,
    instance: Option<Win16HostDdeInstance>,
    status: Win16DdeOperationCancellationStatus,
    failure: Option<Arc<RuntimeError>>,
) {
    if let Some(current) = receipt.cancelled_operations.iter_mut().find(|entry| entry.operation == operation) {
        current.instance = instance.or(current.instance);
        current.status = status;
        if failure.is_some() { current.failure = failure; }
    } else {
        receipt.cancelled_operations.push(Win16DdeOperationCancellation {
            operation,
            instance,
            status,
            failure,
        });
    }
}

pub(super) fn record_failure(
    receipt: &mut Win16DdeAbortReceipt,
    phase: Win16DdeAbortPhase,
    frame: Option<Win16HostDdeCallbackFrame>,
    operation: Option<Win16HostDdeOperation>,
    instance: Option<Win16HostDdeInstance>,
    status: Win16DdeCleanupStatus,
    error: RuntimeError,
) {
    push_failure_once(receipt, Win16DdeCleanupFailure {
        phase,
        frame,
        operation,
        instance,
        status,
        cause: Arc::new(error),
    });
}
