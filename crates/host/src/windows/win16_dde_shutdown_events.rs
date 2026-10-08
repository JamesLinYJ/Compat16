//! DDE abort event reconciliation for exact native owner receipts.

use std::sync::{mpsc, Arc};

use runtime::Win16HostDdeValue;

use super::*;
use super::{record_failure, upsert_callback, upsert_native_transfer_guard, upsert_operation};

impl Win16DdeHost {
    pub(super) fn cancel_pending_callbacks(&mut self, receipt: &mut Win16DdeAbortReceipt) {
        for (frame, pending) in &mut self.pending_callbacks {
            if pending.reply_sent {
                continue;
            }
            match pending.reply.send(Win16DdeCallbackReply::CancelledByOwnerShutdown) {
                Ok(()) => {
                    pending.reply_sent = true;
                    pending.abort_reply_sent = true;
                    upsert_callback(
                        receipt,
                        *frame,
                        pending.parent,
                        Some(pending.instance),
                        Win16DdeCallbackCancellationStatus::Requested,
                        Win16DdeCancellationSource::OwnerShutdown,
                        None,
                    );
                }
                Err(_) => {
                    let error = Arc::new(disconnected(
                        "send owner-shutdown cancellation for the exact DDE frame",
                    ));
                    upsert_callback(
                        receipt,
                        *frame,
                        pending.parent,
                        Some(pending.instance),
                        Win16DdeCallbackCancellationStatus::Retained,
                        Win16DdeCancellationSource::OwnerShutdown,
                        Some(Arc::clone(&error)),
                    );
                    record_failure(
                        receipt,
                        Win16DdeAbortPhase::CancelCallback,
                        Some(*frame),
                        pending.parent,
                        Some(pending.instance),
                        Win16DdeCleanupStatus::Retained,
                        super::shared_runtime_error(
                            error,
                            "send owner-shutdown cancellation for the exact DDE frame",
                        ),
                    );
                }
            }
        }
    }

    pub(super) fn poll_abort_events(&mut self, receipt: &mut Win16DdeAbortReceipt) {
        let pending_events = std::mem::take(&mut self.pending_events);
        for (_, events) in pending_events {
            for event in events {
                self.handle_abort_event(event, receipt);
            }
        }
        let callback_completions = std::mem::take(&mut self.pending_callback_completions);
        for (frame, (parent, result)) in callback_completions {
            self.handle_abort_event(
                WorkerEvent::CallbackFrameComplete { frame, parent, result },
                receipt,
            );
        }
        loop {
            match self.event_receiver.try_recv() {
                Ok(event) => self.handle_abort_event(event, receipt),
                Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => break,
            }
        }
    }

    fn handle_abort_event(&mut self, event: WorkerEvent, receipt: &mut Win16DdeAbortReceipt) {
        match event {
            WorkerEvent::Callback { frame, parent, callback, reply } => {
                let instance = callback.host_instance;
                match self.callback_step(frame, parent, callback, reply) {
                    Ok(_) => {
                        if let Some(operation) = parent {
                            upsert_operation(
                                receipt,
                                operation,
                                Some(instance),
                                Win16DdeOperationCancellationStatus::Requested,
                                None,
                            );
                        }
                        upsert_callback(
                            receipt,
                            frame,
                            parent,
                            Some(instance),
                            Win16DdeCallbackCancellationStatus::Requested,
                            Win16DdeCancellationSource::OwnerShutdown,
                            None,
                        );
                        self.cancel_pending_callbacks(receipt);
                    }
                    Err(error) => record_failure(
                        receipt,
                        Win16DdeAbortPhase::CancelCallback,
                        Some(frame),
                        parent,
                        Some(instance),
                        Win16DdeCleanupStatus::Unresolved,
                        error,
                    ),
                }
            }
            WorkerEvent::CallbackFrameComplete { frame, parent, result } => {
                let acknowledgement_failure = result.err().map(Arc::new);
                match self.pending_callbacks.get(&frame) {
                    Some(pending) if pending.parent != parent => record_failure(
                        receipt,
                        Win16DdeAbortPhase::ReconcileRuntimeLedger,
                        Some(frame),
                        pending.parent,
                        Some(pending.instance),
                        Win16DdeCleanupStatus::Unresolved,
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "DDE callback shutdown acknowledgement changed its exact parent operation",
                        ),
                    ),
                    Some(pending) => {
                        upsert_callback(
                            receipt,
                            frame,
                            parent,
                            Some(pending.instance),
                            Win16DdeCallbackCancellationStatus::FrameAcknowledged,
                            if pending.abort_reply_sent {
                                Win16DdeCancellationSource::OwnerShutdown
                            } else {
                                Win16DdeCancellationSource::GuestReply
                            },
                            acknowledgement_failure.clone(),
                        );
                        if let Some(pending) = self.pending_callbacks.get_mut(&frame) {
                            pending.acknowledged = true;
                            pending.acknowledgement_failure = acknowledgement_failure;
                        }
                    }
                    None => {}
                }
            }
            WorkerEvent::Complete {
                operation,
                entered_worker,
                result,
            } => {
                self.pending_operations.remove(&operation);
                let operation_instance = self
                    .pending_operation_instances
                    .get(&operation)
                    .and_then(|record| record.instance);
                let transfer_identity = self.pending_transfer_guards.get(&operation).copied();
                let cancelled_by_owner = receipt.cancelled_callbacks.iter().any(|callback| {
                    callback.parent_operation == Some(operation)
                        && callback.source == Win16DdeCancellationSource::OwnerShutdown
                });
                let (result, completion_failure) = match result {
                    Ok(result) => (Some(result), None),
                    Err(error) => (None, Some(Arc::new(error))),
                };
                let cancellation_status = if !entered_worker {
                    Win16DdeOperationCancellationStatus::CancelledByOwnerShutdown
                } else if completion_failure.is_some() {
                    Win16DdeOperationCancellationStatus::NativeCompleteError
                } else if cancelled_by_owner {
                    Win16DdeOperationCancellationStatus::CancelledByOwnerShutdown
                } else {
                    Win16DdeOperationCancellationStatus::CompletedDuringAbort
                };
                if let Some(record) = self.pending_operation_instances.get_mut(&operation) {
                    if let Some(result) = result.as_ref() {
                        record.request_phase = Some(
                            runtime::Win16DdeOperationRequestPhase::NativeCompleteReturned,
                        );
                        record.failure = None;
                        record.completed_result = Some(result.clone());
                    } else if let Some(cause) = completion_failure.as_ref() {
                        record.request_phase = Some(
                            runtime::Win16DdeOperationRequestPhase::NativeCompleteError,
                        );
                        record.failure = Some(Arc::clone(cause));
                    }
                }
                if let Some((expected_data, expected_instance)) = transfer_identity {
                    let transfer_result = result
                        .as_ref()
                        .and_then(|result| result.data_transfer.as_ref());
                    if !entered_worker {
                        upsert_native_transfer_guard(
                            receipt,
                            operation,
                            expected_data,
                            expected_instance,
                            Win16DdeNativeTransferGuardSource::NotEntered,
                            None,
                        );
                        self.pending_transfer_guards.remove(&operation);
                    } else if let Some(transfer) = transfer_result {
                        if transfer.token == expected_data {
                            let source = match result.as_ref().map(|result| &result.value) {
                                Some(Win16HostDdeValue::ClientTransaction {
                                    entered_native: false,
                                    ..
                                }) => Win16DdeNativeTransferGuardSource::PreflightRejected,
                                _ => Win16DdeNativeTransferGuardSource::NativeCompletion(
                                    transfer.outcome,
                                ),
                            };
                            upsert_native_transfer_guard(
                                receipt,
                                operation,
                                expected_data,
                                expected_instance,
                                source,
                                completion_failure.clone(),
                            );
                            self.pending_transfer_guards.remove(&operation);
                        } else {
                            let error = Arc::new(RuntimeError::new(
                                Kind::InternalInvariant,
                                "DDE transaction completion changed its exact transfer token",
                            ));
                            upsert_native_transfer_guard(
                                receipt,
                                operation,
                                expected_data,
                                expected_instance,
                                Win16DdeNativeTransferGuardSource::Retained,
                                Some(Arc::clone(&error)),
                            );
                            record_failure(
                                receipt,
                                Win16DdeAbortPhase::ReconcileRuntimeLedger,
                                None,
                                Some(operation),
                                Some(expected_instance),
                                Win16DdeCleanupStatus::Retained,
                                super::shared_runtime_error(
                                    error,
                                    "DDE transaction completion changed its exact transfer token",
                                ),
                            );
                        }
                    }
                } else if result.as_ref().is_some_and(|result| result.data_transfer.is_some())
                {
                    record_failure(
                        receipt,
                        Win16DdeAbortPhase::ReconcileRuntimeLedger,
                        None,
                        Some(operation),
                        operation_instance,
                        Win16DdeCleanupStatus::Unresolved,
                        RuntimeError::new(
                            Kind::InternalInvariant,
                            "DDE completion returned a transfer receipt without a registered exact owner identity",
                        ),
                    );
                }
                upsert_operation(
                    receipt,
                    operation,
                    operation_instance.or_else(|| transfer_identity.map(|(_, instance)| instance)),
                    cancellation_status,
                    completion_failure,
                );
            }
            WorkerEvent::Diagnostic(diagnostic) => self.diagnostics.push_back(diagnostic),
            WorkerEvent::ShutdownFailure(_) => {}
            WorkerEvent::Failure(error) => record_failure(
                receipt,
                Win16DdeAbortPhase::ReceiveReceipt,
                None,
                None,
                None,
                Win16DdeCleanupStatus::Retained,
                error,
            ),
        }
    }

    pub(super) fn poll_shutdown_report(&mut self, receipt: &mut Win16DdeAbortReceipt) {
        if self.shutdown_report.is_some() || self.shutdown_receiver.is_none() {
            return;
        }
        let Some(receiver) = self.shutdown_receiver.as_ref() else {
            return;
        };
        match receiver.try_recv() {
            Ok(report) => self.shutdown_report = Some(report),
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => record_failure(
                receipt,
                Win16DdeAbortPhase::ReceiveReceipt,
                None,
                None,
                None,
                Win16DdeCleanupStatus::Retained,
                disconnected("receive DDE native owner shutdown evidence"),
            ),
        }
    }

    pub(super) fn reconcile_native_transfer_guard_report(
        &mut self,
        receipt: &mut Win16DdeAbortReceipt,
        reported: &[Win16DdeNativeTransferGuardReceipt],
    ) -> Result<(), RuntimeError> {
        for actual in reported {
            match self.pending_transfer_guards.get(&actual.operation).copied() {
                Some((data, instance)) if data == actual.data && instance == actual.instance => {
                    upsert_native_transfer_guard(
                        receipt,
                        actual.operation,
                        actual.data,
                        actual.instance,
                        actual.source,
                        actual.failure.clone(),
                    );
                    if actual.source != Win16DdeNativeTransferGuardSource::Retained {
                        self.pending_transfer_guards.remove(&actual.operation);
                        let status = receipt
                            .cancelled_operations
                            .iter()
                            .find(|entry| entry.operation == actual.operation)
                            .map(|entry| entry.status);
                        if matches!(
                            status,
                            Some(
                                Win16DdeOperationCancellationStatus::Requested
                                    | Win16DdeOperationCancellationStatus::Retained
                            )
                        ) {
                            upsert_operation(
                                receipt,
                                actual.operation,
                                Some(actual.instance),
                                Win16DdeOperationCancellationStatus::CancelledByOwnerShutdown,
                                actual.failure.clone(),
                            );
                        }
                    }
                }
                Some((data, instance)) => {
                    let error = Arc::new(RuntimeError::new(
                        Kind::InternalInvariant,
                        "DDE native shutdown report changed its host transfer identity",
                    ));
                    upsert_native_transfer_guard(
                        receipt,
                        actual.operation,
                        data,
                        instance,
                        Win16DdeNativeTransferGuardSource::Retained,
                        Some(Arc::clone(&error)),
                    );
                    record_failure(
                        receipt,
                        Win16DdeAbortPhase::ReconcileRuntimeLedger,
                        None,
                        Some(actual.operation),
                        Some(instance),
                        Win16DdeCleanupStatus::Retained,
                        super::shared_runtime_error(
                            error,
                            "DDE native shutdown report changed its host transfer identity",
                        ),
                    );
                }
                None => {
                    let error = Arc::new(RuntimeError::new(
                        Kind::InternalInvariant,
                        "DDE native shutdown report contains an unregistered transfer identity",
                    ));
                    upsert_native_transfer_guard(
                        receipt,
                        actual.operation,
                        actual.data,
                        actual.instance,
                        Win16DdeNativeTransferGuardSource::Retained,
                        Some(Arc::clone(&error)),
                    );
                    record_failure(
                        receipt,
                        Win16DdeAbortPhase::ReconcileRuntimeLedger,
                        None,
                        Some(actual.operation),
                        Some(actual.instance),
                        Win16DdeCleanupStatus::Retained,
                        super::shared_runtime_error(
                            error,
                            "DDE native shutdown report contains an unregistered transfer identity",
                        ),
                    );
                }
            }
        }
        let mut remaining = Vec::new();
        remaining
            .try_reserve(self.pending_transfer_guards.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve exact DDE transfer identities for shutdown reconciliation",
                    error,
                )
            })?;
        remaining.extend(
            self.pending_transfer_guards
                .iter()
                .map(|(operation, (data, instance))| (*operation, *data, *instance)),
        );
        for (operation, data, instance) in remaining {
            if reported.iter().any(|actual| actual.operation == operation) {
                continue;
            }
            let error = Arc::new(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE native owner omitted the exact registered transfer guard from shutdown evidence",
            ));
            upsert_native_transfer_guard(
                receipt,
                operation,
                data,
                instance,
                Win16DdeNativeTransferGuardSource::Retained,
                Some(Arc::clone(&error)),
            );
            record_failure(
                receipt,
                Win16DdeAbortPhase::ReconcileRuntimeLedger,
                None,
                Some(operation),
                Some(instance),
                Win16DdeCleanupStatus::Retained,
                super::shared_runtime_error(
                    error,
                    "DDE native owner omitted the exact registered transfer guard from shutdown evidence",
                ),
            );
        }
        Ok(())
    }

}
