//! Process-scope retention for MCI client receipts through native quiescence.

use std::error::Error;
use std::fmt;

use super::super::combine_failure_kind;
use super::client::{
    release_mci_worker_quarantine_slot, retain_mci_worker_quarantine_slot,
    mark_worker_shutdown_receipt, mark_worker_thread_joined, worker_is_joined,
};
use super::*;

pub(super) struct RetainedMciRuntimeError(Arc<RuntimeError>);

impl RetainedMciRuntimeError {
    pub(super) fn new(error: Arc<RuntimeError>) -> Self {
        Self(error)
    }
}

impl fmt::Debug for RetainedMciRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedMciRuntimeError")
            .field("kind", &self.0.kind())
            .finish()
    }
}

impl fmt::Display for RetainedMciRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0.as_ref(), formatter)
    }
}

impl Error for RetainedMciRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}

impl Win16MciWorker {
    fn retain_shutdown_failure(&mut self, error: RuntimeError) {
        debug_assert!(
            self.shutdown_failures.len() < RETAINED_SHUTDOWN_FAILURE_CAPACITY,
            "MCI shutdown failure receipt reservation must cover every Drop branch"
        );
        self.shutdown_failures.push(Arc::new(error));
    }

    fn retain_drain_result(
        &mut self,
        result: Result<Option<RuntimeError>, RuntimeError>,
        context: &'static str,
    ) {
        match result {
            Ok(None) => {}
            Ok(Some(error)) | Err(error) => {
                self.retain_shutdown_failure(error.with_context(context));
            }
        }
    }

    fn join_worker(&mut self) -> bool {
        let Some(thread) = self.thread.take() else {
            return worker_is_joined(self.quarantine_slot);
        };
        match thread.join() {
            Ok(()) => {
                mark_worker_thread_joined(self.quarantine_slot);
                let progress_receipt = {
                    let mut progress = self
                        .shutdown_progress
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    progress.as_mut().map(|receipt| {
                        receipt.owner_thread_joined = true;
                        receipt.clone()
                    })
                };
                if let Some(receipt) = progress_receipt {
                    self.shutdown_receipt = Some(receipt);
                } else if let Some(receipt) = &mut self.shutdown_receipt {
                    receipt.owner_thread_joined = true;
                }
                worker_is_joined(self.quarantine_slot)
            }
            Err(_) => {
                self.retain_shutdown_failure(RuntimeError::new(
                    Kind::InternalInvariant,
                    "native MCI owner thread panicked before quiescence was confirmed",
                ));
                false
            }
        }
    }

    fn request_shutdown(&mut self) {
        let (response, receive) = mpsc::channel();
        if let Err(error) = self.sender.send(WorkerCommand::Shutdown(response)) {
            self.retain_shutdown_failure(RuntimeError::with_source(
                Kind::HostFailure,
                "enqueue native MCI worker shutdown",
                error,
            ));
            return;
        }
        if let Err(error) = self.wake_owner() {
            self.retain_shutdown_failure(error.with_context(
                "native MCI owner shutdown command is retained while wake is retried",
            ));
        }
        match receive.recv_timeout(Duration::from_millis(250)) {
            Ok(Ok(receipt)) => {
                self.shutdown_receipt = Some(receipt.clone());
                mark_worker_shutdown_receipt(self.quarantine_slot, &receipt);
                let joined = self.join_worker();
                if !joined
                    || !receipt.device_registry_drained
                    || !receipt.yield_source_history_complete
                    || !receipt.notification_ledger_drained
                    || !receipt.notification_window_destroyed
                    || !receipt.notification_class_unregistered
                    || !receipt.owner_loop_returned
                {
                    self.retain_shutdown_failure(super::receipt::shutdown_receipt_error(
                        self.shutdown_receipt
                            .clone()
                            .unwrap_or(receipt),
                    ));
                }
            }
            Ok(Err(error)) => self.retain_shutdown_failure(error.with_context(
                "native MCI owner has not confirmed close and notification quiescence",
            )),
            Err(RecvTimeoutError::Timeout) => self.retain_shutdown_failure(RuntimeError::new(
                Kind::HostFailure,
                "native MCI owner is still draining resources after shutdown timeout",
            )),
            Err(RecvTimeoutError::Disconnected) => {
                self.retain_shutdown_failure(RuntimeError::new(
                    Kind::HostFailure,
                    "native MCI owner stopped before shutdown quiescence was confirmed",
                ))
            }
        }
    }

    fn log_retained_receipts(&self, joined: bool) {
        let (ledger_failure, snapshot) = {
            let notifications = self
                .notifications
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            (notifications.first_pending_failure(), notifications.quiescence_snapshot())
        };
        let (routes, events, callback_failures, typed_failures, ledger_retired) = snapshot;
        if let Some(failure) = ledger_failure {
            eprintln!("runtime: MCI process quarantine retains its typed notification cause: {failure}");
        }
        if !ledger_retired {
            eprintln!(
                "runtime: MCI notification ledger remains quarantined with {} route(s), {} event(s), {} callback failure(s), and {} typed failure(s)",
                routes, events, callback_failures, typed_failures
            );
        }
        if let Some(kind) = self
            .shutdown_failures
            .iter()
            .map(|error| error.kind())
            .reduce(combine_failure_kind)
        {
            eprintln!(
                "runtime: MCI owner shutdown retained {} typed cause(s) with aggregate category [{}]",
                self.shutdown_failures.len(),
                kind.as_str()
            );
        }
        for (index, error) in self.shutdown_failures.iter().enumerate() {
            eprintln!(
                "runtime: MCI owner shutdown receipt {} retained [{}]: {error}",
                index + 1,
                error.kind().as_str()
            );
        }
        for (operation, pending) in &self.pending {
            eprintln!(
                "runtime: MCI operation {} retains its exact continuation response at frame {}",
                operation.0, pending.frame.0
            );
        }
        for receipt in &self.deferred_receipts {
            match receipt {
                DeferredWorkerReceipt::Begin { operation, .. } => eprintln!(
                    "runtime: MCI operation {} retains its exact queued begin response receiver",
                    operation.0
                ),
                DeferredWorkerReceipt::Resume {
                    operation, frame, ..
                } => eprintln!(
                    "runtime: MCI operation {} frame {} retains its exact resume acceptance receiver",
                    operation.0, frame.0
                ),
                DeferredWorkerReceipt::Quiesce { request, .. } => eprintln!(
                    "runtime: MCI quiescence retains exact response ownership for {} device(s), {} registration(s), {} pending Begin(s), and {} yield frame(s)",
                    request.devices.len(), request.registrations.len(), request.pending_begins.len(), request.active_yields.len()
                ),
            }
        }
        for operation in &self.unclaimed {
            match &operation.outcome {
                UnclaimedMciOutcome::AwaitingYieldResult { expected } => eprintln!(
                    "runtime: MCI operation {} frame {} retains its accepted continuation receipt",
                    operation.operation.0, expected.owner.frame.0
                ),
                UnclaimedMciOutcome::Step(MciWorkerStep {
                    step: Win16HostMciStep::Yield(event),
                    ..
                }) => eprintln!(
                    "runtime: MCI operation {} yield frame {} retains its exact result receipt",
                    operation.operation.0, event.frame.0
                ),
                UnclaimedMciOutcome::Step(MciWorkerStep {
                    step: Win16HostMciStep::Complete(_),
                    ..
                }) => eprintln!(
                    "runtime: MCI operation {} retains its exact completed result receipt",
                    operation.operation.0
                ),
                UnclaimedMciOutcome::UnexpectedBeginStep { error, .. } => eprintln!(
                    "runtime: MCI operation {} retains an unexpected begin receipt and its typed cause: {error}",
                    operation.operation.0
                ),
                UnclaimedMciOutcome::UnexpectedStep {
                    expected, error, ..
                } => eprintln!(
                    "runtime: MCI operation {} frame {} retains an unexpected native step and its typed cause: {error}",
                    expected.owner.operation.0, expected.owner.frame.0
                ),
                UnclaimedMciOutcome::Failure { error, frame, .. } => match frame {
                    Some(frame) => eprintln!(
                        "runtime: MCI operation {} frame {} retains its exact failure receipt: {error}",
                        operation.operation.0, frame.0
                    ),
                    None => eprintln!(
                        "runtime: MCI operation {} retains its exact failure receipt: {error}",
                        operation.operation.0
                    ),
                },
            }
        }
        for quiescence in &self.completed_quiescences {
            match &quiescence.result {
                Ok(receipt) => {
                    let status = match receipt.status {
                        runtime::Win16HostMciQuiescenceStatus::NotStarted => "not started",
                        runtime::Win16HostMciQuiescenceStatus::Retained => "retained",
                        runtime::Win16HostMciQuiescenceStatus::Quiesced => "quiesced",
                    };
                    eprintln!(
                        "runtime: MCI quiescence receipt is {status}, with {} confirmed phase(s) and {} retained owner(s)",
                        receipt.confirmed.len(), receipt.retained.len()
                    );
                }
                Err(error) => eprintln!(
                    "runtime: MCI quiescence receipt retained for {} exact requested owner(s): {error}",
                    quiescence.request.devices.len()
                        .saturating_add(quiescence.request.registrations.len())
                        .saturating_add(quiescence.request.pending_begins.len())
                        .saturating_add(quiescence.request.active_yields.len())
                ),
            }
        }
        if let Some(receipt) = &self.shutdown_receipt {
            eprintln!(
                "runtime: MCI shutdown receipt phases: device registry drained={}, yield-source history complete={} ({} exact proofs), notification ledger drained={}, window destroyed={}, class unregistered={}, owner loop returned={}, thread joined={}",
                receipt.device_registry_drained,
                receipt.yield_source_history_complete,
                receipt.disabled_yield_sources.len(),
                receipt.notification_ledger_drained,
                receipt.notification_window_destroyed,
                receipt.notification_class_unregistered,
                receipt.owner_loop_returned,
                receipt.owner_thread_joined
            );
            for cause in &receipt.resolved_causes {
                eprintln!("runtime: MCI shutdown recovered cause: {cause}");
            }
        }
        if !joined {
            eprintln!(
                "runtime: MCI worker channels, native owner, and exact receipts remain quarantined until worker quiescence"
            );
        }
    }
}

impl Drop for Win16MciWorker {
    fn drop(&mut self) {
        let initial_drain = self.drain_deferred_receipts();
        self.retain_drain_result(
            initial_drain,
            "retain deferred-receipt wake or reconciliation failure while releasing owner client",
        );

        if self.thread.as_ref().is_some_and(JoinHandle::is_finished) {
            let _ = self.join_worker();
        } else {
            self.request_shutdown();
        }

        if worker_is_joined(self.quarantine_slot) {
            let final_drain = self.drain_deferred_receipts();
            self.retain_drain_result(
                final_drain,
                "retain final deferred-receipt wake or reconciliation failure after native owner quiescence",
            );
        }

        let joined = worker_is_joined(self.quarantine_slot);
        self.log_retained_receipts(joined);
        if joined {
            self.state.take();
            release_mci_worker_quarantine_slot(self.quarantine_slot);
        } else if let Some(owner) = self.state.take() {
            // The worker may still execute native calls or post callbacks. Move
            // the complete client owner into its pre-reserved process slot;
            // logging alone would destroy the exact channel and close receipts.
            retain_mci_worker_quarantine_slot(self.quarantine_slot, owner);
        }
    }
}
