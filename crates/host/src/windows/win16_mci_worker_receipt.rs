//! Typed diagnostics for MCI receipts whose original guest return path is gone.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use super::super::combine_failure_kind;
use super::*;
use super::MciWorkerShutdownReceipt;

impl Win16MciWorkerState {
    pub(super) fn receipt_blocker(&self, wake_error: Option<RuntimeError>) -> RuntimeError {
        let detail = if let Some(receipt) = self.deferred_receipts.first() {
            match receipt {
                DeferredWorkerReceipt::Begin { operation, .. } => format!(
                    "MCI operation {} still has an enqueued begin receipt",
                    operation.0
                ),
                DeferredWorkerReceipt::Resume {
                    operation, frame, ..
                } => format!(
                    "MCI operation {} frame {} still has an enqueued resume receipt",
                    operation.0, frame.0
                ),
                DeferredWorkerReceipt::Quiesce { request, .. } => format!(
                    "MCI quiescence for {} device(s), {} yield registration(s), {} pending Begin(s), and {} active yield frame(s) still has an enqueued receipt",
                    request.devices.len(), request.registrations.len(), request.pending_begins.len(), request.active_yields.len()
                ),
            }
        } else if let Some(operation) = self.unclaimed.first() {
            let phase = match &operation.outcome {
                UnclaimedMciOutcome::AwaitingYieldResult { expected } => format!(
                    "resume acceptance for frame {} is reconciled, but its exact continuation result is pending",
                    expected.owner.frame.0
                ),
                UnclaimedMciOutcome::Step(MciWorkerStep {
                    step: Win16HostMciStep::Yield(event),
                    ..
                }) => format!(
                    "yield frame {} completed after its guest callback path was lost",
                    event.frame.0,
                ),
                UnclaimedMciOutcome::Step(MciWorkerStep {
                    step: Win16HostMciStep::Complete(_),
                    ..
                }) => {
                    "terminal native result is retained without its original guest return path".to_owned()
                }
                UnclaimedMciOutcome::UnexpectedBeginStep { error, .. } => format!(
                    "native begin returned an unexpected step and retains its typed failure: {error}"
                ),
                UnclaimedMciOutcome::UnexpectedStep { expected, error, .. } => format!(
                    "native response for operation {} frame {} returned an unexpected step and retains its typed failure: {error}",
                    expected.owner.operation.0, expected.owner.frame.0
                ),
                UnclaimedMciOutcome::Failure { frame: Some(frame), .. } => format!(
                    "terminal native failure from frame {} is retained without its original guest return path",
                    frame.0
                ),
                UnclaimedMciOutcome::Failure { frame: None, .. } => {
                    "terminal native failure is retained without its original guest return path".to_owned()
                }
            };
            format!("MCI operation {} {phase}", operation.operation.0)
        } else if let Some(receipt) = self.completed_quiescences.first() {
            format!(
                "MCI quiescence result for {} exact requested owner(s) remains unreconciled",
                receipt.request.devices.len()
                    .saturating_add(receipt.request.registrations.len())
                    .saturating_add(receipt.request.active_yields.len())
            )
        } else {
            "MCI worker retains a result owner that still needs reconciliation".to_owned()
        };

        // Inspect by reference, leaving queued receivers, completed receipts,
        // and native worker ownership intact for the next reconciliation pass.
        let mut kind = wake_error.as_ref().map(RuntimeError::kind);
        let mut worker_failures = Vec::new();
        for operation in &self.unclaimed {
            let (error, frame) = match &operation.outcome {
                UnclaimedMciOutcome::Failure { error, frame, .. } => (Some(error), *frame),
                UnclaimedMciOutcome::UnexpectedBeginStep { error, .. }
                | UnclaimedMciOutcome::UnexpectedStep { error, .. } => {
                    (Some(error), operation.source_frame)
                }
                _ => (None, operation.source_frame),
            };
            if let Some(error) = error {
                kind = Some(match kind {
                    Some(primary) => combine_failure_kind(primary, error.kind()),
                    None => error.kind(),
                });
                worker_failures.push(RetainedMciWorkerFailure {
                    operation: operation.operation,
                    frame,
                    error: Arc::clone(error),
                });
            }
        }
        let message = format!(
            "{detail}; native owner and exact receipt state remain retained for reconciliation"
        );
        let Some(kind) = kind else {
            return RuntimeError::new(Kind::HostFailure, message);
        };
        RuntimeError::with_source(
            kind,
            message,
            MciReceiptBlockerCause {
                wake_error: wake_error.map(Arc::new),
                worker_failures,
            },
        )
    }
}

pub(super) fn shutdown_receipt_error(receipt: MciWorkerShutdownReceipt) -> RuntimeError {
    RuntimeError::with_source(
        Kind::HostFailure,
        "native MCI worker shutdown did not confirm every owner phase and thread join",
        MciWorkerShutdownReceiptFailure(receipt),
    )
}

#[derive(Debug)]
struct MciWorkerShutdownReceiptFailure(MciWorkerShutdownReceipt);

impl fmt::Display for MciWorkerShutdownReceiptFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let receipt = &self.0;
        write!(
            formatter,
            "shutdown phases: device registry drained={}, closed identities={}, yield-source history complete={} ({} exact proofs), notification ledger drained={}, window destroyed={}, class unregistered={}, owner loop returned={}, thread joined={}",
            receipt.device_registry_drained,
            receipt.closed_devices.len(),
            receipt.yield_source_history_complete,
            receipt.disabled_yield_sources.len(),
            receipt.notification_ledger_drained,
            receipt.notification_window_destroyed,
            receipt.notification_class_unregistered,
            receipt.owner_loop_returned,
            receipt.owner_thread_joined
        )?;
        for evidence in &receipt.disabled_yield_sources {
            if let Win16HostMciQuiescenceEvidence::YieldSourceDisabled {
                owner,
                set_result,
                observed_installed,
            } = evidence
            {
                write!(
                    formatter,
                    "; yield registration {} on device {}:{}: set result {}, still installed={}",
                    owner.registration.0,
                    owner.device.token,
                    owner.device.generation,
                    set_result,
                    observed_installed
                )?;
            }
        }
        for cause in &receipt.resolved_causes {
            write!(formatter, "; recovered cause: {cause}")?;
        }
        Ok(())
    }
}

impl Error for MciWorkerShutdownReceiptFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0
            .resolved_causes
            .first()
            .map(|cause| cause.as_ref() as &(dyn Error + 'static))
    }
}

#[derive(Debug)]
struct RetainedMciWorkerFailure {
    operation: Win16HostMciOperationId,
    frame: Option<Win16HostMciYieldFrame>,
    error: Arc<RuntimeError>,
}

#[derive(Debug)]
struct MciReceiptBlockerCause {
    wake_error: Option<Arc<RuntimeError>>,
    worker_failures: Vec<RetainedMciWorkerFailure>,
}

impl fmt::Display for MciReceiptBlockerCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut wrote_cause = false;
        if let Some(error) = &self.wake_error {
            write!(formatter, "wake failure: {error}")?;
            wrote_cause = true;
        }
        for failure in &self.worker_failures {
            if wrote_cause {
                formatter.write_str("; ")?;
            }
            match failure.frame {
                Some(frame) => write!(
                    formatter,
                    "MCI operation {} frame {} retained failure: {}",
                    failure.operation.0, frame.0, failure.error
                )?,
                None => write!(
                    formatter,
                    "MCI operation {} retained failure: {}",
                    failure.operation.0, failure.error
                )?,
            }
            wrote_cause = true;
        }
        Ok(())
    }
}

impl Error for MciReceiptBlockerCause {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(error) = self
            .wake_error
            .as_deref()
            .filter(|error| error.kind() == Kind::InternalInvariant)
        {
            return Some(error as &(dyn Error + 'static));
        }
        if let Some(error) = self
            .worker_failures
            .iter()
            .map(|failure| failure.error.as_ref())
            .find(|error| error.kind() == Kind::InternalInvariant)
        {
            return Some(error as &(dyn Error + 'static));
        }
        self.wake_error
            .as_deref()
            .map(|error| error as &(dyn Error + 'static))
            .or_else(|| {
                self.worker_failures
                    .first()
                    .map(|failure| failure.error.as_ref() as &(dyn Error + 'static))
            })
    }
}
