//! Exact result reconciliation for an already-enqueued MCI Begin command.

use super::*;

pub(super) fn entered_yield_failure(
    error: &RuntimeError,
) -> Option<MciEnteredYieldFailure> {
    super::super::entered_yield_failure(error)
}

pub(super) fn entered_yield_failure_frame(
    error: &RuntimeError,
) -> Option<Win16HostMciYieldFrame> {
    entered_yield_failure(error).and_then(|failure| failure.frame)
}

impl Win16MciWorker {
    pub(in crate::windows::win16_mci_owner) fn reconcile_begin(
        &mut self,
        operation: Win16HostMciOperationId,
    ) -> Result<Option<Win16HostMciStep>, RuntimeError> {
        if operation.0 == 0 {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "MCI Begin reconciliation received a zero operation identity",
            ));
        }
        let drain = self.drain_deferred_receipts();
        let drain_error = match drain {
            Ok(Some(error)) | Err(error) => Some(error),
            Ok(None) => None,
        };
        if let Some(error) = drain_error {
            return Err(error.with_context(format!(
                "reconcile MCI operation {} after preserving every ready owner receipt",
                operation.0
            )));
        }
        if let Some(index) = self
            .unclaimed
            .iter()
            .position(|receipt| receipt.operation == operation)
        {
            let receipt = &self.unclaimed[index];
            if receipt.source_frame.is_some() {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "MCI Begin reconciliation found a yield-resume receipt for the same operation",
                ));
            }
            return match &receipt.outcome {
                UnclaimedMciOutcome::Step(step) => {
                    if step.returned_yield.is_some() {
                        return Err(RuntimeError::new(
                            Kind::InternalInvariant,
                            "MCI Begin result carries an unexpected yield-return ACK and remains retained",
                        ));
                    }
                    match &step.step {
                        Win16HostMciStep::Yield(event) if event.operation != operation => {
                            Err(RuntimeError::new(
                                Kind::InternalInvariant,
                                "MCI Begin result yield names a different operation identity",
                            ))
                        }
                        _ => {
                            let step = step.step.clone();
                            self.unclaimed.swap_remove(index);
                            Ok(Some(step))
                        }
                    }
                }
                UnclaimedMciOutcome::UnexpectedBeginStep { error, .. }
                | UnclaimedMciOutcome::Failure { error, .. } => Err(RuntimeError::with_source(
                    error.kind(),
                    "MCI Begin result remains attached to its original operation owner",
                    super::super::quarantine::RetainedMciRuntimeError::new(Arc::clone(error)),
                )),
                UnclaimedMciOutcome::AwaitingYieldResult { .. }
                | UnclaimedMciOutcome::UnexpectedStep { .. } => Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "MCI Begin reconciliation found a receipt from another native phase",
                )),
            };
        }

        let waiting = self.deferred_receipts.iter().any(|receipt| {
            matches!(receipt, DeferredWorkerReceipt::Begin { operation: current, .. } if *current == operation)
        });
        if waiting {
            // The still-live exact Begin receiver remains authoritative even
            // if waking or reconciling a different receipt also failed.
            return Ok(None);
        }
        Err(RuntimeError::new(
            Kind::InternalInvariant,
            format!(
                "MCI Begin operation {} is unknown to the retained worker receipt ledger",
                operation.0
            ),
        ))
    }
}
