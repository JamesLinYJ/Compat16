//! Exact USER PostGuestNotification operation outcomes shared by WAVE and MIDI.

use std::sync::Arc;

use crate::{
    DiagnosticKind as Kind, RuntimeError, Win16NativeWindowOperationKind,
    Win16NativeWindowOperationState, Win16WindowAbortReceipt,
    Win16WindowOperationStartedFailure, Win16WindowResult, Win16WindowStep,
    Win16WindowTerminalAck, Win16WindowTerminalSourceTop,
};

use super::Win16State;

#[derive(Debug)]
pub(super) enum WindowPostOutcome {
    /// A local target check rejected the post before a USER operation began.
    Completed(bool),
    StartedFailure(Arc<Win16WindowOperationStartedFailure>),
    /// The USER source row returned normally. Its exact proof/result stays on
    /// the originating multimedia row until read back and consumed.
    SourceRetired(WindowPostRetirement),
    /// The host returned a step without a verifiable normal retirement proof.
    /// Keep the step on the existing owner and never issue the post twice.
    Retained(WindowPostAttempt),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowPostRetirementPhase {
    NeedsReadback,
    ReadBack,
    Consumed,
}

#[derive(Clone, Debug)]
pub(super) struct WindowPostRetirement {
    proof: Arc<crate::Win16WindowSourceRetiredProof>,
    result: Arc<Win16WindowStep>,
    posted: Option<bool>,
    phase: WindowPostRetirementPhase,
    carrier_failure: Option<Arc<RuntimeError>>,
    first_cause: Option<Arc<RuntimeError>>,
}

#[derive(Clone, Debug)]
pub(super) enum WindowPostAttempt {
    SourceRetired(WindowPostRetirement),
    Unproven {
        result: Arc<Win16WindowStep>,
        first_cause: Arc<RuntimeError>,
    },
}

pub(super) fn resolve_window_post_step(
    step: Win16WindowStep,
) -> Result<WindowPostOutcome, RuntimeError> {
    match step {
        Win16WindowStep::StartedFailure(failure) => {
            if failure.operation.operation_id.0 == 0
                || failure.worker_generation == 0
                || failure.operation.kind
                    != Win16NativeWindowOperationKind::PostGuestNotification
            {
                let first_cause = Arc::new(window_post_invariant(
                    "USER POST StartedFailure has no exact operation identity",
                ));
                return Ok(WindowPostOutcome::Retained(WindowPostAttempt::Unproven {
                    result: Arc::new(Win16WindowStep::StartedFailure(failure)),
                    first_cause,
                }));
            }
            Ok(WindowPostOutcome::StartedFailure(failure))
        }
        Win16WindowStep::SourceRetired { proof, result } => {
            let result = Arc::new(*result);
            let posted = match result.as_ref() {
                Win16WindowStep::Complete(Win16WindowResult::NotificationPosted(posted)) => {
                    Some(*posted)
                }
                _ => None,
            };
            let carrier_failure = if proof.operation.operation_id.0 == 0
                || proof.worker_generation == 0
                || proof.operation.kind
                    != Win16NativeWindowOperationKind::PostGuestNotification
                || proof.state != Win16NativeWindowOperationState::Returned
                || posted.is_none()
            {
                Some(Arc::new(window_post_invariant(
                    "USER POST SourceRetired carrier changed its exact operation, state, or result",
                )))
            } else {
                None
            };
            Ok(WindowPostOutcome::SourceRetired(WindowPostRetirement {
                proof,
                result,
                posted,
                phase: WindowPostRetirementPhase::NeedsReadback,
                first_cause: carrier_failure.clone(),
                carrier_failure,
            }))
        }
        other => {
            let cause = Arc::new(window_post_invariant(
                "USER POST returned without its exact normal source-retirement proof",
            ));
            Ok(WindowPostOutcome::Retained(WindowPostAttempt::Unproven {
                result: Arc::new(other),
                first_cause: cause,
            }))
        }
    }
}

pub(super) fn window_post_attempt_result(attempt: &WindowPostAttempt) -> Option<bool> {
    match attempt {
        WindowPostAttempt::SourceRetired(receipt) => receipt.posted,
        WindowPostAttempt::Unproven { .. } => None,
    }
}

pub(super) fn window_post_attempt_consumed(attempt: &WindowPostAttempt) -> bool {
    matches!(attempt,
        WindowPostAttempt::SourceRetired(WindowPostRetirement {
            phase: WindowPostRetirementPhase::Consumed,
            ..
        }))
}

fn window_step_kind(step: &Win16WindowStep) -> &'static str {
    match step {
        Win16WindowStep::Started { .. } => "Started",
        Win16WindowStep::StartedFailure(_) => "StartedFailure",
        Win16WindowStep::DdeStartedFailure(_) => "DdeStartedFailure",
        Win16WindowStep::SourceRetired { .. } => "SourceRetired",
        Win16WindowStep::DdeSourceRetired { .. } => "DdeSourceRetired",
        Win16WindowStep::PendingGuestWork { .. } => "PendingGuestWork",
        Win16WindowStep::NativeDropRetired(_) => "NativeDropRetired",
        Win16WindowStep::PendingModalGuestWork { .. } => "PendingModalGuestWork",
        Win16WindowStep::DdeCallback(_) => "DdeCallback",
        Win16WindowStep::Callback { .. } => "Callback",
        Win16WindowStep::NativeSubclassCallback { .. } => "NativeSubclassCallback",
        Win16WindowStep::DialogCallback { .. } => "DialogCallback",
        Win16WindowStep::GuestTimerCallback { .. } => "GuestTimerCallback",
        Win16WindowStep::WindowPropertyCallback { .. } => "WindowPropertyCallback",
        Win16WindowStep::MetafileCallback { .. } => "MetafileCallback",
        Win16WindowStep::GrayStringCallback { .. } => "GrayStringCallback",
        Win16WindowStep::Untranslated { .. } => "Untranslated",
        Win16WindowStep::Diagnostic(_) => "Diagnostic",
        Win16WindowStep::Complete(_) => "Complete",
    }
}

/// Advance only the cached normal POST owner. A retry reuses the same proof
/// and never issues another native USER post.
pub(super) fn consume_window_post_attempt(
    host: &mut impl crate::RuntimeHost,
    attempt: &mut WindowPostAttempt,
) -> Result<bool, RuntimeError> {
    let receipt = match attempt {
        WindowPostAttempt::SourceRetired(receipt) => receipt,
        WindowPostAttempt::Unproven { result, first_cause } => {
            return Err(RuntimeError::with_source(
                first_cause.kind(),
                format!(
                    "Win16 USER POST {} result remains retained without its normal source proof",
                    window_step_kind(result.as_ref()),
                ),
                Arc::clone(first_cause),
            ));
        }
    };

    if receipt.posted
        != match receipt.result.as_ref() {
            Win16WindowStep::Complete(Win16WindowResult::NotificationPosted(posted)) => {
                Some(*posted)
            }
            _ => None,
        }
    {
        let error = window_post_invariant(
            "cached USER POST result changed from its exact returned step",
        );
        if receipt.first_cause.is_none() {
            receipt.first_cause = Some(Arc::new(error));
        }
    }

    if receipt.phase == WindowPostRetirementPhase::NeedsReadback {
        let proof = receipt.proof.as_ref();
        let readback = match host.win16_window_source_retirement(
            proof.operation.clone(),
            proof.worker_generation,
        ) {
            Ok(readback) => readback,
            Err(error) => return Err(retain_post_cause(receipt, error)),
        };
        let Some(readback) = readback else {
            return Err(retain_post_cause(
                receipt,
                RuntimeError::new(
                    Kind::CompatibilityGap,
                    "USER returned SourceRetired while its exact proof remains live",
                ),
            ));
        };
        if readback.as_ref() != proof {
            return Err(retain_post_cause(
                receipt,
                window_post_invariant("USER POST proof readback changed exact operation identity"),
            ));
        }
        receipt.phase = WindowPostRetirementPhase::ReadBack;
    }
    if receipt.phase == WindowPostRetirementPhase::ReadBack {
        if let Err(error) = host.win16_window_source_retirement_consumed(receipt.proof.as_ref()) {
            return Err(retain_post_cause(receipt, error));
        }
        receipt.phase = WindowPostRetirementPhase::Consumed;
    }
    if let Some(cause) = &receipt.carrier_failure {
        return Err(RuntimeError::with_source(
            cause.kind(),
            "Win16 USER POST carrier was consumed but its result remains invalid",
            Arc::clone(cause),
        ));
    }
    receipt.posted.ok_or_else(|| {
        window_post_invariant("consumed USER POST receipt omitted its exact boolean result")
    })
}

fn retain_post_cause(
    receipt: &mut WindowPostRetirement,
    error: RuntimeError,
) -> RuntimeError {
    let cause = match receipt.first_cause.as_ref() {
        Some(cause) => Arc::clone(cause),
        None => {
            let cause = Arc::new(error);
            receipt.first_cause = Some(Arc::clone(&cause));
            cause
        }
    };
    RuntimeError::with_source(
        cause.kind(),
        "Win16 USER POST proof consumption remains retryable on its exact owner",
        cause,
    )
}

pub(super) fn started_failure_error(
    failure: &Win16WindowOperationStartedFailure,
    context: &str,
) -> RuntimeError {
    RuntimeError::with_source(
        failure.cause.kind(),
        format!(
            "{context}; retained USER POST operation {}:{}",
            failure.operation.operation_id.0,
            failure.worker_generation,
        ),
        Arc::clone(&failure.cause),
    )
}

impl Win16State {
    pub(super) fn terminal_ack_for_post_failure(
        &self,
        failure: &Win16WindowOperationStartedFailure,
        receipt: &Win16WindowAbortReceipt,
        top: &Win16WindowTerminalSourceTop,
    ) -> Result<Win16WindowTerminalAck, RuntimeError> {
        let cached = self.window_abort_receipt.as_ref().ok_or_else(|| {
            window_post_invariant("USER POST retirement has no cached abort receipt")
        })?;
        if cached.request_id != receipt.request_id
            || cached.worker_generation != receipt.worker_generation
            || receipt.request_id == 0
            || receipt.worker_generation == 0
            || failure.worker_generation != receipt.worker_generation
            || failure.operation.operation_id.0 == 0
            || failure.operation.kind
                != Win16NativeWindowOperationKind::PostGuestNotification
        {
            return Err(window_post_invariant(
                "USER POST retirement does not use the exact cached abort generation",
            ));
        }
        match top {
            Win16WindowTerminalSourceTop::User {
                operation,
                kind,
                state,
                worker_generation,
            } if *operation == failure.operation.operation_id
                && *kind == failure.operation.kind
                && *state == failure.state
                && *worker_generation == failure.worker_generation => {}
            _ => {
                return Err(window_post_invariant(
                    "USER POST retirement is not the exact shared source-stack top",
                ));
            }
        }
        if receipt.cancelled_callbacks.iter().any(|cancelled| {
            cancelled.operation_id == failure.operation.operation_id
        }) || receipt.cancelled_modals.iter().any(|cancelled| {
            cancelled.operation_id == failure.operation.operation_id.0
        }) {
            return Err(window_post_invariant(
                "USER POST abort receipt unexpectedly includes callback or modal children",
            ));
        }
        let active_count = receipt
            .active_operations
            .iter()
            .filter(|operation| **operation == failure.operation)
            .count();
        match failure.state {
            Win16NativeWindowOperationState::Active if active_count == 1 => {}
            Win16NativeWindowOperationState::Returned if active_count == 0 => {}
            _ => {
                return Err(window_post_invariant(
                    "USER POST state does not match its retained abort proof",
                ));
            }
        }
        Ok(Win16WindowTerminalAck {
            worker_generation: failure.worker_generation,
            operation: failure.operation.clone(),
            state: failure.state,
            callbacks: Vec::new(),
            modals: Vec::new(),
        })
    }
}

fn window_post_invariant(message: &'static str) -> RuntimeError {
    RuntimeError::new(Kind::InternalInvariant, message)
}
