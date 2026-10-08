//! Run-entry reconciliation for a MCI Begin request accepted by the host.

use std::error::Error;
use std::sync::Arc;

use guest_core::memory::Memory;

use super::{
    Win16MciContinuation, Win16MciFinishPhase, Win16MciState,
    Win16State,
};
use crate::{DiagnosticKind, RuntimeError, RuntimeHost, Win16HostMciStep};

#[derive(Debug)]
struct MciPendingBeginFailure {
    operation: crate::Win16HostMciOperationId,
    phase: crate::Win16HostMciBeginFailurePhase,
    original_cause: Arc<RuntimeError>,
    retry_cause: Option<Arc<RuntimeError>>,
    cached_step: bool,
    yield_event: Option<crate::Win16HostMciYieldEvent>,
}

impl std::fmt::Display for MciPendingBeginFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MCI operation {} remains in {:?}; original host cause: {}",
            self.operation.0, self.phase, self.original_cause
        )?;
        if !self.cached_step {
            formatter.write_str(
                "; original Begin result is still awaited and any yield frame is unknown",
            )?;
        }
        if let Some(event) = self.yield_event {
            write!(
                formatter,
                "; exact cached yield is operation {} frame {} device {}:{} registration {}",
                event.operation.0,
                event.frame.0,
                event.device.token,
                event.device.generation,
                event.registration.0
            )?;
        }
        if let Some(cause) = &self.retry_cause {
            write!(formatter, "; latest retry cause: {cause}")?;
        }
        Ok(())
    }
}

impl Error for MciPendingBeginFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.original_cause.as_ref())
    }
}

#[derive(Debug)]
struct MciBeginRetryHistory {
    earlier: Arc<RuntimeError>,
    later: Arc<RuntimeError>,
}

impl std::fmt::Display for MciBeginRetryHistory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "earlier retry cause: {}; later retry cause: {}", self.earlier, self.later)
    }
}

impl Error for MciBeginRetryHistory {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.earlier.as_ref())
    }
}

pub(super) fn retry_pending_begin(
    state: &mut Win16State,
    cpu: &mut x86_cpu::Cpu,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<(), RuntimeError> {
    let context = state
        .mci
        .pending_begin
        .as_ref()
        .map(|pending| pending.cpu_context.clone())
        .ok_or_else(|| {
            RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "MCI Begin retry has no retained request owner",
            )
        })?;
    if let Err(error) = cpu.restore_context(&context) {
        let error = crate::runtime_error(error);
        retain_retry_cause(&mut state.mci, Arc::new(error));
        return Err(pending_begin_error(&state.mci));
    }

    if state
        .mci
        .pending_begin
        .as_ref()
        .is_some_and(|pending| pending.cached_step.is_none())
    {
        let operation = state
            .mci
            .pending_begin
            .as_ref()
            .expect("pending Begin is retained")
            .operation;
        match host.win16_mci_reconcile_begin(operation) {
            Ok(Some(step)) => {
                // Publish the exact full host result into the runtime owner
                // before any guest callback, writeback, or native resume.
                if let Win16HostMciStep::Complete(result) = &step {
                    let proof = crate::Win16HostMciOperationCompletion {
                        operation,
                        native_return_value: result.return_value,
                    };
                    if !state.mci.completed_operations.contains(&proof) {
                        state.mci.completed_operations.push(proof);
                    }
                }
                state
                    .mci
                    .pending_begin
                    .as_mut()
                    .expect("pending Begin is retained")
                    .cached_step = Some(step);
            }
            Ok(None) => {
                let cause = Arc::new(RuntimeError::new(
                    DiagnosticKind::CompatibilityGap,
                    "the original enqueued MCI Begin result is not available yet",
                ));
                if state
                    .mci
                    .pending_begin
                    .as_ref()
                    .is_some_and(|pending| pending.retry_failure.is_none())
                {
                    state
                        .mci
                        .pending_begin
                        .as_mut()
                        .expect("pending Begin is retained")
                        .retry_failure = Some(cause);
                }
                return Err(pending_begin_error(&state.mci));
            }
            Err(error) => {
                retain_retry_cause(&mut state.mci, Arc::new(error));
                return Err(pending_begin_error(&state.mci));
            }
        }
    }

    let invalid_yield = state.mci.pending_begin.as_ref().and_then(|pending| {
        if pending.cached_step_failure.is_some() {
            return None;
        }
        match pending.cached_step.as_ref() {
            Some(Win16HostMciStep::Yield(event))
                if event.operation != pending.operation || event.frame.0 == 0 =>
            {
                Some((pending.operation, *event))
            }
            _ => None,
        }
    });
    if let Some((expected_operation, event)) = invalid_yield {
        let cause = Arc::new(RuntimeError::new(
            DiagnosticKind::InternalInvariant,
            format!(
                "exact MCI Begin result for operation {} contains yield operation {} frame {}; the full mismatched result remains cached",
                expected_operation.0,
                event.operation.0,
                event.frame.0
            ),
        ));
        if let Some(pending) = state.mci.pending_begin.as_mut() {
            pending.cached_step_failure = Some(Arc::clone(&cause));
        }
        retain_retry_cause(&mut state.mci, cause);
        return Err(pending_begin_error(&state.mci));
    }
    if state
        .mci
        .pending_begin
        .as_ref()
        .is_some_and(|pending| pending.cached_step_failure.is_some())
    {
        return Err(pending_begin_error(&state.mci));
    }
    let cached = state
        .mci
        .pending_begin
        .as_ref()
        .and_then(|pending| pending.cached_step.as_ref())
        .ok_or_else(|| {
            RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "MCI Begin reconciliation returned without retaining its exact result",
            )
        })?;
    match cached {
        Win16HostMciStep::Complete(result) => {
            let (request, result, return_to, return_kind) = {
                let pending = state
                    .mci
                    .pending_begin
                    .as_ref()
                    .expect("pending Begin is retained");
                (
                    pending.request.clone(),
                    result.clone(),
                    pending.return_to,
                    pending.return_kind,
                )
            };
            let resolved_count = state
                .mci
                .pending_begin
                .as_ref()
                .map(|pending| 1 + usize::from(pending.retry_failure.is_some()))
                .unwrap_or(1);
            state
                .mci
                .resolved_finish_causes
                .try_reserve(resolved_count)
                .map_err(|error| {
                    RuntimeError::with_source(
                        DiagnosticKind::ResourceExhausted,
                        "reserve MCI Begin retry history before guest result projection",
                        error,
                    )
                })?;
            if let Err(error) = super::completion::complete(
                state,
                request,
                result,
                &mut cpu.regs,
                memory,
                host,
                return_to,
                return_kind,
            ) {
                retain_retry_cause(&mut state.mci, Arc::new(error));
                return Err(pending_begin_error(&state.mci));
            }
            let pending = state
                .mci
                .pending_begin
                .take()
                .expect("completed Begin owner remains retained");
            state.mci.resolved_finish_causes.push(pending.cause);
            if let Some(cause) = pending.retry_failure {
                state.mci.resolved_finish_causes.push(cause);
            }
        }
        Win16HostMciStep::Yield(event) => {
            // Copy the exact event before taking its owner out of pending_begin.
            let event = *event;
            let resolved_count = state
                .mci
                .pending_begin
                .as_ref()
                .map(|pending| 1 + usize::from(pending.retry_failure.is_some()))
                .unwrap_or(1);
            state
                .mci
                .resolved_finish_causes
                .try_reserve(resolved_count)
                .map_err(|error| {
                    RuntimeError::with_source(
                        DiagnosticKind::ResourceExhausted,
                        "reserve MCI Begin retry history before callback publication",
                        error,
                    )
                })?;
            let pending = state
                .mci
                .pending_begin
                .take()
                .expect("yielding Begin owner remains retained");
            let continuation = Win16MciContinuation {
                request: pending.request,
                callback_id: pending.callback_id,
                next_callback_id: None,
                operation: event.operation,
                event,
                active_call: None,
                cpu_context: pending.cpu_context,
                caller_code: pending.caller_code,
                return_to: pending.return_to,
                return_kind: pending.return_kind,
                finish_phase: Win16MciFinishPhase::PreEntryPending,
                guest_return: None,
                next_event: None,
                completed_result: None,
                unexpected_step: None,
                finish_failure: None,
                invalid_return_snapshot: None,
                returned_yields: Vec::new(),
            };
            let result = state.publish_mci_yield_callback(
                continuation,
                &mut cpu.regs,
                memory,
            );
            state.mci.resolved_finish_causes.push(pending.cause);
            if let Some(cause) = pending.retry_failure {
                state.mci.resolved_finish_causes.push(cause);
            }
            result?;
        }
    }
    Ok(())
}

fn retain_retry_cause(state: &mut Win16MciState, next: Arc<RuntimeError>) {
    let Some(pending) = state.pending_begin.as_mut() else {
        return;
    };
    pending.retry_failure = Some(match pending.retry_failure.take() {
        Some(earlier) => {
            let kind = earlier.kind().with_cleanup(next.kind());
            Arc::new(RuntimeError::with_source(
                kind,
                "MCI Begin retry preserves both typed reconciliation failures",
                MciBeginRetryHistory { earlier, later: next },
            ))
        }
        None => next,
    });
}

fn pending_begin_error(state: &Win16MciState) -> RuntimeError {
    let pending = state
        .pending_begin
        .as_ref()
        .expect("pending Begin remains owned while its error is constructed");
    let yield_event = pending.cached_step.as_ref().and_then(|step| match step {
        Win16HostMciStep::Yield(event) => Some(*event),
        Win16HostMciStep::Complete(_) => None,
    });
    let kind = pending
        .retry_failure
        .as_ref()
        .map_or(pending.cause.kind(), |cause| {
            pending.cause.kind().with_cleanup(cause.kind())
        });
    RuntimeError::with_source(
        kind,
        "MCI Begin retains its exact request and entry CPU context for run-entry reconciliation",
        MciPendingBeginFailure {
            operation: pending.operation,
            phase: pending.phase,
            original_cause: Arc::clone(&pending.cause),
            retry_cause: pending.retry_failure.as_ref().map(Arc::clone),
            cached_step: pending.cached_step.is_some(),
            yield_event,
        },
    )
}
