//! Shared wake, publication and receipt state for one retained NetBIOS source.

use super::{MultimediaWakeSender, PendingRequest, RuntimeError, WakeStatus};
use std::sync::{Arc, Mutex, PoisonError};

pub(super) fn teardown_receipt(
    pending: &PendingRequest,
    status: &WakeStatus,
    reason: runtime::Win16HostNetbiosTeardownReason,
) -> runtime::Win16HostNetbiosTeardownReceipt {
    let cached = pending.teardown_receipt.as_ref();
    let phase = if status.native_terminal && status.event_closed && status.worker_joined {
        runtime::Win16HostNetbiosTeardownPhase::NativeOwnerRetired
    } else if status.no_consumer && status.native_wait_failed && !status.native_terminal {
        runtime::Win16HostNetbiosTeardownPhase::NativeOwnerQuarantined
    } else if status.worker_joined {
        runtime::Win16HostNetbiosTeardownPhase::WorkerJoinFailed
    } else if status.teardown_error.is_some() && status.native_terminal && !status.event_closed {
        runtime::Win16HostNetbiosTeardownPhase::EventCloseFailed
    } else if status.native_terminal && status.event_closed {
        runtime::Win16HostNetbiosTeardownPhase::WorkerJoinPending
    } else if status.teardown_requested {
        runtime::Win16HostNetbiosTeardownPhase::TeardownRequested
    } else if status.terminal_pending
        && status.completion_publication
            == runtime::Win16HostNetbiosCompletionPublication::None
    {
        runtime::Win16HostNetbiosTeardownPhase::TerminalUnpublished
    } else if status.completion_publication
        != runtime::Win16HostNetbiosCompletionPublication::None
        && pending.completion_delivered
    {
        runtime::Win16HostNetbiosTeardownPhase::CompletionDeliveredAwaitingGuestAck
    } else if status.native_terminal {
        runtime::Win16HostNetbiosTeardownPhase::NativeTerminal
    } else {
        runtime::Win16HostNetbiosTeardownPhase::NativePending
    };
    let cause = cached.and_then(|receipt| receipt.cause.as_ref().map(Arc::clone))
        .or_else(|| status.native_wait_error.as_ref().map(Arc::clone))
        .or_else(|| pending.completion_error.as_ref().map(Arc::clone))
        .or_else(|| status.failure_diagnostics.completion_projection.first.as_ref().map(Arc::clone))
        .or_else(|| status.first_wake_error.as_ref().map(Arc::clone))
        .or_else(|| status.wake_retry_error.as_ref().map(Arc::clone))
        .or_else(|| status.no_consumer_error.as_ref().map(Arc::clone));
    let cleanup_error = cached.and_then(|receipt| receipt.cleanup_error.as_ref().map(Arc::clone))
        .or_else(|| status.teardown_error.as_ref().map(Arc::clone))
        .or_else(|| status.no_consumer_error.as_ref().map(Arc::clone))
        .or_else(|| status.additional_wake_error.as_ref().map(Arc::clone));
    runtime::Win16HostNetbiosTeardownReceipt {
        id: pending.id,
        reason,
        phase,
        completion_publication: status.completion_publication,
        native_terminal: status.native_terminal,
        event_closed: status.event_closed,
        worker_joined: status.worker_joined,
        cause,
        cleanup_error,
        failure_diagnostics: status.failure_diagnostics.clone(),
    }
}

pub(super) fn remember_teardown_error(status: &mut WakeStatus, error: RuntimeError) {
    if status.teardown_error.is_none() {
        status.teardown_error = Some(Arc::new(error));
    }
}

pub(super) fn remember_native_event_close_error(
    status: &mut WakeStatus,
    cause: Arc<RuntimeError>,
    context: &'static str,
) {
    status.failure_diagnostics.native_event_close.record(Arc::clone(&cause));
    remember_teardown_error(status, retained_runtime_error(cause, context));
}

pub(super) fn remember_worker_join_error(
    status: &mut WakeStatus,
    cause: Arc<RuntimeError>,
    context: &'static str,
) {
    status.failure_diagnostics.worker_join.record(Arc::clone(&cause));
    remember_teardown_error(status, retained_runtime_error(cause, context));
}

pub(super) fn remember_teardown_handoff_error(status: &mut WakeStatus, error: RuntimeError) {
    let cause = Arc::new(error);
    status.failure_diagnostics.teardown_handoff.record(Arc::clone(&cause));
    remember_teardown_error(
        status,
        retained_runtime_error(cause, "send the exact NetBIOS teardown request to its worker"),
    );
}

pub(super) fn mark_no_consumer(status: &mut WakeStatus, error: RuntimeError) {
    status.no_consumer = true;
    let error = Arc::new(error);
    status.failure_diagnostics.no_consumer.record(Arc::clone(&error));
    if status.no_consumer_error.is_none() {
        status.no_consumer_error = Some(error);
    }
}

pub(super) fn request_wake(status: &Arc<Mutex<WakeStatus>>, terminal: bool) {
    let mut status = status.lock().unwrap_or_else(PoisonError::into_inner);
    if terminal && status.completion_publication != runtime::Win16HostNetbiosCompletionPublication::None {
        return;
    }
    status.pending = true;
    status.terminal_pending |= terminal;
}

pub(super) fn completion_publication_is(
    status: &Arc<Mutex<WakeStatus>>,
    expected: runtime::Win16HostNetbiosCompletionPublication,
) -> bool {
    status.lock().unwrap_or_else(PoisonError::into_inner).completion_publication
        == expected
}

pub(super) fn publish_pending_wake(
    multimedia_wake: &MultimediaWakeSender,
    shared: &Arc<Mutex<WakeStatus>>,
) -> Result<(), RuntimeError> {
    let mut status = shared.lock().unwrap_or_else(PoisonError::into_inner);
    if !status.pending {
        return Ok(());
    }
    match multimedia_wake.signal() {
        Ok(()) => {
            status.pending = false;
            status.wake_retry_error = None;
            if status.terminal_pending {
                status.completion_publication =
                    runtime::Win16HostNetbiosCompletionPublication::SharedWake;
                status.terminal_pending = false;
            }
            Ok(())
        }
        Err(error) => {
            let failure = Arc::new(error);
            status.failure_diagnostics.wake_publication.record(Arc::clone(&failure));
            if status.first_wake_error.is_none() {
                status.first_wake_error = Some(Arc::clone(&failure));
            } else if status.additional_wake_error.is_none() {
                // Keep the original cached cleanup Arc stable. Repeated
                // retries update only the saturating phase count above.
                status.additional_wake_error = Some(Arc::clone(&failure));
            }
            let retained = match status.wake_retry_error.as_ref().map(Arc::clone) {
                Some(current) => current,
                None => {
                    status.wake_retry_error = Some(Arc::clone(&failure));
                    Arc::clone(&failure)
                }
            };
            Err(retained_runtime_error(
                retained,
                "publish the retained NetBIOS completion through the USER/modal wake",
            ))
        }
    }
}

pub(super) fn retained_runtime_error(error: Arc<RuntimeError>, message: &'static str) -> RuntimeError {
    RuntimeError::with_source(error.kind(), message, SharedRuntimeError(error))
}

#[derive(Debug)]
struct SharedRuntimeError(Arc<RuntimeError>);

impl std::fmt::Display for SharedRuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.0.as_ref(), formatter)
    }
}

impl std::error::Error for SharedRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
