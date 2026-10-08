//! Native owner shutdown report assembly after the DDE worker loop exits.

use std::sync::Arc;

use runtime::{DiagnosticKind as Kind, RuntimeError};

use super::{WorkerContext, WorkerTlsGuard, callback_replies, control_window, native};

pub(super) fn finalize(
    context: &WorkerContext,
    tls_guard: &mut WorkerTlsGuard,
    window: control_window::ControlWindow,
) {
    let mut shutdown_result = super::take_shutdown_error(context).map_or(Ok(()), Err);
    if let Some(error) = super::take_fatal_failure(context) {
        shutdown_result = super::combine_result(shutdown_result, Err(error));
    }
    if let Some(error) = super::take_emergency_failure(context) {
        shutdown_result = super::combine_result(shutdown_result, Err(error));
    }
    let reply_report = callback_replies::release_failed_callback_replies(context);
    let instance_report = native::uninitialize_all(context);
    let control_window_destroyed = match control_window::destroy(window) {
        Ok(()) => true,
        Err(error) => {
            shutdown_result = super::combine_result(shutdown_result, Err(error));
            false
        }
    };
    let all_native_callbacks_returned = context.active_callbacks.borrow().is_empty()
        && !context.untracked_callback_failure.get();
    let all_active_operations_returned = context.active_operations.borrow().is_empty();
    if !reply_report.all_released_or_transferred {
        shutdown_result = super::combine_result(
            shutdown_result,
            Err(RuntimeError::new(
                Kind::InternalInvariant,
                "DDE native reply owner ledger did not prove complete transfer or release",
            )),
        );
    }
    if !instance_report.all_transfer_guards_retired {
        shutdown_result = super::combine_result(
            shutdown_result,
            Err(RuntimeError::new(
                Kind::HostFailure,
                "DDE native transfer guard map did not prove exact retirement",
            )),
        );
    }
    tls_guard.clear();
    let terminal_error = match shutdown_result {
        Ok(()) => None,
        Err(error) => {
            let shared = Arc::new(error);
            let event_error = RuntimeError::with_source(
                shared.kind(),
                "DDEML owner shutdown failed",
                Arc::clone(&shared),
            );
            let receipt_error = RuntimeError::with_source(
                shared.kind(),
                "DDEML owner shutdown receipt contains this failure",
                Arc::clone(&shared),
            );
            match context.event_sender.send(super::WorkerEvent::ShutdownFailure(event_error)) {
                Ok(()) => Some(Arc::new(receipt_error)),
                Err(_) => Some(Arc::new(receipt_error.with_cleanup(
                    "the DDEML shutdown failure notification could not be published",
                    super::disconnected("publish a DDEML shutdown failure notification"),
                ))),
            }
        }
    };
    let native_owner_receipt = runtime::Win16DdeNativeOwnerShutdownReceipt {
        owner: context.owner,
        worker_generation: context.worker_generation,
        request_id: context.shutdown_request_id.get().unwrap_or(0),
        all_native_callbacks_returned,
        all_active_operations_returned,
        all_native_replies_released_or_transferred: reply_report.all_released_or_transferred,
        all_native_transfer_guards_retired: instance_report.all_transfer_guards_retired,
        all_native_instances_uninitialized: instance_report.all_uninitialized,
        control_window_destroyed,
    };
    let mut cleanup_failures = reply_report.failures;
    cleanup_failures.extend(instance_report.failures);
    if let Some(error) = terminal_error.as_ref() {
        cleanup_failures.push(runtime::Win16DdeCleanupFailure {
            phase: runtime::Win16DdeAbortPhase::DestroyControlWindow,
            frame: None,
            operation: None,
            instance: None,
            status: if control_window_destroyed {
                runtime::Win16DdeCleanupStatus::RetriedAndReleased
            } else {
                runtime::Win16DdeCleanupStatus::Unresolved
            },
            cause: Arc::clone(error),
        });
    }
    let report = super::super::WorkerShutdownReport {
        native_owner_receipt,
        native_instances: instance_report.instances,
        native_transfer_guards: instance_report.transfer_guards,
        native_replies: reply_report.replies,
        cleanup_failures,
        terminal_error,
    };
    let _ = context.shutdown_completion.send(report);
}
