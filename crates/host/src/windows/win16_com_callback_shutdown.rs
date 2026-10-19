//! Exact cancellation acknowledgements and native callback-stack retirement.

use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::TryRecvError;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16ComHostCallbackFailureKind, Win16ComHostStep,
};

use super::{
    CallbackEndpoint, CallbackShared, Win16ComCallbackRuntime, Win16ComHostCallbackRoute,
    callback_failure,
};
use std::sync::{Arc, Weak};

pub(super) struct NativeCallbackDispatchGuard<'a>(&'a AtomicUsize);

impl Drop for NativeCallbackDispatchGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

pub(super) fn enter_native_dispatch(shared: &CallbackShared) -> NativeCallbackDispatchGuard<'_> {
    shared
        .active_native_dispatches
        .fetch_add(1, Ordering::AcqRel);
    NativeCallbackDispatchGuard(&shared.active_native_dispatches)
}

pub(super) fn seal_and_cancel_pending(
    callbacks: &Win16ComCallbackRuntime,
    context: &'static str,
) -> Result<(), RuntimeError> {
    let mut pending = callbacks.shared.pending.lock().map_err(|_| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "COM callback state lock was poisoned during Seal",
        )
    })?;
    let additional = pending
        .frames
        .values()
        .filter(|callback| callback.reply.is_some())
        .count();
    pending
        .sealed_receipts
        .try_reserve(additional)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact COM callback Seal receipts",
                error,
            )
        })?;
    pending.closed = true;

    for callback in pending.frames.values_mut() {
        let Some(reply) = callback.reply.take() else {
            continue;
        };
        let checked_failure = callback_failure(
            Win16ComHostCallbackFailureKind::CheckedGuestCallback,
            context,
        );
        let failure = if reply
            .send(super::Win16ComHostCallbackOutcome::Failed(
                checked_failure.clone(),
            ))
            .is_ok()
        {
            checked_failure
        } else {
            callback_failure(
                Win16ComHostCallbackFailureKind::CallbackTransport,
                "checked COM callback receiver had already retired before owner Seal",
            )
        };
        callback.sealed_failure = Some(failure.clone());
        // The original callback and acknowledgement stay in the frame. Only
        // an owning-STA native-return boundary may publish its failure receipt.
    }
    if additional != 0
        && (crate::windows::win32_safe::set_event(callbacks.shared.worker_wake.as_raw_handle() as _))
            == 0
    {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "wake USER STA to return sealed native COM callbacks",
        ));
    }
    Ok(())
}

pub(super) fn sealed_receipts_polled(shared: &CallbackShared) -> bool {
    shared
        .pending
        .lock()
        .map(|pending| pending.sealed_receipts.is_empty())
        .unwrap_or(false)
}

pub(super) fn has_pending_failures(shared: &CallbackShared) -> bool {
    let failures = match shared.failures.lock() {
        Ok(failures) => failures,
        Err(poisoned) => poisoned.into_inner(),
    };
    !failures.is_empty()
}

pub(super) fn native_stacks_quiet(shared: &CallbackShared) -> bool {
    if shared.active_native_dispatches.load(Ordering::Acquire) != 0 {
        return false;
    }
    let Ok(mut pending) = shared.pending.lock() else {
        return false;
    };
    // Called by the USER STA after its native dispatch scopes return. A reply
    // send, a disconnected channel, or an empty frame map is not that proof.
    let additional = pending
        .frames
        .values()
        .filter(|callback| callback.sealed_failure.is_some())
        .count();
    if pending.sealed_receipts.try_reserve(additional).is_err() {
        return false;
    }
    let super::CallbackPendingState {
        frames,
        sealed_receipts,
        ..
    } = &mut *pending;
    frames.retain(|frame, callback| {
        if callback.reply.is_some() {
            return true;
        }
        let Some(acknowledgement) = callback.acknowledgement.as_mut() else {
            return true;
        };
        match acknowledgement.try_recv() {
            Ok(()) => {
                if let Some(failure) = callback.sealed_failure.take() {
                    sealed_receipts.push(Win16ComHostStep::CallbackFailed {
                        frame: Some(*frame),
                        parent: callback.parent,
                        owner: callback.owner,
                        route: callback.route,
                        failure,
                    });
                }
                false
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => true,
        }
    });
    frames.is_empty()
}

pub(super) fn cancel_pending_frames(
    shared: &CallbackShared,
    context: String,
    close: bool,
) -> Vec<Win16ComHostStep> {
    let mut steps = Vec::new();
    let has_frames = {
        let mut pending = match shared.pending.lock() {
            Ok(pending) => pending,
            Err(poisoned) => poisoned.into_inner(),
        };
        if close {
            pending.closed = true;
        }
        for (frame, callback) in pending.frames.iter_mut() {
            let Some(reply) = callback.reply.take() else {
                continue;
            };
            let failure = callback_failure(
                Win16ComHostCallbackFailureKind::CallbackTransport,
                context.clone(),
            );
            let _ = reply.send(super::Win16ComHostCallbackOutcome::Failed(failure.clone()));
            callback.sealed_failure = Some(failure.clone());
            // This returned value is a cancellation signal. Runtime ingress
            // exposes the receipt only after the native return and real ACK.
            steps.push(Win16ComHostStep::CallbackFailed {
                frame: Some(*frame),
                parent: callback.parent,
                owner: callback.owner,
                route: callback.route,
                failure,
            });
        }
        !steps.is_empty()
    };
    if has_frames {
        (crate::windows::win32_safe::set_event(shared.worker_wake.as_raw_handle() as _));
    }
    steps
}

pub(super) fn remove_endpoint(
    shared: &CallbackShared,
    route: Win16ComHostCallbackRoute,
    expected: &Arc<CallbackEndpoint>,
) {
    if let Ok(mut endpoints) = shared.endpoints.lock() {
        let is_expected = endpoints
            .get(&route)
            .and_then(Weak::upgrade)
            .is_some_and(|actual| Arc::ptr_eq(&actual, expected));
        if is_expected {
            endpoints.remove(&route);
        }
    }
}
