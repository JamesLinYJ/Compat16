//! Exact callback publication for native MCI yield frames.

use guest_core::{Registers, memory::Memory};

use super::{CallbackKind, Win16MciContinuation, Win16MciFinishPhase, Win16State, errors};
use crate::{DiagnosticKind as Kind, RuntimeError};

impl Win16State {
    pub(super) fn publish_mci_yield_callback(
        &mut self,
        mut continuation: Win16MciContinuation,
        registers: &mut Registers,
        memory: &mut Memory,
    ) -> Result<(), RuntimeError> {
        let callback_id = continuation.callback_id;
        let event = continuation.event;
        if let Err(error) = self.mci.active.try_reserve(1) {
            return Err(retain_unpublished(
                self,
                continuation,
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve exact MCI yield continuation before callback entry",
                    error,
                ),
            ));
        }
        if let Err(error) = self.callback_kinds.try_reserve(1) {
            return Err(retain_unpublished(
                self,
                continuation,
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve exact MCI callback LIFO binding before guest entry",
                    error,
                ),
            ));
        }

        continuation.active_call = None;
        continuation.finish_phase = Win16MciFinishPhase::PreEntryPending;
        self.mci.active.push(continuation);
        self.callback_kinds.push(CallbackKind::Mci);

        let active_call = match self.prepare_yield_callback(event, registers, memory) {
            Ok(active_call) => active_call,
            Err(cause) => return Err(retain_published_preentry(self, callback_id, cause)),
        };

        if !self.mci.callback_top_matches(callback_id)
            || !matches!(self.callback_kinds.last(), Some(CallbackKind::Mci))
        {
            let cause = RuntimeError::new(
                Kind::InternalInvariant,
                "MCI callback publication lost its exact active/LIFO top after FAR entry",
            );
            if let Some(continuation) = self
                .mci
                .active
                .iter_mut()
                .find(|continuation| continuation.callback_id == callback_id)
            {
                continuation.active_call = Some(active_call);
                continuation.finish_phase = Win16MciFinishPhase::GuestCallback;
                let cause = errors::retain_finish_failure(
                    &mut continuation.finish_failure,
                    cause,
                );
                return Err(finish_failure(continuation, cause));
            }
            return Err(cause.with_context(
                "entered MCI callback frame has no continuation owner to retain",
            ));
        }

        let continuation = self
            .mci
            .active
            .last_mut()
            .expect("the exact MCI callback top was checked");
        continuation.active_call = Some(active_call);
        continuation.invalid_return_snapshot = None;
        continuation.finish_phase = Win16MciFinishPhase::GuestCallback;
        Ok(())
    }
}

fn retain_unpublished(
    state: &mut Win16State,
    mut continuation: Win16MciContinuation,
    cause: RuntimeError,
) -> RuntimeError {
    continuation.active_call = None;
    continuation.finish_phase = Win16MciFinishPhase::PreEntryAborted;
    let cause = errors::retain_finish_failure(&mut continuation.finish_failure, cause);
    state.mci.pending_cleanup.push(super::Win16MciPendingCleanup {
        continuation,
        unexpected_step: None,
    });
    let retained = state
        .mci
        .pending_cleanup
        .last()
        .expect("reserved MCI pending slot was filled");
    finish_failure(&retained.continuation, cause)
}

fn retain_published_preentry(
    state: &mut Win16State,
    callback_id: super::super::CallbackFrameId,
    cause: RuntimeError,
) -> RuntimeError {
    let Some(continuation) = state
        .mci
        .active
        .iter_mut()
        .find(|continuation| continuation.callback_id == callback_id)
    else {
        return cause.with_context(
            "MCI FAR entry failed after its exact continuation owner disappeared",
        );
    };
    continuation.active_call = None;
    continuation.finish_phase = Win16MciFinishPhase::PreEntryAborted;
    let cause = errors::retain_finish_failure(&mut continuation.finish_failure, cause);
    finish_failure(continuation, cause)
}

fn finish_failure(
    continuation: &Win16MciContinuation,
    cause: std::sync::Arc<RuntimeError>,
) -> RuntimeError {
    RuntimeError::with_source(
        cause.kind(),
        "MCI yield callback retains its exact native and guest owner phase",
        super::errors::MciFinishFailure {
            callback_id: continuation.callback_id,
            event: continuation.event,
            phase: continuation.finish_phase,
            guest_return: continuation.guest_return,
            cancellation_gap: errors::cancellation_gap(continuation.finish_phase),
            unexpected_step: None,
            guest_return_snapshot: continuation.invalid_return_snapshot,
            cause,
        },
    )
}
