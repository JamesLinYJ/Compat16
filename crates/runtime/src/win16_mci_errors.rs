//! Typed diagnostics for retained MCI callback and native-yield phases.

use super::Win16MciFinishPhase;
use super::{super::CallbackFrameId, Win16MciGuestReturnSnapshot};
use crate::{DiagnosticKind, RuntimeError, Win16HostMciYieldEvent};
use std::sync::Arc;

#[derive(Debug)]
pub(super) struct MciFinishFailure {
    pub(super) callback_id: CallbackFrameId,
    pub(super) event: Win16HostMciYieldEvent,
    pub(super) phase: Win16MciFinishPhase,
    pub(super) guest_return: Option<u16>,
    pub(super) cause: Arc<RuntimeError>,
    pub(super) unexpected_step: Option<crate::Win16HostMciResumeReceipt>,
    pub(super) guest_return_snapshot: Option<Win16MciGuestReturnSnapshot>,
    /// The legacy target contract used by this runtime does not establish a
    /// cancellation return value for an already active YIELDPROC. Keep that
    /// gap typed beside the exact retained phase instead of inventing a WORD.
    pub(super) cancellation_gap: Option<Arc<RuntimeError>>,
}

impl std::fmt::Display for MciFinishFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let phase = match self.phase {
            Win16MciFinishPhase::PreEntryPending => "pre-entry pending",
            Win16MciFinishPhase::PreEntryAborted => "pre-entry aborted",
            Win16MciFinishPhase::GuestCallback => "guest callback",
            Win16MciFinishPhase::GuestReturnValidation => "guest return validation",
            Win16MciFinishPhase::RestoreCaller => "caller context restore",
            Win16MciFinishPhase::ResumeNative => "native resume",
            Win16MciFinishPhase::EnterNextCallback => "next guest callback entry",
            Win16MciFinishPhase::CompleteGuestCall => "guest call completion",
            Win16MciFinishPhase::UnexpectedHostStep => "unexpected host step",
        };
        write!(
            formatter,
            "MCI callback {} for operation {} frame {} on device token {} generation {} remains in {}",
            self.callback_id.0,
            self.event.operation.0,
            self.event.frame.0,
            self.event.device.token,
            self.event.device.generation,
            phase,
        )?;
        if let Some(value) = self.guest_return {
            write!(formatter, " with cached guest WORD {value:#06x}")?;
        }
        if let Some(snapshot) = self.guest_return_snapshot {
            write!(
                formatter,
                " with retained guest return state CS:IP={:04X}:{:04X} SS:SP={:04X}:{:04X} AX={:04X} DX={:04X}",
                snapshot.cs, snapshot.ip, snapshot.ss, snapshot.sp, snapshot.ax, snapshot.dx,
            )?;
        }
        write!(formatter, ": {}", self.cause)?;
        if let Some(gap) = &self.cancellation_gap {
            write!(formatter, "; native yield cancellation is unresolved: {gap}")?;
        }
        if let Some(step) = &self.unexpected_step {
            write!(
                formatter,
                "; exact unexpected host resume for operation {} frame {} on device token {} generation {} retained",
                step.returned_yield.owner.operation.0,
                step.returned_yield.owner.frame.0,
                step.returned_yield.owner.device.token,
                step.returned_yield.owner.device.generation,
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for MciFinishFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

pub(super) fn cancellation_gap(phase: Win16MciFinishPhase) -> Option<Arc<RuntimeError>> {
    (!matches!(phase, Win16MciFinishPhase::CompleteGuestCall)).then(|| {
        Arc::new(RuntimeError::new(
            DiagnosticKind::CompatibilityGap,
            "no verified native MCI YIELDPROC cancellation WORD is available for this retained phase",
        ))
    })
}

pub(super) fn retain_finish_failure(
    slot: &mut Option<Arc<RuntimeError>>,
    next: RuntimeError,
) -> Arc<RuntimeError> {
    let next = Arc::new(next);
    let retained = match slot.take() {
        Some(previous) => {
            let kind = previous.kind().with_cleanup(next.kind());
            Arc::new(RuntimeError::with_source(
                kind,
                "MCI callback phase retains both prior and current typed failures",
                MciFinishFailureHistory { previous, next },
            ))
        }
        None => next,
    };
    *slot = Some(Arc::clone(&retained));
    retained
}

#[derive(Debug)]
struct MciFinishFailureHistory {
    previous: Arc<RuntimeError>,
    next: Arc<RuntimeError>,
}

impl std::fmt::Display for MciFinishFailureHistory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "previous failure: {}; current failure: {}",
            self.previous, self.next
        )
    }
}

impl std::error::Error for MciFinishFailureHistory {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.next.as_ref())
    }
}
