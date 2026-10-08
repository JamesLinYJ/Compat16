use super::super::WorkerThreadState;
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostMciDevice, Win16HostMciOperationId,
    Win16HostMciYieldFrame,
};
use std::error::Error;
use std::fmt;
use std::sync::{Arc, PoisonError};

#[derive(Clone, Copy, Debug)]
pub(super) enum MciWorkerWaitPhase {
    OwnerLoop,
    ShutdownRetry,
    Yield {
        operation: Win16HostMciOperationId,
        frame: Win16HostMciYieldFrame,
        device: Win16HostMciDevice,
    },
}

impl fmt::Display for MciWorkerWaitPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OwnerLoop => formatter.write_str("the MCI owner command loop"),
            Self::ShutdownRetry => formatter.write_str("MCI owner shutdown retry"),
            Self::Yield {
                operation,
                frame,
                device,
            } => write!(
                formatter,
                "MCI operation {} YIELD frame {} for device token {} generation {}",
                operation.0, frame.0, device.token, device.generation
            ),
        }
    }
}

#[derive(Debug)]
struct MciWorkerWaitFailure {
    phase: MciWorkerWaitPhase,
    wait_result: u32,
    last_error: Option<u32>,
}

impl fmt::Display for MciWorkerWaitFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "MsgWaitForMultipleObjects returned 0x{:08X} during {}",
            self.wait_result, self.phase
        )?;
        if let Some(last_error) = self.last_error {
            write!(formatter, "; Win32 last-error 0x{last_error:08X}")?;
        }
        Ok(())
    }
}

impl Error for MciWorkerWaitFailure {}

pub(super) fn retain_wait_failure(
    state: &WorkerThreadState,
    phase: MciWorkerWaitPhase,
    wait_result: u32,
    last_error: Option<u32>,
) {
    let cause = Arc::new(RuntimeError::with_source(
        Kind::HostFailure,
        "native MCI worker wait failed; its original worker and native operation remain owned",
        MciWorkerWaitFailure {
            phase,
            wait_result,
            last_error,
        },
    ));
    let retained_first = state
        .notifications
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .retain_worker_wait_failure(cause);
    if retained_first {
        retry_worker_wait_wake(state);
    }
}

/// Retry only the no-payload USER wake until the runtime reads the retained
/// cause; successful publication is not proof that the consumer saw it.
pub(super) fn retry_worker_wait_wake(state: &WorkerThreadState) {
    let pending = state
        .notifications
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .worker_wait_wake_pending();
    if !pending {
        return;
    }
    match state.multimedia_wake.signal() {
        Ok(()) => {}
        Err(error) => state
            .notifications
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain_worker_wait_wake_failure(error),
    }
}
