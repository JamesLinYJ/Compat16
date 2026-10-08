//! Coalesced requests to revisit WinSock sources at a runtime safe point.
//!
//! The timer is only a compatibility poll demand while an async-select route
//! or unacknowledged event is owned. It never reads a socket or manufactures
//! readiness; RuntimeHost's nonblocking poll produces the actual event. The
//! shared USER signal carries no guest-visible message and does not acknowledge
//! a retained network source.

use std::fmt;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use runtime::{DiagnosticKind, RuntimeError};

use super::multimedia_wake::MultimediaWakeSender;

const POLL_CADENCE: Duration = Duration::from_millis(50);
const RETRY_COOLDOWN: Duration = Duration::from_millis(250);
const FAILURES_PER_COOLDOWN: u8 = 3;

#[derive(Clone)]
pub(super) struct NetworkWakeHub {
    shared: Arc<NetworkWakeShared>,
}

struct NetworkWakeShared {
    sender: MultimediaWakeSender,
    state: Arc<WakeState>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

struct WakeState {
    control: Mutex<WakeControl>,
    changed: Condvar,
}

#[derive(Default)]
struct WakeControl {
    stopped: bool,
    poll_demands: usize,
    requested: bool,
    consecutive_failures: u8,
    first_failure: Option<Arc<RuntimeError>>,
    failure_reported: bool,
}

impl fmt::Debug for NetworkWakeHub {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("NetworkWakeHub").finish_non_exhaustive()
    }
}

impl NetworkWakeHub {
    pub(super) fn new(sender: MultimediaWakeSender) -> Self {
        Self {
            shared: Arc::new(NetworkWakeShared {
                sender,
                state: Arc::new(WakeState {
                    control: Mutex::new(WakeControl::default()),
                    changed: Condvar::new(),
                }),
                worker: Mutex::new(None),
            }),
        }
    }

    /// Start the wake-only worker before the caller accepts a native async
    /// operation. Thread creation failure is reported before that effect.
    pub(super) fn ensure_started(&self) -> Result<(), RuntimeError> {
        let mut worker = self.shared.worker.lock().map_err(|_| {
            RuntimeError::new(DiagnosticKind::InternalInvariant,
                "WinSock wake-worker owner mutex was poisoned")
        })?;
        if worker.is_some() {
            return Ok(());
        }
        if lock_control(&self.shared.state).stopped {
            return Err(RuntimeError::new(DiagnosticKind::HostFailure,
                "WinSock wake owner is shutting down"));
        }
        let state = Arc::clone(&self.shared.state);
        let sender = self.shared.sender.clone();
        *worker = Some(std::thread::Builder::new()
            .name("win16-winsock-wake".to_owned())
            .spawn(move || wake_worker(state, sender))
            .map_err(|error| RuntimeError::with_source(
                DiagnosticKind::ResourceExhausted,
                "start the WinSock safe-point wake worker",
                error,
            ))?);
        Ok(())
    }

    pub(super) fn set_poll_demands(&self, count: usize) {
        let mut control = lock_control(&self.shared.state);
        if control.stopped {
            return;
        }
        let was_idle = control.poll_demands == 0;
        control.poll_demands = count;
        if was_idle && count != 0 {
            control.requested = true;
            self.shared.state.changed.notify_one();
        }
    }

    /// Record a queued completion/event before asking USER to revisit runtime
    /// safe points. A wake is only a hint; ownership stays in the source FIFO.
    pub(super) fn request_poll(&self) {
        let mut control = lock_control(&self.shared.state);
        if control.stopped {
            return;
        }
        control.requested = true;
        self.shared.state.changed.notify_one();
    }

    /// Report the first signal failure once. The worker retains its typed
    /// cause while bounded retries continue; a later successful wake clears it.
    pub(super) fn take_failure(&self) -> Option<RuntimeError> {
        let mut control = lock_control(&self.shared.state);
        if control.failure_reported {
            return None;
        }
        let failure = control.first_failure.as_ref()?.clone();
        control.failure_reported = true;
        Some(RuntimeError::with_source(
            failure.kind(),
            "WinSock source remains retained after a USER wake signal failure",
            failure,
        ))
    }

    pub(super) fn shutdown(&self) {
        {
            let mut control = lock_control(&self.shared.state);
            control.stopped = true;
            control.requested = false;
            control.poll_demands = 0;
            self.shared.state.changed.notify_all();
        }
        let worker = self.shared.worker.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(worker) = worker {
            let _ = worker.join();
        }
    }
}

fn wake_worker(state: Arc<WakeState>, sender: MultimediaWakeSender) {
    loop {
        let mut control = lock_control(&state);
        while !control.stopped && !has_demand(&control) {
            control = state.changed.wait(control)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        if control.stopped {
            return;
        }

        let throttled = control.consecutive_failures >= FAILURES_PER_COOLDOWN;
        let delay = if throttled { RETRY_COOLDOWN } else { POLL_CADENCE };
        let deadline = Instant::now() + delay;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let (next, result) = state.changed.wait_timeout(control, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            control = next;
            if control.stopped {
                return;
            }
            if result.timed_out() || !throttled {
                break;
            }
        }
        if !has_demand(&control) {
            continue;
        }
        if throttled {
            control.consecutive_failures = 0;
        }
        // Clear this request before dropping the lock. Requests arriving
        // during SetEvent then remain set instead of being erased on return.
        control.requested = false;
        drop(control);

        let result = sender.signal();
        let mut control = lock_control(&state);
        match result {
            Ok(()) => {
                control.consecutive_failures = 0;
                // Preserve an unreported cause until Runtime reaches a safe
                // point and observes it. Once reported, this successful
                // signal closes that failure episode and allows a new cause.
                if control.failure_reported {
                    control.first_failure = None;
                    control.failure_reported = false;
                }
            }
            Err(error) => {
                control.requested = true;
                if control.first_failure.is_none() {
                    control.first_failure = Some(Arc::new(error));
                }
                control.consecutive_failures = control.consecutive_failures.saturating_add(1);
            }
        }
    }
}

fn has_demand(control: &WakeControl) -> bool {
    control.requested || control.poll_demands != 0
}

fn lock_control(state: &WakeState) -> std::sync::MutexGuard<'_, WakeControl> {
    state.control.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
