//! Shared no-payload wake signal for native guest-work mailboxes.
//!
//! A producer must first retain its typed event in its own mailbox, then call
//! `signal`. The USER worker observes only the shared generation; it never
//! receives family payloads, native handles, or guest addresses here.
//! Producers must quiesce and resolve their retained events before the USER
//! worker is shut down; cloning this sender keeps the event handle alive but
//! does not keep the worker thread or a consumer alive.

use std::io;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use runtime::{DiagnosticKind as Kind, RuntimeError};

#[derive(Clone)]
pub(crate) struct MultimediaWakeSender {
    event: Arc<OwnedHandle>,
    generation: Arc<AtomicU64>,
    worker_alive: Arc<AtomicBool>,
    modal_control: Arc<super::win16_modal::ModalWorkerControl>,
    _modal_abort_owner: Arc<super::win16_windows::ModalWakeDispatcher>,
}

impl MultimediaWakeSender {
    pub(super) fn from_worker_event(
        event: Arc<OwnedHandle>,
        generation: Arc<AtomicU64>,
        worker_alive: Arc<AtomicBool>,
        modal_control: Arc<super::win16_modal::ModalWorkerControl>,
        modal_abort_owner: Arc<super::win16_windows::ModalWakeDispatcher>,
    ) -> Self {
        Self {
            event,
            generation,
            worker_alive,
            modal_control,
            _modal_abort_owner: modal_abort_owner,
        }
    }

    /// Readiness is an independent observer. It never resets USER's event or
    /// acknowledges the typed source payload represented by this generation.
    pub(crate) fn generation_observer(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.generation)
    }

    /// Report the irreversible USER-lane state so a producer can request its
    /// own exact cleanup handoff after normal publication becomes impossible.
    pub(crate) fn terminal_requested(&self) -> bool {
        self.modal_control.terminal_requested()
    }

    /// Publish a no-payload wake after the caller retains its typed event.
    /// Any error leaves that source event owned by its producer; it is not an
    /// acknowledgement, even when the shared epoch advanced successfully.
    pub(crate) fn signal(&self) -> Result<(), RuntimeError> {
        if !self.worker_alive.load(Ordering::Acquire) {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "Win16 USER worker has exited; multimedia wake ownership remains with the producer",
            ));
        }
        let modal_publish = self.modal_control.publish_multimedia_wake(&self.generation);

        // SAFETY: this clone keeps the worker's auto-reset event alive while
        // SetEvent uses its process-local handle.
        let set_event =
            if (crate::windows::win32_safe::set_event(self.event.as_raw_handle() as _)) == 0 {
                let code = crate::windows::win32_safe::last_error();
                Err(RuntimeError::with_source(
                    Kind::HostFailure,
                    format!("signal the Win16 USER worker event (Windows error {code})"),
                    io::Error::from_raw_os_error(code as i32),
                ))
            } else {
                Ok(())
            };
        match (modal_publish, set_event) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(primary), Ok(())) | (Ok(()), Err(primary)) => Err(primary),
            (Err(primary), Err(additional)) => Err(RuntimeError::with_source(
                primary.kind().with_cleanup(additional.kind()),
                "publish the modal marker and wake the Win16 USER worker",
                WakeFailurePair {
                    primary,
                    additional,
                },
            )),
        }
    }
}

#[derive(Debug)]
struct WakeFailurePair {
    primary: RuntimeError,
    additional: RuntimeError,
}

impl std::fmt::Display for WakeFailurePair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; additional failure: {}",
            self.primary, self.additional
        )
    }
}

impl std::error::Error for WakeFailurePair {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
