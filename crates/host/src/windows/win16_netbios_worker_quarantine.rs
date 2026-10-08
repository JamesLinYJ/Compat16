//! Retain worker-owned native pointers when no command consumer can service them.

use super::*;
use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};

pub(super) fn abandon_until_terminal(owner: &mut NativeNcbOwner) {
    note_no_consumer(
        &owner.wake_status,
        "NetBIOS worker lost its command or completion consumer while native ownership remained active",
    );
    if !owner.cancel_requested {
        super::cancel_native(owner);
    }
    loop {
        match unsafe { WaitForSingleObject(owner.event, u32::MAX) } {
            WAIT_OBJECT_0 => {
                owner.terminal = true;
                owner.in_flight = false;
                super::mark_native_terminal(&owner.wake_status);
                close_after_terminal(owner);
                return;
            }
            WAIT_TIMEOUT => park_after_failed_wait(
                owner,
                RuntimeError::new(
                    Kind::HostFailure,
                    "infinite NetBIOS event wait timed out without native terminal proof",
                ),
            ),
            WAIT_FAILED => park_after_failed_wait(
                owner,
                last_error("wait for abandoned NetBIOS native owner"),
            ),
            _ => park_after_failed_wait(
                owner,
                RuntimeError::new(
                    Kind::HostFailure,
                    "unexpected native NetBIOS event wait result cannot prove completion",
                ),
            ),
        }
    }
}

pub(super) fn close_after_terminal(owner: &mut NativeNcbOwner) {
    if !owner.terminal {
        abandon_until_terminal(owner);
    }
    note_no_consumer(
        &owner.wake_status,
        "NetBIOS worker lost its completion or command consumer after native terminal",
    );
    if owner.event.is_null() {
        return;
    }
    if unsafe { CloseHandle(owner.event) } != 0 {
        owner.event = std::ptr::null_mut();
        owner.wake_status.lock().unwrap_or_else(PoisonError::into_inner).event_closed = true;
    } else {
        park_after_close_failure(
            owner,
            last_error("close terminal NetBIOS event after owner abandonment"),
        );
    }
}

impl Drop for NativeNcbOwner {
    fn drop(&mut self) {
        if !self.start_reported {
            let startup = if self.in_flight {
                Ok(WorkerStart::Accepted(super::pending_status(&self.call)))
            } else {
                Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "NetBIOS worker exited before it could classify its native submission",
                ))
            };
            let _ = super::send_worker_start(self, startup);
        }
        if !self.in_flight {
            self.terminal = true;
            super::mark_native_terminal(&self.wake_status);
        }
        let event_closed = self.wake_status.lock()
            .unwrap_or_else(PoisonError::into_inner).event_closed;
        if self.terminal && self.start_reported && !event_closed {
            note_no_consumer(
                &self.wake_status,
                "NetBIOS worker exited after native terminal before exact source release",
            );
        }
        if self.in_flight && !self.terminal {
            note_no_consumer(
                &self.wake_status,
                "NetBIOS worker unwound while an accepted native NCB still required service",
            );
            if !self.cancel_requested {
                super::cancel_native(self);
            }
            loop {
                match unsafe { WaitForSingleObject(self.event, u32::MAX) } {
                    WAIT_OBJECT_0 => {
                        self.terminal = true;
                        self.in_flight = false;
                        super::mark_native_terminal(&self.wake_status);
                        break;
                    }
                    WAIT_TIMEOUT => park_after_failed_wait(
                        self,
                        RuntimeError::new(
                            Kind::HostFailure,
                            "infinite NetBIOS event wait timed out without native terminal proof",
                        ),
                    ),
                    WAIT_FAILED => park_after_failed_wait(
                        self,
                        last_error("wait for in-flight NetBIOS owner during worker drop"),
                    ),
                    _ => park_after_failed_wait(
                        self,
                        RuntimeError::new(
                            Kind::HostFailure,
                            "unexpected native NetBIOS event wait result cannot prove completion",
                        ),
                    ),
                }
            }
        }
        if !self.event.is_null() && self.terminal {
            if unsafe { CloseHandle(self.event) } != 0 {
                self.event = std::ptr::null_mut();
                self.wake_status.lock().unwrap_or_else(PoisonError::into_inner).event_closed = true;
            } else {
                park_after_close_failure(
                    self,
                    last_error("close exact terminal NetBIOS event during worker drop"),
                );
            }
        }
    }
}

fn note_no_consumer(status: &SharedWakeStatus, message: &'static str) {
    let mut status = status.lock().unwrap_or_else(PoisonError::into_inner);
    super::super::mark_no_consumer(
        &mut status,
        RuntimeError::new(Kind::HostFailure, message),
    );
}

fn park_after_failed_wait(owner: &mut NativeNcbOwner, error: RuntimeError) -> ! {
    let error = std::sync::Arc::new(error);
    super::mark_native_wait_failed(&owner.wake_status, Some(std::sync::Arc::clone(&error)));
    note_no_consumer(
        &owner.wake_status,
        "native NetBIOS event wait failed with no worker consumer; native owner is quarantined",
    );
    // The event supplies no completion proof after WAIT_FAILED. Park this
    // worker with the exact NCB, buffer, event, and first typed cause alive;
    // process teardown is the only boundary that can reclaim this owner.
    loop {
        std::thread::park();
    }
}

fn park_after_close_failure(owner: &mut NativeNcbOwner, error: RuntimeError) -> ! {
    let error = std::sync::Arc::new(error);
    {
        let mut status = owner.wake_status.lock().unwrap_or_else(PoisonError::into_inner);
        status.failure_diagnostics.native_event_close.record(std::sync::Arc::clone(&error));
        if status.teardown_error.is_none() {
            status.teardown_error = Some(std::sync::Arc::clone(&error));
        }
        super::super::mark_no_consumer(
            &mut status,
            RuntimeError::new(
                Kind::HostFailure,
                "terminal NetBIOS event could not be closed after its worker consumer disappeared",
            ),
        );
    }
    // CloseHandle failure gives no proof that the exact handle was released.
    // Keep the owner alive and stop issuing commands because no consumer can
    // retry this handle safely.
    loop {
        std::thread::park();
    }
}
