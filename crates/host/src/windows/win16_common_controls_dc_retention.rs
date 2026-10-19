//! Same-thread retry ownership for toolbar DIB screen DCs.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::Graphics::Gdi::HDC;

use super::win16_window_worker::WorkerState;

#[derive(Debug)]
pub(super) struct ToolbarDcReleaseOwner {
    // Store the opaque HDC bits rather than a raw pointer: this owner moves
    // through the process-retention mutex after its creating worker exits.
    pub(super) dc: usize,
    pub(super) creator_thread: u32,
    pub(super) worker_retirement_id: u64,
}

/// Reserve the same-thread retry record before GetDC can acquire an HDC.
pub(super) fn reserve(state: &Rc<RefCell<WorkerState>>) -> Result<(), RuntimeError> {
    let mut worker = state.try_borrow_mut().map_err(|_| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "toolbar DC release ledger is already borrowed",
        )
    })?;
    let reserved = worker
        .pending_toolbar_dc_release_reservations
        .checked_add(1)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "toolbar DC release reservation count overflow",
            )
        })?;
    worker
        .pending_toolbar_dc_releases
        .try_reserve(reserved)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve same-thread toolbar DC release owner",
                error,
            )
        })?;
    worker
        .toolbar_bitmap_retention
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .reserve_dc_release_slot()?;
    worker.pending_toolbar_dc_release_reservations = reserved;
    Ok(())
}

pub(super) fn cancel_reservation(state: &Rc<RefCell<WorkerState>>) -> Result<(), RuntimeError> {
    let mut worker = state.try_borrow_mut().map_err(|_| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "toolbar DC release ledger is already borrowed",
        )
    })?;
    worker.pending_toolbar_dc_release_reservations = worker
        .pending_toolbar_dc_release_reservations
        .checked_sub(1)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "toolbar DC release reservation underflow",
            )
        })?;
    worker
        .toolbar_bitmap_retention
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .cancel_dc_release_slot()?;
    Ok(())
}

/// Keep a failed ReleaseDC owner in the worker that created it.
pub(super) fn retain(state: &Rc<RefCell<WorkerState>>, dc: HDC) -> Result<(), RuntimeError> {
    let mut worker = state.try_borrow_mut().map_err(|_| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "toolbar DC release ledger is already borrowed",
        )
    })?;
    if worker.pending_toolbar_dc_release_reservations == 0
        || worker.pending_toolbar_dc_releases.len() == worker.pending_toolbar_dc_releases.capacity()
    {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "toolbar DC owner was acquired without its reserved retry slot",
        ));
    }
    let worker_retirement_id = worker.worker_retirement_id;
    worker
        .pending_toolbar_dc_releases
        .push(ToolbarDcReleaseOwner {
            dc: dc as usize,
            creator_thread: (crate::windows::win32_safe::current_thread_id()),
            worker_retirement_id,
        });
    worker.pending_toolbar_dc_release_reservations -= 1;
    Ok(())
}

/// Retry only on the owner thread; a failed record remains for later shutdown.
pub(super) fn retry(state: &Rc<RefCell<WorkerState>>) -> Result<(), RuntimeError> {
    let thread_id = crate::windows::win32_safe::current_thread_id();
    let mut worker = state.try_borrow_mut().map_err(|_| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "toolbar DC release ledger is already borrowed",
        )
    })?;
    let retention = Arc::clone(&worker.toolbar_bitmap_retention);
    let mut failure = retry_list(
        &mut worker.pending_toolbar_dc_releases,
        &retention,
        thread_id,
    )
    .err();
    if worker.pending_toolbar_dc_release_reservations != 0 {
        remember(
            &mut failure,
            RuntimeError::new(
                Kind::InternalInvariant,
                "toolbar worker reached retirement with an unfulfilled DC release reservation",
            ),
        );
    }
    failure.map_or(Ok(()), Err)
}

pub(super) fn retry_list(
    pending: &mut Vec<ToolbarDcReleaseOwner>,
    retention: &Arc<Mutex<super::win16_common_controls_bitmap_pins::ToolbarBitmapRetention>>,
    thread_id: u32,
) -> Result<(), RuntimeError> {
    let mut failure = None;
    let mut index = 0;
    while index < pending.len() {
        let (creator_thread, dc) = {
            let owner = &pending[index];
            (owner.creator_thread, owner.dc)
        };
        if creator_thread != thread_id {
            remember(
                &mut failure,
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "toolbar HDC retry attempted on a thread other than its creator",
                ),
            );
            index += 1;
            continue;
        }
        // ReleaseDC must run on the thread that acquired the GetDC handle.
        if (crate::windows::win32_safe::release_dc(std::ptr::null_mut(), dc as HDC)) != 0 {
            pending.remove(index);
            let reservation = retention
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .cancel_dc_release_slot();
            if let Err(error) = reservation {
                remember(&mut failure, error);
            }
        } else {
            let error = crate::windows::win32_safe::last_error();
            remember(
                &mut failure,
                RuntimeError::new(
                    Kind::HostFailure,
                    format!("ReleaseDC retry failed on creator thread (last error {error})"),
                ),
            );
            index += 1;
        }
    }
    failure.map_or(Ok(()), Err)
}

fn remember(slot: &mut Option<RuntimeError>, error: RuntimeError) {
    *slot = Some(match slot.take() {
        Some(primary) => {
            let kind = primary.kind().with_cleanup(error.kind());
            RuntimeError::with_source(
                kind,
                "multiple toolbar screen-DC releases failed",
                ToolbarDcReleaseFailures {
                    primary,
                    next: error,
                },
            )
        }
        None => error,
    });
}

#[derive(Debug)]
struct ToolbarDcReleaseFailures {
    primary: RuntimeError,
    next: RuntimeError,
}

impl std::fmt::Display for ToolbarDcReleaseFailures {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; another ReleaseDC failed: {}",
            self.primary, self.next
        )
    }
}

impl std::error::Error for ToolbarDcReleaseFailures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
