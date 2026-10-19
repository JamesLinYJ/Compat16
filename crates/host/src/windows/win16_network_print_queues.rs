//! Native Windows queue snapshots and asynchronous printer-change watches.
//!
//! The runtime owns Win16 HWNDs, WORD job IDs, and guest queue blocks. This
//! adapter retains only native printer/notification handles and returns
//! owned DTOs; it never stores or posts a guest window handle.

use std::collections::HashMap;
use std::ptr;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostNetworkQueueOperation as Operation,
    Win16HostNetworkQueueResult as ResultValue, Win16HostNetworkQueueWatch,
    Win16HostSpoolDiagnostic, Win16HostSpoolResult as SpoolResult, Win16HostTaskOwner,
};
use windows_sys::Win32::Foundation::{
    ERROR_INVALID_HANDLE, ERROR_NOT_SUPPORTED, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Graphics::Printing::{
    ClosePrinter, FindClosePrinterChangeNotification, FindFirstPrinterChangeNotification,
    FindNextPrinterChangeNotification, PRINTER_CHANGE_JOB, PRINTER_CHANGE_PRINTER, PRINTER_HANDLE,
};
use windows_sys::Win32::System::Threading::WaitForSingleObject;

use super::guest_text::GuestTextCodec;
use super::win16_spool_jobs::Win16SpoolJobs;

#[path = "win16_network_print_snapshot.rs"]
mod snapshot;
use snapshot::{SnapshotBuildFailure, build_snapshot, last_error_or_not_supported, open_printer};

const PRINTER_INFO_LEVEL: u32 = 2;
const JOB_INFO_LEVEL: u32 = 2;
const MAX_BUFFER_ATTEMPTS: usize = 3;

#[derive(Default)]
pub(crate) struct Win16NetworkPrintQueues {
    watches: HashMap<Win16HostNetworkQueueWatch, NativeQueueWatch>,
    /// Printer handles left by failed snapshot/watch closes, scoped to the
    /// task that opened the temporary native handle.
    orphaned_printers: Vec<(Win16HostTaskOwner, PRINTER_HANDLE)>,
    orphaned_notifications: Vec<HANDLE>,
    next_watch: u64,
}

struct NativeQueueWatch {
    printer: Option<PRINTER_HANDLE>,
    notification: Option<HANDLE>,
    // WNetWatchQueue's szUser is advisory. Windows' queue-level change flags
    // do not identify which username changed, so retain the filter while
    // delivering queue-wide events instead of claiming user-level filtering.
    _user: Option<Vec<u16>>,
}

struct PrinterHandleGuard(Option<PRINTER_HANDLE>);

impl PrinterHandleGuard {
    fn new(printer: PRINTER_HANDLE) -> Self {
        Self(Some(printer))
    }

    fn raw(&self) -> PRINTER_HANDLE {
        self.0.unwrap_or_default()
    }

    fn close(&mut self) -> Result<(), (PRINTER_HANDLE, u32)> {
        let Some(printer) = self.0.take() else {
            return Ok(());
        };
        // SAFETY: this guard owns the printer handle and closes it once.
        if unsafe { ClosePrinter(printer) } == 0 {
            Err((printer, last_error_or_not_supported()))
        } else {
            Ok(())
        }
    }
}

impl Drop for PrinterHandleGuard {
    fn drop(&mut self) {
        if let Some(printer) = self.0.take() {
            // SAFETY: this guard owns the printer handle and is its final
            // cleanup path when an earlier branch exits unexpectedly.
            unsafe { ClosePrinter(printer) };
        }
    }
}

impl Win16NetworkPrintQueues {
    pub(crate) fn active_watch_count(&self) -> usize {
        // Keep safe-point wakeups while a partially released watch still
        // retains its printer handle. A retired HWND sweep must be able to
        // retry Unwatch even when the notification handle already closed.
        self.watches.len()
    }

    /// Execute one native queue operation. Guest-owned queue buffers, HWNDs,
    /// and selectors stay in the runtime; job IDs are registered through the
    /// existing task-owned spool-job table so native DWORD IDs are never
    /// narrowed into a guest WORD.
    pub(crate) fn execute(
        &mut self,
        codec: GuestTextCodec,
        operation: Operation,
        spool_jobs: &mut Win16SpoolJobs,
        notification_source_id: Option<u64>,
    ) -> Result<ResultValue, RuntimeError> {
        match operation {
            Operation::Watch {
                owner,
                local_device,
                user,
            } => {
                let source_id = notification_source_id.ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "WindowsHost did not allocate a shared WNet notification source ID",
                    )
                })?;
                if source_id == 0 || source_id == u64::MAX {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "WindowsHost supplied a reserved WNet notification source ID",
                    ));
                }
                self.watch(codec, owner, &local_device, user.as_deref(), source_id)
            }
            Operation::Unwatch { watch } => self.unwatch(watch),
            Operation::Snapshot { owner, queue, user } => {
                self.snapshot(codec, owner, &queue, user.as_deref(), spool_jobs)
            }
            Operation::PeekChanges => {
                let (changed, failed_watch, native_error) = self.peek_changes()?;
                Ok(ResultValue::Changes {
                    changed,
                    failed_watch,
                    native_error,
                })
            }
        }
    }

    fn watch(
        &mut self,
        codec: GuestTextCodec,
        owner: Win16HostTaskOwner,
        local_device: &[u8],
        user: Option<&[u8]>,
        notification_source_id: u64,
    ) -> Result<ResultValue, RuntimeError> {
        self.watches.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate Win16 native printer watch",
                error,
            )
        })?;
        self.orphaned_printers.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve printer-watch cleanup",
                error,
            )
        })?;
        self.orphaned_notifications
            .try_reserve(1)
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve notification-watch cleanup",
                    error,
                )
            })?;
        let watch = self.allocate_watch()?;
        let user = user.map(|username| codec.to_wide_z(username)).transpose()?;

        let (mut printer, _) = match open_printer(codec, local_device)? {
            Ok(opened) => opened,
            Err(error) => {
                return Ok(ResultValue::Watch {
                    watch: None,
                    notification_source_id: None,
                    native_error: Some(error),
                });
            }
        };
        // SAFETY: the guard owns a valid OpenPrinterW handle; null options use
        // the native provider's ordinary job/printer change notification.
        let notification = unsafe {
            FindFirstPrinterChangeNotification(
                printer.raw(),
                PRINTER_CHANGE_JOB | PRINTER_CHANGE_PRINTER,
                0,
                ptr::null(),
            )
        };
        if notification.is_null() || notification == INVALID_HANDLE_VALUE {
            let error = last_error_or_not_supported();
            self.close_printer_into_orphans(owner, &mut printer);
            return Ok(ResultValue::Watch {
                watch: None,
                notification_source_id: None,
                native_error: Some(error),
            });
        }

        let raw_printer = printer.0.take().ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "printer watch lost its owned printer handle",
            )
        })?;
        self.watches.insert(
            watch,
            NativeQueueWatch {
                printer: Some(raw_printer),
                notification: Some(notification),
                _user: user,
            },
        );
        Ok(ResultValue::Watch {
            watch: Some(watch),
            notification_source_id: Some(notification_source_id),
            native_error: None,
        })
    }

    fn unwatch(&mut self, watch: Win16HostNetworkQueueWatch) -> Result<ResultValue, RuntimeError> {
        let Some(native) = self.watches.get_mut(&watch) else {
            return Ok(ResultValue::Status {
                succeeded: false,
                native_error: Some(ERROR_INVALID_HANDLE),
            });
        };

        let mut first_error = None;
        if let Some(notification) = native.notification {
            // SAFETY: this retryable registry entry owns the notification.
            if unsafe { FindClosePrinterChangeNotification(notification) } == 0 {
                first_error = Some(last_error_or_not_supported());
            } else {
                native.notification = None;
            }
        }
        if let Some(printer) = native.printer {
            // SAFETY: this retryable registry entry owns the printer handle.
            if unsafe { ClosePrinter(printer) } == 0 {
                first_error.get_or_insert_with(last_error_or_not_supported);
            } else {
                native.printer = None;
            }
        }
        let fully_released = native.notification.is_none() && native.printer.is_none();
        if fully_released {
            self.watches.remove(&watch);
        }
        Ok(ResultValue::Status {
            succeeded: fully_released,
            native_error: if fully_released {
                None
            } else {
                first_error.or(Some(ERROR_NOT_SUPPORTED))
            },
        })
    }

    fn snapshot(
        &mut self,
        codec: GuestTextCodec,
        owner: Win16HostTaskOwner,
        queue: &[u8],
        _user: Option<&[u8]>,
        spool_jobs: &mut Win16SpoolJobs,
    ) -> Result<ResultValue, RuntimeError> {
        // WNetLockQueueData's szUser is advisory. The WFW contract explicitly
        // allows a full queue listing, so retain the argument at the owned
        // host boundary but do not filter QUEUESTRUCT/JOBSTRUCT records.
        self.orphaned_printers.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve printer snapshot cleanup",
                error,
            )
        })?;
        let (mut printer, printer_name) = match open_printer(codec, queue)? {
            Ok(opened) => opened,
            Err(error) => {
                return Ok(ResultValue::Snapshot {
                    snapshot: None,
                    native_error: Some(error),
                    cleanup_jobs: Vec::new(),
                    diagnostic: None,
                });
            }
        };

        let result = build_snapshot(owner, codec, printer.raw(), &printer_name, spool_jobs);
        let close_error = self.close_printer_into_orphans(owner, &mut printer);
        match result {
            Ok(Ok(snapshot)) => {
                let diagnostic = close_error.map(|error| Win16HostSpoolDiagnostic {
                    kind: Kind::HostFailure,
                    message: format!(
                        "ClosePrinter for WNet queue snapshot failed with Windows error {error}"
                    ),
                });
                Ok(ResultValue::Snapshot {
                    snapshot: Some(snapshot),
                    native_error: close_error,
                    cleanup_jobs: Vec::new(),
                    diagnostic,
                })
            }
            Ok(Err(error)) => {
                let diagnostic = close_error.map(|close_error| Win16HostSpoolDiagnostic {
                    kind: Kind::HostFailure,
                    message: format!("queue snapshot failed with Windows error {error}; closing its printer handle also failed with error {close_error}"),
                });
                Ok(ResultValue::Snapshot {
                    snapshot: None,
                    native_error: Some(error),
                    cleanup_jobs: Vec::new(),
                    diagnostic,
                })
            }
            Err(failure) => {
                let SnapshotBuildFailure {
                    error,
                    mut cleanup_jobs,
                } = failure;
                let mut retained = 0usize;
                let mut cleanup_native_error = None;
                let mut diagnostic_kind = error.kind();
                let mut diagnostic_message = format!("build WNet queue snapshot: {error}");
                for index in 0..cleanup_jobs.len() {
                    let token = cleanup_jobs[index];
                    match spool_jobs.release_snapshot_network_job(token) {
                        Ok(SpoolResult::Status {
                            succeeded: true, ..
                        }) => {}
                        Ok(SpoolResult::Status {
                            succeeded: false,
                            native_error,
                        }) => {
                            cleanup_jobs[retained] = token;
                            retained += 1;
                            cleanup_native_error = cleanup_native_error.or(native_error);
                        }
                        Ok(_) => {
                            cleanup_jobs[retained] = token;
                            retained += 1;
                            diagnostic_kind = Kind::InternalInvariant;
                            diagnostic_message.push_str(
                                "; snapshot-token rollback returned a different host result",
                            );
                        }
                        Err(cleanup_error) => {
                            cleanup_jobs[retained] = token;
                            retained += 1;
                            cleanup_native_error =
                                Some(cleanup_native_error.unwrap_or(ERROR_NOT_SUPPORTED));
                            diagnostic_kind = cleanup_error.kind();
                            diagnostic_message.push_str(&format!(
                                "; rollback token {} failed: {cleanup_error}",
                                token.token()
                            ));
                        }
                    }
                }
                cleanup_jobs.truncate(retained);
                if let Some(close_error) = close_error {
                    cleanup_native_error = cleanup_native_error.or(Some(close_error));
                    diagnostic_message.push_str(&format!(
                        "; closing the queue printer handle failed with Windows error {close_error}"
                    ));
                }
                let native_error = cleanup_native_error.unwrap_or(ERROR_NOT_SUPPORTED);
                Ok(ResultValue::Snapshot {
                    snapshot: None,
                    native_error: Some(native_error),
                    cleanup_jobs,
                    diagnostic: Some(Win16HostSpoolDiagnostic {
                        kind: diagnostic_kind,
                        message: diagnostic_message,
                    }),
                })
            }
        }
    }

    fn peek_changes(
        &mut self,
    ) -> Result<
        (
            Vec<Win16HostNetworkQueueWatch>,
            Option<Win16HostNetworkQueueWatch>,
            Option<u32>,
        ),
        RuntimeError,
    > {
        let mut changed = Vec::new();
        changed
            .try_reserve_exact(self.watches.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "allocate printer-change result list",
                    error,
                )
            })?;

        for (watch, native) in &self.watches {
            let Some(notification) = native.notification else {
                // Unwatch already closed the change notification but still
                // has a printer handle whose close must be retried.
                continue;
            };
            // A zero timeout makes this an ordinary non-blocking queue peek.
            // The runtime posts SP_QUEUECHANGED asynchronously after it
            // validates the watch's guest HWND generation.
            // SAFETY: this registry owns a live notification handle; a zero
            // timeout does not block the runtime's queue pump.
            let waited = unsafe { WaitForSingleObject(notification, 0) };
            if waited == WAIT_TIMEOUT {
                continue;
            }
            if waited == WAIT_FAILED {
                return Ok((changed, Some(*watch), Some(last_error_or_not_supported())));
            }
            if waited != WAIT_OBJECT_0 {
                return Ok((changed, Some(*watch), Some(ERROR_INVALID_HANDLE)));
            }

            let mut flags = 0u32;
            // SAFETY: the notification belongs to this registry. Null optional
            // outputs request only the change flags and let the API reset the
            // waitable notification after this non-blocking observation.
            if unsafe {
                FindNextPrinterChangeNotification(
                    notification,
                    &mut flags,
                    ptr::null(),
                    ptr::null_mut(),
                )
            } == 0
            {
                return Ok((changed, Some(*watch), Some(last_error_or_not_supported())));
            }
            if flags != 0 {
                changed.push(*watch);
            }
        }
        Ok((changed, None, None))
    }

    fn allocate_watch(&mut self) -> Result<Win16HostNetworkQueueWatch, RuntimeError> {
        let first = if self.next_watch == 0 {
            1
        } else {
            self.next_watch
        };
        let mut candidate = first;
        loop {
            let watch = Win16HostNetworkQueueWatch::new(candidate);
            if !self.watches.contains_key(&watch) {
                self.next_watch = candidate.wrapping_add(1);
                if self.next_watch == 0 {
                    self.next_watch = 1;
                }
                return Ok(watch);
            }
            candidate = candidate.wrapping_add(1);
            if candidate == 0 {
                candidate = 1;
            }
            if candidate == first {
                return Err(RuntimeError::new(
                    Kind::ResourceExhausted,
                    "Win16 native printer watch token space is exhausted",
                ));
            }
        }
    }

    pub(crate) fn release_owner_orphans(
        &mut self,
        owner: Win16HostTaskOwner,
    ) -> Result<ResultValue, RuntimeError> {
        let mut succeeded = true;
        let mut native_error = None;
        let mut index = 0;
        while index < self.orphaned_printers.len() {
            if self.orphaned_printers[index].0 != owner {
                index += 1;
                continue;
            }
            let printer = self.orphaned_printers[index].1;
            // SAFETY: this owner-tagged temporary handle was retained after a
            // failed ClosePrinter call and is retried against that same value.
            if unsafe { ClosePrinter(printer) } != 0 {
                self.orphaned_printers.swap_remove(index);
            } else {
                succeeded = false;
                native_error.get_or_insert_with(last_error_or_not_supported);
                index += 1;
            }
        }
        Ok(ResultValue::Status {
            succeeded,
            native_error,
        })
    }

    fn close_printer_into_orphans(
        &mut self,
        owner: Win16HostTaskOwner,
        printer: &mut PrinterHandleGuard,
    ) -> Option<u32> {
        match printer.close() {
            Ok(()) => None,
            Err((handle, error)) => {
                self.orphaned_printers.push((owner, handle));
                Some(error)
            }
        }
    }
}

impl Drop for Win16NetworkPrintQueues {
    fn drop(&mut self) {
        for (_, native) in self.watches.drain() {
            // The owner is shutting down; release the notification before its
            // matching printer handle. No guest watch outlives this registry.
            // SAFETY: `Some`, `FindClosePrinterChangeNotification`, `ClosePrinter` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
            unsafe {
                if let Some(notification) = native.notification {
                    FindClosePrinterChangeNotification(notification);
                }
                if let Some(printer) = native.printer {
                    ClosePrinter(printer);
                }
            }
        }
        for notification in self.orphaned_notifications.drain(..) {
            // SAFETY: `FindClosePrinterChangeNotification` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
            unsafe { FindClosePrinterChangeNotification(notification) };
        }
        for (_, printer) in self.orphaned_printers.drain(..) {
            // SAFETY: ClosePrinter closes a printer handle this owner opened.
            unsafe { ClosePrinter(printer) };
        }
    }
}
