//! Retain toolbar bitmap owners until their USER worker has actually joined.

use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use runtime::RuntimeError;
use windows_sys::Win32::System::Threading::GetCurrentThreadId;

use super::{WorkerState, worker_join_failure};
use super::super::win16_common_controls_bitmap_pins::{
    ToolbarBitmapRetention, retire_worker_after_join,
};

pub(super) fn join_worker_before_ready(
    thread: JoinHandle<()>,
    worker_id: u64,
    toolbar_bitmap_retention: &Arc<Mutex<ToolbarBitmapRetention>>,
    retention_slot_reserved: &mut bool,
) -> Result<(), RuntimeError> {
    let join_failure = thread.join().err().map(|payload|
        shared_worker_error(worker_join_failure(payload), "worker exited before readiness"));
    let bitmap_failure = retire_worker_after_join(
        worker_id, toolbar_bitmap_retention, retention_slot_reserved).err();
    match (join_failure, bitmap_failure) {
        (None, None) => Ok(()),
        (Some(error), None) | (None, Some(error)) => Err(error),
        (Some(primary), Some(cleanup)) => Err(combine_worker_failures(primary, cleanup,
            "worker startup join and bitmap retirement both failed")),
    }
}

pub(super) fn combine_worker_failures(
    primary: RuntimeError,
    cleanup: RuntimeError,
    context: &'static str,
) -> RuntimeError {
    let kind = primary.kind().with_cleanup(cleanup.kind());
    RuntimeError::with_source(kind, context, WorkerCleanupFailure { primary, cleanup })
}

fn shared_worker_error(error: Arc<RuntimeError>, context: &'static str) -> RuntimeError {
    RuntimeError::with_source(error.kind(), context, SharedWorkerCause(error))
}

#[derive(Debug)]
struct SharedWorkerCause(Arc<RuntimeError>);

impl std::fmt::Display for SharedWorkerCause {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, formatter)
    }
}

impl std::error::Error for SharedWorkerCause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

#[derive(Debug)]
struct WorkerCleanupFailure {
    primary: RuntimeError,
    cleanup: RuntimeError,
}

impl std::fmt::Display for WorkerCleanupFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}; cleanup also failed: {}", self.primary, self.cleanup)
    }
}

impl std::error::Error for WorkerCleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}

#[derive(Debug)]
struct WorkerCleanupPair { primary: RuntimeError, cleanup: RuntimeError }

impl std::fmt::Display for WorkerCleanupPair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}; cleanup also failed: {}", self.primary, self.cleanup)
    }
}

impl std::error::Error for WorkerCleanupPair {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.primary) }
}

impl Drop for WorkerState {
    fn drop(&mut self) {
        let retention = Arc::clone(&self.toolbar_bitmap_retention);
        if let Err(error) = super::super::win16_common_controls_dc_retention::
            retry_list(
                &mut self.pending_toolbar_dc_releases,
                &retention,
                unsafe { GetCurrentThreadId() },
            )
        {
            eprintln!("runtime: {error}; HDC remains process-retained because ReleaseDC is creator-thread only");
        }
        if !self.pending_toolbar_dc_releases.is_empty() {
            let mut retained = retention.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Err(primary) = retained.append_dc_owners_reserved(
                &mut self.pending_toolbar_dc_releases,
            ) {
                let owners = std::mem::take(&mut self.pending_toolbar_dc_releases);
                match retained.retain_emergency_dc_owners(owners) {
                    Ok(()) => eprintln!("runtime: {primary}; HDC owners moved to emergency retention"),
                    Err((secondary, owners)) => {
                        eprintln!("runtime: {primary}; {secondary}; creator-thread HDC record could not be retained");
                        match retained.retain_overflow_dc_owners(owners) {
                            Ok(()) => {
                                let kind = primary.kind().with_cleanup(secondary.kind());
                                retained.record_failure(RuntimeError::with_source(kind,
                                    "failed ReleaseDC owner moved to overflow retirement storage",
                                    WorkerCleanupPair { primary, cleanup: secondary }), false)
                            }
                            Err(owners) => {
                                let kind = primary.kind().with_cleanup(secondary.kind());
                                retained.record_failure(RuntimeError::with_source(kind,
                                    "failed ReleaseDC owner could not enter any retention storage",
                                    RetainedToolbarDcOwnerFailure { primary, secondary, _owners: owners }), true)
                            }
                        }
                    }
                }
            }
        }
        if self.pending_toolbar_dc_release_reservations != 0 {
            eprintln!("runtime: toolbar worker exited with an unfulfilled HDC release reservation");
        }
        if self.toolbar_bitmap_sidecars.is_empty() {
            return;
        }
        let mut retained = self.toolbar_bitmap_retention.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // CreateToolbarEx may synchronously reenter guest code. TBADDBITMAP also
        // requires the source HBITMAP to live until toolbar destruction, so the
        // shared WorkerRetention pool spans this worker's actual JoinHandle join.
        if let Err(error) = retained.append_reserved(&mut self.toolbar_bitmap_sidecars) {
            let append_error = error;
            match retained.retain_emergency(std::mem::take(&mut self.toolbar_bitmap_sidecars)) {
                Ok(()) => eprintln!("runtime: {append_error}; owners moved to emergency retention"),
                Err((retention_error, owners)) => {
                    eprintln!("runtime: {append_error}; {retention_error}");
                    match retained.retain_overflow_sidecars(owners) {
                        Ok(()) => {
                            let kind = append_error.kind().with_cleanup(retention_error.kind());
                            retained.record_failure(RuntimeError::with_source(kind,
                                "toolbar bitmap owner moved to overflow retirement storage",
                                WorkerCleanupPair { primary: append_error,
                                    cleanup: retention_error }), false)
                        }
                        Err(owners) => {
                            let kind = append_error.kind().with_cleanup(retention_error.kind());
                            retained.record_failure(RuntimeError::with_source(kind,
                                "toolbar bitmap owner could not enter any retention storage",
                                RetainedToolbarOwnerFailure { append: append_error,
                                    emergency: retention_error, _owners: owners }), true)
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
struct RetainedToolbarOwnerFailure {
    append: RuntimeError,
    emergency: RuntimeError,
    // Keep failed toolbar HWND/HBITMAP sidecars alive for error lifetime.
    _owners: Vec<super::super::win16_common_controls_bitmap_pins::ToolbarBitmapSidecar>,
}

impl std::fmt::Display for RetainedToolbarOwnerFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}; emergency retention also failed: {}",
            self.append, self.emergency)
    }
}

impl std::error::Error for RetainedToolbarOwnerFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.append) }
}

#[derive(Debug)]
struct RetainedToolbarDcOwnerFailure {
    primary: RuntimeError,
    secondary: RuntimeError,
    // Keep failed HDC release owners alive for error lifetime.
    _owners: Vec<super::super::win16_common_controls_dc_retention::ToolbarDcReleaseOwner>,
}

impl std::fmt::Display for RetainedToolbarDcOwnerFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}; emergency HDC retention also failed: {}",
            self.primary, self.secondary)
    }
}

impl std::error::Error for RetainedToolbarDcOwnerFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.primary) }
}
