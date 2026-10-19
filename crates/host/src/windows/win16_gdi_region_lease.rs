//! Owned snapshots of native regions passed to the USER worker.

use std::sync::Arc;

use runtime::Win16HostGdiObject;
use windows_sys::Win32::Graphics::Gdi::{HGDIOBJ, HRGN};

/// Owns a copied region independently from the guest's original HRGN.
///
/// Microsoft documents that GDI does not serialize shared objects across
/// threads and deleting an object while another thread uses it is unpredictable:
/// https://learn.microsoft.com/en-us/windows/win32/procthread/multiple-threads-and-gdi-objects
/// The worker therefore receives a CreateRectRgn/CombineRgn snapshot, never
/// the original object. Its source token is used only for caller-thread commit.
struct RegionSnapshot {
    source: Win16HostGdiObject,
    native: usize,
}

impl RegionSnapshot {
    fn new(source: Win16HostGdiObject, native: HRGN) -> Arc<Self> {
        Arc::new(Self {
            source,
            native: native as usize,
        })
    }

    fn native(&self) -> HRGN {
        self.native as HRGN
    }
}

impl Drop for RegionSnapshot {
    fn drop(&mut self) {
        // SAFETY: This is the owned CreateRectRgn snapshot, represented as
        // integer bits so the lease remains Send across the worker boundary.
        crate::windows::win32_safe::delete_object(self.native as HGDIOBJ);
    }
}

/// Keeps one independent region snapshot alive until all worker/pending owners finish.
#[derive(Clone)]
pub(in crate::windows) struct Win16RegionLease {
    snapshot: Arc<RegionSnapshot>,
}

impl Win16RegionLease {
    pub(in crate::windows) fn new(source: Win16HostGdiObject, native: HRGN) -> Self {
        Self {
            snapshot: RegionSnapshot::new(source, native),
        }
    }

    pub(in crate::windows) fn source_token(&self) -> Win16HostGdiObject {
        self.snapshot.source
    }

    /// Returns the independent worker snapshot, not the guest's original HRGN.
    pub(in crate::windows) fn native(&self) -> HRGN {
        self.snapshot.native()
    }
}

impl std::fmt::Debug for Win16RegionLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Win16RegionLease").finish()
    }
}
