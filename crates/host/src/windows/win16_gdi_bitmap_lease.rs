//! Independent bitmap snapshot leased from the guest GDI object table.

use std::sync::Arc;

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostGdiObject};
use windows_sys::Win32::Graphics::Gdi::{HBITMAP, HGDIOBJ};
use windows_sys::Win32::UI::WindowsAndMessaging::{CopyImage, IMAGE_BITMAP};

struct BitmapSnapshot {
    source: Win16HostGdiObject,
    native: usize,
}

impl BitmapSnapshot {
    fn delete(&mut self) -> Result<(), RuntimeError> {
        if self.native == 0 {
            return Ok(());
        }
        // SAFETY: `native` is the independent HBITMAP created by CopyImage.
        if (crate::windows::win32_safe::delete_object(self.native as HGDIOBJ)) == 0 {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "DeleteObject failed for a leased toolbar bitmap snapshot",
            ));
        }
        self.native = 0;
        Ok(())
    }
}

impl Drop for BitmapSnapshot {
    fn drop(&mut self) {
        // Drop is only a last-resort cleanup. Explicit owner retirement calls
        // `release` first so a failed DeleteObject remains a typed error.
        if self.native != 0 {
            crate::windows::win32_safe::delete_object(self.native as HGDIOBJ);
        }
    }
}

/// Pins an independent native copy while a USER operation may reenter guest
/// code that deletes the original Win16 HBITMAP.
pub(super) struct Win16BitmapLease {
    snapshot: Arc<BitmapSnapshot>,
}

impl Win16BitmapLease {
    pub(super) fn snapshot(source: Win16HostGdiObject, native: HBITMAP) -> Option<Self> {
        // LR_COPYRETURNORG is intentionally absent: the worker must own a new
        // bitmap that cannot be invalidated by guest DeleteObject reentry.
        // SAFETY: CopyImage copies an image handle this process owns.
        let copied = unsafe { CopyImage(native.cast(), IMAGE_BITMAP, 0, 0, 0) };
        if copied.is_null() {
            return None;
        }
        Some(Self {
            snapshot: Arc::new(BitmapSnapshot {
                source,
                native: copied as usize,
            }),
        })
    }

    pub(super) fn native(&self) -> HBITMAP {
        self.snapshot.native as HBITMAP
    }

    pub(super) fn try_release(&mut self) -> Result<(), RuntimeError> {
        let snapshot = Arc::get_mut(&mut self.snapshot).ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "toolbar bitmap snapshot still has a second owner at retirement",
            )
        })?;
        snapshot.delete()
    }
}

impl Clone for Win16BitmapLease {
    fn clone(&self) -> Self {
        Self {
            snapshot: Arc::clone(&self.snapshot),
        }
    }
}

impl std::fmt::Debug for Win16BitmapLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Win16BitmapLease")
            .field("source", &self.snapshot.source)
            .finish_non_exhaustive()
    }
}
