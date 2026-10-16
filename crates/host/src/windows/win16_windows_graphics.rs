//! Runtime-thread DIB lifetime pins for resumable native drawing operations.

use super::super::win16_wing_dib_storage::Win16DibNativeUse;
use super::{Win16Dcs, Win16Objects, Win16Windows};
use runtime::{RuntimeError, Win16HostDc, Win16NativeCallbackSource};
use windows_sys::Win32::Graphics::Gdi::{GetCurrentObject, OBJ_BITMAP};

pub(super) struct DrawingLease {
    target: Win16HostDc,
    // These guards are deliberately !Send. Their owner, mapping and native
    // lifetime management remain on the guest-runtime thread. The USER worker
    // receives only its checked HDC token and flushes drawing at handoffs.
    bitmaps: Vec<(usize, Win16DibNativeUse)>,
}

impl DrawingLease {
    pub(super) fn capture(
        dcs: &Win16Dcs,
        objects: &Win16Objects,
        target: Win16HostDc,
    ) -> Result<Self, RuntimeError> {
        let mut lease = Self {
            target,
            bitmaps: Vec::new(),
        };
        lease.refresh(dcs, objects, None)?;
        Ok(lease)
    }

    fn refresh(
        &mut self,
        dcs: &Win16Dcs,
        objects: &Win16Objects,
        callback_dc: Option<Win16HostDc>,
    ) -> Result<(), RuntimeError> {
        // A callback can change the selected bitmap of either DC. Re-read
        // actual GDI selections before the worker resumes, retaining every
        // encountered WinG owner until the exact native source returns.
        for dc in [Some(self.target), callback_dc].into_iter().flatten() {
            let Some(dc) = dcs.lease_dc(dc)? else {
                continue;
            };
            // SAFETY: The HDC is pinned, and this query precedes the native
            // begin/resume command while its worker is not drawing on the DC.
            let bitmap = unsafe { GetCurrentObject(dc.native(), OBJ_BITMAP as u32) };
            if bitmap.is_null()
                || self
                    .bitmaps
                    .iter()
                    .any(|(native, _)| *native == bitmap as usize)
            {
                continue;
            }
            let Some(owner) = objects.dib_owner_for_native(bitmap) else {
                continue;
            };
            self.bitmaps.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    runtime::DiagnosticKind::ResourceExhausted,
                    "retain WinG DIB owner for native drawing continuation",
                    error,
                )
            })?;
            self.bitmaps.push((bitmap as usize, owner.pin_native()?));
        }
        Ok(())
    }
}

impl Win16Windows {
    pub(super) fn refresh_pending_graphics(
        &mut self,
        objects: &Win16Objects,
    ) -> Result<(), RuntimeError> {
        for pending in &mut self.pending {
            let Some(lease) = &mut pending.graphics else {
                continue;
            };
            let callback_dc = pending
                .awaiting_source
                .and_then(|source| match source.source {
                    Win16NativeCallbackSource::GrayString { dc } => Some(dc),
                    _ => None,
                });
            lease.refresh(&self.dcs, objects, callback_dc)?;
        }
        Ok(())
    }

    pub(in crate::windows) fn release_graphics_after_abort(&mut self) {
        // The caller has obtained the real USER abort receipt. No native
        // drawing remains; callback CPU frames can now retire on runtime.
        for pending in &mut self.pending {
            pending.graphics = None;
        }
    }
}
