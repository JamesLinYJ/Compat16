//! Short-lock HDC leases for native operations that may reenter USER.

use std::sync::{Arc, Mutex};

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostDc, Win16HostWindow};
use windows_sys::Win32::Graphics::Gdi::HDC;

use super::{DcOrigin, Win16DcState, Win16Dcs, WindowDcLease};

/// Keeps a table-owned native HDC alive without holding the table mutex across
/// USER/GDI calls. This pin is a host synchronization measure, not a Win16
/// API-visible claim that a device context is busy. The raw handle is exposed
/// only inside the host adapter.
pub(in crate::windows) struct Win16DcUse {
    shared: Arc<Mutex<Win16DcState>>,
    token: Win16HostDc,
    // Keep the lease Send without an unsafe impl; convert only at native use.
    native: usize,
}

impl Win16DcUse {
    pub(in crate::windows) fn native(&self) -> HDC {
        self.native as HDC
    }
}

impl Drop for Win16DcUse {
    fn drop(&mut self) {
        // Drop cannot return a poisoned-lock error. Recover only to balance
        // this lease; the poison remains set, and future acquisitions report it.
        let mut state = self
            .shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let handle = state.objects.get(&self.token).map(|dc| dc.handle);
        let remove_retired = match state.objects.get_mut(&self.token) {
            Some(dc) => {
                debug_assert!(dc.pin_count > 0, "Win16 HDC lease count underflow");
                if dc.pin_count == 0 {
                    false
                } else {
                    dc.pin_count -= 1;
                    dc.pin_count == 0 && dc.retire_on_unpin
                }
            }
            None => false,
        };
        if remove_retired {
            state.objects.remove(&self.token);
        }
        if let Some(handle) = handle {
            state.remove_retired_unpinned_aliases(handle);
        }
    }
}

impl Win16Dcs {
    /// Pins one live native HDC under a short table lock. The returned lease
    /// owns the shared table state until the native operation has finished.
    pub(in crate::windows) fn lease_dc(
        &self,
        token: Win16HostDc,
    ) -> Result<Option<Win16DcUse>, RuntimeError> {
        let mut state = self.shared.lock().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 host device-context lease table mutex is poisoned",
            )
        })?;
        if !state.native_resource_available(token) {
            return Ok(None);
        }
        let Some(dc) = state.objects.get_mut(&token) else {
            return Ok(None);
        };
        let Some(pin_count) = dc.pin_count.checked_add(1) else {
            return Err(RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 host device-context lease count exhausted",
            ));
        };
        dc.pin_count = pin_count;
        let native = dc.handle;
        drop(state);
        Ok(Some(Win16DcUse {
            shared: Arc::clone(&self.shared),
            token,
            native,
        }))
    }

    /// Reserves a borrowed USER DC for its matching native release. Once this
    /// reservation is set, new leases cannot race ReleaseDC or EndPaint.
    pub(in crate::windows) fn window_dc_native(
        &self,
        token: Win16HostDc,
        window: Win16HostWindow,
        lease: WindowDcLease,
    ) -> Option<HDC> {
        self.lock().begin_window_dc_release(token, window, lease)
    }

    pub(in crate::windows) fn forget_window_dc(
        &self,
        token: Win16HostDc,
        window: Win16HostWindow,
        lease: WindowDcLease,
    ) -> bool {
        self.lock().forget_window_dc(token, window, lease)
    }

    pub(in crate::windows) fn cancel_window_dc_release(
        &self,
        token: Win16HostDc,
        window: Win16HostWindow,
        lease: WindowDcLease,
    ) -> bool {
        self.lock().cancel_window_dc_release(token, window, lease)
    }

    pub(in crate::windows) fn forget_callback_dc(
        &self,
        token: Win16HostDc,
        window: Win16HostWindow,
    ) -> bool {
        self.lock().forget_callback_dc(token, window)
    }

    /// Reports a native use or release reservation owned by this window.
    /// Alias tokens for the same raw HDC participate in the same check.
    pub(in crate::windows) fn window_has_active_dc(&self, window: Win16HostWindow) -> bool {
        self.lock().window_has_active_dc(window)
    }

    /// Retires this window's borrowed DC identities without making a native
    /// ReleaseDC/DeleteDC call. Active group users defer identity removal.
    pub(in crate::windows) fn retire_window(&self, window: Win16HostWindow) {
        self.lock().retire_window(window)
    }

    pub(in crate::windows) fn delete(&self, token: Win16HostDc) -> bool {
        self.lock().delete(token)
    }

    pub(in crate::windows) fn release_screen(&self, token: Win16HostDc) -> bool {
        self.lock().release_screen(token)
    }
}

impl Win16DcState {
    /// Looks up an HDC only when its logical alias is live and no matching
    /// ReleaseDC/EndPaint reservation is active for the raw native resource.
    /// This host synchronization state is not an API-visible DC busy status.
    pub(super) fn native_resource_available(&self, token: Win16HostDc) -> bool {
        self.objects.get(&token).is_some_and(|dc| {
            !dc.retire_on_unpin && !self.native_group_has_release_pending(dc.handle)
        })
    }

    pub(super) fn window_dc_native(
        &self,
        token: Win16HostDc,
        window: Win16HostWindow,
        lease: WindowDcLease,
    ) -> Option<HDC> {
        let native = self.objects.get(&token)?;
        match native.origin {
            DcOrigin::Window {
                window: owner,
                lease: kind,
            } if owner == window && kind == lease => Some(native.handle()),
            _ => None,
        }
    }

    fn window_has_active_dc(&self, window: Win16HostWindow) -> bool {
        self.objects.values().any(|dc| {
            matches!(dc.origin, DcOrigin::Window { window: owner, .. } if owner == window)
                && self.native_group_has_pin_or_pending(dc.handle)
        })
    }

    fn retire_window(&mut self, window: Win16HostWindow) {
        let tokens: Vec<_> = self
            .objects
            .iter()
            .filter_map(|(token, dc)| {
                matches!(dc.origin, DcOrigin::Window { window: owner, .. } if owner == window)
                    .then_some(*token)
            })
            .collect();
        for token in tokens {
            let Some(handle) = self.objects.get(&token).map(|dc| dc.handle) else {
                continue;
            };
            if self.native_group_has_pin_or_pending(handle) {
                if let Some(dc) = self.objects.get_mut(&token) {
                    dc.retire_on_unpin = true;
                }
            } else {
                self.objects.remove(&token);
            }
        }
    }

    fn begin_window_dc_release(
        &mut self,
        token: Win16HostDc,
        window: Win16HostWindow,
        lease: WindowDcLease,
    ) -> Option<HDC> {
        if lease == WindowDcLease::Callback {
            return None;
        }
        let native = self.objects.get(&token)?;
        if native.retire_on_unpin
            || !matches!(native.origin,
            DcOrigin::Window { window: owner, lease: kind }
                if owner == window && kind == lease)
        {
            return None;
        }
        let handle = native.handle;
        if self.native_group_has_pin_or_pending(handle) {
            return None;
        }
        self.set_native_group_release_pending(handle, true);
        Some(handle as HDC)
    }

    pub(super) fn forget_window_dc(
        &mut self,
        token: Win16HostDc,
        window: Win16HostWindow,
        lease: WindowDcLease,
    ) -> bool {
        let Some(native) = self.objects.get(&token) else {
            return false;
        };
        let handle = native.handle;
        let matches_release = matches!(native.origin,
            DcOrigin::Window { window: owner, lease: kind }
                if owner == window && kind == lease);
        if !matches_release || !native.release_pending || self.native_group_has_pin(handle) {
            return false;
        }
        self.objects.remove(&token);
        self.set_native_group_release_pending(handle, false);
        self.remove_retired_unpinned_aliases(handle);
        true
    }

    pub(super) fn cancel_window_dc_release(
        &mut self,
        token: Win16HostDc,
        window: Win16HostWindow,
        lease: WindowDcLease,
    ) -> bool {
        let Some(native) = self.objects.get(&token) else {
            return false;
        };
        let handle = native.handle;
        let matches_release = matches!(native.origin,
            DcOrigin::Window { window: owner, lease: kind }
                if owner == window && kind == lease);
        if !matches_release || !native.release_pending {
            return false;
        }
        self.set_native_group_release_pending(handle, false);
        self.remove_retired_unpinned_aliases(handle);
        true
    }

    pub(super) fn forget_callback_dc(
        &mut self,
        token: Win16HostDc,
        window: Win16HostWindow,
    ) -> bool {
        let Some(native) = self.objects.get_mut(&token) else {
            return false;
        };
        if !matches!(native.origin,
            DcOrigin::Window { window: owner, lease: WindowDcLease::Callback }
                if owner == window)
        {
            return false;
        }
        if native.pin_count != 0 {
            // Callback HDC retirement is internal. Remove the alias as soon
            // as its active native operation releases the final pin.
            native.retire_on_unpin = true;
            return false;
        }
        self.objects.remove(&token);
        true
    }

    pub(super) fn delete(&mut self, token: Win16HostDc) -> bool {
        let Some(&native) = self.objects.get(&token) else {
            return false;
        };
        if self.native_group_has_pin_or_pending(native.handle)
            || native.retire_on_unpin
            || !matches!(
                native.origin,
                DcOrigin::Compatible | DcOrigin::Information | DcOrigin::Created
            )
        {
            return false;
        }
        // SAFETY: The table owns this live HDC and removes it only after GDI
        // reports successful deletion. Active leases block this operation.
        if (crate::windows::win32_safe::delete_dc(native.handle())) == 0 {
            return false;
        }
        // DeleteDC destroys the native object itself, so aliases of this exact
        // raw HDC can no longer be used. Their token origins stay distinct up
        // to this successful native retirement.
        self.objects
            .retain(|_, alias| alias.handle != native.handle);
        true
    }

    pub(super) fn release_screen(&mut self, token: Win16HostDc) -> bool {
        let Some(&native) = self.objects.get(&token) else {
            return false;
        };
        if self.native_group_has_pin_or_pending(native.handle)
            || native.retire_on_unpin
            || !matches!(native.origin, DcOrigin::Screen)
        {
            return false;
        }
        // SAFETY: This DC was acquired for the null screen HWND above.
        if (crate::windows::win32_safe::release_dc(std::ptr::null_mut(), native.handle())) == 0 {
            return false;
        }
        self.objects.remove(&token);
        true
    }

    fn native_group_has_pin(&self, handle: usize) -> bool {
        self.objects
            .values()
            .any(|dc| dc.handle == handle && dc.pin_count != 0)
    }

    fn native_group_has_release_pending(&self, handle: usize) -> bool {
        self.objects
            .values()
            .any(|dc| dc.handle == handle && dc.release_pending)
    }

    pub(super) fn native_group_has_pin_or_pending(&self, handle: usize) -> bool {
        self.objects
            .values()
            .any(|dc| dc.handle == handle && (dc.pin_count != 0 || dc.release_pending))
    }

    fn set_native_group_release_pending(&mut self, handle: usize, pending: bool) {
        for dc in self.objects.values_mut().filter(|dc| dc.handle == handle) {
            dc.release_pending = pending;
        }
    }

    fn remove_retired_unpinned_aliases(&mut self, handle: usize) {
        if self.native_group_has_pin_or_pending(handle) {
            return;
        }
        self.objects
            .retain(|_, dc| dc.handle != handle || !dc.retire_on_unpin || dc.pin_count != 0);
    }
}
