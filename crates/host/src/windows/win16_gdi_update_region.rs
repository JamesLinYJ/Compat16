//! HDC lifetime protection for the synchronous clipping-region query.

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::Graphics::Gdi::ExcludeUpdateRgn;

use super::{Win16Dcs, Win16HostDc};
use runtime::RuntimeError;

impl Win16Dcs {
    /// Pins the HDC under a short lock, then calls USER without holding the
    /// shared table mutex so synchronous callbacks cannot deadlock DC cleanup.
    pub(in crate::windows) fn exclude_update_region(
        &self,
        token: Win16HostDc,
        window: HWND,
    ) -> Result<Option<u16>, RuntimeError> {
        let Some(dc) = self.lease_dc(token)? else { return Ok(None); };
        // SAFETY: The RAII lease keeps this validated table-owned HDC alive
        // for the call. `window` is a native HWND resolved by the USER worker.
        Ok(Some(unsafe { ExcludeUpdateRgn(dc.native(), window) } as u16))
    }
}
