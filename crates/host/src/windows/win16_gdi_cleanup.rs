//! DC cleanup results preserve the native component that owns each lease.

use runtime::{Win16HostDc, Win16HostGdiCleanup};
use super::{DcOrigin, Win16DcState};

impl Win16DcState {
    pub(super) fn cleanup(&mut self, token: Win16HostDc) -> bool {
        matches!(self.cleanup_state(token), Win16HostGdiCleanup::Released)
    }

    pub(super) fn cleanup_state(&mut self, token: Win16HostDc) -> Win16HostGdiCleanup {
        let released = match self.objects.get(&token).map(|dc| dc.origin) {
            Some(DcOrigin::Compatible | DcOrigin::Information | DcOrigin::Created) => {
                self.delete(token)
            }
            Some(DcOrigin::Metafile) => self.close_metafile(token).consumed,
            Some(DcOrigin::Screen) => self.release_screen(token),
            // USER owns window/paint/callback DC leases on its worker thread.
            // Task cleanup has already closed native windows and callbacks;
            // retiring the guest alias does not transfer that lease to GDI or
            // authorize a ReleaseDC/DeleteDC call on another thread.
            Some(DcOrigin::Window { .. }) => return Win16HostGdiCleanup::Borrowed,
            None => return Win16HostGdiCleanup::Absent,
        };
        if released { Win16HostGdiCleanup::Released } else { Win16HostGdiCleanup::Failed }
    }
}
