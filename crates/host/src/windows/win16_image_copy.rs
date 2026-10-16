//! Native image copies pinned across USER without holding the image-table lock.

use super::{ImageKind, NativeIconGuard, Win16Images};
use runtime::{RuntimeError, Win16HostCursor, Win16HostIcon};
use windows_sys::Win32::UI::WindowsAndMessaging::{CopyImage, IMAGE_CURSOR, IMAGE_ICON};

impl Win16Images {
    pub(in crate::windows) fn copy_icon(
        &self,
        source: Win16HostIcon,
    ) -> Result<Option<Win16HostIcon>, RuntimeError> {
        self.copy_image(source.0, ImageKind::Icon)
            .map(|copy| copy.map(Win16HostIcon))
    }

    pub(in crate::windows) fn copy_cursor(
        &self,
        source: Win16HostCursor,
    ) -> Result<Option<Win16HostCursor>, RuntimeError> {
        self.copy_image(source.0, ImageKind::Cursor)
            .map(|copy| copy.map(Win16HostCursor))
    }

    fn copy_image(&self, token: u64, kind: ImageKind) -> Result<Option<u64>, RuntimeError> {
        let source = self
            .lock()?
            .images
            .get(&token)
            .filter(|image| image.image.kind == kind)
            .cloned();
        let Some(source) = source else {
            return Ok(None);
        };
        let image_type = match kind {
            ImageKind::Icon => IMAGE_ICON,
            ImageKind::Cursor => IMAGE_CURSOR,
        };
        // SAFETY: Retain owned sources while USER copies their pixels and
        // attributes, including cursor hotspots. Borrowed images retain their
        // external native USER lifetime contract; USER validates the handle.
        // Zero dimensions preserve its size. Flags zero create a new object;
        // they never delete, reload or return the original image.
        // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-copyimage
        let copy = unsafe { CopyImage(source.image.handle(), image_type, 0, 0, 0) };
        if copy.is_null() {
            return Ok(None);
        }
        let result = self
            .insert_owned(NativeIconGuard::new_kind(copy, kind))
            .map(Some);
        drop(source);
        result
    }
}
