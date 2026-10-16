//! Independent USER.CopyIcon/CopyCursor results in the task's image namespace.

use super::{GuestImage, Win16State};
use crate::{DiagnosticKind, RuntimeError, RuntimeHost};
use win16_abi::Win16UserResourcesRequest;

impl Win16State {
    pub(in crate::win16_runtime) fn copy_user_image(
        &mut self,
        request: Win16UserResourcesRequest,
        host: &mut impl RuntimeHost,
    ) -> Result<u16, RuntimeError> {
        // SDK 3.1 supplies the creating guest HINSTANCE as the first WORD.
        // As with CreateIcon/CreateCursor, its native lifetime belongs to the
        // task's image table. No guest instance becomes a native module handle,
        // and the copy never enters the original module's resource cache.
        let image = match request {
            Win16UserResourcesRequest::CopyIcon { icon, .. } => {
                let Some(source) = self.guest_images.icon(icon) else {
                    return Ok(0);
                };
                let Some(copy) = host.win16_copy_icon(source)? else {
                    return Ok(0);
                };
                GuestImage::Icon(copy)
            }
            Win16UserResourcesRequest::CopyCursor { cursor, .. } => {
                let Some(source) = self.guest_images.cursor(cursor) else {
                    return Ok(0);
                };
                let Some(copy) = host.win16_copy_cursor(source)? else {
                    return Ok(0);
                };
                GuestImage::Cursor(copy)
            }
            _ => {
                return Err(RuntimeError::new(
                    DiagnosticKind::InternalInvariant,
                    "non-copy request reached USER image copying",
                ));
            }
        };
        if let Some(handle) = self.guest_images.allocate(image) {
            return Ok(handle);
        }
        // The native copy already owns its resource. A full guest handle
        // table must release that unpublished copy while preserving the source.
        match image {
            GuestImage::Icon(icon) => host.win16_release_icon(icon)?,
            GuestImage::Cursor(cursor) => host.win16_release_cursor(cursor)?,
        }
        Ok(0)
    }
}
