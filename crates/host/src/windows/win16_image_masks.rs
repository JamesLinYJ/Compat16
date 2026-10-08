//! Native icon/cursor mask constructors using the shared image ownership table.

use super::{Win16Images, ImageKind, NativeImage, destroy};
use runtime::{RuntimeError, Win16HostIcon, Win16HostCursor, Win16HostImageMasks};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{CreateIcon, CreateCursor, HICON};

impl Win16Images {
    pub(in crate::windows) fn create_icon_masks(&self, masks: &Win16HostImageMasks)
        -> Result<Option<Win16HostIcon>, RuntimeError>
    {
        if !masks.valid() { return Ok(None); }
        // CreateIcon has no buffer lengths. Shared extent checks retain the
        // complete WORD-aligned arrays across USER's synchronous copy.
        // HINSTANCE names the native creating module, never the guest instance.
        let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
        let icon = unsafe { CreateIcon(instance, i32::from(masks.width), i32::from(masks.height),
            masks.planes, masks.bits_per_pixel, masks.and_mask.as_ptr(), masks.xor_mask.as_ptr()) };
        self.retain_mask_image(icon, ImageKind::Icon).map(|token| token.map(Win16HostIcon))
    }

    pub(in crate::windows) fn create_cursor_masks(&self, masks: &Win16HostImageMasks, x: i16, y: i16)
        -> Result<Option<Win16HostCursor>, RuntimeError>
    {
        if masks.planes != 1 || masks.bits_per_pixel != 1 || !masks.valid() { return Ok(None); }
        let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
        // Both arrays are validated monochrome masks; Windows owns hotspot
        // acceptance, pixel interpretation and the returned cursor lifetime.
        let cursor = unsafe { CreateCursor(instance, i32::from(x), i32::from(y),
            i32::from(masks.width), i32::from(masks.height),
            masks.and_mask.as_ptr().cast(), masks.xor_mask.as_ptr().cast()) };
        self.retain_mask_image(cursor, ImageKind::Cursor).map(|token| token.map(Win16HostCursor))
    }

    fn retain_mask_image(&self, native: HICON, kind: ImageKind) -> Result<Option<u64>, RuntimeError> {
        if native.is_null() { return Ok(None); }
        match self.insert(native, kind, true) {
            Ok(token) => Ok(Some(token)),
            Err(error) => {
                destroy(NativeImage::new(native, kind, true));
                Err(error)
            }
        }
    }
}
