//! GetDCEx factories and ownership transfer of its optional clipping region.

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostDc, Win16HostGdiObject};
use windows_sys::Win32::{
    Foundation::HWND,
    Graphics::Gdi::{
        CombineRgn, CreateRectRgn, DeleteObject, GetDCEx, HDC, HRGN, RGN_COPY, RGN_ERROR,
    },
};

use super::{
    win16_gdi::Win16Dcs,
    win16_gdi_objects::{Win16Objects, Win16RegionLease},
};

struct ClipCopy(HRGN);

impl Drop for ClipCopy {
    fn drop(&mut self) {
        // SAFETY: This copy is uniquely owned until a successful GetDCEx
        // transfers it to USER, at which point the guard is forgotten.
        unsafe {
            DeleteObject(self.0.cast());
        }
    }
}

pub(super) fn acquire_native(window: HWND, region: Option<&Win16RegionLease>, flags: u32) -> HDC {
    let clip = if flags & 0xc0 != 0 {
        if let Some(region) = region {
            // A lease may be shared with a pending operation. USER must get a
            // separate unique copy: it deletes hrgnClip after successful
            // DCX_INTERSECTRGN/DCX_EXCLUDERGN acquisition (GetDCEx contract).
            // https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-getdcex
            let native = unsafe { CreateRectRgn(0, 0, 0, 0) };
            if native.is_null() {
                return std::ptr::null_mut();
            }
            let owned = ClipCopy(native);
            // SAFETY: Both regions are live, RGN_COPY ignores its third
            // argument, and no mutable shared region is exposed to USER.
            if unsafe { CombineRgn(native, region.native(), std::ptr::null_mut(), RGN_COPY) }
                == RGN_ERROR
            {
                return std::ptr::null_mut();
            }
            Some(owned)
        } else {
            None
        }
    } else {
        None
    };
    let native_clip = clip.as_ref().map_or(std::ptr::null_mut(), |clip| clip.0);
    // SAFETY: window is NULL or an HWND resolved by the window worker. The
    // unique clip copy remains live throughout this native call. Flags retain
    // native visible-region, parent, cache and window-style semantics.
    let dc = unsafe { GetDCEx(window, native_clip, flags) };
    if !dc.is_null()
        && let Some(clip) = clip
    {
        std::mem::forget(clip);
    }
    dc
}

pub(super) fn acquire_screen(
    dcs: &Win16Dcs,
    objects: &mut Win16Objects,
    region: Option<Win16HostGdiObject>,
    flags: u32,
) -> Result<Option<Win16HostDc>, RuntimeError> {
    let region = region.filter(|_| flags & 0xc0 != 0);
    let snapshot = match region {
        Some(token) => match objects.lease_region(token)? {
            Some(lease) => Some(lease),
            None => return Ok(None),
        },
        None => None,
    };
    let native = acquire_native(std::ptr::null_mut(), snapshot.as_ref(), flags);
    // adopt_screen_dc also releases an unpublished native DC if the opaque
    // identity table is exhausted. Both operations remain on this thread.
    let Some(dc) = dcs.adopt_screen_dc(native)? else {
        return Ok(None);
    };
    if let Some(region) = region
        && let Err(error) = objects.consume_region(region)
    {
        if !dcs.release_screen(dc) {
            return Err(RuntimeError::with_source(
                Kind::InternalInvariant,
                "GetDCEx region transfer failed and its screen DC could not be released",
                error,
            ));
        }
        return Err(error);
    }
    Ok(Some(dc))
}
