//! Noninteractive ScrollDC tests using owned memory DCs and monochrome bitmaps.

use super::*;
use crate::windows::{guest_text::GuestTextCodec, win16_gdi_objects::Win16Objects};
use runtime::{Win16HostDc, Win16HostRect};
use std::ptr;
use windows_sys::Win32::Graphics::Gdi::{
    BLACKNESS, CreateBitmap, GetPixel, GetRgnBox, HDC, HGDIOBJ, MM_ANISOTROPIC, PatBlt,
    SelectObject, SetMapMode, SetPixel, SetViewportExtEx, SetViewportOrgEx, SetWindowExtEx,
    WHITE_BRUSH,
};

struct Surface {
    dcs: Win16Dcs,
    token: Win16HostDc,
    native: HDC,
    bitmap: HGDIOBJ,
    previous: HGDIOBJ,
}

impl Surface {
    fn new() -> Self {
        let dcs = Win16Dcs::with_text_codec(GuestTextCodec::new(1252).unwrap());
        let token = dcs.create_compatible(None).unwrap().unwrap();
        let lease = dcs.lease_dc(token).unwrap().unwrap();
        let native = lease.native();
        // SAFETY: Creates a private 16x16 monochrome bitmap with no input bits.
        let bitmap = unsafe { CreateBitmap(16, 16, 1, 1, ptr::null()) };
        assert!(!bitmap.is_null());
        let previous = unsafe { SelectObject(native, bitmap) };
        assert!(!previous.is_null() && previous as usize != usize::MAX);
        // SAFETY: PatBlt uses a live device context owned by this process.
        assert_ne!(unsafe { PatBlt(native, 0, 0, 16, 16, BLACKNESS) }, 0);
        // SAFETY: SetPixel writes one pixel on a live DC.
        assert_eq!(unsafe { SetPixel(native, 8, 5, 0x00ff_ffff) }, 0x00ff_ffff);
        Self {
            dcs,
            token,
            native,
            bitmap,
            previous,
        }
    }

    fn operation(&self, dx: i16, dy: i16) -> Operation {
        Operation::ScrollDC {
            dc: self.token,
            dx,
            dy,
            scroll_rect: Some(Win16HostRect {
                left: 0,
                top: 0,
                right: 16,
                bottom: 16,
            }),
            clip_rect: Some(Win16HostRect {
                left: 0,
                top: 0,
                right: 16,
                bottom: 16,
            }),
            update_region: None,
            update_rect_is_null: false,
        }
    }
}

impl Drop for Surface {
    fn drop(&mut self) {
        // SAFETY: Restore the stock bitmap before deleting the test-owned bitmap.
        // No test lease or native operation is active during teardown.
        unsafe {
            SelectObject(self.native, self.previous);
            crate::windows::win32_safe::delete_object(self.bitmap);
        }
        self.dcs.delete(self.token);
    }
}

#[test]
fn scroll_dc_native_moves_memory_bitmap_pixels_and_returns_update_bounds() {
    for (dx, dy) in [(2, 0), (-2, 3)] {
        let surface = Surface::new();
        let mut objects = Win16Objects::new();
        let token = objects.create_region().unwrap().unwrap();
        let snapshot = objects.lease_region(token).unwrap().unwrap();
        let mut operation = surface.operation(dx, dy);
        let Operation::ScrollDC { update_region, .. } = &mut operation else {
            unreachable!()
        };
        *update_region = Some(token);
        let regions = [(token, Some(snapshot.clone()))].into_iter().collect();
        let result = execute(&surface.dcs, &operation, &regions).unwrap();
        let ResultValue::Rect {
            value: 1,
            rect: Some(bounds),
        } = result
        else {
            panic!("native memory-DC ScrollDC failed: {result:?}");
        };
        // GDI flushes pending drawing as needed for GetPixel.
        // SAFETY: GetPixel reads one pixel on a live DC.
        assert_eq!(
            unsafe { GetPixel(surface.native, 8 + i32::from(dx), 5 + i32::from(dy)) },
            0x00ff_ffff
        );
        // SAFETY: GetPixel reads one pixel on a live DC.
        assert_eq!(unsafe { GetPixel(surface.native, 8, 5) }, 0);
        let mut region_bounds = RECT::default();
        // SAFETY: `GetRgnBox` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        assert_ne!(
            unsafe { GetRgnBox(snapshot.native(), &mut region_bounds) },
            0
        );
        assert_eq!(bounds, host_rect(region_bounds));
        if dy == 0 {
            assert_eq!(
                bounds,
                Win16HostRect {
                    left: 0,
                    top: 0,
                    right: 2,
                    bottom: 16
                }
            );
        }
    }
}

#[test]
fn scroll_dc_native_keeps_null_outputs_and_rejects_unknown_resources_before_pixels() {
    let surface = Surface::new();
    let mut operation = surface.operation(2, 0);
    let Operation::ScrollDC { update_region, .. } = &mut operation else {
        unreachable!()
    };
    *update_region = Some(Win16HostGdiObject(u64::MAX));
    assert_eq!(
        execute(&surface.dcs, &operation, &BTreeMap::new()).unwrap(),
        ResultValue::Rect {
            value: 0,
            rect: None
        }
    );
    // SAFETY: GetPixel reads one pixel on a live DC.
    assert_eq!(unsafe { GetPixel(surface.native, 8, 5) }, 0x00ff_ffff);
    let mut objects = Win16Objects::new();
    // A mapped non-region GDI object must fail, never become an optional NULL.
    let brush = objects
        .intern_borrowed(crate::windows::win32_safe::stock_object(WHITE_BRUSH))
        .unwrap();
    let invalid_region = objects.lease_region(brush).unwrap();
    assert!(invalid_region.is_none());
    let Operation::ScrollDC { update_region, .. } = &mut operation else {
        unreachable!()
    };
    *update_region = Some(brush);
    let regions = [(brush, invalid_region)].into_iter().collect();
    assert_eq!(
        execute(&surface.dcs, &operation, &regions).unwrap(),
        ResultValue::Rect {
            value: 0,
            rect: None
        }
    );
    // SAFETY: GetPixel reads one pixel on a live DC.
    assert_eq!(unsafe { GetPixel(surface.native, 8, 5) }, 0x00ff_ffff);
    let Operation::ScrollDC {
        dc,
        update_region,
        update_rect_is_null,
        scroll_rect,
        clip_rect,
        ..
    } = &mut operation
    else {
        unreachable!()
    };
    *update_region = None;
    *update_rect_is_null = true;
    *scroll_rect = None;
    *clip_rect = None;
    *dc = Win16HostDc(u64::MAX);
    assert_eq!(
        execute(&surface.dcs, &operation, &BTreeMap::new()).unwrap(),
        ResultValue::Rect {
            value: 0,
            rect: None
        }
    );
    // SAFETY: GetPixel reads one pixel on a live DC.
    assert_eq!(unsafe { GetPixel(surface.native, 8, 5) }, 0x00ff_ffff);
    let Operation::ScrollDC { dc, .. } = &mut operation else {
        unreachable!()
    };
    *dc = surface.token;
    assert_eq!(
        execute(&surface.dcs, &operation, &BTreeMap::new()).unwrap(),
        ResultValue::Rect {
            value: 1,
            rect: None
        }
    );
    // SAFETY: GetPixel reads one pixel on a live DC.
    assert_eq!(unsafe { GetPixel(surface.native, 10, 5) }, 0x00ff_ffff);
}

#[test]
fn scroll_dc_native_preserves_nondefault_mapping_against_direct_api() {
    let surface = Surface::new();
    // SAFETY: All mapping changes are limited to this test's owned memory DC.
    unsafe {
        assert_ne!(SetMapMode(surface.native, MM_ANISOTROPIC), 0);
        assert_ne!(SetWindowExtEx(surface.native, 8, 8, ptr::null_mut()), 0);
        assert_ne!(SetViewportExtEx(surface.native, 16, 16, ptr::null_mut()), 0);
        assert_ne!(SetViewportOrgEx(surface.native, 1, 2, ptr::null_mut()), 0);
    }
    let logical = Win16HostRect {
        left: 0,
        top: 0,
        right: 6,
        bottom: 6,
    };
    let native = native_rect(logical);
    let mut expected = RECT::default();
    // SAFETY: ScrollDC reads optional caller-owned RECTs.
    let native_value = unsafe {
        ScrollDC(
            surface.native,
            -2,
            1,
            &native,
            &native,
            ptr::null_mut(),
            &mut expected,
        )
    };
    assert_ne!(native_value, 0);
    let operation = Operation::ScrollDC {
        dc: surface.token,
        dx: -2,
        dy: 1,
        scroll_rect: Some(logical),
        clip_rect: Some(logical),
        update_region: None,
        update_rect_is_null: false,
    };
    assert_eq!(
        execute(&surface.dcs, &operation, &BTreeMap::new()).unwrap(),
        ResultValue::Rect {
            value: 1,
            rect: Some(host_rect(expected))
        }
    );
}
