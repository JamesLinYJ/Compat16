use super::super::guest_text::GuestTextCodec;
use super::super::{
    win16_gdi::Win16Dcs, win16_gdi_object_factories, win16_gdi_objects::Win16Objects,
};
use super::*;
use runtime::Win16GdiObjectOperation;
use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAP, BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS, GetDC, GetDIBits, GetObjectW,
    HBITMAP, HDC, LoadBitmapW,
};

const PAIRS: [(u16, u16); 8] = [
    (32767, 32754),
    (32765, 32753),
    (32764, 32752),
    (32763, 32751),
    (32762, 32750),
    (32757, 32749),
    (32756, 32748),
    (32755, 32747),
];

#[test]
fn oem_bitmap_legacy_names_resolve_to_the_same_native_glyphs() {
    for (old, native) in PAIRS {
        assert_eq!(native_resource_id(old), native);
    }
}

#[test]
fn oem_bitmap_other_resource_ids_remain_unchanged() {
    for id in 0..=u16::MAX {
        if !PAIRS.iter().any(|(old, _)| *old == id) {
            assert_eq!(native_resource_id(id), id);
        }
    }
}

struct Bitmap(HBITMAP);
impl Drop for Bitmap {
    fn drop(&mut self) {
        (crate::windows::win32_safe::delete_object(self.0.cast()));
    }
}

struct Screen(HDC);
impl Screen {
    fn new() -> Self {
        // SAFETY: GetDC returns a device context for the HWND or the screen when the HWND is null.
        let dc = unsafe { GetDC(std::ptr::null_mut()) };
        assert!(!dc.is_null());
        Self(dc)
    }
}
impl Drop for Screen {
    fn drop(&mut self) {
        (crate::windows::win32_safe::release_dc(std::ptr::null_mut(), self.0));
    }
}

fn pixels(dc: HDC, bitmap: HBITMAP) -> (i32, i32, Vec<[u8; 3]>) {
    let mut object = BITMAP::default();
    assert_eq!(
        // SAFETY: GetObjectW writes into a caller-owned buffer of the byte count passed with it.
        unsafe {
            GetObjectW(
                bitmap.cast(),
                std::mem::size_of::<BITMAP>() as i32,
                (&mut object as *mut BITMAP).cast(),
            )
        },
        std::mem::size_of::<BITMAP>() as i32
    );
    assert!(object.bmWidth > 0 && object.bmWidth <= 4096);
    assert!(object.bmHeight > 0 && object.bmHeight <= 4096);
    let mut info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: object.bmWidth,
            biHeight: -object.bmHeight,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut bytes = vec![0; object.bmWidth as usize * object.bmHeight as usize * 4];
    assert_eq!(
        // SAFETY: `GetDIBits` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        unsafe {
            GetDIBits(
                dc,
                bitmap,
                0,
                object.bmHeight as u32,
                bytes.as_mut_ptr().cast(),
                &mut info,
                DIB_RGB_COLORS,
            )
        },
        object.bmHeight
    );
    // BI_RGB's unused alpha byte is not a pixel-color contract.
    let rgb = bytes
        .chunks_exact(4)
        .map(|pixel| [pixel[0], pixel[1], pixel[2]])
        .collect();
    (object.bmWidth, object.bmHeight, rgb)
}

#[test]
#[ignore = "requires Windows USER/GDI and a screen DC"]
fn oem_bitmap_native_legacy_outputs_match_current_user_glyph_pixels() {
    let mut objects = Win16Objects::new();
    let dcs = Win16Dcs::with_text_codec(GuestTextCodec::new(1252).unwrap());
    let screen = Screen::new();
    for (old, canonical) in PAIRS {
        // SAFETY: `LoadBitmapW` receives a host pointer formed in this function. The pointer is non-null when dereferenced, stays live for this synchronous call, and is not a guest address.
        let expected = Bitmap(unsafe {
            LoadBitmapW(std::ptr::null_mut(), usize::from(canonical) as *const u16)
        });
        assert!(!expected.0.is_null());
        let object = win16_gdi_object_factories::create(
            &mut objects,
            &dcs,
            Win16GdiObjectOperation::LoadSystemBitmap { resource_id: old },
        )
        .unwrap()
        .expect("legacy OEM bitmap");
        let native = objects.native_bitmap(object).unwrap();
        assert_eq!(
            pixels(screen.0, native),
            pixels(screen.0, expected.0),
            "OEM ID {old}"
        );
        assert!(objects.delete(object));
    }
}

#[test]
#[ignore = "requires Windows USER/GDI and a screen DC"]
fn oem_bitmap_native_loads_are_independently_owned_and_invalid_ids_fail() {
    let mut objects = Win16Objects::new();
    let dcs = Win16Dcs::with_text_codec(GuestTextCodec::new(1252).unwrap());
    let screen = Screen::new();
    let mut load = || {
        win16_gdi_object_factories::create(
            &mut objects,
            &dcs,
            Win16GdiObjectOperation::LoadSystemBitmap { resource_id: 32762 },
        )
        .unwrap()
        .unwrap()
    };
    let first = load();
    let second = load();
    assert_ne!(first, second);
    let bitmap = objects.native_bitmap(second).unwrap();
    let before = pixels(screen.0, bitmap);
    assert!(objects.delete(first));
    assert!(!objects.delete(first));
    assert_eq!(pixels(screen.0, bitmap), before);
    assert!(objects.delete(second));
    assert!(
        win16_gdi_object_factories::create(
            &mut objects,
            &dcs,
            Win16GdiObjectOperation::LoadSystemBitmap {
                resource_id: 0x1234
            }
        )
        .unwrap()
        .is_none()
    );
}
