//! Aligned native GetObject queries with pointer-free result descriptions.

use super::Win16Objects;
use super::super::guest_text::GuestTextCodec;
use super::super::win16_gdi::fonts::guest_face_name;
use runtime::{RuntimeError, Win16GdiObjectInfo as Info, Win16HostGdiObject,
    Win16HostBitmapInfo, Win16HostLogBrush, Win16HostLogFont, Win16HostLogPen};
use windows_sys::Win32::Graphics::Gdi::{
    GetObjectW, GetObjectType, HGDIOBJ, BITMAP, LOGBRUSH, LOGFONTW, LOGPEN,
    OBJ_BITMAP, OBJ_BRUSH, OBJ_FONT, OBJ_PAL, OBJ_PEN, BS_SOLID, BS_NULL, BS_HATCHED, BS_PATTERN,
};

impl Win16Objects {
    pub(in crate::windows) fn query_object(
        &mut self,
        token: Win16HostGdiObject,
        codec: GuestTextCodec,
    )
        -> Result<Option<Info>, RuntimeError>
    {
        let Some(object) = self.objects.get(&token) else { return Ok(None); };
        let native = object.handle;
        // The table retains ownership for this synchronous call. No guest
        // callback runs while these aligned Windows structures are filled.
        let kind = unsafe { GetObjectType(native) } as i32;
        let info = match kind {
            OBJ_PEN => read::<LOGPEN>(native).map(|pen| Info::Pen(Win16HostLogPen {
                style: pen.lopnStyle as u16, width_x: pen.lopnWidth.x as i16,
                width_y: pen.lopnWidth.y as i16, color: pen.lopnColor,
            })),
            OBJ_FONT => {
                let Some(font) = read_wide::<LOGFONTW>(native) else {
                    return Ok(None);
                };
                Some(Info::Font(Win16HostLogFont {
                    height: font.lfHeight as i16, width: font.lfWidth as i16,
                    escapement: font.lfEscapement as i16, orientation: font.lfOrientation as i16,
                    weight: font.lfWeight as i16, italic: font.lfItalic, underline: font.lfUnderline,
                    strikeout: font.lfStrikeOut, char_set: font.lfCharSet,
                    out_precision: font.lfOutPrecision, clip_precision: font.lfClipPrecision,
                    quality: font.lfQuality, pitch_and_family: font.lfPitchAndFamily,
                    face_name: guest_face_name(codec, &font.lfFaceName)?,
                }))
            }
            OBJ_BITMAP => read::<BITMAP>(native).map(|bitmap| Info::Bitmap(Win16HostBitmapInfo {
                kind: bitmap.bmType as i16, width: bitmap.bmWidth as i16,
                height: bitmap.bmHeight as i16, width_bytes: bitmap.bmWidthBytes as i16,
                planes: bitmap.bmPlanes as u8, bits_per_pixel: bitmap.bmBitsPixel as u8,
            })),
            OBJ_BRUSH => {
                let Some(brush) = read::<LOGBRUSH>(native) else { return Ok(None); };
                let pattern = if brush.lbStyle == BS_PATTERN {
                    Some(self.intern_borrowed(brush.lbHatch as HGDIOBJ)?)
                } else { None };
                if matches!(brush.lbStyle, BS_SOLID | BS_NULL | BS_HATCHED | BS_PATTERN) {
                    Some(Info::Brush { brush: Win16HostLogBrush {
                        style: brush.lbStyle as u16, color: brush.lbColor,
                        hatch: if brush.lbStyle == BS_HATCHED { brush.lbHatch as u32 } else { 0 },
                    }, pattern })
                } else {
                    // DIB pattern fields may contain native memory addresses.
                    // A reverse guest-global mapping is required before exposing them.
                    Some(Info::UnsupportedBrush)
                }
            }
            OBJ_PAL => {
                // GetObject writes a WORD, but requires DWORD-aligned storage.
                let mut count = 0u32;
                let result = unsafe { GetObjectW(native, 2, (&mut count as *mut u32).cast()) };
                (result == 2).then_some(Info::Palette(count as u16))
            }
            _ => None,
        };
        Ok(info)
    }
}

fn read<T: Default>(native: HGDIOBJ) -> Option<T> {
    let mut value = T::default();
    // Only native GDI POD types reach this private helper; Windows receives
    // their actual size and alignment, never a guest buffer or wire layout.
    let result = unsafe {
        GetObjectW(native, std::mem::size_of::<T>() as i32, (&mut value as *mut T).cast())
    };
    (result == std::mem::size_of::<T>() as i32).then_some(value)
}

fn read_wide<T: Default>(native: HGDIOBJ) -> Option<T> {
    let mut value = T::default();
    // GetObjectW fills aligned native Unicode structures; only LOGFONTW uses
    // this helper, never the fixed-layout guest or runtime record.
    let result = unsafe {
        GetObjectW(native, std::mem::size_of::<T>() as i32, (&mut value as *mut T).cast())
    };
    (result == std::mem::size_of::<T>() as i32).then_some(value)
}
