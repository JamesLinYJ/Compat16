use super::WindowingError;
use super::context::WindowContext;
use graphics::{HostEvent, Rect, Surface};
use std::mem::size_of;
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BeginPaint, COLOR_WINDOW, DIB_RGB_COLORS, EndPaint, FillRect,
    GetSysColorBrush, PAINTSTRUCT, SRCCOPY, StretchDIBits,
};
use windows_sys::Win32::UI::WindowsAndMessaging::GetClientRect;

pub(super) struct OwnedDib {
    pub(super) width: i32,
    pub(super) height: i32,
    pub(super) bgra: Vec<u8>,
}

impl OwnedDib {
    pub(super) fn from_surface(surface: &Surface) -> Result<Self, WindowingError> {
        let width = i32::try_from(surface.width()).map_err(|_| WindowingError::InvalidRectangle)?;
        let height =
            i32::try_from(surface.height()).map_err(|_| WindowingError::InvalidRectangle)?;
        let byte_count = surface
            .pixels()
            .len()
            .checked_mul(4)
            .ok_or(WindowingError::AllocationFailed)?;
        let mut bgra = Vec::new();
        bgra.try_reserve_exact(byte_count)
            .map_err(|_| WindowingError::AllocationFailed)?;
        for color in surface.pixels() {
            bgra.extend_from_slice(&[color.blue, color.green, color.red, 0]);
        }
        Ok(Self {
            width,
            height,
            bgra,
        })
    }

    fn try_clone(&self) -> Result<Self, WindowingError> {
        let mut bgra = Vec::new();
        bgra.try_reserve_exact(self.bgra.len())
            .map_err(|_| WindowingError::AllocationFailed)?;
        bgra.extend_from_slice(&self.bgra);
        Ok(Self {
            width: self.width,
            height: self.height,
            bgra,
        })
    }

    pub(super) fn bitmap_info(&self) -> BITMAPINFO {
        let mut info = BITMAPINFO::default();
        info.bmiHeader.biSize =
            size_of::<windows_sys::Win32::Graphics::Gdi::BITMAPINFOHEADER>() as u32;
        info.bmiHeader.biWidth = self.width;
        // Negative height marks a top-down DIB; Surface row zero is its top row.
        info.bmiHeader.biHeight = -self.height;
        info.bmiHeader.biPlanes = 1;
        info.bmiHeader.biBitCount = 32;
        info.bmiHeader.biCompression = BI_RGB;
        info.bmiHeader.biSizeImage = self.bgra.len() as u32;
        info
    }
}

/// Copies an owned top-down 32-bit DIB to the current paint DC. The DC clips
/// the full-client stretch to the invalid region supplied by BeginPaint.
pub(super) fn paint_window(hwnd: HWND, context: &WindowContext) {
    let mut session = PaintSession::begin(hwnd);
    let damage = session.paint.rcPaint;
    context.emit(HostEvent::Paint {
        window: context.handle,
        damage: Rect::new(damage.left, damage.top, damage.right, damage.bottom),
    });

    if session.hdc.is_null() {
        context.report_native_failure("BeginPaint");
        session.finish();
        return;
    }

    let mut client = RECT::default();
    crate::windows::win32_safe::set_last_error(0);
    // SAFETY: GetClientRect writes into a caller-owned RECT that outlives the call.
    if unsafe { GetClientRect(hwnd, &mut client) } == 0 {
        context.report_native_failure("GetClientRect");
        session.finish();
        return;
    }
    let client_width = i64::from(client.right) - i64::from(client.left);
    let client_height = i64::from(client.bottom) - i64::from(client.top);
    let Some((client_width, client_height)) = i32::try_from(client_width)
        .ok()
        .zip(i32::try_from(client_height).ok())
    else {
        context.report_failure(WindowingError::InvalidRectangle);
        session.finish();
        return;
    };

    let dib = match context.surface.lock() {
        Ok(surface) => match surface.as_ref() {
            Some(surface) => match surface.try_clone() {
                Ok(dib) => Some(dib),
                Err(error) => {
                    context.report_failure(error);
                    None
                }
            },
            None => None,
        },
        Err(_) => {
            context.report_failure(WindowingError::SurfaceStatePoisoned);
            None
        }
    };

    let draw_ok = if let Some(dib) = dib {
        if client_width == 0 || client_height == 0 {
            true
        } else {
            let info = dib.bitmap_info();
            // SAFETY: dib owns a tightly packed BGRA buffer sized for the
            // positive dimensions in its BITMAPINFO, and both pointers remain
            // valid for the duration of this synchronous GDI call.
            unsafe {
                crate::windows::win32_safe::set_last_error(0);
                let copied = StretchDIBits(
                    session.hdc,
                    0,
                    0,
                    client_width,
                    client_height,
                    0,
                    0,
                    dib.width,
                    dib.height,
                    dib.bgra.as_ptr().cast(),
                    &info,
                    DIB_RGB_COLORS,
                    SRCCOPY,
                );
                copied > 0
            }
        }
    } else {
        // The system brush is OS-owned; FillRect borrows it for this call.
        // SAFETY: FillRect borrows a caller-owned RECT and a brush that stay live for the call. GetSysColorBrush returns a system brush for an integer color index.
        unsafe {
            crate::windows::win32_safe::set_last_error(0);
            FillRect(
                session.hdc,
                &session.paint.rcPaint,
                GetSysColorBrush(COLOR_WINDOW),
            ) != 0
        }
    };
    if !draw_ok {
        context.report_native_failure("StretchDIBits/FillRect");
    }
    if !session.finish() {
        context.report_native_failure("EndPaint");
    }
}

pub(super) fn invalidate(hwnd: HWND, rect: Option<&RECT>) -> i32 {
    // SAFETY: InvalidateRect borrows an optional caller-owned RECT for this call.
    unsafe {
        crate::windows::win32_safe::set_last_error(0);
        windows_sys::Win32::Graphics::Gdi::InvalidateRect(
            hwnd,
            rect.map_or(std::ptr::null(), |rect| rect),
            1,
        )
    }
}

struct PaintSession {
    hwnd: HWND,
    paint: PAINTSTRUCT,
    hdc: windows_sys::Win32::Graphics::Gdi::HDC,
    ended: bool,
}

impl PaintSession {
    fn begin(hwnd: HWND) -> Self {
        let mut paint = PAINTSTRUCT::default();
        crate::windows::win32_safe::set_last_error(0);
        // SAFETY: BeginPaint writes into a caller-owned PAINTSTRUCT that outlives the call.
        let hdc = unsafe { BeginPaint(hwnd, &mut paint) };
        Self {
            hwnd,
            paint,
            hdc,
            ended: false,
        }
    }

    fn finish(&mut self) -> bool {
        if self.ended {
            return true;
        }
        self.ended = true;
        crate::windows::win32_safe::set_last_error(0);
        // SAFETY: EndPaint reads the PAINTSTRUCT returned by the matching BeginPaint.
        unsafe { EndPaint(self.hwnd, &self.paint) != 0 }
    }
}

impl Drop for PaintSession {
    fn drop(&mut self) {
        if !self.ended {
            self.ended = true;
            // SAFETY: EndPaint reads the PAINTSTRUCT returned by the matching BeginPaint.
            unsafe {
                EndPaint(self.hwnd, &self.paint);
            }
        }
    }
}
