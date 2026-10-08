//! Native USER drawing calls that consume retained Win16 GDI/image identities.

use runtime::{
    RuntimeError, Win16DrawingOperation as Op, Win16DrawingRect,
    Win16DrawingResult as ResultValue, Win16HostBrush,
};
use windows_sys::Win32::Foundation::RECT;
use windows_sys::Win32::Graphics::Gdi::{DrawFocusRect, FrameRect, GetSysColorBrush, HBRUSH, InvertRect};
use windows_sys::Win32::UI::WindowsAndMessaging::DrawIcon;

use super::{super::win16_gdi::Win16Dcs, super::win16_gdi_objects::Win16Objects};
use super::super::win16_images::Win16Images;

pub(super) fn execute(
    dcs: &Win16Dcs,
    objects: &Win16Objects,
    images: &Win16Images,
    operation: Op,
) -> Result<ResultValue, RuntimeError> {
    use Op::*;

    match operation {
        UserInvertRect { dc, rect } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else { return Ok(ResultValue::Void); };
            let rect = native_rect(rect);
            // SAFETY: The DC is pinned and RECT is a local copy for this call.
            let _ = unsafe { InvertRect(dc_use.native(), &rect) };
            Ok(ResultValue::Void)
        }
        UserFrameRect { dc, rect, brush } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else { return Ok(ResultValue::Mode(0)); };
            let Some(brush) = native_brush(objects, brush) else {
                return Ok(ResultValue::Mode(0));
            };
            let rect = native_rect(rect);
            // SAFETY: The table is exclusively borrowed through this synchronous call;
            // the DC lease and local RECT also remain valid through FrameRect.
            Ok(ResultValue::Mode(unsafe { FrameRect(dc_use.native(), &rect, brush) }))
        }
        UserDrawIcon { dc, x, y, icon } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else { return Ok(ResultValue::Bool(false)); };
            let Some(icon_use) = images.lease_icon(icon)? else {
                return Ok(ResultValue::Bool(false));
            };
            // SAFETY: The DC and icon leases pin both native handles through DrawIcon.
            Ok(ResultValue::Bool(unsafe {
                DrawIcon(dc_use.native(), i32::from(x), i32::from(y), icon_use.native()) != 0
            }))
        }
        UserDrawFocusRect { dc, rect } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else { return Ok(ResultValue::Void); };
            let rect = native_rect(rect);
            // SAFETY: The DC is pinned and RECT is a local copy for this call.
            let _ = unsafe { DrawFocusRect(dc_use.native(), &rect) };
            Ok(ResultValue::Void)
        }
        _ => Err(RuntimeError::new(
            runtime::DiagnosticKind::InternalInvariant,
            "non-object USER drawing operation reached its host adapter",
        )),
    }
}

fn native_brush(objects: &Win16Objects, brush: Win16HostBrush) -> Option<HBRUSH> {
    match brush {
        Win16HostBrush::Object(object) => objects.native_brush(object).map(|brush| brush.cast()),
        Win16HostBrush::SystemColor(index) if index <= 30 => {
            // SAFETY: The Win16 COLOR_* index was range-checked; the OS owns this brush.
            let brush = unsafe { GetSysColorBrush(i32::from(index)) };
            (!brush.is_null()).then_some(brush)
        }
        Win16HostBrush::SystemColor(_) => None,
    }
}

fn native_rect(rect: Win16DrawingRect) -> RECT {
    RECT { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom }
}
