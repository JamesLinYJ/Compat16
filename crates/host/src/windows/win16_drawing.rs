//! Windows GDI implementation for already-translated Win16 drawing requests.

use std::ptr;

use runtime::{
    RuntimeError, Win16DrawingOperation, Win16DrawingResult,
};
use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{POINT, RECT, SIZE};
use windows_sys::Win32::Graphics::Gdi::{
    BitBlt, DPtoLP, ExcludeClipRect, GetClipBox, GetCurrentPositionEx,
    GetPixel, GetTextAlign, GetViewportExtEx, GetViewportOrgEx,
    GetWindowExtEx, GetWindowOrgEx, IntersectClipRect, LPtoDP, LineTo, MoveToEx,
    OffsetViewportOrgEx, OffsetWindowOrgEx, PatBlt, Polyline, RectVisible, Rectangle,
    RestoreDC, SaveDC, SetBkColor, SetBkMode, SetMapMode, SetPixel, SetROP2,
    SetStretchBltMode, SetTextAlign, SetTextColor, SetViewportExtEx, SetViewportOrgEx,
    SetTextCharacterExtra, SetTextJustification, SetWindowExtEx, SetWindowOrgEx,
    StretchBlt,
};

use super::{win16_gdi::Win16Dcs, win16_gdi_objects::Win16Objects};

#[path = "win16_drawing_extra.rs"]
mod extra;
#[path = "win16_gdi_text.rs"]
mod text;
#[path = "win16_user_drawing_objects.rs"]
mod user_objects;

fn with_dc<T>(
    dcs: &Win16Dcs,
    token: runtime::Win16HostDc,
    unavailable: T,
    operation: impl FnOnce(windows_sys::Win32::Graphics::Gdi::HDC) -> T,
) -> Result<T, RuntimeError> {
    let Some(dc_use) = dcs.lease_dc(token)? else { return Ok(unavailable); };
    Ok(operation(dc_use.native()))
}

/// Executes one drawing request. Guest handles and pointers never reach this
/// adapter; the DC and object identities resolve only through their host-owned
/// tables.
pub(super) fn execute(
    dcs: &Win16Dcs,
    objects: &mut Win16Objects,
    images: &super::win16_images::Win16Images,
    operation: Win16DrawingOperation,
) -> Result<Win16DrawingResult, RuntimeError> {
    use Win16DrawingOperation as Op;
    use Win16DrawingResult as ResultValue;

    match operation {
        operation @ (Op::UserInvertRect { .. } | Op::UserFrameRect { .. }
            | Op::UserDrawIcon { .. } | Op::UserDrawFocusRect { .. }) => {
            user_objects::execute(dcs, objects, images, operation)
        }
        Op::SetBkColor { dc, color } => Ok(ResultValue::Color(with_dc(
            dcs, dc, u32::MAX, |native| {
                // SAFETY: The HDC lease is live and COLORREF is a scalar.
                unsafe { SetBkColor(native, color) }
            },
        )?)),
        Op::SetBkMode { dc, mode } => Ok(ResultValue::Mode(with_dc(
            dcs, dc, 0, |native| {
                // SAFETY: The HDC lease is live and mode is a scalar.
                unsafe { SetBkMode(native, mode) }
            },
        )?)),
        Op::SetMapMode { dc, mode } => Ok(ResultValue::Mode(with_dc(
            dcs, dc, 0, |native| {
                // SAFETY: The HDC lease is live and mode is a scalar.
                unsafe { SetMapMode(native, mode) }
            },
        )?)),
        Op::SetRop2 { dc, mode } => Ok(ResultValue::Mode(with_dc(
            dcs, dc, 0, |native| {
                // SAFETY: The HDC lease is live and mode is a scalar.
                unsafe { SetROP2(native, mode) }
            },
        )?)),
        Op::SetTextColor { dc, color } => Ok(ResultValue::Color(with_dc(
            dcs, dc, u32::MAX, |native| {
                // SAFETY: The HDC lease is live and COLORREF is a scalar.
                unsafe { SetTextColor(native, color) }
            },
        )?)),
        Op::MoveTo { dc, x, y } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::Point { x: 0, y: 0 });
            };
            let mut previous = POINT { x: 0, y: 0 };
            // SAFETY: The HDC lease and writable POINT remain live during the call.
            let moved = unsafe { MoveToEx(dc_use.native(), x, y, &mut previous) } != 0;
            Ok(if moved {
                ResultValue::Point { x: previous.x, y: previous.y }
            } else {
                ResultValue::Point { x: 0, y: 0 }
            })
        }
        Op::LineTo { dc, x, y } => Ok(ResultValue::Bool(with_dc(
            dcs, dc, false, |native| {
                // SAFETY: The HDC lease is live; both coordinates are scalars.
                unsafe { LineTo(native, x, y) != 0 }
            },
        )?)),
        Op::Rectangle { dc, left, top, right, bottom } => {
            Ok(ResultValue::Bool(with_dc(dcs, dc, false, |native| {
                // SAFETY: The HDC lease is live; rectangle coordinates are scalars.
                unsafe { Rectangle(native, left, top, right, bottom) != 0 }
            })?))
        }
        Op::TextOut { dc, x, y, text, code_page } => {
            Ok(ResultValue::Bool(text::text_out(dcs, dc, x, y, &text, code_page)?))
        }
        Op::BitBlt {
            destination,
            destination_x,
            destination_y,
            width,
            height,
            source,
            source_x,
            source_y,
            rop,
        } => {
            let Some(destination_use) = dcs.lease_dc(destination)? else {
                return Ok(ResultValue::Bool(false));
            };
            let source_use = match source {
                Some(source) => {
                    let Some(source_use) = dcs.lease_dc(source)? else {
                        return Ok(ResultValue::Bool(false));
                    };
                    Some(source_use)
                }
                None => None,
            };
            let source = source_use.as_ref().map_or(ptr::null_mut(), |use_guard| use_guard.native());
            // SAFETY: Both non-null HDCs are pinned; NULL source remains valid
            // for source-independent raster operations. Other args are scalars.
            Ok(ResultValue::Bool(unsafe {
                BitBlt(
                    destination_use.native(),
                    destination_x,
                    destination_y,
                    width,
                    height,
                    source,
                    source_x,
                    source_y,
                    rop,
                )
            } != 0))
        }
        Op::CreateSolidBrush { color } => {
            Ok(ResultValue::Object(objects.create_solid_brush(color)?))
        }
        Op::GetTextExtent { dc, text, code_page } => {
            let measured = text::text_extent(dcs, dc, &text, code_page)?;
            Ok(match measured {
                Some((true, size)) => ResultValue::Size { width: size.cx, height: size.cy },
                _ => ResultValue::Size { width: 0, height: 0 },
            })
        }
        Op::GetTextExtentPoint { dc, text } => {
            let measured = text::text_extent(dcs, dc, &text, None)?;
            Ok(match measured {
                Some((success, size)) => ResultValue::BoolSize {
                    success,
                    width: size.cx,
                    height: size.cy,
                },
                None => ResultValue::BoolSize { success: false, width: 0, height: 0 },
            })
        }
        Op::SetStretchBltMode { dc, mode } => Ok(ResultValue::Mode(with_dc(
            dcs, dc, 0, |native| {
                // SAFETY: The HDC lease and scalar mode remain valid through the call.
                unsafe { SetStretchBltMode(native, mode) }
            },
        )?)),
        Op::GetStretchBltMode { dc } => Ok(ResultValue::Mode(with_dc(
            dcs, dc, 0, |native| {
                // SAFETY: The HDC lease remains live through the query.
                unsafe { windows_sys::Win32::Graphics::Gdi::GetStretchBltMode(native) }
            },
        )?)),
        Op::SetTextAlign { dc, alignment } => Ok(ResultValue::Mode(with_dc(
            dcs, dc, 0, |native| {
                // SAFETY: The HDC lease and scalar alignment remain valid through the call.
                unsafe { SetTextAlign(native, alignment) as i32 }
            },
        )?)),
        Op::GetTextAlign { dc } => Ok(ResultValue::Mode(with_dc(
            dcs, dc, 0, |native| {
                // SAFETY: The HDC lease remains live through the query.
                unsafe { GetTextAlign(native) as i32 }
            },
        )?)),
        Op::SetTextCharacterExtra { dc, extra } => Ok(ResultValue::Mode(with_dc(
            dcs, dc, 0, |native| {
                // SAFETY: The HDC lease and scalar spacing remain valid through the call.
                unsafe { SetTextCharacterExtra(native, extra) }
            },
        )?)),
        Op::GetTextCharacterExtra { dc } => Ok(ResultValue::Mode(with_dc(
            dcs, dc, 0, |native| {
                // SAFETY: The HDC lease remains live through the query.
                unsafe { windows_sys::Win32::Graphics::Gdi::GetTextCharacterExtra(native) }
            },
        )?)),
        Op::SetTextJustification { dc, extra, breaks } => Ok(ResultValue::Bool(with_dc(
            dcs, dc, false, |native| {
                // SAFETY: The HDC lease and scalar spacing parameters remain valid through the call.
                unsafe { SetTextJustification(native, extra, breaks) != 0 }
            },
        )?)),
        Op::SetWindowExt { dc, x, y } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::Size { width: 0, height: 0 });
            };
            let mut old = SIZE { cx: 0, cy: 0 };
            // SAFETY: `old` is a writable SIZE for the synchronous native call.
            let success = unsafe { SetWindowExtEx(dc_use.native(), x, y, &mut old) } != 0;
            Ok(if success {
                ResultValue::Size { width: old.cx, height: old.cy }
            } else {
                ResultValue::Size { width: 0, height: 0 }
            })
        }
        Op::SetWindowOrg { dc, x, y } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::Point { x: 0, y: 0 });
            };
            let mut old = POINT { x: 0, y: 0 };
            // SAFETY: `old` is writable for the synchronous native call.
            let success = unsafe { SetWindowOrgEx(dc_use.native(), x, y, &mut old) } != 0;
            Ok(if success {
                ResultValue::Point { x: old.x, y: old.y }
            } else {
                ResultValue::Point { x: 0, y: 0 }
            })
        }
        Op::SetViewportOrg { dc, x, y } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::Point { x: 0, y: 0 });
            };
            let mut old = POINT { x: 0, y: 0 };
            // SAFETY: `old` is a writable POINT for the synchronous native call.
            let success = unsafe { SetViewportOrgEx(dc_use.native(), x, y, &mut old) } != 0;
            Ok(if success {
                ResultValue::Point { x: old.x, y: old.y }
            } else {
                ResultValue::Point { x: 0, y: 0 }
            })
        }
        Op::SetViewportExt { dc, x, y } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::Size { width: 0, height: 0 });
            };
            let mut old = SIZE { cx: 0, cy: 0 };
            // SAFETY: `old` is a writable SIZE for the synchronous native call.
            let success = unsafe { SetViewportExtEx(dc_use.native(), x, y, &mut old) } != 0;
            Ok(if success {
                ResultValue::Size { width: old.cx, height: old.cy }
            } else {
                ResultValue::Size { width: 0, height: 0 }
            })
        }
        Op::SetWindowExtEx { dc, x, y } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::BoolSize { success: false, width: 0, height: 0 });
            };
            let mut old = SIZE { cx: 0, cy: 0 };
            // SAFETY: `old` is writable for the synchronous native call.
            let success = unsafe { SetWindowExtEx(dc_use.native(), x, y, &mut old) } != 0;
            Ok(ResultValue::BoolSize { success, width: old.cx, height: old.cy })
        }
        Op::SetViewportExtEx { dc, x, y } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::BoolSize { success: false, width: 0, height: 0 });
            };
            let mut old = SIZE { cx: 0, cy: 0 };
            // SAFETY: `old` is writable for the synchronous native call.
            let success = unsafe { SetViewportExtEx(dc_use.native(), x, y, &mut old) } != 0;
            Ok(ResultValue::BoolSize { success, width: old.cx, height: old.cy })
        }
        Op::SetViewportOrgEx { dc, x, y } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::BoolPoint {
                    success: false,
                    point: runtime::Win16DrawingPoint { x: 0, y: 0 },
                });
            };
            let mut old = POINT { x: 0, y: 0 };
            // SAFETY: `old` is writable for the synchronous native call.
            let success = unsafe { SetViewportOrgEx(dc_use.native(), x, y, &mut old) } != 0;
            Ok(ResultValue::BoolPoint {
                success,
                point: runtime::Win16DrawingPoint { x: old.x, y: old.y },
            })
        }
        Op::GetWindowExt { dc } => get_size(dcs, dc, GetWindowExtEx),
        Op::GetViewportExt { dc } => get_size(dcs, dc, GetViewportExtEx),
        Op::GetWindowOrg { dc } => get_point(dcs, dc, GetWindowOrgEx),
        Op::GetViewportOrg { dc } => get_point(dcs, dc, GetViewportOrgEx),
        Op::GetWindowExtEx { dc } => get_size_ex(dcs, dc, GetWindowExtEx),
        Op::GetViewportExtEx { dc } => get_size_ex(dcs, dc, GetViewportExtEx),
        Op::GetWindowOrgEx { dc } => get_point_ex(dcs, dc, GetWindowOrgEx),
        Op::GetViewportOrgEx { dc } => get_point_ex(dcs, dc, GetViewportOrgEx),
        Op::GetCurrentPositionEx { dc } => get_point_ex(dcs, dc, GetCurrentPositionEx),
        Op::GetCurrentPosition { dc } => get_point(dcs, dc, GetCurrentPositionEx),
        Op::MoveToEx { dc, x, y } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::BoolPoint {
                    success: false,
                    point: runtime::Win16DrawingPoint { x: 0, y: 0 },
                });
            };
            let mut previous = POINT { x: 0, y: 0 };
            // SAFETY: `previous` is writable for the synchronous native call.
            let success = unsafe { MoveToEx(dc_use.native(), x, y, &mut previous) } != 0;
            Ok(ResultValue::BoolPoint {
                success,
                point: runtime::Win16DrawingPoint { x: previous.x, y: previous.y },
            })
        }
        Op::SetWindowOrgEx { dc, x, y } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::BoolPoint {
                    success: false,
                    point: runtime::Win16DrawingPoint { x: 0, y: 0 },
                });
            };
            let mut old = POINT { x: 0, y: 0 };
            // SAFETY: `old` is writable for the synchronous native call.
            let success = unsafe { SetWindowOrgEx(dc_use.native(), x, y, &mut old) } != 0;
            Ok(ResultValue::BoolPoint {
                success,
                point: runtime::Win16DrawingPoint { x: old.x, y: old.y },
            })
        }
        Op::OffsetWindowOrg { dc, x, y } => {
            offset_org(dcs, dc, x, y, OffsetWindowOrgEx)
        }
        Op::OffsetWindowOrgEx { dc, x, y } => {
            offset_org_ex(dcs, dc, x, y, OffsetWindowOrgEx)
        }
        Op::OffsetViewportOrg { dc, x, y } => {
            offset_org(dcs, dc, x, y, OffsetViewportOrgEx)
        }
        Op::OffsetViewportOrgEx { dc, x, y } => {
            offset_org_ex(dcs, dc, x, y, OffsetViewportOrgEx)
        }
        Op::ScaleWindowExt { dc, x_num, x_den, y_num, y_den } => {
            scale_ext(dcs, dc, x_num, x_den, y_num, y_den, windows_sys::Win32::Graphics::Gdi::ScaleWindowExtEx)
        }
        Op::ScaleViewportExt { dc, x_num, x_den, y_num, y_den } => {
            scale_ext(dcs, dc, x_num, x_den, y_num, y_den, windows_sys::Win32::Graphics::Gdi::ScaleViewportExtEx)
        }
        Op::ScaleWindowExtEx { dc, x_num, x_den, y_num, y_den } => {
            scale_ext_ex(dcs, dc, x_num, x_den, y_num, y_den, windows_sys::Win32::Graphics::Gdi::ScaleWindowExtEx)
        }
        Op::ScaleViewportExtEx { dc, x_num, x_den, y_num, y_den } => {
            scale_ext_ex(dcs, dc, x_num, x_den, y_num, y_den, windows_sys::Win32::Graphics::Gdi::ScaleViewportExtEx)
        }
        Op::SaveDc { dc } => Ok(ResultValue::SaveDc(with_dc(dcs, dc, 0, |native| {
            // SAFETY: The HDC lease remains live through SaveDC.
            unsafe { SaveDC(native) }
        })?)),
        Op::RestoreDc { dc, saved } => Ok(ResultValue::Bool(with_dc(
            dcs, dc, false, |native| {
                // SAFETY: The HDC lease and saved-level scalar remain valid through RestoreDC.
                unsafe { RestoreDC(native, saved) != 0 }
            },
        )?)),
        Op::SetPixel { dc, x, y, color } => Ok(ResultValue::Color(with_dc(
            dcs, dc, u32::MAX, |native| {
                // SAFETY: The HDC lease and scalar color/coordinates remain valid through SetPixel.
                unsafe { SetPixel(native, x, y, color) }
            },
        )?)),
        Op::GetPixel { dc, x, y } => Ok(ResultValue::Color(with_dc(
            dcs, dc, u32::MAX, |native| {
                // SAFETY: The HDC lease and scalar coordinates remain valid through GetPixel.
                unsafe { GetPixel(native, x, y) }
            },
        )?)),
        Op::PatBlt { dc, x, y, width, height, rop } => Ok(ResultValue::Bool(with_dc(
            dcs, dc, false, |native| {
                // SAFETY: The HDC lease and scalar arguments remain valid through PatBlt.
                unsafe { PatBlt(native, x, y, width, height, rop) != 0 }
            },
        )?)),
        Op::StretchBlt {
            destination, destination_x, destination_y, destination_width, destination_height,
            source, source_x, source_y, source_width, source_height, rop,
        } => {
            let Some(destination_use) = dcs.lease_dc(destination)? else {
                return Ok(ResultValue::Bool(false));
            };
            let source_use = match source {
                Some(source) => {
                    let Some(source_use) = dcs.lease_dc(source)? else {
                        return Ok(ResultValue::Bool(false));
                    };
                    Some(source_use)
                }
                None => None,
            };
            let source = source_use.as_ref().map_or(ptr::null_mut(), |use_guard| use_guard.native());
            // SAFETY: Both non-null HDCs are pinned; NULL source remains valid
            // for source-independent ROPs.
            Ok(ResultValue::Bool(unsafe {
                StretchBlt(destination_use.native(), destination_x, destination_y, destination_width,
                    destination_height, source, source_x, source_y, source_width, source_height, rop)
            } != 0))
        }
        Op::Polyline { dc, points } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else { return Ok(ResultValue::Bool(false)); };
            let Some(count) = i32::try_from(points.len()).ok() else {
                return Ok(ResultValue::Bool(false));
            };
            let native_points = points.iter().map(|point| POINT { x: point.x, y: point.y }).collect::<Vec<_>>();
            // SAFETY: `native_points` is a contiguous owned POINT array valid throughout the call.
            Ok(ResultValue::Bool(unsafe { Polyline(dc_use.native(), native_points.as_ptr(), count) } != 0))
        }
        Op::DpToLp { dc, points } => transform_points(dcs, dc, points, DPtoLP),
        Op::LpToDp { dc, points } => transform_points(dcs, dc, points, LPtoDP),
        Op::ExcludeClipRect { dc, rect } => Ok(ResultValue::RegionComplexity(with_dc(
            dcs, dc, 0, |native| {
                // SAFETY: The HDC lease and copied rectangle remain valid through the call.
                unsafe { ExcludeClipRect(native, rect.left, rect.top, rect.right, rect.bottom) }
            },
        )?)),
        Op::IntersectClipRect { dc, rect } => Ok(ResultValue::RegionComplexity(with_dc(
            dcs, dc, 0, |native| {
                // SAFETY: The HDC lease and copied rectangle remain valid through the call.
                unsafe { IntersectClipRect(native, rect.left, rect.top, rect.right, rect.bottom) }
            },
        )?)),
        Op::GetClipBox { dc } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::Rect { complexity: 0,
                    rect: runtime::Win16DrawingRect { left: 0, top: 0, right: 0, bottom: 0 } });
            };
            let mut rect = RECT { left: 0, top: 0, right: 0, bottom: 0 };
            // SAFETY: `rect` is a valid writable RECT for this synchronous call.
            let complexity = unsafe { GetClipBox(dc_use.native(), &mut rect) };
            Ok(ResultValue::Rect { complexity,
                rect: runtime::Win16DrawingRect { left: rect.left, top: rect.top,
                    right: rect.right, bottom: rect.bottom } })
        }
        Op::RectVisible { dc, rect } => Ok(ResultValue::Bool(with_dc(
            dcs, dc, false, |native| {
                let rect = RECT { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom };
                // SAFETY: The HDC lease and local RECT are valid through the synchronous call.
                unsafe { RectVisible(native, &rect) != 0 }
            },
        )?)),
        Op::ExtTextOut { dc, x, y, options, rect, text, spacing, code_page } => {
            Ok(ResultValue::Bool(text::ext_text_out(
                dcs, dc, x, y, options, rect, &text, spacing.as_deref(), code_page,
            )?))
        }
        Op::SetLayout { dc, layout } => Ok(ResultValue::Dword(with_dc(
            dcs, dc, 0xFFFF_FFFF, |native| {
                // SAFETY: The HDC lease is live and the layout dword is a scalar.
                unsafe { windows_sys::Win32::Graphics::Gdi::SetLayout(native, layout) }
            },
        )?)),
        Op::AcceptTextCodePage { page } => Ok(ResultValue::Bool(
            super::guest_text::GuestTextCodec::new(u32::from(page)).is_ok(),
        )),
        operation => extra::execute(dcs, objects, operation),
    }
}

fn get_size(
    dcs: &Win16Dcs,
    dc: runtime::Win16HostDc,
    getter: unsafe extern "system" fn(windows_sys::Win32::Graphics::Gdi::HDC, *mut SIZE) -> BOOL,
) -> Result<Win16DrawingResult, RuntimeError> {
    let Some(dc_use) = dcs.lease_dc(dc)? else {
        return Ok(Win16DrawingResult::Size { width: 0, height: 0 });
    };
    let mut size = SIZE { cx: 0, cy: 0 };
    // SAFETY: The HDC lease and writable `size` remain live through the query.
    let success = unsafe { getter(dc_use.native(), &mut size) } != 0;
    Ok(if success {
        Win16DrawingResult::Size { width: size.cx, height: size.cy }
    } else {
        Win16DrawingResult::Size { width: 0, height: 0 }
    })
}

fn get_size_ex(
    dcs: &Win16Dcs,
    dc: runtime::Win16HostDc,
    getter: unsafe extern "system" fn(windows_sys::Win32::Graphics::Gdi::HDC, *mut SIZE) -> BOOL,
) -> Result<Win16DrawingResult, RuntimeError> {
    let Some(dc_use) = dcs.lease_dc(dc)? else {
        return Ok(Win16DrawingResult::BoolSize { success: false, width: 0, height: 0 });
    };
    let mut size = SIZE { cx: 0, cy: 0 };
    // SAFETY: The HDC lease and writable `size` remain live through the query.
    let success = unsafe { getter(dc_use.native(), &mut size) } != 0;
    Ok(Win16DrawingResult::BoolSize { success, width: size.cx, height: size.cy })
}

fn get_point(
    dcs: &Win16Dcs,
    dc: runtime::Win16HostDc,
    getter: unsafe extern "system" fn(windows_sys::Win32::Graphics::Gdi::HDC, *mut POINT) -> BOOL,
) -> Result<Win16DrawingResult, RuntimeError> {
    let Some(dc_use) = dcs.lease_dc(dc)? else {
        return Ok(Win16DrawingResult::Point { x: 0, y: 0 });
    };
    let mut point = POINT { x: 0, y: 0 };
    // SAFETY: The HDC lease and writable `point` remain live through the query.
    let success = unsafe { getter(dc_use.native(), &mut point) } != 0;
    Ok(if success {
        Win16DrawingResult::Point { x: point.x, y: point.y }
    } else {
        Win16DrawingResult::Point { x: 0, y: 0 }
    })
}

fn get_point_ex(
    dcs: &Win16Dcs,
    dc: runtime::Win16HostDc,
    getter: unsafe extern "system" fn(windows_sys::Win32::Graphics::Gdi::HDC, *mut POINT) -> BOOL,
) -> Result<Win16DrawingResult, RuntimeError> {
    let Some(dc_use) = dcs.lease_dc(dc)? else {
        return Ok(Win16DrawingResult::BoolPoint {
            success: false,
            point: runtime::Win16DrawingPoint { x: 0, y: 0 },
        });
    };
    let mut point = POINT { x: 0, y: 0 };
    // SAFETY: The HDC lease and writable `point` remain live through the query.
    let success = unsafe { getter(dc_use.native(), &mut point) } != 0;
    Ok(Win16DrawingResult::BoolPoint {
        success,
        point: runtime::Win16DrawingPoint { x: point.x, y: point.y },
    })
}

fn offset_org(
    dcs: &Win16Dcs,
    dc: runtime::Win16HostDc,
    x: i32,
    y: i32,
    offset: unsafe extern "system" fn(
        windows_sys::Win32::Graphics::Gdi::HDC,
        i32,
        i32,
        *mut POINT,
    ) -> BOOL,
) -> Result<Win16DrawingResult, RuntimeError> {
    let Some(dc_use) = dcs.lease_dc(dc)? else {
        return Ok(Win16DrawingResult::Point { x: 0, y: 0 });
    };
    let mut previous = POINT { x: 0, y: 0 };
    // SAFETY: The HDC lease and writable `previous` value remain live through the call.
    let success = unsafe { offset(dc_use.native(), x, y, &mut previous) } != 0;
    Ok(if success {
        Win16DrawingResult::Point { x: previous.x, y: previous.y }
    } else {
        Win16DrawingResult::Point { x: 0, y: 0 }
    })
}

fn offset_org_ex(
    dcs: &Win16Dcs,
    dc: runtime::Win16HostDc,
    x: i32,
    y: i32,
    offset: unsafe extern "system" fn(
        windows_sys::Win32::Graphics::Gdi::HDC,
        i32,
        i32,
        *mut POINT,
    ) -> BOOL,
) -> Result<Win16DrawingResult, RuntimeError> {
    let Some(dc_use) = dcs.lease_dc(dc)? else {
        return Ok(Win16DrawingResult::BoolPoint {
            success: false,
            point: runtime::Win16DrawingPoint { x: 0, y: 0 },
        });
    };
    let mut previous = POINT { x: 0, y: 0 };
    // SAFETY: The HDC lease and writable `previous` value remain live through the call.
    let success = unsafe { offset(dc_use.native(), x, y, &mut previous) } != 0;
    Ok(Win16DrawingResult::BoolPoint {
        success,
        point: runtime::Win16DrawingPoint { x: previous.x, y: previous.y },
    })
}

fn scale_ext(
    dcs: &Win16Dcs,
    dc: runtime::Win16HostDc,
    x_num: i32,
    x_den: i32,
    y_num: i32,
    y_den: i32,
    scale: unsafe extern "system" fn(
        windows_sys::Win32::Graphics::Gdi::HDC,
        i32,
        i32,
        i32,
        i32,
        *mut SIZE,
    ) -> BOOL,
) -> Result<Win16DrawingResult, RuntimeError> {
    let Some(dc_use) = dcs.lease_dc(dc)? else {
        return Ok(Win16DrawingResult::Size { width: 0, height: 0 });
    };
    let mut previous = SIZE { cx: 0, cy: 0 };
    // SAFETY: The HDC lease and writable previous extent remain live through the call.
    let success = unsafe { scale(dc_use.native(), x_num, x_den, y_num, y_den, &mut previous) } != 0;
    Ok(if success {
        Win16DrawingResult::Size { width: previous.cx, height: previous.cy }
    } else {
        Win16DrawingResult::Size { width: 0, height: 0 }
    })
}

fn scale_ext_ex(
    dcs: &Win16Dcs,
    dc: runtime::Win16HostDc,
    x_num: i32,
    x_den: i32,
    y_num: i32,
    y_den: i32,
    scale: unsafe extern "system" fn(
        windows_sys::Win32::Graphics::Gdi::HDC,
        i32,
        i32,
        i32,
        i32,
        *mut SIZE,
    ) -> BOOL,
) -> Result<Win16DrawingResult, RuntimeError> {
    let Some(dc_use) = dcs.lease_dc(dc)? else {
        return Ok(Win16DrawingResult::BoolSize { success: false, width: 0, height: 0 });
    };
    let mut previous = SIZE { cx: 0, cy: 0 };
    // SAFETY: The HDC lease and writable previous extent remain live through the call.
    let success = unsafe { scale(dc_use.native(), x_num, x_den, y_num, y_den, &mut previous) } != 0;
    Ok(Win16DrawingResult::BoolSize {
        success,
        width: previous.cx,
        height: previous.cy,
    })
}

fn transform_points(
    dcs: &Win16Dcs,
    dc: runtime::Win16HostDc,
    points: Vec<runtime::Win16DrawingPoint>,
    transform: unsafe extern "system" fn(
        windows_sys::Win32::Graphics::Gdi::HDC,
        *mut POINT,
        i32,
    ) -> BOOL,
) -> Result<Win16DrawingResult, RuntimeError> {
    let Some(dc_use) = dcs.lease_dc(dc)? else {
        return Ok(Win16DrawingResult::Points { success: false, points });
    };
    let Ok(count) = i32::try_from(points.len()) else {
        return Ok(Win16DrawingResult::Points { success: false, points });
    };
    let mut native_points = points.iter().map(|point| POINT { x: point.x, y: point.y }).collect::<Vec<_>>();
    // SAFETY: The HDC lease and owned native point buffer remain live during conversion.
    let success = unsafe { transform(dc_use.native(), native_points.as_mut_ptr(), count) } != 0;
    let points = native_points.into_iter().map(|point| {
        runtime::Win16DrawingPoint { x: point.x, y: point.y }
    }).collect();
    Ok(Win16DrawingResult::Points { success, points })
}
