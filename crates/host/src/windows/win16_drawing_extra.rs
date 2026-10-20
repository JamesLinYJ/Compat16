//! Native shape, region, and USER drawing operations.

use std::ptr;

use runtime::{
    RuntimeError, Win16DrawingOperation as Op, Win16DrawingPoint, Win16DrawingRect,
    Win16DrawingResult as ResultValue, Win16HostBrush, Win16HostDib,
};
use windows_sys::Win32::Foundation::{POINT, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    AbortPath as GdiAbortPath, Arc as GdiArc, BITMAPINFO, BeginPath as GdiBeginPath,
    Chord as GdiChord, CloseFigure as GdiCloseFigure, CombineRgn as GdiCombineRgn,
    Ellipse as GdiEllipse, EndPath as GdiEndPath, ExtFloodFill as GdiExtFloodFill,
    ExtSelectClipRgn as GdiExtSelectClipRgn, FillPath as GdiFillPath, FillRect,
    FillRgn as GdiFillRgn, FlattenPath as GdiFlattenPath, FloodFill as GdiFloodFill,
    FrameRgn as GdiFrameRgn, GetArcDirection as GdiGetArcDirection, GetBkColor as GdiGetBkColor,
    GetBkMode as GdiGetBkMode, GetBrushOrgEx, GetClipRgn as GdiGetClipRgn, GetDCOrgEx,
    GetMapMode as GdiGetMapMode, GetPath as GdiGetPath, GetPolyFillMode as GdiGetPolyFillMode,
    GetROP2 as GdiGetRop2, GetRgnBox as GdiGetRgnBox, GetSysColorBrush,
    GetTextColor as GdiGetTextColor, InvertRgn as GdiInvertRgn, LineDDA as GdiLineDDA,
    OffsetClipRgn as GdiOffsetClipRgn, OffsetRgn as GdiOffsetRgn, PaintRgn as GdiPaintRgn,
    PathToRegion as GdiPathToRegion, Pie as GdiPie, PolyBezier as GdiPolyBezier,
    PolyBezierTo as GdiPolyBezierTo, PolyPolygon as GdiPolyPolygon, Polygon as GdiPolygon,
    PtInRegion as GdiPtInRegion, PtVisible as GdiPtVisible, RGN_ERROR,
    RectInRegion as GdiRectInRegion, RoundRect as GdiRoundRect,
    SelectClipPath as GdiSelectClipPath, SelectClipRgn as GdiSelectClipRgn,
    SetArcDirection as GdiSetArcDirection, SetBrushOrgEx, SetPolyFillMode as GdiSetPolyFillMode,
    SetRectRgn as GdiSetRectRgn, StretchDIBits as GdiStretchDIBits,
    StrokeAndFillPath as GdiStrokeAndFillPath, StrokePath as GdiStrokePath,
    WidenPath as GdiWidenPath,
};
use windows_sys::core::BOOL;

use super::super::{win16_gdi::Win16Dcs, win16_gdi_objects::Win16Objects};
use super::with_dc;

pub(super) fn execute(
    dcs: &Win16Dcs,
    objects: &mut Win16Objects,
    operation: Op,
) -> Result<ResultValue, RuntimeError> {
    use Op::*;

    match operation {
        LineDda {
            x_start,
            y_start,
            x_end,
            y_end,
        } => line_dda(x_start, y_start, x_end, y_end),
        StretchDibits {
            dc,
            destination_x,
            destination_y,
            destination_width,
            destination_height,
            source_x,
            source_y,
            source_width,
            source_height,
            dib,
            usage,
            rop,
        } => stretch_dibits(
            dcs,
            dc,
            destination_x,
            destination_y,
            destination_width,
            destination_height,
            source_x,
            source_y,
            source_width,
            source_height,
            dib,
            usage,
            rop,
        ),
        GetBkColor { dc } => Ok(ResultValue::Color(with_dc(dcs, dc, u32::MAX, |native| {
            // SAFETY: The HDC lease remains live through the query.
            unsafe { GdiGetBkColor(native) }
        })?)),
        GetNearestColor { dc, color } => {
            Ok(ResultValue::Color(with_dc(dcs, dc, u32::MAX, |native| {
                // SAFETY: The checked HDC lease remains live through the native
                // palette query; the guest supplies only a COLORREF scalar.
                unsafe { windows_sys::Win32::Graphics::Gdi::GetNearestColor(native, color) }
            })?))
        }
        GetBkMode { dc } => Ok(ResultValue::Mode(with_dc(dcs, dc, 0, |native| {
            // SAFETY: The HDC lease remains live through the query.
            unsafe { GdiGetBkMode(native) }
        })?)),
        GetMapMode { dc } => Ok(ResultValue::Mode(with_dc(dcs, dc, 0, |native| {
            // SAFETY: The HDC lease remains live through the query.
            unsafe { GdiGetMapMode(native) }
        })?)),
        GetPolyFillMode { dc } => Ok(ResultValue::Mode(with_dc(dcs, dc, 0, |native| {
            // SAFETY: The HDC lease remains live through the query.
            unsafe { GdiGetPolyFillMode(native) }
        })?)),
        GetRop2 { dc } => Ok(ResultValue::Mode(with_dc(dcs, dc, 0, |native| {
            // SAFETY: The HDC lease remains live through the query.
            unsafe { GdiGetRop2(native) }
        })?)),
        GetTextColor { dc } => Ok(ResultValue::Color(with_dc(dcs, dc, u32::MAX, |native| {
            // SAFETY: The HDC lease remains live through the query.
            unsafe { GdiGetTextColor(native) }
        })?)),
        SetPolyFillMode { dc, mode } => Ok(ResultValue::Mode(with_dc(dcs, dc, 0, |native| {
            // SAFETY: The HDC lease and widened Win16 mode remain valid through the call.
            unsafe { GdiSetPolyFillMode(native, mode) }
        })?)),
        SetArcDirection { dc, direction } => {
            Ok(ResultValue::Mode(with_dc(dcs, dc, 0, |native| {
                // SAFETY: The HDC lease and widened Win16 direction remain valid through the call.
                unsafe { GdiSetArcDirection(native, direction) }
            })?))
        }
        GetArcDirection { dc } => Ok(ResultValue::Mode(with_dc(dcs, dc, 0, |native| {
            // SAFETY: The HDC lease remains live through the query.
            unsafe { GdiGetArcDirection(native) }
        })?)),
        SetBrushOrg { dc, x, y } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::Point { x: 0, y: 0 });
            };
            let mut previous = POINT { x: 0, y: 0 };
            // SAFETY: The HDC lease and writable POINT remain live for the call.
            let success = unsafe { SetBrushOrgEx(dc_use.native(), x, y, &mut previous) } != 0;
            Ok(if success {
                ResultValue::Point {
                    x: previous.x,
                    y: previous.y,
                }
            } else {
                ResultValue::Point { x: 0, y: 0 }
            })
        }
        GetBrushOrg { dc } => brush_origin(dcs, dc, false),
        GetBrushOrgEx { dc } => brush_origin(dcs, dc, true),
        GetDcOrg { dc } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::Point { x: 0, y: 0 });
            };
            let mut point = POINT { x: 0, y: 0 };
            // SAFETY: The HDC lease and writable POINT remain live through the query.
            let success = unsafe { GetDCOrgEx(dc_use.native(), &mut point) } != 0;
            Ok(if success {
                ResultValue::Point {
                    x: point.x,
                    y: point.y,
                }
            } else {
                ResultValue::Point { x: 0, y: 0 }
            })
        }
        AbortPath { dc } => path_bool(dcs, dc, GdiAbortPath),
        BeginPath { dc } => path_bool(dcs, dc, GdiBeginPath),
        CloseFigure { dc } => path_bool(dcs, dc, GdiCloseFigure),
        EndPath { dc } => path_bool(dcs, dc, GdiEndPath),
        FillPath { dc } => path_bool(dcs, dc, GdiFillPath),
        FlattenPath { dc } => path_bool(dcs, dc, GdiFlattenPath),
        StrokeAndFillPath { dc } => path_bool(dcs, dc, GdiStrokeAndFillPath),
        StrokePath { dc } => path_bool(dcs, dc, GdiStrokePath),
        WidenPath { dc } => path_bool(dcs, dc, GdiWidenPath),
        SelectClipPath { dc, mode } => Ok(ResultValue::Bool(with_dc(dcs, dc, false, |native| {
            // SAFETY: The HDC lease and copied region-combine mode remain valid through the call.
            unsafe { GdiSelectClipPath(native, mode) != 0 }
        })?)),
        ExtSelectClipRgn { dc, region, mode } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::RegionComplexity(RGN_ERROR));
            };
            let native_region = match region {
                Some(token) => match objects.native_region(token) {
                    Some(region) => region,
                    None => return Ok(ResultValue::RegionComplexity(RGN_ERROR)),
                },
                None => ptr::null_mut(),
            };
            // SAFETY: The HDC lease and optional HRGN are valid; mode is passed through.
            Ok(ResultValue::RegionComplexity(unsafe {
                GdiExtSelectClipRgn(dc_use.native(), native_region, mode)
            }))
        }
        PolyBezier { dc, valid, points } => poly_bezier(dcs, dc, valid, points, false),
        PolyBezierTo { dc, valid, points } => poly_bezier(dcs, dc, valid, points, true),
        GetPath { dc, capacity } => get_path(dcs, dc, capacity),
        PathToRegion { dc } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::Object(None));
            };
            // SAFETY: The HDC lease spans the call; GDI returns a newly-owned HRGN or NULL.
            let native_region = unsafe { GdiPathToRegion(dc_use.native()) };
            drop(dc_use);
            objects
                .adopt_owned(native_region.cast())
                .map(ResultValue::Object)
        }
        Arc {
            dc,
            left,
            top,
            right,
            bottom,
            start_x,
            start_y,
            end_x,
            end_y,
        } => {
            Ok(ResultValue::Bool(with_dc(dcs, dc, false, |native| {
                // SAFETY: The HDC lease and copied coordinates remain valid through the call.
                unsafe {
                    GdiArc(
                        native, left, top, right, bottom, start_x, start_y, end_x, end_y,
                    ) != 0
                }
            })?))
        }
        Ellipse { dc, rect } => Ok(ResultValue::Bool(with_dc(dcs, dc, false, |native| {
            // SAFETY: The HDC lease and owned rectangle remain valid through the call.
            unsafe { GdiEllipse(native, rect.left, rect.top, rect.right, rect.bottom) != 0 }
        })?)),
        FloodFill { dc, x, y, color } => {
            Ok(ResultValue::Bool(with_dc(dcs, dc, false, |native| {
                // SAFETY: The HDC lease and scalar arguments remain valid through the call.
                unsafe { GdiFloodFill(native, x, y, color) != 0 }
            })?))
        }
        Pie {
            dc,
            left,
            top,
            right,
            bottom,
            start_x,
            start_y,
            end_x,
            end_y,
        } => {
            Ok(ResultValue::Bool(with_dc(dcs, dc, false, |native| {
                // SAFETY: The HDC lease and copied coordinates remain valid through the call.
                unsafe {
                    GdiPie(
                        native, left, top, right, bottom, start_x, start_y, end_x, end_y,
                    ) != 0
                }
            })?))
        }
        RoundRect {
            dc,
            rect,
            ellipse_width,
            ellipse_height,
        } => {
            Ok(ResultValue::Bool(with_dc(dcs, dc, false, |native| {
                // SAFETY: The HDC lease and scalar geometry remain valid for this call.
                unsafe {
                    GdiRoundRect(
                        native,
                        rect.left,
                        rect.top,
                        rect.right,
                        rect.bottom,
                        ellipse_width,
                        ellipse_height,
                    ) != 0
                }
            })?))
        }
        OffsetClipRgn { dc, x, y } => Ok(ResultValue::RegionComplexity(with_dc(
            dcs,
            dc,
            RGN_ERROR,
            |native| {
                // SAFETY: The HDC lease and scalar offsets remain valid through the call.
                unsafe { GdiOffsetClipRgn(native, x, y) }
            },
        )?)),
        Polygon { dc, points } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::Bool(false));
            };
            let Some(count) = i32::try_from(points.len()).ok() else {
                return Ok(ResultValue::Bool(false));
            };
            let native_points = points.iter().map(native_point).collect::<Vec<_>>();
            // SAFETY: `native_points` is a contiguous owned POINT array live through the call.
            Ok(ResultValue::Bool(unsafe {
                GdiPolygon(dc_use.native(), native_points.as_ptr(), count) != 0
            }))
        }
        FillRgn { dc, region, brush } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::Bool(false));
            };
            let (Some(native_region), Some(native_brush)) =
                (objects.native_region(region), objects.native_brush(brush))
            else {
                return Ok(ResultValue::Bool(false));
            };
            // SAFETY: The HDC lease and both validated object handles remain live through the call.
            Ok(ResultValue::Bool(unsafe {
                GdiFillRgn(dc_use.native(), native_region, native_brush.cast()) != 0
            }))
        }
        FrameRgn {
            dc,
            region,
            brush,
            width,
            height,
        } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::Bool(false));
            };
            let (Some(native_region), Some(native_brush)) =
                (objects.native_region(region), objects.native_brush(brush))
            else {
                return Ok(ResultValue::Bool(false));
            };
            // SAFETY: The HDC lease and both validated objects remain live; dimensions are scalars.
            Ok(ResultValue::Bool(unsafe {
                GdiFrameRgn(
                    dc_use.native(),
                    native_region,
                    native_brush.cast(),
                    width,
                    height,
                ) != 0
            }))
        }
        InvertRgn { dc, region } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::Bool(false));
            };
            let Some(native_region) = objects.native_region(region) else {
                return Ok(ResultValue::Bool(false));
            };
            // SAFETY: The HDC lease and validated HRGN remain live through the call.
            Ok(ResultValue::Bool(unsafe {
                GdiInvertRgn(dc_use.native(), native_region) != 0
            }))
        }
        PaintRgn { dc, region } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::Bool(false));
            };
            let Some(native_region) = objects.native_region(region) else {
                return Ok(ResultValue::Bool(false));
            };
            // SAFETY: The HDC lease and validated HRGN remain live through the call.
            Ok(ResultValue::Bool(unsafe {
                GdiPaintRgn(dc_use.native(), native_region) != 0
            }))
        }
        SelectClipRgn { dc, region } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::RegionComplexity(RGN_ERROR));
            };
            let native_region = match region {
                Some(region) => {
                    let Some(native_region) = objects.native_region(region) else {
                        return Ok(ResultValue::RegionComplexity(RGN_ERROR));
                    };
                    native_region
                }
                None => ptr::null_mut(),
            };
            // SAFETY: The HDC lease and optional validated HRGN remain live; NULL clears clipping.
            Ok(ResultValue::RegionComplexity(unsafe {
                GdiSelectClipRgn(dc_use.native(), native_region)
            }))
        }
        CombineRgn {
            destination,
            source1,
            source2,
            mode,
        } => {
            let (Some(destination), Some(source1)) = (
                objects.native_region(destination),
                objects.native_region(source1),
            ) else {
                return Ok(ResultValue::RegionComplexity(RGN_ERROR));
            };
            let source2 = match source2 {
                Some(token) => {
                    let Some(region) = objects.native_region(token) else {
                        return Ok(ResultValue::RegionComplexity(RGN_ERROR));
                    };
                    region
                }
                None => ptr::null_mut(),
            };
            // SAFETY: Destination and source1 are validated retained regions;
            // source2 is a validated region or NULL, with native GDI applying mode semantics.
            Ok(ResultValue::RegionComplexity(unsafe {
                GdiCombineRgn(destination, source1, source2, mode)
            }))
        }
        EqualRgn { region1, region2 } => {
            let (Some(region1), Some(region2)) = (
                objects.native_region(region1),
                objects.native_region(region2),
            ) else {
                return Ok(ResultValue::Bool(false));
            };
            // SAFETY: Both region handles are validated and retained.
            Ok(ResultValue::Bool(unsafe {
                windows_sys::Win32::Graphics::Gdi::EqualRgn(region1, region2) != 0
            }))
        }
        OffsetRgn { region, x, y } => {
            let Some(region) = objects.native_region(region) else {
                return Ok(ResultValue::RegionComplexity(RGN_ERROR));
            };
            // SAFETY: The region is validated and retained; offsets are scalar values.
            Ok(ResultValue::RegionComplexity(unsafe {
                GdiOffsetRgn(region, x, y)
            }))
        }
        PtVisible { dc, x, y } => Ok(ResultValue::Bool(with_dc(dcs, dc, false, |native| {
            // SAFETY: The HDC lease and scalar coordinates remain valid through the call.
            unsafe { GdiPtVisible(native, x, y) != 0 }
        })?)),
        GetRgnBox { region } => {
            let Some(region) = objects.native_region(region) else {
                return Ok(ResultValue::Rect {
                    complexity: RGN_ERROR,
                    rect: zero_rect(),
                });
            };
            let mut rect = RECT {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            };
            // SAFETY: The HRGN is retained and `rect` is a writable native RECT.
            let complexity = unsafe { GdiGetRgnBox(region, &mut rect) };
            let (complexity, rect) = guest_region_rect(complexity, rect);
            Ok(ResultValue::Rect { complexity, rect })
        }
        PtInRegion { region, x, y } => Ok(ResultValue::Bool(
            objects.native_region(region).is_some_and(|native| {
                // SAFETY: The region is validated and retained; coordinates are scalar values.
                unsafe { GdiPtInRegion(native, x, y) != 0 }
            }),
        )),
        SetRectRgn { region, rect } => Ok(ResultValue::Bool(
            objects.native_region(region).is_some_and(|native| {
                // SAFETY: The region is validated and retained; rectangle is an owned value.
                unsafe { GdiSetRectRgn(native, rect.left, rect.top, rect.right, rect.bottom) != 0 }
            }),
        )),
        GetClipRgn { dc } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::Object(None));
            };
            let Some(token) = objects.create_region()? else {
                return Ok(ResultValue::Object(None));
            };
            let Some(region) = objects.native_region(token) else {
                objects.delete(token);
                return Ok(ResultValue::Object(None));
            };
            // SAFETY: The HDC lease and temporary owned HRGN remain live through the call.
            let status = unsafe { GdiGetClipRgn(dc_use.native(), region) };
            if status == 1 {
                Ok(ResultValue::Object(Some(token)))
            } else {
                objects.delete(token);
                Ok(ResultValue::Object(None))
            }
        }
        RectInRegion { region, rect } => Ok(ResultValue::Bool(
            objects.native_region(region).is_some_and(|native| {
                let native_rect = native_rect(rect);
                // SAFETY: The region is retained and `native_rect` is valid through the call.
                unsafe { GdiRectInRegion(native, &native_rect) != 0 }
            }),
        )),
        Chord {
            dc,
            left,
            top,
            right,
            bottom,
            start_x,
            start_y,
            end_x,
            end_y,
        } => {
            Ok(ResultValue::Bool(with_dc(dcs, dc, false, |native| {
                // SAFETY: The HDC lease and copied coordinates remain valid through the call.
                unsafe {
                    GdiChord(
                        native, left, top, right, bottom, start_x, start_y, end_x, end_y,
                    ) != 0
                }
            })?))
        }
        ExtFloodFill {
            dc,
            x,
            y,
            color,
            fill_type,
        } => {
            Ok(ResultValue::Bool(with_dc(dcs, dc, false, |native| {
                // SAFETY: The HDC lease and scalar parameters remain valid through the call.
                unsafe { GdiExtFloodFill(native, x, y, color, fill_type as u32) != 0 }
            })?))
        }
        PolyPolygon {
            dc,
            valid,
            polygon_count,
            points,
            polygon_counts,
        } => {
            if !valid {
                return Ok(ResultValue::Bool(false));
            }
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::Bool(false));
            };
            if polygon_count <= 0
                || points.is_empty()
                || usize::try_from(polygon_count).ok() != Some(polygon_counts.len())
            {
                return Ok(ResultValue::Bool(false));
            }
            let point_count = polygon_counts.iter().try_fold(0_usize, |sum, count| {
                usize::try_from(*count)
                    .ok()
                    .and_then(|count| sum.checked_add(count))
            });
            if point_count != Some(points.len()) {
                return Ok(ResultValue::Bool(false));
            }
            let native_points = points.iter().map(native_point).collect::<Vec<_>>();
            // SAFETY: Both slices are owned contiguous arrays and their aggregate lengths were validated.
            Ok(ResultValue::Bool(unsafe {
                GdiPolyPolygon(
                    dc_use.native(),
                    native_points.as_ptr(),
                    polygon_counts.as_ptr(),
                    polygon_count,
                ) != 0
            }))
        }
        UserFillRect { dc, rect, brush } => {
            let Some(dc_use) = dcs.lease_dc(dc)? else {
                return Ok(ResultValue::Bool(false));
            };
            let Some(native_brush) = native_brush(objects, brush) else {
                return Ok(ResultValue::Bool(false));
            };
            let rect = native_rect(rect);
            // SAFETY: HDC and HBRUSH are native retained/system handles; RECT is local and valid.
            Ok(ResultValue::Bool(unsafe {
                FillRect(dc_use.native(), &rect, native_brush) != 0
            }))
        }
        UserDrawText {
            dc,
            text,
            count,
            rect,
            flags,
        } => super::text::draw_text(dcs, dc, text, count, rect, flags),
        UserTabbedTextOut {
            dc,
            x,
            y,
            text,
            tab_stops,
            tab_origin,
        } => super::text::tabbed_text(dcs, dc, &text, &tab_stops, Some((x, y, tab_origin))),
        UserGetTabbedTextExtent {
            dc,
            text,
            tab_stops,
        } => super::text::tabbed_text(dcs, dc, &text, &tab_stops, None),
        _ => Err(RuntimeError::new(
            runtime::DiagnosticKind::InternalInvariant,
            "unhandled operation reached Win16 drawing extra adapter",
        )),
    }
}

fn brush_origin(
    dcs: &Win16Dcs,
    dc: runtime::Win16HostDc,
    ex: bool,
) -> Result<ResultValue, RuntimeError> {
    let Some(dc_use) = dcs.lease_dc(dc)? else {
        return Ok(if ex {
            ResultValue::BoolPoint {
                success: false,
                point: Win16DrawingPoint { x: 0, y: 0 },
            }
        } else {
            ResultValue::Point { x: 0, y: 0 }
        });
    };
    let mut point = POINT { x: 0, y: 0 };
    // SAFETY: The HDC lease and local writable point are valid for this call.
    let success = unsafe { GetBrushOrgEx(dc_use.native(), &mut point) } != 0;
    if ex {
        Ok(ResultValue::BoolPoint {
            success,
            point: Win16DrawingPoint {
                x: point.x,
                y: point.y,
            },
        })
    } else {
        Ok(ResultValue::Point {
            x: if success { point.x } else { 0 },
            y: if success { point.y } else { 0 },
        })
    }
}

fn path_bool(
    dcs: &Win16Dcs,
    dc: runtime::Win16HostDc,
    operation: unsafe extern "system" fn(windows_sys::Win32::Graphics::Gdi::HDC) -> BOOL,
) -> Result<ResultValue, RuntimeError> {
    Ok(ResultValue::Bool(with_dc(dcs, dc, false, |native| {
        // SAFETY: The HDC lease remains live through the GDI path routine.
        unsafe { operation(native) != 0 }
    })?))
}

fn poly_bezier(
    dcs: &Win16Dcs,
    dc: runtime::Win16HostDc,
    valid: bool,
    points: Vec<Win16DrawingPoint>,
    to: bool,
) -> Result<ResultValue, RuntimeError> {
    if !valid {
        return Ok(ResultValue::Bool(false));
    }
    let Some(dc_use) = dcs.lease_dc(dc)? else {
        return Ok(ResultValue::Bool(false));
    };
    let Ok(count) = u32::try_from(points.len()) else {
        return Ok(ResultValue::Bool(false));
    };
    let native_points = points.iter().map(native_point).collect::<Vec<_>>();
    // SAFETY: The point buffer is owned and contiguous for this synchronous GDI call.
    let success = unsafe {
        if to {
            GdiPolyBezierTo(dc_use.native(), native_points.as_ptr(), count)
        } else {
            GdiPolyBezier(dc_use.native(), native_points.as_ptr(), count)
        }
    } != 0;
    Ok(ResultValue::Bool(success))
}

fn get_path(
    dcs: &Win16Dcs,
    dc: runtime::Win16HostDc,
    capacity: i32,
) -> Result<ResultValue, RuntimeError> {
    let Some(dc_use) = dcs.lease_dc(dc)? else {
        return Ok(ResultValue::Path {
            count: -1,
            points: Vec::new(),
            point_types: Vec::new(),
        });
    };
    if !(0..=u16::MAX as i32).contains(&capacity) {
        return Ok(ResultValue::Path {
            count: -1,
            points: Vec::new(),
            point_types: Vec::new(),
        });
    }
    let capacity = capacity as usize;
    let mut points = Vec::<POINT>::new();
    let mut point_types = Vec::<u8>::new();
    points.try_reserve_exact(capacity).map_err(|error| {
        RuntimeError::with_source(
            runtime::DiagnosticKind::ResourceExhausted,
            "reserve native GetPath points",
            error,
        )
    })?;
    point_types.try_reserve_exact(capacity).map_err(|error| {
        RuntimeError::with_source(
            runtime::DiagnosticKind::ResourceExhausted,
            "reserve native GetPath point types",
            error,
        )
    })?;
    points.resize(capacity, POINT { x: 0, y: 0 });
    point_types.resize(capacity, 0);
    let point_pointer = if capacity == 0 {
        ptr::null_mut()
    } else {
        points.as_mut_ptr()
    };
    let type_pointer = if capacity == 0 {
        ptr::null_mut()
    } else {
        point_types.as_mut_ptr()
    };
    // SAFETY: Both output arrays are owned and writable when capacity is nonzero; NULL is used for a zero-capacity request.
    let count = unsafe {
        GdiGetPath(
            dc_use.native(),
            point_pointer,
            type_pointer,
            capacity as i32,
        )
    };
    // A zero-capacity GetPath call returns the required point count without
    // writing either array. Its positive count is not a buffer overflow.
    if count < 0 || (capacity != 0 && count as usize > capacity) {
        return Ok(ResultValue::Path {
            count: -1,
            points: Vec::new(),
            point_types: Vec::new(),
        });
    }
    points.truncate(count as usize);
    point_types.truncate(count as usize);
    Ok(ResultValue::Path {
        count,
        points: points
            .into_iter()
            .map(|point| Win16DrawingPoint {
                x: point.x,
                y: point.y,
            })
            .collect(),
        point_types,
    })
}

fn native_brush(
    objects: &Win16Objects,
    brush: Win16HostBrush,
) -> Option<windows_sys::Win32::Graphics::Gdi::HBRUSH> {
    match brush {
        Win16HostBrush::Object(object) => objects.native_brush(object).map(|brush| brush.cast()),
        Win16HostBrush::SystemColor(index) if index <= 30 => {
            // SAFETY: The Win16 COLOR_* index was range-checked and the OS owns the returned brush.
            let brush = unsafe { GetSysColorBrush(i32::from(index)) };
            (!brush.is_null()).then_some(brush)
        }
        Win16HostBrush::SystemColor(_) => None,
    }
}

fn native_point(point: &Win16DrawingPoint) -> POINT {
    POINT {
        x: point.x,
        y: point.y,
    }
}

fn native_rect(rect: Win16DrawingRect) -> RECT {
    RECT {
        left: rect.left,
        top: rect.top,
        right: rect.right,
        bottom: rect.bottom,
    }
}

fn host_rect(rect: RECT) -> Win16DrawingRect {
    Win16DrawingRect {
        left: rect.left,
        top: rect.top,
        right: rect.right,
        bottom: rect.bottom,
    }
}

/// A Win16 `RECT` stores four signed 16-bit edges. `OffsetRgn` requires region
/// coordinates in -32768..=32767, and `GetClipBox` / `GetRgnBox` publish that
/// same rectangle. The guest writer stores the box only when the complexity is
/// nonzero, then narrows each edge with `as i16`. A native box outside the
/// signed 16-bit range has no verified wrap contract: return `ERROR` (0) and a
/// zero rectangle so the caller buffer stays unchanged.
pub(super) fn guest_region_rect(complexity: i32, rect: RECT) -> (i32, Win16DrawingRect) {
    let guest = host_rect(rect);
    let fits = [guest.left, guest.top, guest.right, guest.bottom]
        .into_iter()
        .all(|edge| i16::try_from(edge).is_ok());
    if complexity != 0 && !fits {
        return (0, zero_rect());
    }
    (complexity, guest)
}

fn zero_rect() -> Win16DrawingRect {
    Win16DrawingRect {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    }
}

struct LineDdaCapture {
    points: Vec<Win16DrawingPoint>,
    point_limit: usize,
    overflow: bool,
}

/// Collect native LineDDA points into a reserved, owned vector. The callback
/// runs synchronously inside GDI and carries only the address of this local
/// collector; guest FAR callbacks are scheduled by the runtime afterward.
// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn capture_line_dda_point(x: i32, y: i32, data: isize) {
    if data == 0 {
        return;
    }
    // SAFETY: `line_dda` passes a live pointer to `LineDdaCapture` for the
    // duration of the synchronous GDI call and reserves its full bound first.
    let capture = unsafe { &mut *(data as *mut LineDdaCapture) };
    if capture.points.len() < capture.point_limit {
        capture.points.push(Win16DrawingPoint { x, y });
    } else {
        capture.overflow = true;
    }
}

fn line_dda(
    x_start: i32,
    y_start: i32,
    x_end: i32,
    y_end: i32,
) -> Result<ResultValue, RuntimeError> {
    const MAX_WIN16_POINTS: usize = 65_536;
    let x_distance = x_start.abs_diff(x_end) as u64;
    let y_distance = y_start.abs_diff(y_end) as u64;
    let Some(point_limit) = usize::try_from(x_distance.max(y_distance) + 1)
        .ok()
        .filter(|count| *count <= MAX_WIN16_POINTS)
    else {
        return Ok(ResultValue::LineDda {
            success: false,
            points: Vec::new(),
        });
    };

    let mut capture = LineDdaCapture {
        points: Vec::new(),
        point_limit,
        overflow: false,
    };
    capture
        .points
        .try_reserve_exact(point_limit)
        .map_err(|error| {
            RuntimeError::with_source(
                runtime::DiagnosticKind::ResourceExhausted,
                "reserve native LineDDA point capture",
                error,
            )
        })?;
    let data = (&mut capture as *mut LineDdaCapture) as isize;
    // SAFETY: Native LineDDA invokes only `capture_line_dda_point` during this
    // call. Its collector pointer remains valid and is never exposed to guest code.
    let success = unsafe {
        GdiLineDDA(
            x_start,
            y_start,
            x_end,
            y_end,
            Some(capture_line_dda_point),
            data,
        )
    } != 0;
    if !success || capture.overflow {
        return Ok(ResultValue::LineDda {
            success: false,
            points: Vec::new(),
        });
    }
    Ok(ResultValue::LineDda {
        success,
        points: capture.points,
    })
}

fn stretch_dibits(
    dcs: &Win16Dcs,
    dc: runtime::Win16HostDc,
    destination_x: i32,
    destination_y: i32,
    destination_width: i32,
    destination_height: i32,
    source_x: i32,
    source_y: i32,
    source_width: i32,
    source_height: i32,
    dib: Win16HostDib,
    usage: u32,
    rop: u32,
) -> Result<ResultValue, RuntimeError> {
    let Some(dc_use) = dcs.lease_dc(dc)? else {
        return Ok(ResultValue::Dibits(-1));
    };
    // A DIB color table begins with either BITMAPCOREHEADER (12 bytes) or a
    // larger INFO header. The runtime has already validated the full format;
    // this guard also protects this native boundary from an empty/malformed
    // typed operation.
    if dib.info.len() < 12 {
        return Ok(ResultValue::Dibits(-1));
    }

    let aligned_info = aligned_dwords(&dib.info, "StretchDIBits info")?;
    let aligned_bits = aligned_dwords(&dib.bits, "StretchDIBits bits")?;

    let bits = if dib.bits.is_empty() {
        ptr::null()
    } else {
        aligned_bits.as_ptr().cast()
    };
    let info = aligned_info.as_ptr().cast::<BITMAPINFO>();
    // SAFETY: The HDC lease remains live; info is native-aligned owned storage and bits
    // is an owned checked buffer. Both remain alive for the synchronous call.
    let result = unsafe {
        GdiStretchDIBits(
            dc_use.native(),
            destination_x,
            destination_y,
            destination_width,
            destination_height,
            source_x,
            source_y,
            source_width,
            source_height,
            bits,
            info,
            usage,
            rop,
        )
    };
    Ok(ResultValue::Dibits(result))
}

fn aligned_dwords(bytes: &[u8], description: &'static str) -> Result<Vec<u32>, RuntimeError> {
    let padded_len = bytes.len().checked_add(3).ok_or_else(|| {
        RuntimeError::new(
            runtime::DiagnosticKind::ResourceExhausted,
            format!("{description} exceeds native addressable size"),
        )
    })?;
    let word_count = padded_len / 4;
    let mut words = Vec::<u32>::new();
    words.try_reserve_exact(word_count).map_err(|error| {
        RuntimeError::with_source(
            runtime::DiagnosticKind::ResourceExhausted,
            format!("reserve aligned native {description}"),
            error,
        )
    })?;
    words.resize(word_count, 0);
    for (index, chunk) in bytes.chunks(4).enumerate() {
        let mut word = [0_u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        words[index] = u32::from_ne_bytes(word);
    }
    Ok(words)
}
