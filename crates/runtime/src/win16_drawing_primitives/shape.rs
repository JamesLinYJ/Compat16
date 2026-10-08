//! Shape GDI primitive requests.

use super::*;

pub(super) fn execute(
    state: &mut Win16State,
    request: Win16ApiRequest,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<u32, RuntimeError> {
    use Win16ApiRequest as Request;

    match request {
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::Arc {
            dc,
            left,
            top,
            right,
            bottom,
            start_x,
            start_y,
            end_x,
            end_y,
        }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            bool_result(
                host.win16_gdi(Operation::Arc {
                    dc,
                    left: i32::from(left),
                    top: i32::from(top),
                    right: i32::from(right),
                    bottom: i32::from(bottom),
                    start_x: i32::from(start_x),
                    start_y: i32::from(start_y),
                    end_x: i32::from(end_x),
                    end_y: i32::from(end_y),
                })?,
                "Arc",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::Ellipse { dc, rect }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            bool_result(
                host.win16_gdi(Operation::Ellipse {
                    dc,
                    rect: rect_to_host(rect),
                })?,
                "Ellipse",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::FloodFill { dc, x, y, color }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            bool_result(
                host.win16_gdi(Operation::FloodFill {
                    dc,
                    x: i32::from(x),
                    y: i32::from(y),
                    color,
                })?,
                "FloodFill",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::Pie {
            dc,
            left,
            top,
            right,
            bottom,
            start_x,
            start_y,
            end_x,
            end_y,
        }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            bool_result(
                host.win16_gdi(Operation::Pie {
                    dc,
                    left: i32::from(left),
                    top: i32::from(top),
                    right: i32::from(right),
                    bottom: i32::from(bottom),
                    start_x: i32::from(start_x),
                    start_y: i32::from(start_y),
                    end_x: i32::from(end_x),
                    end_y: i32::from(end_y),
                })?,
                "Pie",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::RoundRect {
            dc,
            rect,
            ellipse_width,
            ellipse_height,
        }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            bool_result(
                host.win16_gdi(Operation::RoundRect {
                    dc,
                    rect: rect_to_host(rect),
                    ellipse_width: i32::from(ellipse_width),
                    ellipse_height: i32::from(ellipse_height),
                })?,
                "RoundRect",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::OffsetClipRgn { dc, x, y }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            complexity_result(
                host.win16_gdi(Operation::OffsetClipRgn {
                    dc,
                    x: i32::from(x),
                    y: i32::from(y),
                })?,
                "OffsetClipRgn",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::Polygon { dc, count, points }) => {
            if count <= 0 || points.len() != count as usize {
                return Ok(0);
            }
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            let points = points.into_iter().map(point_to_host).collect();
            bool_result(
                host.win16_gdi(Operation::Polygon { dc, points })?,
                "Polygon",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::FillRgn { dc, region, brush }) => {
            let (Some(dc), Some(region), Some(brush)) = (
                state.guest_gdi.dc(dc),
                state.guest_gdi.object(region),
                state.guest_gdi.object(brush),
            ) else {
                return Ok(0);
            };
            bool_result(
                host.win16_gdi(Operation::FillRgn { dc, region, brush })?,
                "FillRgn",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::FrameRgn {
            dc,
            region,
            brush,
            width,
            height,
        }) => {
            let (Some(dc), Some(region), Some(brush)) = (
                state.guest_gdi.dc(dc),
                state.guest_gdi.object(region),
                state.guest_gdi.object(brush),
            ) else {
                return Ok(0);
            };
            bool_result(
                host.win16_gdi(Operation::FrameRgn {
                    dc,
                    region,
                    brush,
                    width: i32::from(width),
                    height: i32::from(height),
                })?,
                "FrameRgn",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::InvertRgn { dc, region }) => {
            let (Some(dc), Some(region)) = (state.guest_gdi.dc(dc), state.guest_gdi.object(region))
            else {
                return Ok(0);
            };
            bool_result(
                host.win16_gdi(Operation::InvertRgn { dc, region })?,
                "InvertRgn",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::PaintRgn { dc, region }) => {
            let (Some(dc), Some(region)) = (state.guest_gdi.dc(dc), state.guest_gdi.object(region))
            else {
                return Ok(0);
            };
            bool_result(
                host.win16_gdi(Operation::PaintRgn { dc, region })?,
                "PaintRgn",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SelectClipRgn { dc, region }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            let region = if region == 0 {
                None
            } else {
                let Some(region) = state.guest_gdi.object(region) else {
                    return Ok(0);
                };
                Some(region)
            };
            complexity_result(
                host.win16_gdi(Operation::SelectClipRgn { dc, region })?,
                "SelectClipRgn",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::CombineRgn {
            destination,
            source1,
            source2,
            mode,
        }) => {
            let (Some(destination), Some(source1)) = (
                state.guest_gdi.object(destination),
                state.guest_gdi.object(source1),
            ) else {
                return Ok(0);
            };
            let source2 = if source2 == 0 {
                None
            } else {
                let Some(source2) = state.guest_gdi.object(source2) else {
                    return Ok(0);
                };
                Some(source2)
            };
            complexity_result(
                host.win16_gdi(Operation::CombineRgn {
                    destination,
                    source1,
                    source2,
                    mode: i32::from(mode),
                })?,
                "CombineRgn",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::EqualRgn { first, second }) => {
            let (Some(region1), Some(region2)) = (
                state.guest_gdi.object(first),
                state.guest_gdi.object(second),
            ) else {
                return Ok(0);
            };
            bool_result(
                host.win16_gdi(Operation::EqualRgn { region1, region2 })?,
                "EqualRgn",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::OffsetRgn { region, x, y }) => {
            let Some(region) = state.guest_gdi.object(region) else {
                return Ok(0);
            };
            complexity_result(
                host.win16_gdi(Operation::OffsetRgn {
                    region,
                    x: i32::from(x),
                    y: i32::from(y),
                })?,
                "OffsetRgn",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::PtVisible { dc, x, y }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            bool_result(
                host.win16_gdi(Operation::PtVisible {
                    dc,
                    x: i32::from(x),
                    y: i32::from(y),
                })?,
                "PtVisible",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetRgnBox { region, output }) => {
            let Some(region) = state.guest_gdi.object(region) else {
                return Ok(0);
            };
            let output = state.preflight_drawing_output(memory, output, 8)?;
            match host.win16_gdi(Operation::GetRgnBox { region })? {
                HostResult::Rect { complexity, rect } => {
                    if complexity != 0 {
                        state.write_drawing_rect(memory, output, rect)?;
                    }
                    Ok(complexity as u16 as u32)
                }
                _ => Err(wrong_result("GetRgnBox")),
            }
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::PtInRegion { region, x, y }) => {
            let Some(region) = state.guest_gdi.object(region) else {
                return Ok(0);
            };
            bool_result(
                host.win16_gdi(Operation::PtInRegion {
                    region,
                    x: i32::from(x),
                    y: i32::from(y),
                })?,
                "PtInRegion",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SetRectRgn {
            region,
            left,
            top,
            right,
            bottom,
        }) => {
            let Some(region) = state.guest_gdi.object(region) else {
                return Ok(0);
            };
            bool_result(
                host.win16_gdi(Operation::SetRectRgn {
                    region,
                    rect: drawing_rect(left, top, right, bottom),
                })?,
                "SetRectRgn",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetClipRgn { dc }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            match host.win16_gdi(Operation::GetClipRgn { dc })? {
                HostResult::Object(Some(region)) => {
                    if let Some(handle) = state.guest_gdi.allocate_object(region) {
                        Ok(u32::from(handle))
                    } else {
                        let _ = host.win16_delete_object(region)?;
                        Ok(0)
                    }
                }
                HostResult::Object(None) => Ok(0),
                _ => Err(wrong_result("GetClipRgn")),
            }
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::RectInRegion { region, rect }) => {
            let Some(region) = state.guest_gdi.object(region) else {
                return Ok(0);
            };
            let Some(rect) = rect else {
                return Ok(0);
            };
            bool_result(
                host.win16_gdi(Operation::RectInRegion {
                    region,
                    rect: rect_to_host(rect),
                })?,
                "RectInRegion",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::Chord {
            dc,
            left,
            top,
            right,
            bottom,
            start_x,
            start_y,
            end_x,
            end_y,
        }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            bool_result(
                host.win16_gdi(Operation::Chord {
                    dc,
                    left: i32::from(left),
                    top: i32::from(top),
                    right: i32::from(right),
                    bottom: i32::from(bottom),
                    start_x: i32::from(start_x),
                    start_y: i32::from(start_y),
                    end_x: i32::from(end_x),
                    end_y: i32::from(end_y),
                })?,
                "Chord",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::ExtFloodFill {
            dc,
            x,
            y,
            color,
            fill_type,
        }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            bool_result(
                host.win16_gdi(Operation::ExtFloodFill {
                    dc,
                    x: i32::from(x),
                    y: i32::from(y),
                    color,
                    fill_type: i32::from(fill_type),
                })?,
                "ExtFloodFill",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::PolyPolygon {
            dc,
            valid,
            polygon_count,
            points,
            point_counts,
        }) => {
            if !valid
                || points.len()
                    != point_counts
                        .iter()
                        .try_fold(0_usize, |sum, count| {
                            usize::try_from(*count)
                                .ok()
                                .and_then(|count| sum.checked_add(count))
                        })
                        .unwrap_or(usize::MAX)
                || point_counts.len() != usize::from(polygon_count)
            {
                return Ok(0);
            }
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            let points = points.into_iter().map(point_to_host).collect();
            let polygon_counts = point_counts.into_iter().map(i32::from).collect();
            bool_result(
                host.win16_gdi(Operation::PolyPolygon {
                    dc,
                    valid,
                    polygon_count: i32::from(polygon_count),
                    points,
                    polygon_counts,
                })?,
                "PolyPolygon",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::PolyBezier {
            dc,
            count,
            valid,
            points,
        }) => bezier(state, host, dc, count, valid, points, false),
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::PolyBezierTo {
            dc,
            count,
            valid,
            points,
        }) => bezier(state, host, dc, count, valid, points, true),
        request => Err(wrong_result(unhandled_name(&request))),
    }
}
