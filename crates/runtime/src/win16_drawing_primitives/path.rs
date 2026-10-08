//! Path GDI primitive requests.

use super::*;

pub(super) fn execute(
    state: &mut Win16State,
    request: Win16ApiRequest,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<u32, RuntimeError> {
    use Win16ApiRequest as Request;

    match request {
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetPath {
            dc,
            count,
            output_points,
            output_types,
        }) => {
            if count < 0 {
                return Ok(u32::from(u16::MAX));
            }
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(u32::from(u16::MAX));
            };
            let output_points = if count == 0 {
                None
            } else {
                Some(state.preflight_drawing_output(memory, output_points, point_bytes(count)?)?)
            };
            let output_types = if count == 0 {
                None
            } else {
                Some(state.preflight_drawing_output(memory, output_types, count as usize)?)
            };
            match host.win16_gdi(Operation::GetPath {
                dc,
                capacity: i32::from(count),
            })? {
                HostResult::Path {
                    count: result,
                    points,
                    point_types,
                } => {
                    if result < 0 {
                        return Ok(u32::from(u16::MAX));
                    }
                    if count == 0 {
                        // Size queries do not access the guest output pointers;
                        // the host reports a count with no returned arrays.
                        if !points.is_empty() || !point_types.is_empty() {
                            return Err(wrong_result("GetPath query buffers"));
                        }
                        return Ok(result as u16 as u32);
                    }
                    let result_count =
                        usize::try_from(result).map_err(|_| wrong_result("GetPath count"))?;
                    if result_count > count as usize
                        || points.len() != result_count
                        || point_types.len() != result_count
                    {
                        return Err(wrong_result("GetPath buffers"));
                    }
                    if let (Some(points_output), Some(types_output)) = (output_points, output_types)
                    {
                        state.write_drawing_points(memory, points_output, &points)?;
                        state.write_text_bytes(memory, types_output, &point_types)?;
                    }
                    Ok(result as u16 as u32)
                }
                _ => Err(wrong_result("GetPath")),
            }
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::PathToRegion { dc }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            match host.win16_gdi(Operation::PathToRegion { dc })? {
                HostResult::Object(Some(region)) => {
                    if let Some(handle) = state.guest_gdi.allocate_object(region) {
                        Ok(u32::from(handle))
                    } else {
                        let _ = host.win16_delete_object(region)?;
                        Ok(0)
                    }
                }
                HostResult::Object(None) => Ok(0),
                _ => Err(wrong_result("PathToRegion")),
            }
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::AbortPath { dc }) => path_bool(
            state,
            host,
            dc,
            |dc| Operation::AbortPath { dc },
            "AbortPath",
        ),
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::BeginPath { dc }) => path_bool(
            state,
            host,
            dc,
            |dc| Operation::BeginPath { dc },
            "BeginPath",
        ),
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::CloseFigure { dc }) => path_bool(
            state,
            host,
            dc,
            |dc| Operation::CloseFigure { dc },
            "CloseFigure",
        ),
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::EndPath { dc }) => {
            path_bool(state, host, dc, |dc| Operation::EndPath { dc }, "EndPath")
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::FillPath { dc }) => {
            path_bool(state, host, dc, |dc| Operation::FillPath { dc }, "FillPath")
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::FlattenPath { dc }) => path_bool(
            state,
            host,
            dc,
            |dc| Operation::FlattenPath { dc },
            "FlattenPath",
        ),
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::StrokeAndFillPath { dc }) => {
            path_bool(
                state,
                host,
                dc,
                |dc| Operation::StrokeAndFillPath { dc },
                "StrokeAndFillPath",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::StrokePath { dc }) => path_bool(
            state,
            host,
            dc,
            |dc| Operation::StrokePath { dc },
            "StrokePath",
        ),
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::WidenPath { dc }) => path_bool(
            state,
            host,
            dc,
            |dc| Operation::WidenPath { dc },
            "WidenPath",
        ),
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SelectClipPath { dc, mode }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            bool_result(
                host.win16_gdi(Operation::SelectClipPath {
                    dc,
                    mode: i32::from(mode),
                })?,
                "SelectClipPath",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::ExtSelectClipRgn {
            dc,
            region,
            mode,
        }) => {
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
                host.win16_gdi(Operation::ExtSelectClipRgn {
                    dc,
                    region,
                    mode: i32::from(mode),
                })?,
                "ExtSelectClipRgn",
            )
        }
        request => Err(wrong_result(unhandled_name(&request))),
    }
}
