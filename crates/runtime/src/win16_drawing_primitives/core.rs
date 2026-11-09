//! Core GDI primitive requests.

use super::*;

pub(super) fn execute(
    state: &mut Win16State,
    request: Win16ApiRequest,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<u32, RuntimeError> {
    use Win16ApiRequest as Request;

    match request {
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetMapMode { dc }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            mode_value(host.win16_gdi(Operation::GetMapMode { dc })?, "GetMapMode")
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetPolyFillMode { dc }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            mode_value(
                host.win16_gdi(Operation::GetPolyFillMode { dc })?,
                "GetPolyFillMode",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetRop2 { dc }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            mode_value(host.win16_gdi(Operation::GetRop2 { dc })?, "GetROP2")
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SetPolyFillMode { dc, mode }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            mode_result(
                host.win16_gdi(Operation::SetPolyFillMode {
                    dc,
                    mode: i32::from(mode),
                })?,
                "SetPolyFillMode",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SetArcDirection {
            dc,
            direction,
        }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            mode_result(
                host.win16_gdi(Operation::SetArcDirection {
                    dc,
                    direction: i32::from(direction),
                })?,
                "SetArcDirection",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetArcDirection { dc }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            mode_value(
                host.win16_gdi(Operation::GetArcDirection { dc })?,
                "GetArcDirection",
            )
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SetBrushOrg { dc, x, y }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            match host.win16_gdi(Operation::SetBrushOrg {
                dc,
                x: i32::from(x),
                y: i32::from(y),
            })? {
                HostResult::Point { x, y } => Ok(signed_brush_origin(x, y).unwrap_or(0)),
                _ => Err(wrong_result("SetBrushOrg")),
            }
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetBrushOrg { dc }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            match host.win16_gdi(Operation::GetBrushOrg { dc })? {
                HostResult::Point { x, y } => Ok(signed_brush_origin(x, y).unwrap_or(0)),
                _ => Err(wrong_result("GetBrushOrg")),
            }
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetBrushOrgEx { dc, output }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            let output = state.preflight_drawing_output(memory, output, 4)?;
            match host.win16_gdi(Operation::GetBrushOrgEx { dc })? {
                HostResult::BoolPoint { success, point } => {
                    // Volume 2: nonzero on success and zero otherwise. The
                    // POINT is two signed ints. A coordinate outside that int
                    // is the failure result, and the guest point stays as it was.
                    if success && signed_brush_origin(point.x, point.y).is_some() {
                        state.write_drawing_point(memory, output, point)?;
                        Ok(1)
                    } else {
                        Ok(0)
                    }
                }
                _ => Err(wrong_result("GetBrushOrgEx")),
            }
        }
        Request::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetDcOrg { dc }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            point_value(host.win16_gdi(Operation::GetDcOrg { dc })?, "GetDCOrg")
        }
        request => Err(wrong_result(unhandled_name(&request))),
    }
}

/// Programmer's Reference, Volume 2: `GetBrushOrg` and `SetBrushOrg` return
/// the origin in the low and high words, and `GetBrushOrgEx` stores the same
/// origin in a `POINT` of signed ints. `(0, 0)` is a real origin and is
/// distinct from a host coordinate that does not fit in that int.
fn signed_brush_origin(x: i32, y: i32) -> Option<u32> {
    let (Ok(x), Ok(y)) = (i16::try_from(x), i16::try_from(y)) else {
        return None;
    };
    Some(pack_words(i32::from(x), i32::from(y)))
}
