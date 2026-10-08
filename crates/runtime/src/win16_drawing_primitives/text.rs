//! Text GDI primitive requests.

use super::*;

pub(super) fn execute(
    state: &mut Win16State,
    request: Win16ApiRequest,
    host: &mut impl RuntimeHost,
) -> Result<u32, RuntimeError> {
    use Win16ApiRequest as Request;

    match request {
        Request::GdiText(win16_abi::Win16GdiTextRequest::GetNearestColor { dc, color }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else { return Ok(u32::MAX); };
            color_value(host.win16_gdi(Operation::GetNearestColor { dc, color })?, "GetNearestColor")
        }
        Request::GdiText(win16_abi::Win16GdiTextRequest::GetBkColor { dc }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(u32::MAX);
            };
            color_value(host.win16_gdi(Operation::GetBkColor { dc })?, "GetBkColor")
        }
        Request::GdiText(win16_abi::Win16GdiTextRequest::GetBkMode { dc }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(0);
            };
            mode_value(host.win16_gdi(Operation::GetBkMode { dc })?, "GetBkMode")
        }
        Request::GdiText(win16_abi::Win16GdiTextRequest::GetTextColor { dc }) => {
            let Some(dc) = state.guest_gdi.dc(dc) else {
                return Ok(u32::MAX);
            };
            color_value(
                host.win16_gdi(Operation::GetTextColor { dc })?,
                "GetTextColor",
            )
        }
        request => Err(wrong_result(unhandled_name(&request))),
    }
}
