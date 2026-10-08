//! Win16 primitive, clip-region, and path exports.

use guest_core::memory::Memory;
use win16_abi::Win16ApiRequest;

use super::{
    HostResult, Operation, Win16State, drawing_rect, pack_words, point_to_host, rect_to_host,
    wrong_result,
};
use crate::{RuntimeError, RuntimeHost, Win16HostDc};

#[path = "win16_drawing_primitives/core.rs"]
mod core;
#[path = "win16_drawing_primitives/path.rs"]
mod path;
#[path = "win16_drawing_primitives/shape.rs"]
mod shape;
#[path = "win16_drawing_primitives/text.rs"]
mod text;

pub(super) fn execute(
    state: &mut Win16State,
    request: Win16ApiRequest,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<u32, RuntimeError> {
    use Win16ApiRequest as Request;

    match request {
        request @ Request::GdiText(
            win16_abi::Win16GdiTextRequest::GetBkColor { .. }
            | win16_abi::Win16GdiTextRequest::GetNearestColor { .. }
            | win16_abi::Win16GdiTextRequest::GetBkMode { .. }
            | win16_abi::Win16GdiTextRequest::GetTextColor { .. },
        ) => text::execute(state, request, host),
        request @ Request::GdiDrawing(
            win16_abi::Win16GdiDrawingRequest::AbortPath { .. }
            | win16_abi::Win16GdiDrawingRequest::BeginPath { .. }
            | win16_abi::Win16GdiDrawingRequest::CloseFigure { .. }
            | win16_abi::Win16GdiDrawingRequest::EndPath { .. }
            | win16_abi::Win16GdiDrawingRequest::ExtSelectClipRgn { .. }
            | win16_abi::Win16GdiDrawingRequest::FillPath { .. }
            | win16_abi::Win16GdiDrawingRequest::FlattenPath { .. }
            | win16_abi::Win16GdiDrawingRequest::GetPath { .. }
            | win16_abi::Win16GdiDrawingRequest::PathToRegion { .. }
            | win16_abi::Win16GdiDrawingRequest::SelectClipPath { .. }
            | win16_abi::Win16GdiDrawingRequest::StrokeAndFillPath { .. }
            | win16_abi::Win16GdiDrawingRequest::StrokePath { .. }
            | win16_abi::Win16GdiDrawingRequest::WidenPath { .. },
        ) => path::execute(state, request, memory, host),
        request @ Request::GdiDrawing(
            win16_abi::Win16GdiDrawingRequest::Arc { .. }
            | win16_abi::Win16GdiDrawingRequest::Chord { .. }
            | win16_abi::Win16GdiDrawingRequest::CombineRgn { .. }
            | win16_abi::Win16GdiDrawingRequest::Ellipse { .. }
            | win16_abi::Win16GdiDrawingRequest::EqualRgn { .. }
            | win16_abi::Win16GdiDrawingRequest::ExtFloodFill { .. }
            | win16_abi::Win16GdiDrawingRequest::FillRgn { .. }
            | win16_abi::Win16GdiDrawingRequest::FloodFill { .. }
            | win16_abi::Win16GdiDrawingRequest::FrameRgn { .. }
            | win16_abi::Win16GdiDrawingRequest::GetClipRgn { .. }
            | win16_abi::Win16GdiDrawingRequest::GetRgnBox { .. }
            | win16_abi::Win16GdiDrawingRequest::InvertRgn { .. }
            | win16_abi::Win16GdiDrawingRequest::OffsetClipRgn { .. }
            | win16_abi::Win16GdiDrawingRequest::OffsetRgn { .. }
            | win16_abi::Win16GdiDrawingRequest::PaintRgn { .. }
            | win16_abi::Win16GdiDrawingRequest::Pie { .. }
            | win16_abi::Win16GdiDrawingRequest::PolyBezier { .. }
            | win16_abi::Win16GdiDrawingRequest::PolyBezierTo { .. }
            | win16_abi::Win16GdiDrawingRequest::PolyPolygon { .. }
            | win16_abi::Win16GdiDrawingRequest::Polygon { .. }
            | win16_abi::Win16GdiDrawingRequest::PtInRegion { .. }
            | win16_abi::Win16GdiDrawingRequest::PtVisible { .. }
            | win16_abi::Win16GdiDrawingRequest::RectInRegion { .. }
            | win16_abi::Win16GdiDrawingRequest::RoundRect { .. }
            | win16_abi::Win16GdiDrawingRequest::SelectClipRgn { .. }
            | win16_abi::Win16GdiDrawingRequest::SetRectRgn { .. },
        ) => shape::execute(state, request, memory, host),
        request => core::execute(state, request, memory, host),
    }
}

fn path_bool(
    state: &Win16State,
    host: &mut impl RuntimeHost,
    guest_dc: u16,
    make_operation: fn(Win16HostDc) -> Operation,
    name: &'static str,
) -> Result<u32, RuntimeError> {
    let Some(dc) = state.guest_gdi.dc(guest_dc) else {
        return Ok(0);
    };
    bool_result(host.win16_gdi(make_operation(dc))?, name)
}

fn bezier(
    state: &Win16State,
    host: &mut impl RuntimeHost,
    guest_dc: u16,
    count: i16,
    valid: bool,
    points: Vec<win16_abi::Point16>,
    to: bool,
) -> Result<u32, RuntimeError> {
    if !valid || count <= 0 || points.len() != count as usize {
        return Ok(0);
    }
    let Some(dc) = state.guest_gdi.dc(guest_dc) else {
        return Ok(0);
    };
    let points = points.into_iter().map(point_to_host).collect();
    let operation = if to {
        Operation::PolyBezierTo { dc, valid, points }
    } else {
        Operation::PolyBezier { dc, valid, points }
    };
    bool_result(host.win16_gdi(operation)?, "PolyBezier/PolyBezierTo")
}

fn bool_result(result: HostResult, name: &'static str) -> Result<u32, RuntimeError> {
    match result {
        HostResult::Bool(success) => Ok(u32::from(u16::from(success))),
        _ => Err(wrong_result(name)),
    }
}

fn color_value(result: HostResult, name: &'static str) -> Result<u32, RuntimeError> {
    match result {
        HostResult::Color(color) => Ok(color),
        _ => Err(wrong_result(name)),
    }
}

fn complexity_result(result: HostResult, name: &'static str) -> Result<u32, RuntimeError> {
    match result {
        HostResult::RegionComplexity(value) => Ok(value as u16 as u32),
        _ => Err(wrong_result(name)),
    }
}

fn mode_result(result: HostResult, name: &'static str) -> Result<u32, RuntimeError> {
    match result {
        HostResult::Mode(value) => Ok(value as u16 as u32),
        _ => Err(wrong_result(name)),
    }
}

fn mode_value(result: HostResult, name: &'static str) -> Result<u32, RuntimeError> {
    match result {
        HostResult::Mode(value) => Ok(value as u16 as u32),
        _ => Err(wrong_result(name)),
    }
}

fn point_value(result: HostResult, name: &'static str) -> Result<u32, RuntimeError> {
    match result {
        HostResult::Point { x, y } => Ok(pack_words(x, y)),
        _ => Err(wrong_result(name)),
    }
}

fn point_bytes(count: i16) -> Result<usize, RuntimeError> {
    usize::try_from(count)
        .ok()
        .and_then(|count| count.checked_mul(4))
        .ok_or_else(|| {
            RuntimeError::new(
                crate::DiagnosticKind::GuestFault,
                "Win16 GetPath point capacity overflows guest memory",
            )
        })
}

fn unhandled_name(_request: &Win16ApiRequest) -> &'static str {
    "unexpected GDI drawing request"
}
