//! USER drawing exports layered over the shared GDI DC/object translation.

use guest_core::memory::Memory;
use win16_abi::{Win16ApiRequest, window_geometry::Rect16};

use super::Win16State;
use crate::{
    DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16DrawingOperation as Operation,
    Win16DrawingRect, Win16DrawingResult as HostResult, Win16HostBrush,
};

const DT_CALCRECT: u16 = 0x0400;
const DT_TABSTOP: u16 = 0x0080;
/// `DT_TOP` through `DT_INTERNAL` from the Windows 3.1 SDK `WINDOWS.H`.
const WIN31_DRAW_TEXT: u16 = 0x1FFF;

fn win31_draw_text_flags(flags: u16) -> u16 {
    if flags & DT_TABSTOP != 0 {
        flags
    } else {
        flags & WIN31_DRAW_TEXT
    }
}

const FIRST_COLOR_BRUSH: u16 = 1;
const LAST_COLOR_BRUSH: u16 = 31;

impl Win16State {
    /// Executes USER's drawing helpers using the same guest HDC/HBRUSH table as
    /// GDI. USER-specific rectangle and text semantics stay at this boundary.
    pub(super) fn user_service_drawing(
        &mut self,
        request: Win16ApiRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match request {
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Drawing(
                win16_abi::Win16UserDrawingRequest::TabbedTextOut {
                    dc, x, y, text, count, tab_count, tab_stops, tab_origin,
                },
            )) => {
                let Some(tab_stops) = tabbed_text_stops(&text, count, tab_count, tab_stops)? else {
                    return Ok(0);
                };
                let Some(dc) = self.guest_gdi.dc(dc) else { return Ok(0); };
                match host.win16_gdi(Operation::UserTabbedTextOut {
                    dc, x: i32::from(x), y: i32::from(y), text, tab_stops,
                    tab_origin: i32::from(tab_origin),
                })? {
                    HostResult::PackedTextExtent(value) => Ok(value),
                    _ => Err(wrong_result("TabbedTextOut")),
                }
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Drawing(
                win16_abi::Win16UserDrawingRequest::GetTabbedTextExtent {
                    dc, text, count, tab_count, tab_stops,
                },
            )) => {
                let Some(tab_stops) = tabbed_text_stops(&text, count, tab_count, tab_stops)? else {
                    return Ok(0);
                };
                let Some(dc) = self.guest_gdi.dc(dc) else { return Ok(0); };
                match host.win16_gdi(Operation::UserGetTabbedTextExtent { dc, text, tab_stops })? {
                    HostResult::PackedTextExtent(value) => Ok(value),
                    _ => Err(wrong_result("GetTabbedTextExtent")),
                }
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Drawing(
                win16_abi::Win16UserDrawingRequest::InvertRect { dc, rect },
            )) => {
                let (Some(dc), Some(rect)) = (self.guest_gdi.dc(dc), rect) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::UserInvertRect {
                    dc,
                    rect: rect_to_host(rect),
                })? {
                    HostResult::Void => Ok(0),
                    _ => Err(wrong_result("InvertRect")),
                }
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Drawing(
                win16_abi::Win16UserDrawingRequest::FrameRect { dc, rect, brush },
            )) => {
                let (Some(dc), Some(rect)) = (self.guest_gdi.dc(dc), rect) else {
                    return Ok(0);
                };
                let brush = if (FIRST_COLOR_BRUSH..=LAST_COLOR_BRUSH).contains(&brush) {
                    Win16HostBrush::SystemColor(brush - 1)
                } else {
                    let Some(brush) = self.guest_gdi.object(brush) else {
                        return Ok(0);
                    };
                    Win16HostBrush::Object(brush)
                };
                match host.win16_gdi(Operation::UserFrameRect {
                    dc,
                    rect: rect_to_host(rect),
                    brush,
                })? {
                    HostResult::Mode(value) => Ok(value as u16 as u32),
                    _ => Err(wrong_result("FrameRect")),
                }
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Drawing(
                win16_abi::Win16UserDrawingRequest::DrawIcon { dc, x, y, icon },
            )) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                let Some(icon) = self.guest_images.icon(icon) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::UserDrawIcon { dc, x, y, icon })? {
                    HostResult::Bool(success) => Ok(u32::from(u16::from(success))),
                    _ => Err(wrong_result("DrawIcon")),
                }
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Drawing(
                win16_abi::Win16UserDrawingRequest::DrawFocusRect { dc, rect },
            )) => {
                let (Some(dc), Some(rect)) = (self.guest_gdi.dc(dc), rect) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::UserDrawFocusRect {
                    dc,
                    rect: rect_to_host(rect),
                })? {
                    HostResult::Void => Ok(0),
                    _ => Err(wrong_result("DrawFocusRect")),
                }
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Drawing(
                win16_abi::Win16UserDrawingRequest::FillRect { dc, rect, brush },
            )) => {
                let Some(rect) = rect else {
                    return Ok(0);
                };
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                let brush = if (FIRST_COLOR_BRUSH..=LAST_COLOR_BRUSH).contains(&brush) {
                    Win16HostBrush::SystemColor(brush - 1)
                } else {
                    let Some(brush) = self.guest_gdi.object(brush) else {
                        return Ok(0);
                    };
                    Win16HostBrush::Object(brush)
                };
                match host.win16_gdi(Operation::UserFillRect {
                    dc,
                    rect: rect_to_host(rect),
                    brush,
                })? {
                    HostResult::Bool(success) => Ok(u32::from(u16::from(success))),
                    _ => Err(wrong_result("FillRect")),
                }
            }
            Win16ApiRequest::User(win16_abi::Win16UserRequest::Drawing(
                win16_abi::Win16UserDrawingRequest::DrawText {
                    dc,
                    text,
                    count,
                    rect,
                    rect_output,
                    flags,
                },
            )) => {
                // Windows 3.1 flags stop at DT_INTERNAL. Later ellipsis and
                // edit-control bits are cleared unless DT_TABSTOP is using the
                // high byte as its character count.
                let flags = win31_draw_text_flags(flags);
                if count < -1 {
                    return Ok(0);
                }
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                let Some(rect) = rect else {
                    return Ok(0);
                };
                if count >= 0 && text.len() != count as usize {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 DrawText byte count differs from its decoded text",
                    ));
                }
                if count == -1 && text.contains(&0) {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 DrawText null-terminated input retained an embedded NUL",
                    ));
                }

                let output = if flags & DT_CALCRECT != 0 {
                    if rect_output == 0 {
                        return Ok(0);
                    }
                    let pointer = self
                        .selectors
                        .pointer_from_far(rect_output)
                        .map_err(crate::runtime_error)?;
                    self.preflight_text_write(memory, pointer, Rect16::SIZE)?;
                    Some(pointer)
                } else {
                    None
                };

                let result = host.win16_gdi(Operation::UserDrawText {
                    dc,
                    text,
                    count: i32::from(count),
                    rect: Some(rect_to_host(rect)),
                    flags: u32::from(flags),
                })?;
                match result {
                    HostResult::DrawText { height, rect } => {
                        if height < 0 {
                            return Err(RuntimeError::new(
                                Kind::InternalInvariant,
                                "native DrawText returned a negative height",
                            ));
                        }
                        if let Some(pointer) = output {
                            match rect {
                                Some(rect) => self.write_user_rect(memory, pointer, rect)?,
                                None if height == 0 => {}
                                None => {
                                    return Err(RuntimeError::new(
                                        Kind::InternalInvariant,
                                        "DrawText with DT_CALCRECT omitted a successful rectangle",
                                    ));
                                }
                            }
                        }
                        Ok(u32::from(height.min(i32::from(i16::MAX)) as u16))
                    }
                    _ => Err(wrong_result("DrawText")),
                }
            }
            _ => Err(RuntimeError::new(
                Kind::InternalInvariant,
                "non-USER drawing request reached the USER drawing bridge",
            )),
        }
    }

    fn write_user_rect(
        &self,
        memory: &mut Memory,
        pointer: win16_abi::SegmentedPointer,
        rect: Win16DrawingRect,
    ) -> Result<(), RuntimeError> {
        let rect = Rect16 {
            left: guest_coordinate(rect.left),
            top: guest_coordinate(rect.top),
            right: guest_coordinate(rect.right),
            bottom: guest_coordinate(rect.bottom),
        };
        self.write_text_bytes(memory, pointer, &rect.encode())
    }
}

fn tabbed_text_stops(
    text: &[u8],
    count: i16,
    tab_count: i16,
    tab_stops: Option<Vec<i16>>,
) -> Result<Option<Vec<i32>>, RuntimeError> {
    if count < 0 || tab_count < 0 {
        return Ok(None);
    }
    if text.len() != count as usize {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 tabbed text byte count differs from its decoded text",
        ));
    }
    let Some(stops) = tab_stops else {
        // Win16 accepts a null tab array and uses the default eight average
        // character widths even when its count is positive. Normalize that
        // case to the documented native count-zero/null default contract.
        return Ok(Some(Vec::new()));
    };
    if stops.len() != tab_count as usize {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 tabbed text stop count differs from its decoded array",
        ));
    }
    let mut native = Vec::new();
    native.try_reserve_exact(stops.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, "reserve Win16 tabbed text stops", error,
    ))?;
    native.extend(stops.into_iter().map(i32::from));
    Ok(Some(native))
}

fn rect_to_host(rect: Rect16) -> Win16DrawingRect {
    Win16DrawingRect {
        left: i32::from(rect.left),
        top: i32::from(rect.top),
        right: i32::from(rect.right),
        bottom: i32::from(rect.bottom),
    }
}

fn guest_coordinate(value: i32) -> i16 {
    value.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
}

fn wrong_result(operation: &'static str) -> RuntimeError {
    RuntimeError::new(
        Kind::InternalInvariant,
        format!("native USER {operation} returned the wrong result type"),
    )
}
