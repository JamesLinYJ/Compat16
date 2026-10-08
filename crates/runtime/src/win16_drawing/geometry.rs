//! Geometry requests handled by the direct Win16 GDI adapter.

use super::*;

impl Win16State {
    pub(super) fn drawing_geometry_requests(
        &mut self,
        request: Win16ApiRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        match request {
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SetMapMode {
                dc,
                mode,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::SetMapMode {
                    dc,
                    mode: i32::from(mode),
                })? {
                    HostResult::Mode(previous) => Ok(previous as u16 as u32),
                    _ => Err(wrong_result("SetMapMode")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SetRop2 {
                dc,
                mode,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::SetRop2 {
                    dc,
                    mode: i32::from(mode),
                })? {
                    HostResult::Mode(previous) => Ok(previous as u16 as u32),
                    _ => Err(wrong_result("SetROP2")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::MoveTo { dc, x, y }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::MoveTo {
                    dc,
                    x: i32::from(x),
                    y: i32::from(y),
                })? {
                    HostResult::Point { x, y } => Ok(pack_words(x, y)),
                    _ => Err(wrong_result("MoveTo")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::LineTo { dc, x, y }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::LineTo {
                    dc,
                    x: i32::from(x),
                    y: i32::from(y),
                })? {
                    HostResult::Bool(result) => Ok(u32::from(u16::from(result))),
                    _ => Err(wrong_result("LineTo")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::Rectangle {
                dc,
                left,
                top,
                right,
                bottom,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::Rectangle {
                    dc,
                    left: i32::from(left),
                    top: i32::from(top),
                    right: i32::from(right),
                    bottom: i32::from(bottom),
                })? {
                    HostResult::Bool(result) => Ok(u32::from(u16::from(result))),
                    _ => Err(wrong_result("Rectangle")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::BitBlt {
                destination,
                destination_x,
                destination_y,
                width,
                height,
                source,
                source_x,
                source_y,
                rop,
            }) => {
                let Some(destination) = self.guest_gdi.dc(destination) else {
                    return Ok(0);
                };
                let source = if source == 0 {
                    None
                } else {
                    let Some(source) = self.guest_gdi.dc(source) else {
                        return Ok(0);
                    };
                    Some(source)
                };
                match host.win16_gdi(Operation::BitBlt {
                    destination,
                    destination_x: i32::from(destination_x),
                    destination_y: i32::from(destination_y),
                    width: i32::from(width),
                    height: i32::from(height),
                    source,
                    source_x: i32::from(source_x),
                    source_y: i32::from(source_y),
                    rop,
                })? {
                    HostResult::Bool(result) => Ok(u32::from(u16::from(result))),
                    _ => Err(wrong_result("BitBlt")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SetStretchBltMode {
                dc,
                mode,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::SetStretchBltMode {
                    dc,
                    mode: i32::from(mode),
                })? {
                    HostResult::Mode(previous) => Ok(previous as u16 as u32),
                    _ => Err(wrong_result("SetStretchBltMode")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetStretchBltMode {
                dc,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::GetStretchBltMode { dc })? {
                    HostResult::Mode(mode) => Ok(mode as u16 as u32),
                    _ => Err(wrong_result("GetStretchBltMode")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SetWindowExt {
                dc,
                x,
                y,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::SetWindowExt {
                    dc,
                    x: i32::from(x),
                    y: i32::from(y),
                })? {
                    HostResult::Size { width, height } => Ok(pack_words(width, height)),
                    _ => Err(wrong_result("SetWindowExt")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SetViewportOrg {
                dc,
                x,
                y,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::SetViewportOrg {
                    dc,
                    x: i32::from(x),
                    y: i32::from(y),
                })? {
                    HostResult::Point { x, y } => Ok(pack_words(x, y)),
                    _ => Err(wrong_result("SetViewportOrg")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SetViewportExt {
                dc,
                x,
                y,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::SetViewportExt {
                    dc,
                    x: i32::from(x),
                    y: i32::from(y),
                })? {
                    HostResult::Size { width, height } => Ok(pack_words(width, height)),
                    _ => Err(wrong_result("SetViewportExt")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::ExcludeClipRect {
                dc,
                left,
                top,
                right,
                bottom,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::ExcludeClipRect {
                    dc,
                    rect: drawing_rect(left, top, right, bottom),
                })? {
                    HostResult::RegionComplexity(complexity) => Ok(complexity as u16 as u32),
                    _ => Err(wrong_result("ExcludeClipRect")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::IntersectClipRect {
                dc,
                left,
                top,
                right,
                bottom,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::IntersectClipRect {
                    dc,
                    rect: drawing_rect(left, top, right, bottom),
                })? {
                    HostResult::RegionComplexity(complexity) => Ok(complexity as u16 as u32),
                    _ => Err(wrong_result("IntersectClipRect")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::PatBlt {
                dc,
                x,
                y,
                width,
                height,
                rop,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::PatBlt {
                    dc,
                    x: i32::from(x),
                    y: i32::from(y),
                    width: i32::from(width),
                    height: i32::from(height),
                    rop,
                })? {
                    HostResult::Bool(success) => Ok(u32::from(u16::from(success))),
                    _ => Err(wrong_result("PatBlt")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SaveDC { dc }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::SaveDc { dc })? {
                    HostResult::SaveDc(saved) => Ok(saved as u16 as u32),
                    _ => Err(wrong_result("SaveDC")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::RestoreDC {
                dc,
                saved,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::RestoreDc {
                    dc,
                    saved: i32::from(saved),
                })? {
                    HostResult::Bool(success) => Ok(u32::from(u16::from(success))),
                    _ => Err(wrong_result("RestoreDC")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SetPixel {
                dc,
                x,
                y,
                color,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(u32::MAX);
                };
                match host.win16_gdi(Operation::SetPixel {
                    dc,
                    x: i32::from(x),
                    y: i32::from(y),
                    color,
                })? {
                    HostResult::Color(color) => Ok(color),
                    _ => Err(wrong_result("SetPixel")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetPixel {
                dc,
                x,
                y,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(u32::MAX);
                };
                match host.win16_gdi(Operation::GetPixel {
                    dc,
                    x: i32::from(x),
                    y: i32::from(y),
                })? {
                    HostResult::Color(color) => Ok(color),
                    _ => Err(wrong_result("GetPixel")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::StretchBlt {
                destination,
                destination_x,
                destination_y,
                width,
                height,
                source,
                source_x,
                source_y,
                source_width,
                source_height,
                rop,
            }) => {
                let Some(destination) = self.guest_gdi.dc(destination) else {
                    return Ok(0);
                };
                let source = if source == 0 {
                    None
                } else {
                    let Some(source) = self.guest_gdi.dc(source) else {
                        return Ok(0);
                    };
                    Some(source)
                };
                match host.win16_gdi(Operation::StretchBlt {
                    destination,
                    destination_x: i32::from(destination_x),
                    destination_y: i32::from(destination_y),
                    destination_width: i32::from(width),
                    destination_height: i32::from(height),
                    source,
                    source_x: i32::from(source_x),
                    source_y: i32::from(source_y),
                    source_width: i32::from(source_width),
                    source_height: i32::from(source_height),
                    rop,
                })? {
                    HostResult::Bool(success) => Ok(u32::from(u16::from(success))),
                    _ => Err(wrong_result("StretchBlt")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::Polyline {
                dc,
                count,
                points,
            }) => {
                if count <= 0 {
                    return Ok(0);
                }
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                let points = checked_points(count, points, "Polyline")?
                    .into_iter()
                    .map(point_to_host)
                    .collect();
                match host.win16_gdi(Operation::Polyline { dc, points })? {
                    HostResult::Bool(success) => Ok(u32::from(u16::from(success))),
                    _ => Err(wrong_result("Polyline")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::DPtoLP {
                dc,
                count,
                points,
                output,
            }) => self.transform_points(memory, host, dc, count, points, output, true),
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::LPtoDP {
                dc,
                count,
                points,
                output,
            }) => self.transform_points(memory, host, dc, count, points, output, false),
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetClipBox {
                dc,
                output,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                let output = self.preflight_drawing_output(memory, output, 8)?;
                match host.win16_gdi(Operation::GetClipBox { dc })? {
                    HostResult::Rect { complexity, rect } => {
                        if complexity != 0 {
                            self.write_drawing_rect(memory, output, rect)?;
                        }
                        Ok(complexity as u16 as u32)
                    }
                    _ => Err(wrong_result("GetClipBox")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::RectVisible {
                dc,
                rect,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                let Some(rect) = rect else {
                    return Ok(0);
                };
                let rect = rect_to_host(rect);
                match host.win16_gdi(Operation::RectVisible { dc, rect })? {
                    HostResult::Bool(success) => Ok(u32::from(u16::from(success))),
                    _ => Err(wrong_result("RectVisible")),
                }
            }
            Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetCurrentPositionEx { dc, output },
            ) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                let output = self.preflight_drawing_output(memory, output, 4)?;
                match host.win16_gdi(Operation::GetCurrentPositionEx { dc })? {
                    HostResult::BoolPoint { success, point } => {
                        if success {
                            self.write_drawing_point(memory, output, point)?;
                        }
                        Ok(u32::from(u16::from(success)))
                    }
                    _ => Err(wrong_result("GetCurrentPositionEx")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::MoveToEx {
                dc,
                x,
                y,
                output,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                let output = if output == 0 {
                    None
                } else {
                    Some(self.preflight_drawing_output(memory, output, 4)?)
                };
                match host.win16_gdi(Operation::MoveToEx {
                    dc,
                    x: i32::from(x),
                    y: i32::from(y),
                })? {
                    HostResult::BoolPoint { success, point } => {
                        if success {
                            if let Some(output) = output {
                                self.write_drawing_point(memory, output, point)?;
                            }
                        }
                        Ok(u32::from(u16::from(success)))
                    }
                    _ => Err(wrong_result("MoveToEx")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SetWindowExtEx {
                dc,
                x,
                y,
                output,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                let output = if output == 0 {
                    None
                } else {
                    Some(self.preflight_drawing_output(memory, output, 4)?)
                };
                match host.win16_gdi(Operation::SetWindowExtEx {
                    dc,
                    x: i32::from(x),
                    y: i32::from(y),
                })? {
                    HostResult::BoolSize {
                        success,
                        width,
                        height,
                    } => {
                        if success {
                            if let Some(output) = output {
                                self.write_drawing_size(memory, output, width, height)?;
                            }
                        }
                        Ok(u32::from(u16::from(success)))
                    }
                    _ => Err(wrong_result("SetWindowExtEx")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SetViewportExtEx {
                dc,
                x,
                y,
                output,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                let output = if output == 0 {
                    None
                } else {
                    Some(self.preflight_drawing_output(memory, output, 4)?)
                };
                match host.win16_gdi(Operation::SetViewportExtEx {
                    dc,
                    x: i32::from(x),
                    y: i32::from(y),
                })? {
                    HostResult::BoolSize {
                        success,
                        width,
                        height,
                    } => {
                        if success {
                            if let Some(output) = output {
                                self.write_drawing_size(memory, output, width, height)?;
                            }
                        }
                        Ok(u32::from(u16::from(success)))
                    }
                    _ => Err(wrong_result("SetViewportExtEx")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SetViewportOrgEx {
                dc,
                x,
                y,
                output,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                let output = if output == 0 {
                    None
                } else {
                    Some(self.preflight_drawing_output(memory, output, 4)?)
                };
                match host.win16_gdi(Operation::SetViewportOrgEx {
                    dc,
                    x: i32::from(x),
                    y: i32::from(y),
                })? {
                    HostResult::BoolPoint { success, point } => {
                        if success {
                            if let Some(output) = output {
                                self.write_drawing_point(memory, output, point)?;
                            }
                        }
                        Ok(u32::from(u16::from(success)))
                    }
                    _ => Err(wrong_result("SetViewportOrgEx")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetViewportOrgEx {
                dc,
                output,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                let output = self.preflight_drawing_output(memory, output, 4)?;
                match host.win16_gdi(Operation::GetViewportOrgEx { dc })? {
                    HostResult::BoolPoint { success, point } => {
                        if success {
                            self.write_drawing_point(memory, output, point)?;
                        }
                        Ok(u32::from(u16::from(success)))
                    }
                    _ => Err(wrong_result("GetViewportOrgEx")),
                }
            }
            request => self.drawing_extended(request, memory, host),
        }
    }
}
