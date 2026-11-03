//! Extended state and legacy coordinate-pair drawing exports.

use guest_core::memory::Memory;
use win16_abi::Win16ApiRequest;

use super::{
    HostResult, Operation, Win16State, apply_signed_pair, pack_words, pair_from_point,
    pair_from_size, read_signed_pair, wrong_result,
};
use crate::RuntimeHost;

impl Win16State {
    pub(super) fn drawing_extended(
        &mut self,
        request: Win16ApiRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, crate::RuntimeError> {
        match request {
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SetWindowOrg {
                dc,
                x,
                y,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                apply_signed_pair(
                    host,
                    Operation::GetWindowOrg { dc },
                    Operation::SetWindowOrg {
                        dc,
                        x: i32::from(x),
                        y: i32::from(y),
                    },
                    |x, y| Operation::SetWindowOrg { dc, x, y },
                    pair_from_point,
                    "SetWindowOrg",
                )
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::OffsetWindowOrg {
                dc,
                x,
                y,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                apply_signed_pair(
                    host,
                    Operation::GetWindowOrg { dc },
                    Operation::OffsetWindowOrg {
                        dc,
                        x: i32::from(x),
                        y: i32::from(y),
                    },
                    |x, y| Operation::SetWindowOrg { dc, x, y },
                    pair_from_point,
                    "OffsetWindowOrg",
                )
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::OffsetViewportOrg {
                dc,
                x,
                y,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                apply_signed_pair(
                    host,
                    Operation::GetViewportOrg { dc },
                    Operation::OffsetViewportOrg {
                        dc,
                        x: i32::from(x),
                        y: i32::from(y),
                    },
                    |x, y| Operation::SetViewportOrg { dc, x, y },
                    pair_from_point,
                    "OffsetViewportOrg",
                )
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::ScaleWindowExt {
                dc,
                x_numerator,
                x_denominator,
                y_numerator,
                y_denominator,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                apply_signed_pair(
                    host,
                    Operation::GetWindowExt { dc },
                    Operation::ScaleWindowExt {
                        dc,
                        x_num: i32::from(x_numerator),
                        x_den: i32::from(x_denominator),
                        y_num: i32::from(y_numerator),
                        y_den: i32::from(y_denominator),
                    },
                    |width, height| Operation::SetWindowExt {
                        dc,
                        x: width,
                        y: height,
                    },
                    pair_from_size,
                    "ScaleWindowExt",
                )
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::ScaleViewportExt {
                dc,
                x_numerator,
                x_denominator,
                y_numerator,
                y_denominator,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                apply_signed_pair(
                    host,
                    Operation::GetViewportExt { dc },
                    Operation::ScaleViewportExt {
                        dc,
                        x_num: i32::from(x_numerator),
                        x_den: i32::from(x_denominator),
                        y_num: i32::from(y_numerator),
                        y_den: i32::from(y_denominator),
                    },
                    |width, height| Operation::SetViewportExt {
                        dc,
                        x: width,
                        y: height,
                    },
                    pair_from_size,
                    "ScaleViewportExt",
                )
            }
            Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetCurrentPosition { dc },
            ) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                match host.win16_gdi(Operation::GetCurrentPosition { dc })? {
                    HostResult::Point { x, y } => Ok(pack_words(x, y)),
                    _ => Err(wrong_result("GetCurrentPosition")),
                }
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetViewportExt {
                dc,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                read_signed_pair(
                    host,
                    Operation::GetViewportExt { dc },
                    pair_from_size,
                    "GetViewportExt",
                )
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetViewportOrg {
                dc,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                read_signed_pair(
                    host,
                    Operation::GetViewportOrg { dc },
                    pair_from_point,
                    "GetViewportOrg",
                )
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetWindowExt { dc }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                read_signed_pair(
                    host,
                    Operation::GetWindowExt { dc },
                    pair_from_size,
                    "GetWindowExt",
                )
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetWindowOrg { dc }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                read_signed_pair(
                    host,
                    Operation::GetWindowOrg { dc },
                    pair_from_point,
                    "GetWindowOrg",
                )
            }
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetViewportExtEx {
                dc,
                output,
            }) => self.get_extent_ex(memory, host, dc, output, false),
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetWindowExtEx {
                dc,
                output,
            }) => self.get_extent_ex(memory, host, dc, output, true),
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::GetWindowOrgEx {
                dc,
                output,
            }) => self.get_origin_ex(memory, host, dc, output, false),
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SetWindowOrgEx {
                dc,
                x,
                y,
                output,
            }) => {
                let Some(dc) = self.guest_gdi.dc(dc) else {
                    return Ok(0);
                };
                let output = self.optional_drawing_output(memory, output, 4)?;
                match host.win16_gdi(Operation::SetWindowOrgEx {
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
                    _ => Err(wrong_result("SetWindowOrgEx")),
                }
            }
            Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::OffsetViewportOrgEx { dc, x, y, output },
            ) => self.offset_org_ex(memory, host, dc, x, y, output, false),
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::OffsetWindowOrgEx {
                dc,
                x,
                y,
                output,
            }) => self.offset_org_ex(memory, host, dc, x, y, output, true),
            Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::ScaleViewportExtEx {
                    dc,
                    x_numerator,
                    x_denominator,
                    y_numerator,
                    y_denominator,
                    output,
                },
            ) => self.scale_extent_ex(
                memory,
                host,
                dc,
                x_numerator,
                x_denominator,
                y_numerator,
                y_denominator,
                output,
                false,
            ),
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::ScaleWindowExtEx {
                dc,
                x_numerator,
                x_denominator,
                y_numerator,
                y_denominator,
                output,
            }) => self.scale_extent_ex(
                memory,
                host,
                dc,
                x_numerator,
                x_denominator,
                y_numerator,
                y_denominator,
                output,
                true,
            ),
            request => self.drawing_primitives(request, memory, host),
        }
    }

    fn get_extent_ex(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        guest_dc: u16,
        output_far: u32,
        window: bool,
    ) -> Result<u32, crate::RuntimeError> {
        let Some(dc) = self.guest_gdi.dc(guest_dc) else {
            return Ok(0);
        };
        let output = self.preflight_drawing_output(memory, output_far, 4)?;
        let operation = if window {
            Operation::GetWindowExtEx { dc }
        } else {
            Operation::GetViewportExtEx { dc }
        };
        match host.win16_gdi(operation)? {
            HostResult::BoolSize {
                success,
                width,
                height,
            } => {
                if success {
                    self.write_drawing_size(memory, output, width, height)?;
                }
                Ok(u32::from(u16::from(success)))
            }
            _ => Err(wrong_result("GetWindowExtEx/GetViewportExtEx")),
        }
    }

    fn get_origin_ex(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        guest_dc: u16,
        output_far: u32,
        window: bool,
    ) -> Result<u32, crate::RuntimeError> {
        let Some(dc) = self.guest_gdi.dc(guest_dc) else {
            return Ok(0);
        };
        let output = self.preflight_drawing_output(memory, output_far, 4)?;
        let operation = if window {
            Operation::GetWindowOrgEx { dc }
        } else {
            Operation::GetViewportOrgEx { dc }
        };
        match host.win16_gdi(operation)? {
            HostResult::BoolPoint { success, point } => {
                if success {
                    self.write_drawing_point(memory, output, point)?;
                }
                Ok(u32::from(u16::from(success)))
            }
            _ => Err(wrong_result("GetWindowOrgEx/GetViewportOrgEx")),
        }
    }

    fn offset_org_ex(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        guest_dc: u16,
        x: i16,
        y: i16,
        output_far: u32,
        window: bool,
    ) -> Result<u32, crate::RuntimeError> {
        let Some(dc) = self.guest_gdi.dc(guest_dc) else {
            return Ok(0);
        };
        let output = self.optional_drawing_output(memory, output_far, 4)?;
        let operation = if window {
            Operation::OffsetWindowOrgEx {
                dc,
                x: i32::from(x),
                y: i32::from(y),
            }
        } else {
            Operation::OffsetViewportOrgEx {
                dc,
                x: i32::from(x),
                y: i32::from(y),
            }
        };
        match host.win16_gdi(operation)? {
            HostResult::BoolPoint { success, point } => {
                if success {
                    if let Some(output) = output {
                        self.write_drawing_point(memory, output, point)?;
                    }
                }
                Ok(u32::from(u16::from(success)))
            }
            _ => Err(wrong_result("OffsetWindowOrgEx/OffsetViewportOrgEx")),
        }
    }

    fn scale_extent_ex(
        &mut self,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        guest_dc: u16,
        x_numerator: i16,
        x_denominator: i16,
        y_numerator: i16,
        y_denominator: i16,
        output_far: u32,
        window: bool,
    ) -> Result<u32, crate::RuntimeError> {
        let Some(dc) = self.guest_gdi.dc(guest_dc) else {
            return Ok(0);
        };
        let output = self.optional_drawing_output(memory, output_far, 4)?;
        let (x_num, x_den, y_num, y_den) = (
            i32::from(x_numerator),
            i32::from(x_denominator),
            i32::from(y_numerator),
            i32::from(y_denominator),
        );
        let operation = if window {
            Operation::ScaleWindowExtEx {
                dc,
                x_num,
                x_den,
                y_num,
                y_den,
            }
        } else {
            Operation::ScaleViewportExtEx {
                dc,
                x_num,
                x_den,
                y_num,
                y_den,
            }
        };
        match host.win16_gdi(operation)? {
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
            _ => Err(wrong_result("ScaleWindowExtEx/ScaleViewportExtEx")),
        }
    }
}
