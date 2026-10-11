//! Runtime request arms owned by the Gdi service group.

use guest_core::memory::Memory;
use win16_abi::{Win16ApiRequest, Win16ExportDescriptor};

use super::Win16State;
use super::gdi;
use crate::{DiagnosticKind as Kind, RuntimeError, RuntimeHost};

impl Win16State {
    pub(super) fn dispatch_gdi(
        &mut self,
        request: Win16ApiRequest,
        cpu: &mut x86_cpu::Cpu,
        dos: &mut dos_kernel::DosKernel,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
        descriptor: &Win16ExportDescriptor,
        return_to: (u16, u16, u32),
    ) -> Result<Option<u8>, RuntimeError> {
        let (return_selector, return_offset, return_sp) = return_to;
        let value = match request {
            Win16ApiRequest::GdiDevice(request) => {
                self.execute_gdi_device(request, memory, host)?
            }
            Win16ApiRequest::GdiServices(request) => self.execute_gdi_services(request, memory, host)?,
            request @ (Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::AbortPath { .. },
            )
            | Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::Arc {
                ..
            })
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::BeginPath { .. },
            )
            | Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::Chord {
                ..
            })
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::CloseFigure { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::CombineRgn { .. },
            )
            | Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::DPtoLP {
                ..
            })
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::Ellipse { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::EndPath { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::EqualRgn { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::ExcludeClipRect { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::ExtFloodFill { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::ExtSelectClipRgn { .. },
            )
            | Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::ExtTextOut {
                ..
            })
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::FillPath { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::FillRgn { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::FlattenPath { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::FloodFill { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::FrameRgn { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetArcDirection { .. },
            )
            | Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::GetBkColor {
                ..
            })
            | Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::GetNearestColor { .. })
            | Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::GetBkMode {
                ..
            })
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetBrushOrg { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetBrushOrgEx { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetClipBox { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetClipRgn { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetCurrentPosition { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetCurrentPositionEx { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetDcOrg { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetMapMode { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetPath { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetPixel { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetPolyFillMode { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetRgnBox { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetRop2 { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetStretchBltMode { .. },
            )
            | Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::GetTextAlign {
                ..
            })
            | Win16ApiRequest::GdiText(
                win16_abi::Win16GdiTextRequest::GetTextCharacterExtra { .. },
            )
            | Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::GetTextColor {
                ..
            })
            | Win16ApiRequest::GdiText(
                win16_abi::Win16GdiTextRequest::GetTextExtentPoint { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetViewportExt { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetViewportExtEx { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetViewportOrg { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetViewportOrgEx { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetWindowExt { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetWindowExtEx { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetWindowOrg { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::GetWindowOrgEx { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::IntersectClipRect { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::InvertRgn { .. },
            )
            | Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::LPtoDP {
                ..
            })
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::MoveToEx { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::OffsetClipRgn { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::OffsetRgn { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::OffsetViewportOrg { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::OffsetViewportOrgEx { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::OffsetWindowOrg { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::OffsetWindowOrgEx { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::PaintRgn { .. },
            )
            | Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::PatBlt {
                ..
            })
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::PathToRegion { .. },
            )
            | Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::Pie {
                ..
            })
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::PolyBezier { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::PolyBezierTo { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::PolyPolygon { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::Polygon { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::Polyline { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::PtInRegion { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::PtVisible { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::RectInRegion { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::RectVisible { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::RestoreDC { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::RoundRect { .. },
            )
            | Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::SaveDC {
                ..
            })
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::ScaleViewportExt { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::ScaleViewportExtEx { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::ScaleWindowExt { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::ScaleWindowExtEx { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::SelectClipPath { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::SelectClipRgn { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::SetArcDirection { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::SetBrushOrg { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::SetPixel { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::SetPolyFillMode { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::SetRectRgn { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::SetStretchBltMode { .. },
            )
            | Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::SetTextAlign {
                ..
            })
            | Win16ApiRequest::GdiText(
                win16_abi::Win16GdiTextRequest::SetTextCharacterExtra { .. },
            )
            | Win16ApiRequest::GdiText(
                win16_abi::Win16GdiTextRequest::SetTextJustification { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::SetViewportExt { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::SetViewportExtEx { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::SetViewportOrg { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::SetViewportOrgEx { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::SetWindowExt { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::SetWindowExtEx { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::SetWindowOrg { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::SetWindowOrgEx { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::StretchBlt { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::StrokeAndFillPath { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::StrokePath { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::WidenPath { .. },
            )) => self.drawing(request, memory, host)?,
            request @ (Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::SetBkColor {
                ..
            })
            | Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::SetBkMode {
                ..
            })
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::SetMapMode { .. },
            )
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::SetRop2 { .. },
            )
            | Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::SetTextColor {
                ..
            })
            | Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::MoveTo {
                ..
            })
            | Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::LineTo {
                ..
            })
            | Win16ApiRequest::GdiDrawing(
                win16_abi::Win16GdiDrawingRequest::Rectangle { .. },
            )
            | Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::TextOut {
                ..
            })
            | Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::BitBlt {
                ..
            })
            | Win16ApiRequest::GdiObjects(
                win16_abi::Win16GdiObjectsRequest::CreateSolidBrush { .. },
            )
            | Win16ApiRequest::GdiText(
                win16_abi::Win16GdiTextRequest::GetTextExtent { .. },
            )) => self.drawing(request, memory, host)?,
            Win16ApiRequest::GdiObjects(win16_abi::Win16GdiObjectsRequest::CreatePen {
                style,
                width,
                color,
            }) => u32::from(self.create_pen(style, width, color, host)?),
            Win16ApiRequest::GdiObjects(win16_abi::Win16GdiObjectsRequest::CreatePenIndirect {
                logpen,
            }) => u32::from(self.create_pen_indirect(logpen, host)?),
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::CreateFont {
                height,
                width,
                escapement,
                orientation,
                weight,
                italic,
                underline,
                strikeout,
                char_set,
                out_precision,
                clip_precision,
                quality,
                pitch_and_family,
                face_name,
            }) => u32::from(self.create_font(
                height,
                width,
                escapement,
                orientation,
                weight,
                italic,
                underline,
                strikeout,
                char_set,
                out_precision,
                clip_precision,
                quality,
                pitch_and_family,
                face_name,
                host,
            )?),
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::CreateFontIndirect {
                logfont,
            }) => u32::from(self.create_font_indirect(logfont, host)?),
            Win16ApiRequest::GdiObjects(win16_abi::Win16GdiObjectsRequest::CreateBitmap {
                width,
                height,
                planes,
                bits_per_pixel,
                bits,
            }) => u32::from(self.create_bitmap(
                memory,
                width,
                height,
                planes,
                bits_per_pixel,
                bits,
                host,
            )?),
            Win16ApiRequest::GdiObjects(
                win16_abi::Win16GdiObjectsRequest::CreateBitmapIndirect { bitmap },
            ) => u32::from(self.create_bitmap_indirect(memory, bitmap, host)?),
            Win16ApiRequest::GdiObjects(
                win16_abi::Win16GdiObjectsRequest::CreateBrushIndirect { logbrush },
            ) => u32::from(self.create_brush_indirect(memory, logbrush, host)?),
            Win16ApiRequest::GdiObjects(
                win16_abi::Win16GdiObjectsRequest::CreateCompatibleBitmap { dc, width, height },
            ) => u32::from(self.create_compatible_bitmap(dc, width, height, host)?),
            request @ (Win16ApiRequest::GdiObjects(
                win16_abi::Win16GdiObjectsRequest::CreateEllipticRgn { .. },
            )
            | Win16ApiRequest::GdiObjects(
                win16_abi::Win16GdiObjectsRequest::CreateEllipticRgnIndirect { .. },
            )
            | Win16ApiRequest::GdiObjects(
                win16_abi::Win16GdiObjectsRequest::CreatePolygonRgn { .. },
            )
            | Win16ApiRequest::GdiObjects(
                win16_abi::Win16GdiObjectsRequest::CreateRectRgn { .. },
            )
            | Win16ApiRequest::GdiObjects(
                win16_abi::Win16GdiObjectsRequest::CreateRectRgnIndirect { .. },
            )
            | Win16ApiRequest::GdiObjects(
                win16_abi::Win16GdiObjectsRequest::CreateRoundRectRgn { .. },
            )
            | Win16ApiRequest::GdiObjects(
                win16_abi::Win16GdiObjectsRequest::CreatePolyPolygonRgn { .. },
            )) => u32::from(self.create_region(request, host)?),
            Win16ApiRequest::GdiObjects(
                win16_abi::Win16GdiObjectsRequest::CreateCompatibleDc { source },
            ) => u32::from(self.create_compatible_dc(source, host)?),
            Win16ApiRequest::GdiObjects(win16_abi::Win16GdiObjectsRequest::CreateDc {
                driver,
                device,
                output,
                init_data,
            }) => u32::from(self.create_dc(driver, device, output, init_data, memory, host)?),
            Win16ApiRequest::GdiObjects(win16_abi::Win16GdiObjectsRequest::CreateIc {
                driver,
                device,
                output,
                init_data,
            }) => u32::from(self.create_ic(driver, device, output, init_data, memory, host)?),
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::GetTextMetrics {
                dc,
                output,
            }) => u32::from(self.get_text_metrics(dc, output, memory, host)?),
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::GetTextFace {
                dc,
                count,
                output,
            }) => self.get_text_face(dc, count, output, memory, host)? as u16 as u32,
            Win16ApiRequest::GdiObjects(win16_abi::Win16GdiObjectsRequest::DeleteDc { dc }) => {
                u32::from(self.delete_dc(dc, host)?)
            }
            Win16ApiRequest::GdiObjects(win16_abi::Win16GdiObjectsRequest::GetDeviceCaps {
                dc,
                index,
            }) => self.get_device_caps(dc, index, host)? as u16 as u32,
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::EnumFonts {
                dc,
                face_name,
                callback,
                parameter,
            }) => {
                return self.begin_enum_fonts(
                    cpu,
                    dos,
                    memory,
                    host,
                    super::font_callback::FontEnumerationMode::Fonts,
                    dc,
                    face_name.as_deref(),
                    callback,
                    parameter,
                    (return_selector, return_offset, return_sp),
                );
            }
            Win16ApiRequest::GdiText(win16_abi::Win16GdiTextRequest::EnumFontFamilies {
                dc,
                face_name,
                callback,
                parameter,
            }) => {
                return self.begin_enum_fonts(
                    cpu,
                    dos,
                    memory,
                    host,
                    super::font_callback::FontEnumerationMode::Families,
                    dc,
                    face_name.as_deref(),
                    callback,
                    parameter,
                    (return_selector, return_offset, return_sp),
                );
            }
            Win16ApiRequest::GdiObjects(win16_abi::Win16GdiObjectsRequest::GetStockObject {
                index,
            }) => u32::from(self.get_stock_object(index, host)?),
            Win16ApiRequest::GdiObjects(win16_abi::Win16GdiObjectsRequest::SelectObject {
                dc,
                object,
            }) => u32::from(self.select_object(dc, object, host)?),
            Win16ApiRequest::GdiObjects(win16_abi::Win16GdiObjectsRequest::DeleteObject {
                object,
            }) => u32::from(self.delete_object(object, memory, host)?),
            Win16ApiRequest::GdiObjects(win16_abi::Win16GdiObjectsRequest::UnrealizeObject {
                object,
            }) => u32::from(self.unrealize_object(object, host)?),
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::MulDiv {
                multiplicand,
                multiplier,
                divisor,
            }) => gdi::mul_div16(multiplicand, multiplier, divisor) as u16 as u32,
            Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::LineDda {
                x_start,
                y_start,
                x_end,
                y_end,
                callback,
                data,
            }) => {
                return self.begin_line_dda(
                    cpu,
                    dos,
                    memory,
                    host,
                    x_start,
                    y_start,
                    x_end,
                    y_end,
                    callback,
                    data,
                    (return_selector, return_offset, return_sp),
                    descriptor.return_kind,
                );
            }
            _ => {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 request reached a dispatch group that does not own it",
                ));
            }
        };
        self.complete_return(
            &mut cpu.regs,
            return_selector,
            return_offset,
            return_sp,
            value,
            descriptor.return_kind,
        )
    }
}

#[cfg(test)]
#[path = "win16_gdi_rectangle_predicate_tests.rs"]
mod rectangle_predicate_tests;

#[cfg(test)]
#[path = "win16_dispatch_set_rect_rgn_tests.rs"]
mod set_rect_rgn_tests;
