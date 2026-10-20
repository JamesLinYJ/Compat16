//! Runtime services for checked GDI bitmap, DIB, palette, and print calls.

use guest_core::memory::Memory;
use win16_abi::{
    DibColorTableKind, DibRgbQuad16, DocInfo16, GdiDeviceRequest, PaletteEntry16,
    PaletteTransferKind, PrintOperation, Win16ApiRequest,
};

use super::Win16State;
use crate::{
    Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost, Win16DibColorTableKind,
    Win16DitherPattern, Win16GdiDeviceOperation as Operation,
    Win16GdiDeviceResult as HostResult, Win16HostGdiObject, Win16PaletteTransferKind,
    Win16PrintOperation,
};

const SRCCOPY: u32 = 0x00cc_0020;
// Win16 printing APIs use SP_ERROR (-1) for failure; zero is successful for
// several page/document operations and cannot stand in for an invalid HDC.
const SP_ERROR16: u32 = u16::MAX as u32;

#[path = "win16_gdi_device_services/bitmap.rs"]
mod bitmap;
#[path = "win16_gdi_device_services/objects.rs"]
mod objects;
#[path = "win16_gdi_device_services/object_query.rs"]
mod object_query;
#[path = "win16_gdi_device_services/palette.rs"]
mod palette;
#[path = "win16_gdi_device_services/printing.rs"]
mod printing;
#[path = "win16_gdi_device_services/escape.rs"]
mod escape;

#[derive(Clone, Copy)]
enum BitmapDimensionMode {
    LegacyGet,
    LegacySet {
        width: i16,
        height: i16,
    },
    ExtendedGet {
        output: u32,
    },
    ExtendedSet {
        width: i16,
        height: i16,
        output: u32,
    },
}

impl Win16State {
    pub(super) fn execute_gdi_device(
        &mut self,
        request: GdiDeviceRequest,
        memory: &mut Memory,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        use GdiDeviceRequest as Request;
        match request {
            Request::Escape { dc, escape, input_size, input, output } =>
                self.gdi_escape(memory, dc, escape, input_size, input, output, host),
            Request::GetObject { object, count, output } => self.query_gdi_object(object, count, output, memory, host),
            Request::GetBitmapBits {
                bitmap,
                byte_count,
                output,
            } => self.get_bitmap_bits(memory, bitmap, byte_count, output, host),
            Request::SetBitmapBits {
                bitmap,
                byte_count,
                bytes,
            } => self.set_bitmap_bits(bitmap, byte_count, bytes, host),
            Request::SetDibits {
                bitmap,
                dc,
                start_scan,
                scan_lines,
                bits,
                info,
                color_usage,
            } => self.set_dibits(
                memory,
                bitmap,
                dc,
                start_scan,
                scan_lines,
                bits,
                info,
                color_usage,
                host,
            ),
            Request::GetDibits {
                bitmap,
                dc,
                start_scan,
                scan_lines,
                bits,
                info,
                color_usage,
            } => self.get_dibits(
                memory,
                bitmap,
                dc,
                start_scan,
                scan_lines,
                bits,
                info,
                color_usage,
                host,
            ),
            Request::SetDibitsToDevice {
                dc,
                destination_x,
                destination_y,
                width,
                height,
                source_x,
                source_y,
                start_scan,
                scan_lines,
                bits,
                info,
                color_usage,
            } => self.set_dibits_to_device(
                memory,
                dc,
                destination_x,
                destination_y,
                width,
                height,
                source_x,
                source_y,
                start_scan,
                scan_lines,
                bits,
                info,
                color_usage,
                host,
            ),
            Request::CreateDibitmap {
                dc,
                header,
                init_flags,
                bits,
                info,
                color_usage,
            } => self
                .create_dibitmap(
                    memory,
                    dc,
                    header,
                    init_flags,
                    bits,
                    info,
                    color_usage,
                    host,
                )
                .map(u32::from),
            Request::StretchDibits {
                dc,
                destination_x,
                destination_y,
                destination_width,
                destination_height,
                source_x,
                source_y,
                source_width,
                source_height,
                info,
                bits,
                usage,
                rop,
            } => super::drawing::stretch_dibits(
                self,
                memory,
                host,
                dc,
                destination_x,
                destination_y,
                destination_width,
                destination_height,
                source_x,
                source_y,
                source_width,
                source_height,
                info,
                bits,
                usage,
                rop,
            ),
            Request::CreateDiscardableBitmap { dc, width, height } => {
                self.create_discardable_bitmap(dc, width, height, host)
            }
            Request::CreatePalette { version, entries } => {
                self.create_palette(version, entries, host)
            }
            Request::CreateHalftonePalette { dc } => self.create_halftone_palette(dc, host),
            Request::SelectPalette {
                dc,
                palette,
                force_background,
            } => self.select_palette(dc, palette, force_background, host),
            Request::RealizePalette { dc } => self.realize_palette(dc, false, host),
            Request::RealizeDefaultPalette { dc } => self.realize_palette(dc, true, host),
            Request::UpdateColors { dc } => self.update_colors(dc, host),
            Request::PaletteEntries {
                kind,
                palette,
                start,
                count,
                entries,
                output,
            } => self.palette_entries(memory, kind, palette, start, count, entries, output, host),
            Request::ResizePalette { palette, count } => self.resize_palette(palette, count, host),
            Request::GetNearestPaletteIndex { palette, color } => {
                self.nearest_palette_index(palette, color, host)
            }
            Request::SetSystemPaletteUse { dc, use_mode } => {
                self.system_palette_use(dc, Some(use_mode), host)
            }
            Request::GetSystemPaletteUse { dc } => self.system_palette_use(dc, None, host),
            Request::GetSystemPaletteEntries {
                dc,
                start,
                count,
                output,
            } => self.system_palette_entries(memory, dc, start, count, output, host),
            Request::DibColorTable {
                kind,
                dc,
                start,
                count,
                entries,
                output,
            } => self.dib_color_table(memory, kind, dc, start, count, entries, output, host),
            Request::WinGCreateDc => self.create_compatible_dc(0, host).map(u32::from),
            Request::WinGRecommendDibFormat { info } => {
                self.recommend_win_g_dib_format(memory, info, host)
            }
            Request::WinGCreateBitmap {
                dc,
                info,
                bits_output,
            } => self.create_win_g_bitmap(dc, info, bits_output, memory, host),
            Request::WinGGetDibPointer { bitmap, info } => {
                self.get_win_g_dib_pointer(bitmap, info, memory)
            }
            Request::WinGCreateHalfTonePalette => {
                self.create_wing_halftone_palette(host).map(u32::from)
            }
            Request::WinGCreateHalfToneBrush {
                dc,
                color,
                dither_type,
            } => self.create_wing_halftone_brush(dc, color, dither_type, host),
            Request::WinGBitBlt {
                destination,
                destination_x,
                destination_y,
                width,
                height,
                source,
                source_x,
                source_y,
            } => self.drawing(
                Win16ApiRequest::GdiDrawing(win16_abi::Win16GdiDrawingRequest::BitBlt {
                    destination,
                    destination_x,
                    destination_y,
                    width,
                    height,
                    source,
                    source_x,
                    source_y,
                    rop: SRCCOPY,
                }),
                memory,
                host,
            ),
            Request::WinGStretchBlt {
                destination,
                destination_x,
                destination_y,
                destination_width,
                destination_height,
                source,
                source_x,
                source_y,
                source_width,
                source_height,
            } => self.wing_stretch_blt(
                destination,
                destination_x,
                destination_y,
                destination_width,
                destination_height,
                source,
                source_x,
                source_y,
                source_width,
                source_height,
                host,
            ),
            Request::GetBitmapDimension { bitmap } => {
                self.bitmap_dimension(memory, bitmap, BitmapDimensionMode::LegacyGet, host)
            }
            Request::SetBitmapDimension {
                bitmap,
                width,
                height,
            } => self.bitmap_dimension(
                memory,
                bitmap,
                BitmapDimensionMode::LegacySet { width, height },
                host,
            ),
            Request::GetBitmapDimensionEx { bitmap, output } => self.bitmap_dimension(
                memory,
                bitmap,
                BitmapDimensionMode::ExtendedGet { output },
                host,
            ),
            Request::SetBitmapDimensionEx {
                bitmap,
                width,
                height,
                output,
            } => self.bitmap_dimension(
                memory,
                bitmap,
                BitmapDimensionMode::ExtendedSet {
                    width,
                    height,
                    output,
                },
                host,
            ),
            Request::ResetDc { dc, devmode } => self.reset_dc(dc, devmode, memory, host),
            Request::StartDoc { dc, doc_info } => self.start_doc(dc, doc_info, host),
            Request::Print { operation, dc } => self.print(operation, dc, host),
            // The procedure stays a guest FAR. QueryAbort and the print calls
            // enter it; this call only records it.
            Request::SetAbortProc { dc, callback } => self.set_abort_proc(memory, dc, callback),
        }
    }
}

fn pack_words(low: i16, high: i16) -> u32 {
    u32::from(low as u16) | (u32::from(high as u16) << 16)
}

fn wrong_device_result(operation: &'static str) -> RuntimeError {
    RuntimeError::new(
        Kind::InternalInvariant,
        format!("host returned the wrong result for Win16 GDI {operation}"),
    )
}
