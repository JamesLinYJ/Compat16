//! GetObject translates native descriptions into existing Win16 wire codecs.

use super::*;
use win16_abi::{Access, gdi_abi::{Bitmap16, LogBrush16, LogFont16, LogPen16}};
use crate::Win16GdiObjectInfo as Info;

impl Win16State {
    pub(super) fn query_gdi_object(&mut self, object: u16, count: i16, output: u32,
        memory: &mut Memory, host: &mut impl RuntimeHost) -> Result<u32, RuntimeError>
    {
        if count < 0 || (count == 0 && output != 0) { return Ok(0); }
        let Some(object) = self.guest_gdi.object(object) else { return Ok(0); };
        let result = host.win16_gdi_device(Operation::GetObject { object })?;
        let HostResult::ObjectInfo(info) = result else { return Err(wrong_device_result("GetObject")); };
        let Some(info) = info else { return Ok(0); };
        if output == 0 {
            // A size query does not allocate guest aliases for pointer-bearing
            // fields. The queried size is the guest structure, not host sizeof.
            let size = match &info {
                Info::Pen(_) => LogPen16::SIZE, Info::Font(_) => LogFont16::SIZE,
                Info::Brush { .. } => LogBrush16::SIZE, Info::Bitmap(_) => Bitmap16::SIZE,
                Info::Palette(_) => 2,
                Info::UnsupportedBrush => {
                    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                        "GetObject cannot translate this brush's native storage; zero bytes returned"));
                    return Ok(0);
                }
            };
            return Ok(size as u32);
        }
        let bytes = match info {
            Info::Pen(pen) => LogPen16 {
                style: pen.style, width_x: pen.width_x, width_y: pen.width_y, color: pen.color,
            }.encode().to_vec(),
            Info::Font(font) => LogFont16 {
                dimensions: [font.height, font.width, font.escapement, font.orientation, font.weight],
                styles: [font.italic, font.underline, font.strikeout, font.char_set,
                    font.out_precision, font.clip_precision, font.quality, font.pitch_and_family],
                face_name: font.face_name,
            }.encode().to_vec(),
            Info::Brush { brush, pattern } => {
                let hatch = if let Some(pattern) = pattern {
                    let handle = self.guest_gdi.existing_object(pattern)
                        .or_else(|| self.guest_gdi.allocate_object(pattern));
                    let Some(handle) = handle else { return Ok(0); };
                    handle as i16
                } else { brush.hatch as i16 };
                LogBrush16 { style: brush.style, color: brush.color, hatch }.encode().to_vec()
            }
            Info::Bitmap(bitmap) => Bitmap16 {
                bitmap_type: bitmap.kind, width: bitmap.width, height: bitmap.height,
                width_bytes: bitmap.width_bytes, planes: bitmap.planes, bits_per_pixel: bitmap.bits_per_pixel,
                // A native storage address is not a guest FAR pointer. Bitmap
                // pixel access uses the existing GetBitmapBits/DIB interfaces.
                bits: 0,
            }.encode().to_vec(),
            Info::Palette(entries) => entries.to_le_bytes().to_vec(),
            Info::UnsupportedBrush => {
                host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
                    "GetObject cannot translate this brush's native storage; zero bytes returned"));
                return Ok(0);
            }
        };
        let written = bytes.len().min(count as usize);
        if written == 0 { return Ok(0); }
        let pointer = self.selectors.pointer_from_far(output).map_err(crate::runtime_error)?;
        self.selectors.translate(pointer, Access::Write, written, memory).map_err(crate::runtime_error)?;
        self.selectors.write(memory, pointer, &bytes[..written]).map_err(crate::runtime_error)?;
        Ok(written as u32)
    }
}
