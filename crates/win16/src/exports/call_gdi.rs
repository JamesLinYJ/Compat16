//! Stack argument decoding for GDI drawing and device-information exports.

use super::super::Win16ExportId;
use super::super::request::Win16ApiRequest;
use super::{dword_argument, read_nullable_far_string, word_argument};
use crate::{SelectorTable, Win16Error};
use guest_core::GuestMemory;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[crate::Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    let request = match export {
        Win16ExportId::GdiCreateMetaFile => Win16ApiRequest::GdiObjects(
            super::Win16GdiObjectsRequest::CreateMetaFile {
                path: read_nullable_far_string(dword_argument(arguments, 0)?, selectors, memory)?,
            }),
        Win16ExportId::GdiCloseMetaFile => Win16ApiRequest::GdiObjects(
            super::Win16GdiObjectsRequest::CloseMetaFile { dc: word_argument(arguments, 0)? }),
        Win16ExportId::GdiGetMetaFile => {
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::GetMetaFile {
                path: super::read_far_string(dword_argument(arguments, 0)?, selectors, memory)?,
            })
        }
        Win16ExportId::GdiPlayMetaFile => {
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::PlayMetaFile {
                dc: word_argument(arguments, 0)?,
                metafile: word_argument(arguments, 1)?,
            })
        }
        Win16ExportId::GdiCopyMetaFile => {
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::CopyMetaFile {
                metafile: word_argument(arguments, 0)?,
                path: read_nullable_far_string(dword_argument(arguments, 1)?, selectors, memory)?,
            })
        }
        Win16ExportId::GdiDeleteMetaFile => {
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::DeleteMetaFile {
                metafile: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiEnumObjects => {
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::EnumObjects {
                dc: word_argument(arguments, 0)?,
                object_type: word_argument(arguments, 1)? as i16,
                callback: dword_argument(arguments, 2)?,
                parameter: dword_argument(arguments, 3)? as i32,
            })
        }
        Win16ExportId::GdiGetObject => Win16ApiRequest::GdiDevice(super::super::GdiDeviceRequest::GetObject {
            object: word_argument(arguments, 0)?, count: word_argument(arguments, 1)? as i16,
            output: dword_argument(arguments, 2)?,
        }),
        Win16ExportId::GdiCreateCompatibleDc => {
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::CreateCompatibleDc {
                source: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiDeleteDc => {
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::DeleteDc {
                dc: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiDeleteObject => {
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::DeleteObject {
                object: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiUnrealizeObject => {
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::UnrealizeObject {
                object: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiGetDeviceCaps => {
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::GetDeviceCaps {
                dc: word_argument(arguments, 0)?,
                index: word_argument(arguments, 1)? as i16,
            })
        }
        Win16ExportId::GdiGetMetaFileBits => {
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::GetMetaFileBits {
                metafile: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiSetMetaFileBits => {
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::SetMetaFileBits {
                bits: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiSetMetaFileBitsBetter => {
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::SetMetaFileBitsBetter {
                bits: word_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiGetStockObject => {
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::GetStockObject {
                index: word_argument(arguments, 0)? as i16,
            })
        }
        Win16ExportId::GdiEnumFonts => {
            Win16ApiRequest::GdiText(super::Win16GdiTextRequest::EnumFonts {
                dc: word_argument(arguments, 0)?,
                face_name: read_nullable_far_string(
                    dword_argument(arguments, 1)?,
                    selectors,
                    memory,
                )?,
                callback: dword_argument(arguments, 2)?,
                parameter: dword_argument(arguments, 3)? as i32,
            })
        }
        Win16ExportId::GdiEnumFontFamilies => {
            Win16ApiRequest::GdiText(super::Win16GdiTextRequest::EnumFontFamilies {
                dc: word_argument(arguments, 0)?,
                face_name: read_nullable_far_string(
                    dword_argument(arguments, 1)?,
                    selectors,
                    memory,
                )?,
                callback: dword_argument(arguments, 2)?,
                parameter: dword_argument(arguments, 3)? as i32,
            })
        }
        Win16ExportId::GdiMulDiv => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::MulDiv {
                multiplicand: word_argument(arguments, 0)? as i16,
                multiplier: word_argument(arguments, 1)? as i16,
                divisor: word_argument(arguments, 2)? as i16,
            })
        }
        Win16ExportId::GdiLineDda => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::LineDda {
                x_start: word_argument(arguments, 0)? as i16,
                y_start: word_argument(arguments, 1)? as i16,
                x_end: word_argument(arguments, 2)? as i16,
                y_end: word_argument(arguments, 3)? as i16,
                callback: dword_argument(arguments, 4)?,
                data: dword_argument(arguments, 5)?,
            })
        }
        Win16ExportId::GdiSelectObject => {
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::SelectObject {
                dc: word_argument(arguments, 0)?,
                object: word_argument(arguments, 1)?,
            })
        }
        Win16ExportId::GdiSetBkColor => {
            Win16ApiRequest::GdiText(super::Win16GdiTextRequest::SetBkColor {
                dc: word_argument(arguments, 0)?,
                color: dword_argument(arguments, 1)?,
            })
        }
        Win16ExportId::GdiSetBkMode => {
            Win16ApiRequest::GdiText(super::Win16GdiTextRequest::SetBkMode {
                dc: word_argument(arguments, 0)?,
                mode: word_argument(arguments, 1)? as i16,
            })
        }
        Win16ExportId::GdiSetMapMode => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::SetMapMode {
                dc: word_argument(arguments, 0)?,
                mode: word_argument(arguments, 1)? as i16,
            })
        }
        Win16ExportId::GdiSetRop2 => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::SetRop2 {
                dc: word_argument(arguments, 0)?,
                mode: word_argument(arguments, 1)? as i16,
            })
        }
        Win16ExportId::GdiSetTextColor => {
            Win16ApiRequest::GdiText(super::Win16GdiTextRequest::SetTextColor {
                dc: word_argument(arguments, 0)?,
                color: dword_argument(arguments, 1)?,
            })
        }
        Win16ExportId::GdiLineTo => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::LineTo {
                dc: word_argument(arguments, 0)?,
                x: word_argument(arguments, 1)? as i16,
                y: word_argument(arguments, 2)? as i16,
            })
        }
        Win16ExportId::GdiMoveTo => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::MoveTo {
                dc: word_argument(arguments, 0)?,
                x: word_argument(arguments, 1)? as i16,
                y: word_argument(arguments, 2)? as i16,
            })
        }
        Win16ExportId::GdiRectangle => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::Rectangle {
                dc: word_argument(arguments, 0)?,
                left: word_argument(arguments, 1)? as i16,
                top: word_argument(arguments, 2)? as i16,
                right: word_argument(arguments, 3)? as i16,
                bottom: word_argument(arguments, 4)? as i16,
            })
        }
        Win16ExportId::GdiTextOut => {
            let count = word_argument(arguments, 4)? as i16;
            let text = read_counted_bytes(dword_argument(arguments, 3)?, count, selectors, memory)?;
            Win16ApiRequest::GdiText(super::Win16GdiTextRequest::TextOut {
                dc: word_argument(arguments, 0)?,
                x: word_argument(arguments, 1)? as i16,
                y: word_argument(arguments, 2)? as i16,
                text,
                count,
            })
        }
        Win16ExportId::GdiBitBlt => {
            Win16ApiRequest::GdiDrawing(super::Win16GdiDrawingRequest::BitBlt {
                destination: word_argument(arguments, 0)?,
                destination_x: word_argument(arguments, 1)? as i16,
                destination_y: word_argument(arguments, 2)? as i16,
                width: word_argument(arguments, 3)? as i16,
                height: word_argument(arguments, 4)? as i16,
                source: word_argument(arguments, 5)?,
                source_x: word_argument(arguments, 6)? as i16,
                source_y: word_argument(arguments, 7)? as i16,
                rop: dword_argument(arguments, 8)?,
            })
        }
        Win16ExportId::GdiCreateSolidBrush => {
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::CreateSolidBrush {
                color: dword_argument(arguments, 0)?,
            })
        }
        Win16ExportId::GdiGetTextExtent => {
            let count = word_argument(arguments, 2)? as i16;
            let text = read_counted_bytes(dword_argument(arguments, 1)?, count, selectors, memory)?;
            Win16ApiRequest::GdiText(super::Win16GdiTextRequest::GetTextExtent {
                dc: word_argument(arguments, 0)?,
                text,
                count,
            })
        }
        Win16ExportId::GdiCreateDc | Win16ExportId::GdiCreateIc => {
            let driver =
                read_nullable_far_string(dword_argument(arguments, 0)?, selectors, memory)?;
            let device =
                read_nullable_far_string(dword_argument(arguments, 1)?, selectors, memory)?;
            let output =
                read_nullable_far_string(dword_argument(arguments, 2)?, selectors, memory)?;
            let init_data = dword_argument(arguments, 3)?;
            if export == Win16ExportId::GdiCreateDc {
                Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::CreateDc {
                    driver,
                    device,
                    output,
                    init_data,
                })
            } else {
                Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::CreateIc {
                    driver,
                    device,
                    output,
                    init_data,
                })
            }
        }
        Win16ExportId::GdiGetOutlineTextMetrics => {
            Win16ApiRequest::GdiText(super::Win16GdiTextRequest::GetOutlineTextMetrics {
                dc: word_argument(arguments, 0)?,
                count: word_argument(arguments, 1)?,
                output: dword_argument(arguments, 2)?,
            })
        }
        Win16ExportId::GdiGetTextMetrics => {
            Win16ApiRequest::GdiText(super::Win16GdiTextRequest::GetTextMetrics {
                dc: word_argument(arguments, 0)?,
                output: dword_argument(arguments, 1)?,
            })
        }
        Win16ExportId::GdiGetTextFace => {
            Win16ApiRequest::GdiText(super::Win16GdiTextRequest::GetTextFace {
                dc: word_argument(arguments, 0)?,
                count: word_argument(arguments, 1)? as i16,
                output: dword_argument(arguments, 2)?,
            })
        }
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(request)
}

fn read_counted_bytes(
    far: u32,
    signed_count: i16,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    if signed_count <= 0 {
        return Ok(Vec::new());
    }
    read_exact_bytes(
        far,
        usize::try_from(signed_count).map_err(|_| Win16Error::InvalidRange)?,
        selectors,
        memory,
    )
}

pub(super) fn read_exact_bytes(
    far: u32,
    count: usize,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Vec<u8>, Win16Error> {
    let mut pointer = selectors.pointer_from_far(far)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(count)
        .map_err(|_| Win16Error::OutOfMemory)?;
    bytes.resize(count, 0);
    let mut remaining = count;
    let mut output_offset = 0usize;
    while remaining > 0 {
        let descriptor = selectors.describe(pointer.selector())?;
        let bytes_in_segment = descriptor
            .limit
            .checked_sub(u32::from(pointer.offset()))
            .and_then(|length| length.checked_add(1))
            .and_then(|length| usize::try_from(length).ok())
            .ok_or(Win16Error::InvalidRange)?;
        let chunk = remaining.min(bytes_in_segment);
        if chunk == 0 {
            return Err(Win16Error::InvalidRange);
        }
        let end = output_offset
            .checked_add(chunk)
            .ok_or(Win16Error::InvalidRange)?;
        selectors.read(memory, pointer, &mut bytes[output_offset..end])?;
        remaining -= chunk;
        output_offset = end;
        if remaining > 0 {
            pointer = selectors.add_bytes(
                pointer,
                u32::try_from(chunk).map_err(|_| Win16Error::InvalidRange)?,
            )?;
        }
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "call_enum_font_families_tests.rs"]
mod enum_font_families_tests;

#[cfg(test)]
#[path = "call_get_outline_text_metrics_tests.rs"]
mod outline_text_metrics_tests;
