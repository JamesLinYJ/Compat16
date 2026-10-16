//! Stack decoding for Win16 GDI object-creation requests.

use super::super::request::Win16ApiRequest;
use super::{Win16ExportId, gdi_calls};
use super::{dword_argument, read_nullable_far_string, word_argument};
use crate::gdi_abi::{Bitmap16, LogBrush16, LogFont16, LogPen16};
use crate::{SelectorTable, Win16Argument, Win16Error};
use guest_core::GuestMemory;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    let request = match export {
        Win16ExportId::GdiCreatePen => {
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::CreatePen {
                style: word_argument(arguments, 0)? as i16,
                width: word_argument(arguments, 1)? as i16,
                color: dword_argument(arguments, 2)?,
            })
        }
        Win16ExportId::GdiCreatePenIndirect => {
            let bytes = gdi_calls::read_exact_bytes(
                dword_argument(arguments, 0)?,
                LogPen16::SIZE,
                selectors,
                memory,
            )?;
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::CreatePenIndirect {
                logpen: LogPen16::decode(&bytes).map_err(|_| Win16Error::InvalidRange)?,
            })
        }
        Win16ExportId::GdiCreateFont => {
            Win16ApiRequest::GdiText(super::Win16GdiTextRequest::CreateFont {
                height: word_argument(arguments, 0)? as i16,
                width: word_argument(arguments, 1)? as i16,
                escapement: word_argument(arguments, 2)? as i16,
                orientation: word_argument(arguments, 3)? as i16,
                weight: word_argument(arguments, 4)? as i16,
                italic: word_argument(arguments, 5)?,
                underline: word_argument(arguments, 6)?,
                strikeout: word_argument(arguments, 7)?,
                char_set: word_argument(arguments, 8)?,
                out_precision: word_argument(arguments, 9)?,
                clip_precision: word_argument(arguments, 10)?,
                quality: word_argument(arguments, 11)?,
                pitch_and_family: word_argument(arguments, 12)?,
                face_name: read_nullable_far_string(
                    dword_argument(arguments, 13)?,
                    selectors,
                    memory,
                )?,
            })
        }
        Win16ExportId::GdiCreateFontIndirect => {
            let bytes = gdi_calls::read_exact_bytes(
                dword_argument(arguments, 0)?,
                LogFont16::SIZE,
                selectors,
                memory,
            )?;
            Win16ApiRequest::GdiText(super::Win16GdiTextRequest::CreateFontIndirect {
                logfont: LogFont16::decode(&bytes).map_err(|_| Win16Error::InvalidRange)?,
            })
        }
        Win16ExportId::GdiCreateBitmap => {
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::CreateBitmap {
                width: word_argument(arguments, 0)? as i16,
                height: word_argument(arguments, 1)? as i16,
                planes: word_argument(arguments, 2)?,
                bits_per_pixel: word_argument(arguments, 3)?,
                bits: dword_argument(arguments, 4)?,
            })
        }
        Win16ExportId::GdiCreateBitmapIndirect => {
            let bytes = gdi_calls::read_exact_bytes(
                dword_argument(arguments, 0)?,
                Bitmap16::SIZE,
                selectors,
                memory,
            )?;
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::CreateBitmapIndirect {
                bitmap: Bitmap16::decode(&bytes).map_err(|_| Win16Error::InvalidRange)?,
            })
        }
        // Normalize the direct factories to the existing checked brush route.
        // `hatch` remains a guest scalar/handle: runtime resolves bitmap tokens
        // or snapshots HGLOBAL DIB data before invoking native GDI.
        Win16ExportId::GdiCreateHatchBrush
        | Win16ExportId::GdiCreatePatternBrush
        | Win16ExportId::GdiCreateDibPatternBrush => {
            let (style, color) = match export {
                Win16ExportId::GdiCreateHatchBrush => (2, dword_argument(arguments, 1)?),
                Win16ExportId::GdiCreatePatternBrush => (3, 0),
                Win16ExportId::GdiCreateDibPatternBrush => (5, u32::from(word_argument(arguments, 1)?)),
                _ => unreachable!(),
            };
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::CreateBrushIndirect {
                logbrush: LogBrush16 { style, color, hatch: word_argument(arguments, 0)? as i16 },
            })
        }
        Win16ExportId::GdiCreateBrushIndirect => {
            let bytes = gdi_calls::read_exact_bytes(
                dword_argument(arguments, 0)?,
                LogBrush16::SIZE,
                selectors,
                memory,
            )?;
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::CreateBrushIndirect {
                logbrush: LogBrush16::decode(&bytes).map_err(|_| Win16Error::InvalidRange)?,
            })
        }
        Win16ExportId::GdiCreateCompatibleBitmap => {
            Win16ApiRequest::GdiObjects(super::Win16GdiObjectsRequest::CreateCompatibleBitmap {
                dc: word_argument(arguments, 0)?,
                width: word_argument(arguments, 1)? as i16,
                height: word_argument(arguments, 2)? as i16,
            })
        }
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(request)
}
