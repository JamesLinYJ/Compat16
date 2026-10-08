//! USER rectangle, icon, and text drawing guest argument decoding.

use super::super::request::Win16ApiRequest;
use super::{Win16ExportId, dword_argument, gdi_calls, read_far_string, word_argument};
use crate::window_geometry::Rect16;
use crate::{SelectorTable, Win16Argument, Win16Error};
use guest_core::GuestMemory;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    match export {
        Win16ExportId::UserInvertRect => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Drawing(super::Win16UserDrawingRequest::InvertRect {
                dc: word_argument(arguments, 0)?,
                rect: read_optional_rect(dword_argument(arguments, 1)?, selectors, memory)?,
            }),
        )),
        Win16ExportId::UserFrameRect => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Drawing(super::Win16UserDrawingRequest::FrameRect {
                dc: word_argument(arguments, 0)?,
                rect: read_optional_rect(dword_argument(arguments, 1)?, selectors, memory)?,
                brush: word_argument(arguments, 2)?,
            }),
        )),
        Win16ExportId::UserDrawIcon => Ok(Win16ApiRequest::User(super::Win16UserRequest::Drawing(
            super::Win16UserDrawingRequest::DrawIcon {
                dc: word_argument(arguments, 0)?,
                x: word_argument(arguments, 1)? as i16,
                y: word_argument(arguments, 2)? as i16,
                icon: word_argument(arguments, 3)?,
            },
        ))),
        Win16ExportId::UserDrawFocusRect => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Drawing(super::Win16UserDrawingRequest::DrawFocusRect {
                dc: word_argument(arguments, 0)?,
                rect: read_optional_rect(dword_argument(arguments, 1)?, selectors, memory)?,
            }),
        )),
        Win16ExportId::UserFillRect => Ok(Win16ApiRequest::User(super::Win16UserRequest::Drawing(
            super::Win16UserDrawingRequest::FillRect {
                dc: word_argument(arguments, 0)?,
                rect: read_optional_rect(dword_argument(arguments, 1)?, selectors, memory)?,
                brush: word_argument(arguments, 2)?,
            },
        ))),
        Win16ExportId::UserDrawText => {
            let text_far = dword_argument(arguments, 1)?;
            let count = word_argument(arguments, 2)? as i16;
            let text = match count {
                -1 => read_far_string(text_far, selectors, memory)?,
                value if value > 0 => gdi_calls::read_exact_bytes(
                    text_far,
                    usize::try_from(value).map_err(|_| Win16Error::InvalidRange)?,
                    selectors,
                    memory,
                )?,
                _ => Vec::new(),
            };
            let rect_output = dword_argument(arguments, 3)?;
            Ok(Win16ApiRequest::User(super::Win16UserRequest::Drawing(
                super::Win16UserDrawingRequest::DrawText {
                    dc: word_argument(arguments, 0)?,
                    text,
                    count,
                    rect: read_optional_rect(rect_output, selectors, memory)?,
                    rect_output,
                    flags: word_argument(arguments, 4)?,
                },
            )))
        }
        _ => Err(Win16Error::InvalidRange),
    }
}

fn read_optional_rect(
    far: u32,
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Rect16>, Win16Error> {
    if far == 0 {
        return Ok(None);
    }
    let bytes = gdi_calls::read_exact_bytes(far, Rect16::SIZE, selectors, memory)?;
    let bytes: [u8; Rect16::SIZE] = bytes.try_into().map_err(|_| Win16Error::InvalidRange)?;
    Ok(Some(Rect16::decode(&bytes)))
}
