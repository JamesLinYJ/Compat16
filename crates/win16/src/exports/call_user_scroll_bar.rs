//! USER scrollbar export argument decoding.

use super::call::call_helpers::{dword_argument, word_argument};
use super::request::{Win16ApiRequest, Win16UserScrollBarRequest};
use super::Win16ExportId;
use crate::{Win16Argument, Win16Error};

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[Win16Argument],
) -> Result<Win16ApiRequest, Win16Error> {
    let request = match export {
        Win16ExportId::UserSetScrollPos => Win16UserScrollBarRequest::SetPosition {
            window: word_argument(arguments, 0)?,
            bar: word_argument(arguments, 1)? as i16,
            position: word_argument(arguments, 2)? as i16,
            redraw: word_argument(arguments, 3)? != 0,
        },
        Win16ExportId::UserGetScrollPos => Win16UserScrollBarRequest::GetPosition {
            window: word_argument(arguments, 0)?,
            bar: word_argument(arguments, 1)? as i16,
        },
        Win16ExportId::UserSetScrollRange => Win16UserScrollBarRequest::SetRange {
            window: word_argument(arguments, 0)?,
            bar: word_argument(arguments, 1)? as i16,
            minimum: word_argument(arguments, 2)? as i16,
            maximum: word_argument(arguments, 3)? as i16,
            redraw: word_argument(arguments, 4)? != 0,
        },
        Win16ExportId::UserGetScrollRange => Win16UserScrollBarRequest::GetRange {
            window: word_argument(arguments, 0)?,
            bar: word_argument(arguments, 1)? as i16,
            minimum: dword_argument(arguments, 2)?,
            maximum: dword_argument(arguments, 3)?,
        },
        Win16ExportId::UserShowScrollBar => Win16UserScrollBarRequest::Show {
            window: word_argument(arguments, 0)?,
            bar: word_argument(arguments, 1)? as i16,
            show: word_argument(arguments, 2)? != 0,
        },
        Win16ExportId::UserEnableScrollBar => Win16UserScrollBarRequest::Enable {
            window: word_argument(arguments, 0)?,
            bar: word_argument(arguments, 1)? as i16,
            flags: word_argument(arguments, 2)?,
        },
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(Win16ApiRequest::UserScrollBar(request))
}
