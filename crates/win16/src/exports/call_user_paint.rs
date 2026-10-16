//! USER paint and update-region request decoding boundaries.

use super::super::request::{Win16ApiRequest, Win16UserUpdateRequest};
use super::{Win16ExportId, dword_argument, word_argument};
use crate::{Win16Argument, Win16Error};

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[Win16Argument],
) -> Result<Win16ApiRequest, Win16Error> {
    match export {
        Win16ExportId::UserUpdateWindow
        | Win16ExportId::UserInvalidateRect
        | Win16ExportId::UserInvalidateRgn
        | Win16ExportId::UserValidateRect
        | Win16ExportId::UserValidateRgn
        | Win16ExportId::UserGetUpdateRect
        | Win16ExportId::UserGetUpdateRgn
        | Win16ExportId::UserExcludeUpdateRgn
        | Win16ExportId::UserRedrawWindow
        | Win16ExportId::UserLockWindowUpdate
        | Win16ExportId::UserScrollWindow
        | Win16ExportId::UserScrollDC
        | Win16ExportId::UserScrollWindowEx => decode_update(export, arguments),
        Win16ExportId::UserBeginPaint | Win16ExportId::UserEndPaint => {
            let window = word_argument(arguments, 0)?;
            let paint = dword_argument(arguments, 1)?;
            if export == Win16ExportId::UserBeginPaint {
                Ok(Win16ApiRequest::User(super::Win16UserRequest::Window(
                    super::Win16UserWindowRequest::BeginPaint { window, paint },
                )))
            } else {
                Ok(Win16ApiRequest::User(super::Win16UserRequest::Window(
                    super::Win16UserWindowRequest::EndPaint { window, paint },
                )))
            }
        }
        Win16ExportId::UserGetDc => Ok(Win16ApiRequest::User(super::Win16UserRequest::Window(
            super::Win16UserWindowRequest::GetDc {
                window: word_argument(arguments, 0)?,
            },
        ))),
        Win16ExportId::UserGetWindowDc => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::GetWindowDc {
                window: word_argument(arguments, 0)?,
            }),
        )),
        Win16ExportId::UserGetDcEx => Ok(Win16ApiRequest::User(super::Win16UserRequest::Window(
            super::Win16UserWindowRequest::GetDcEx {
                window: word_argument(arguments, 0)?,
                region: word_argument(arguments, 1)?,
                flags: dword_argument(arguments, 2)?,
            },
        ))),
        Win16ExportId::UserReleaseDc => Ok(Win16ApiRequest::User(super::Win16UserRequest::Window(
            super::Win16UserWindowRequest::ReleaseDc {
                window: word_argument(arguments, 0)?,
                dc: word_argument(arguments, 1)?,
            },
        ))),
        _ => Err(Win16Error::InvalidRange),
    }
}

fn decode_update(
    export: Win16ExportId,
    arguments: &[Win16Argument],
) -> Result<Win16ApiRequest, Win16Error> {
    let request = match export {
        Win16ExportId::UserUpdateWindow => Win16UserUpdateRequest::UpdateWindow {
            window: word_argument(arguments, 0)?,
        },
        Win16ExportId::UserInvalidateRect => Win16UserUpdateRequest::InvalidateRect {
            window: word_argument(arguments, 0)?,
            rect: dword_argument(arguments, 1)?,
            erase: word_argument(arguments, 2)?,
        },
        Win16ExportId::UserInvalidateRgn => Win16UserUpdateRequest::InvalidateRgn {
            window: word_argument(arguments, 0)?,
            region: word_argument(arguments, 1)?,
            erase: word_argument(arguments, 2)?,
        },
        Win16ExportId::UserValidateRect => Win16UserUpdateRequest::ValidateRect {
            window: word_argument(arguments, 0)?,
            rect: dword_argument(arguments, 1)?,
        },
        Win16ExportId::UserValidateRgn => Win16UserUpdateRequest::ValidateRgn {
            window: word_argument(arguments, 0)?,
            region: word_argument(arguments, 1)?,
        },
        Win16ExportId::UserGetUpdateRect => Win16UserUpdateRequest::GetUpdateRect {
            window: word_argument(arguments, 0)?,
            rect: dword_argument(arguments, 1)?,
            erase: word_argument(arguments, 2)?,
        },
        Win16ExportId::UserGetUpdateRgn => Win16UserUpdateRequest::GetUpdateRgn {
            window: word_argument(arguments, 0)?,
            region: word_argument(arguments, 1)?,
            erase: word_argument(arguments, 2)?,
        },
        Win16ExportId::UserExcludeUpdateRgn => Win16UserUpdateRequest::ExcludeUpdateRgn {
            dc: word_argument(arguments, 0)?,
            window: word_argument(arguments, 1)?,
        },
        Win16ExportId::UserRedrawWindow => Win16UserUpdateRequest::RedrawWindow {
            window: word_argument(arguments, 0)?,
            rect: dword_argument(arguments, 1)?,
            region: word_argument(arguments, 2)?,
            flags: word_argument(arguments, 3)?,
        },
        Win16ExportId::UserLockWindowUpdate => Win16UserUpdateRequest::LockWindowUpdate {
            window: word_argument(arguments, 0)?,
        },
        Win16ExportId::UserScrollWindow => Win16UserUpdateRequest::ScrollWindow {
            window: word_argument(arguments, 0)?,
            dx: word_argument(arguments, 1)? as i16,
            dy: word_argument(arguments, 2)? as i16,
            scroll_rect: dword_argument(arguments, 3)?,
            clip_rect: dword_argument(arguments, 4)?,
        },
        Win16ExportId::UserScrollDC => Win16UserUpdateRequest::ScrollDC {
            dc: word_argument(arguments, 0)?,
            dx: word_argument(arguments, 1)? as i16,
            dy: word_argument(arguments, 2)? as i16,
            scroll_rect: dword_argument(arguments, 3)?,
            clip_rect: dword_argument(arguments, 4)?,
            update_region: word_argument(arguments, 5)?,
            update_rect: dword_argument(arguments, 6)?,
        },
        Win16ExportId::UserScrollWindowEx => Win16UserUpdateRequest::ScrollWindowEx {
            window: word_argument(arguments, 0)?,
            dx: word_argument(arguments, 1)? as i16,
            dy: word_argument(arguments, 2)? as i16,
            scroll_rect: dword_argument(arguments, 3)?,
            clip_rect: dword_argument(arguments, 4)?,
            update_region: word_argument(arguments, 5)?,
            update_rect: dword_argument(arguments, 6)?,
            flags: word_argument(arguments, 7)?,
        },
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(Win16ApiRequest::UserUpdate(request))
}

#[cfg(test)]
#[path = "call_scroll_dc_tests.rs"]
mod scroll_dc_tests;
