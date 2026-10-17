//! Stack argument decoding for the USER message-queue ABI group.

use super::super::Win16ExportId;
use super::super::request::Win16ApiRequest;
use super::{dword_argument, word_argument};
use crate::{SelectorTable, Win16Error};
use guest_core::GuestMemory;

pub(super) fn decode(
    export: Win16ExportId,
    arguments: &[crate::Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    match export {
        Win16ExportId::UserPostQuitMessage => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Messages(super::Win16UserMessagesRequest::PostQuitMessage {
                exit_code: word_argument(arguments, 0)?,
            }),
        )),
        Win16ExportId::UserGetMessage => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Messages(super::Win16UserMessagesRequest::GetMessage {
                output: dword_argument(arguments, 0)?,
                window: word_argument(arguments, 1)?,
                min_message: word_argument(arguments, 2)?,
                max_message: word_argument(arguments, 3)?,
            }),
        )),
        Win16ExportId::UserPeekMessage => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Messages(super::Win16UserMessagesRequest::PeekMessage {
                output: dword_argument(arguments, 0)?,
                window: word_argument(arguments, 1)?,
                min_message: word_argument(arguments, 2)?,
                max_message: word_argument(arguments, 3)?,
                flags: word_argument(arguments, 4)?,
            }),
        )),
        Win16ExportId::UserTranslateMessage | Win16ExportId::UserDispatchMessage => {
            let raw_message = dword_argument(arguments, 0)?;
            let pointer = selectors.pointer_from_far(raw_message)?;
            let message = crate::user_abi::Msg16::read_from(selectors, memory, pointer)?;
            if export == Win16ExportId::UserTranslateMessage {
                Ok(Win16ApiRequest::User(super::Win16UserRequest::Messages(
                    super::Win16UserMessagesRequest::TranslateMessage { message },
                )))
            } else {
                Ok(Win16ApiRequest::User(super::Win16UserRequest::Messages(
                    super::Win16UserMessagesRequest::DispatchMessage { message },
                )))
            }
        }
        Win16ExportId::UserSetTimer => Ok(Win16ApiRequest::User(super::Win16UserRequest::Window(
            super::Win16UserWindowRequest::SetTimer {
                window: word_argument(arguments, 0)?,
                timer_id: word_argument(arguments, 1)?,
                interval: word_argument(arguments, 2)?,
                callback: dword_argument(arguments, 3)?,
            },
        ))),
        Win16ExportId::UserKillTimer => Ok(Win16ApiRequest::User(super::Win16UserRequest::Window(
            super::Win16UserWindowRequest::KillTimer {
                window: word_argument(arguments, 0)?,
                timer_id: word_argument(arguments, 1)?,
            },
        ))),
        Win16ExportId::UserSetSystemTimer => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::SetSystemTimer {
                window: word_argument(arguments, 0)?,
                timer_id: word_argument(arguments, 1)?,
                interval: word_argument(arguments, 2)?,
                callback: dword_argument(arguments, 3)?,
            }),
        )),
        Win16ExportId::UserKillSystemTimer => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::KillSystemTimer {
                window: word_argument(arguments, 0)?,
                timer_id: word_argument(arguments, 1)?,
            }),
        )),
        Win16ExportId::UserSetCapture => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::SetCapture {
                window: word_argument(arguments, 0)?,
            }),
        )),
        Win16ExportId::UserReleaseCapture => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::ReleaseCapture),
        )),
        Win16ExportId::UserSetFocus => Ok(Win16ApiRequest::User(super::Win16UserRequest::Window(
            super::Win16UserWindowRequest::SetFocus {
                window: word_argument(arguments, 0)?,
            },
        ))),
        Win16ExportId::UserGetFocus => Ok(Win16ApiRequest::User(super::Win16UserRequest::Window(
            super::Win16UserWindowRequest::GetFocus,
        ))),
        Win16ExportId::UserGetCapture => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::GetCapture),
        )),
        Win16ExportId::UserWaitMessage => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Messages(super::Win16UserMessagesRequest::WaitMessage),
        )),
        Win16ExportId::UserGetMessagePos => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Messages(super::Win16UserMessagesRequest::GetMessagePos),
        )),
        Win16ExportId::UserGetMessageTime => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Messages(super::Win16UserMessagesRequest::GetMessageTime),
        )),
        Win16ExportId::UserGetMessageExtraInfo => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Messages(super::Win16UserMessagesRequest::GetMessageExtraInfo),
        )),
        Win16ExportId::UserInSendMessage => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Messages(super::Win16UserMessagesRequest::InSendMessage),
        )),
        Win16ExportId::UserQuerySendMessage => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Messages(super::Win16UserMessagesRequest::QuerySendMessage {
                message: dword_argument(arguments, 3)?,
            }),
        )),
        Win16ExportId::UserReplyMessage => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Messages(super::Win16UserMessagesRequest::ReplyMessage {
                result: dword_argument(arguments, 0)? as i32,
            }),
        )),
        Win16ExportId::UserGetInputState => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Messages(super::Win16UserMessagesRequest::GetInputState),
        )),
        Win16ExportId::UserPostMessage | Win16ExportId::UserSendMessage => {
            let window = word_argument(arguments, 0)?;
            let message = word_argument(arguments, 1)?;
            let w_param = word_argument(arguments, 2)?;
            let l_param = dword_argument(arguments, 3)?;
            if export == Win16ExportId::UserPostMessage {
                Ok(Win16ApiRequest::User(super::Win16UserRequest::Messages(
                    super::Win16UserMessagesRequest::PostMessage {
                        window,
                        message,
                        w_param,
                        l_param,
                    },
                )))
            } else {
                Ok(Win16ApiRequest::User(super::Win16UserRequest::Messages(
                    super::Win16UserMessagesRequest::SendMessage {
                        window,
                        message,
                        w_param,
                        l_param,
                    },
                )))
            }
        }
        Win16ExportId::UserSendDlgItemMessage => {
            Ok(Win16ApiRequest::User(super::Win16UserRequest::Messages(
                super::Win16UserMessagesRequest::SendDlgItemMessage {
                    dialog: word_argument(arguments, 0)?,
                    id: word_argument(arguments, 1)?,
                    message: word_argument(arguments, 2)?,
                    w_param: word_argument(arguments, 3)?,
                    l_param: dword_argument(arguments, 4)?,
                },
            )))
        }
        Win16ExportId::UserPostAppMessage => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Messages(super::Win16UserMessagesRequest::PostAppMessage {
                task: word_argument(arguments, 0)?,
                message: word_argument(arguments, 1)?,
                w_param: word_argument(arguments, 2)?,
                l_param: dword_argument(arguments, 3)?,
            }),
        )),
        Win16ExportId::UserCallWindowProc => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Messages(super::Win16UserMessagesRequest::CallWindowProc {
                procedure: dword_argument(arguments, 0)?,
                window: word_argument(arguments, 1)?,
                message: word_argument(arguments, 2)?,
                w_param: word_argument(arguments, 3)?,
                l_param: dword_argument(arguments, 4)?,
            }),
        )),
        Win16ExportId::UserGetKeyboardState => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Messages(super::Win16UserMessagesRequest::GetKeyboardState {
                output: dword_argument(arguments, 0)?,
            }),
        )),
        Win16ExportId::UserSetKeyboardState => {
            let bytes = super::gdi_calls::read_exact_bytes(
                dword_argument(arguments, 0)?,
                256,
                selectors,
                memory,
            )?;
            let mut state = [0_u8; 256];
            state.copy_from_slice(&bytes);
            Ok(Win16ApiRequest::User(super::Win16UserRequest::Messages(
                super::Win16UserMessagesRequest::SetKeyboardState { state },
            )))
        }
        Win16ExportId::UserGetQueueStatus => Ok(Win16ApiRequest::User(
            super::Win16UserRequest::Messages(super::Win16UserMessagesRequest::GetQueueStatus {
                flags: word_argument(arguments, 0)?,
            }),
        )),
        _ => Err(Win16Error::InvalidRange),
    }
}
