//! Export decoder arms owned by the User API module group.

use super::*;

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[crate::Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16ApiRequest>, Win16Error> {
    if matches!(descriptor.ordinal(), 499 | 501..=512 | 514..=533) {
        return super::super::call_user_network::decode(
            descriptor.ordinal(), arguments, selectors, memory,
        ).map(|request| request.map(Win16ApiRequest::NetworkRedirector));
    }
    let request = match descriptor.id {
        Win16ExportId::UserSetWindowsHook
        | Win16ExportId::UserCallMsgFilter
        | Win16ExportId::UserUnhookWindowsHook
        | Win16ExportId::UserDefHookProc
        | Win16ExportId::UserSetWindowsHookEx
        | Win16ExportId::UserUnhookWindowsHookEx
        | Win16ExportId::UserCallNextHookEx => {
            return user_hooks_calls::decode(descriptor.id, arguments).map(Some);
        }
        Win16ExportId::UserIsChild => Win16ApiRequest::User(Win16UserRequest::ChildLookup(
            Win16UserChildLookupRequest::IsChild {
                parent: word_argument(arguments, 0)?, child: word_argument(arguments, 1)?,
            })),
        Win16ExportId::UserChildWindowFromPoint => Win16ApiRequest::User(Win16UserRequest::ChildLookup(
            Win16UserChildLookupRequest::ChildWindowFromPoint {
                parent: word_argument(arguments, 0)?, point: dword_argument(arguments, 1)?,
            })),
        Win16ExportId::UserChildWindowFromPointEx => Win16ApiRequest::User(Win16UserRequest::ChildLookup(
            Win16UserChildLookupRequest::ChildWindowFromPointEx {
                parent: word_argument(arguments, 0)?, point: dword_argument(arguments, 1)?,
                flags: word_argument(arguments, 2)?,
            })),
        Win16ExportId::UserDefFrameProc => Win16ApiRequest::User(Win16UserRequest::Mdi(
            Win16UserMdiRequest::DefFrameProc {
                frame: word_argument(arguments, 0)?, mdi_client: word_argument(arguments, 1)?,
                message: word_argument(arguments, 2)?, w_param: word_argument(arguments, 3)?,
                l_param: dword_argument(arguments, 4)?,
            })),
        Win16ExportId::UserDefMDIChildProc => Win16ApiRequest::User(Win16UserRequest::Mdi(
            Win16UserMdiRequest::DefMDIChildProc {
                window: word_argument(arguments, 0)?, message: word_argument(arguments, 1)?,
                w_param: word_argument(arguments, 2)?, l_param: dword_argument(arguments, 3)?,
            })),
        Win16ExportId::UserTranslateMDISysAccel => {
            let pointer = selectors.pointer_from_far(dword_argument(arguments, 1)?)?;
            Win16ApiRequest::User(Win16UserRequest::Mdi(Win16UserMdiRequest::TranslateMDISysAccel {
                mdi_client: word_argument(arguments, 0)?,
                message: crate::user_abi::Msg16::read_from(selectors, memory, pointer)?,
            }))
        }
        Win16ExportId::UserEnumWindows => Win16ApiRequest::WindowEnumeration(
            super::super::Win16WindowEnumerationRequest::Desktop {
                callback: dword_argument(arguments, 0)?, data: dword_argument(arguments, 1)?,
            }),
        Win16ExportId::UserEnumChildWindows => Win16ApiRequest::WindowEnumeration(
            super::super::Win16WindowEnumerationRequest::Children {
                parent: word_argument(arguments, 0)?, callback: dword_argument(arguments, 1)?,
                data: dword_argument(arguments, 2)?,
            }),
        Win16ExportId::UserEnumTaskWindows => Win16ApiRequest::WindowEnumeration(
            super::super::Win16WindowEnumerationRequest::Task {
                task: word_argument(arguments, 0)?, callback: dword_argument(arguments, 1)?,
                data: dword_argument(arguments, 2)?,
            }),
        // USER publishes these palette entrypoints too. They share the GDI
        // request, handle mapping and native behavior; only export identity differs.
        Win16ExportId::UserSelectPalette => Win16ApiRequest::GdiDevice(
            super::super::GdiDeviceRequest::SelectPalette {
                dc: word_argument(arguments, 0)?, palette: word_argument(arguments, 1)?,
                force_background: word_argument(arguments, 2)? != 0,
            },
        ),
        Win16ExportId::UserRealizePalette => Win16ApiRequest::GdiDevice(
            super::super::GdiDeviceRequest::RealizePalette { dc: word_argument(arguments, 0)? },
        ),
        Win16ExportId::UserWvsprintf => {
            super::call_user_string_format::decode_wvsprintf(arguments, selectors, memory)?
        }
        Win16ExportId::UserGetCursor
        | Win16ExportId::UserSetCursor
        | Win16ExportId::UserShowCursor
        | Win16ExportId::UserWinHelp
        | Win16ExportId::UserLoadAccelerators
        | Win16ExportId::UserTranslateAccelerator => {
            user_cursor_accelerator_calls::decode(descriptor.id, arguments, selectors, memory)?
        }
        Win16ExportId::UserSetScrollPos
        | Win16ExportId::UserGetScrollPos
        | Win16ExportId::UserSetScrollRange
        | Win16ExportId::UserGetScrollRange
        | Win16ExportId::UserShowScrollBar
        | Win16ExportId::UserEnableScrollBar => {
            super::super::call_user_scroll_bar::decode(descriptor.id, arguments)?
        }
        Win16ExportId::UserRemoveProp
        | Win16ExportId::UserGetProp
        | Win16ExportId::UserSetProp
        | Win16ExportId::UserEnumProps => {
            call_window_properties::decode(descriptor.id, &arguments, selectors, memory)?
        }
        Win16ExportId::UserGetClassWord
        | Win16ExportId::UserSetClassWord
        | Win16ExportId::UserGetClassLong
        | Win16ExportId::UserSetClassLong => Win16ApiRequest::ClassData(
            class_data::decode_class_data(descriptor.ordinal(), arguments)?,
        ),
        Win16ExportId::UserSetParent
        | Win16ExportId::UserGetWindowWord
        | Win16ExportId::UserSetWindowWord
        | Win16ExportId::UserGetWindowLong
        | Win16ExportId::UserSetWindowLong => Win16ApiRequest::WindowData(
            window_data::decode_window_data(descriptor.ordinal(), &arguments)?,
        ),
        Win16ExportId::UserDestroyIcon | Win16ExportId::UserDestroyCursor => {
            Win16ApiRequest::DestroyImage(decode_destroy_image(descriptor.ordinal(), &arguments)?)
        }
        Win16ExportId::UserAnsiLower => Win16ApiRequest::User(super::Win16UserRequest::Ansi(
            super::Win16UserAnsiRequest::AnsiLower {
                target: ansi_case_target(dword_argument(&arguments, 0)?, selectors, memory)?,
            },
        )),
        Win16ExportId::UserAnsiUpper => Win16ApiRequest::User(super::Win16UserRequest::Ansi(
            super::Win16UserAnsiRequest::AnsiUpper {
                target: ansi_case_target(dword_argument(&arguments, 0)?, selectors, memory)?,
            },
        )),
        Win16ExportId::UserAnsiUpperBuff | Win16ExportId::UserAnsiLowerBuff => {
            Win16ApiRequest::User(super::Win16UserRequest::Ansi(
                super::Win16UserAnsiRequest::AnsiCaseBuffer {
                    pointer: dword_argument(&arguments, 0)?,
                    length: word_argument(&arguments, 1)?,
                    upper: descriptor.id == Win16ExportId::UserAnsiUpperBuff,
                },
            ))
        }
        Win16ExportId::UserAnsiNext => Win16ApiRequest::User(super::Win16UserRequest::Ansi(
            super::Win16UserAnsiRequest::AnsiNext {
                pointer: dword_argument(&arguments, 0)?,
            },
        )),
        Win16ExportId::UserAnsiPrev => Win16ApiRequest::User(super::Win16UserRequest::Ansi(
            super::Win16UserAnsiRequest::AnsiPrev {
                start: dword_argument(&arguments, 0)?,
                current: dword_argument(&arguments, 1)?,
            },
        )),
        Win16ExportId::UserDefWindowProc => Win16ApiRequest::User(
            super::Win16UserRequest::Messages(super::Win16UserMessagesRequest::DefWindowProc {
                window: word_argument(&arguments, 0)?,
                message: word_argument(&arguments, 1)?,
                w_param: word_argument(&arguments, 2)?,
                l_param: dword_argument(&arguments, 3)?,
            }),
        ),
        Win16ExportId::UserPostQuitMessage
        | Win16ExportId::UserGetMessage
        | Win16ExportId::UserPeekMessage
        | Win16ExportId::UserTranslateMessage
        | Win16ExportId::UserDispatchMessage
        | Win16ExportId::UserSetTimer
        | Win16ExportId::UserKillTimer
        | Win16ExportId::UserSetCapture
        | Win16ExportId::UserReleaseCapture
        | Win16ExportId::UserSetFocus
        | Win16ExportId::UserGetFocus
        | Win16ExportId::UserGetCapture
        | Win16ExportId::UserPostMessage
        | Win16ExportId::UserSendMessage
        | Win16ExportId::UserSendDlgItemMessage
        | Win16ExportId::UserWaitMessage
        | Win16ExportId::UserPostAppMessage
        | Win16ExportId::UserGetMessagePos
        | Win16ExportId::UserGetMessageTime
        | Win16ExportId::UserCallWindowProc
        | Win16ExportId::UserGetKeyboardState
        | Win16ExportId::UserSetKeyboardState
        | Win16ExportId::UserGetQueueStatus
        | Win16ExportId::UserGetInputState => {
            user_messages::decode(descriptor.id, &arguments, selectors, memory)?
        }
        Win16ExportId::UserBeginPaint
        | Win16ExportId::UserEndPaint
        | Win16ExportId::UserUpdateWindow
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
        | Win16ExportId::UserScrollWindowEx
        | Win16ExportId::UserGetDc
        | Win16ExportId::UserGetWindowDc
        | Win16ExportId::UserReleaseDc => user_paint_calls::decode(descriptor.id, &arguments)?,
        Win16ExportId::UserFillRect
        | Win16ExportId::UserDrawText
        | Win16ExportId::UserInvertRect
        | Win16ExportId::UserFrameRect
        | Win16ExportId::UserDrawIcon
        | Win16ExportId::UserDrawFocusRect => {
            user_drawing_calls::decode(descriptor.id, &arguments, selectors, memory)?
        }
        Win16ExportId::UserRegisterWindowMessage
        | Win16ExportId::UserRegisterClipboardFormat
        | Win16ExportId::UserGetClipboardFormatName => {
            user_clipboard::decode(descriptor.id, &arguments, selectors, memory)?
        }
        Win16ExportId::UserDialogBox
        | Win16ExportId::UserEndDialog
        | Win16ExportId::UserCreateDialog
        | Win16ExportId::UserIsDialogMessage
        | Win16ExportId::UserGetDlgItem
        | Win16ExportId::UserSetDlgItemText
        | Win16ExportId::UserGetDlgItemText
        | Win16ExportId::UserSetDlgItemInt
        | Win16ExportId::UserGetDlgItemInt
        | Win16ExportId::UserCheckRadioButton
        | Win16ExportId::UserCheckDlgButton
        | Win16ExportId::UserIsDlgButtonChecked
        | Win16ExportId::UserDlgDirSelect
        | Win16ExportId::UserDlgDirList
        | Win16ExportId::UserAdjustWindowRect
        | Win16ExportId::UserMapDialogRect
        | Win16ExportId::UserOpenClipboard
        | Win16ExportId::UserCloseClipboard
        | Win16ExportId::UserEmptyClipboard
        | Win16ExportId::UserGetClipboardOwner
        | Win16ExportId::UserSetClipboardData
        | Win16ExportId::UserGetClipboardData
        | Win16ExportId::UserCountClipboardFormats
        | Win16ExportId::UserEnumClipboardFormats
        | Win16ExportId::UserSetClipboardViewer
        | Win16ExportId::UserGetClipboardViewer
        | Win16ExportId::UserChangeClipboardChain
        | Win16ExportId::UserIsClipboardFormatAvailable
        | Win16ExportId::UserDlgDirSelectComboBox
        | Win16ExportId::UserDlgDirListComboBox
        | Win16ExportId::UserDialogBoxIndirect
        | Win16ExportId::UserCreateDialogIndirect
        | Win16ExportId::UserGetNextDlgGroupItem
        | Win16ExportId::UserGetNextDlgTabItem
        | Win16ExportId::UserDialogBoxParam
        | Win16ExportId::UserDialogBoxIndirectParam
        | Win16ExportId::UserCreateDialogParam
        | Win16ExportId::UserCreateDialogIndirectParam
        | Win16ExportId::UserGetOpenClipboardWindow
        | Win16ExportId::UserGetPriorityClipboardFormat
        | Win16ExportId::UserDlgDirSelectEx
        | Win16ExportId::UserDlgDirSelectComboBoxEx
        | Win16ExportId::UserAdjustWindowRectEx
        | Win16ExportId::UserDefDlgProc
        | Win16ExportId::UserSystemParametersInfo
        | Win16ExportId::UserOldExitWindows
        | Win16ExportId::UserExitWindows
        | Win16ExportId::UserExitWindowsExec => Win16ApiRequest::UserFamily(
            super::super::user_family::decode_user_family(
                descriptor.id.ordinal(),
                &arguments,
                selectors,
                memory,
            )?
            .ok_or(Win16Error::InvalidRange)?,
        ),
        Win16ExportId::UserGetWindowText
        | Win16ExportId::UserSetWindowText
        | Win16ExportId::UserGetWindowTextLength => {
            user_text::decode(descriptor.id, &arguments, selectors, memory)?
        }
        Win16ExportId::UserCreateMenu
        | Win16ExportId::UserDestroyMenu
        | Win16ExportId::UserCheckMenuItem
        | Win16ExportId::UserEnableMenuItem
        | Win16ExportId::UserGetSystemMenu
        | Win16ExportId::UserGetMenu
        | Win16ExportId::UserGetSubMenu
        | Win16ExportId::UserSetMenu
        | Win16ExportId::UserDrawMenuBar
        | Win16ExportId::UserGetMenuString
        | Win16ExportId::UserGetMenuState
        | Win16ExportId::UserGetMenuItemCount
        | Win16ExportId::UserInsertMenu
        | Win16ExportId::UserAppendMenu
        | Win16ExportId::UserRemoveMenu
        | Win16ExportId::UserDeleteMenu
        | Win16ExportId::UserCreatePopupMenu
        | Win16ExportId::UserTrackPopupMenu
        | Win16ExportId::UserLoadMenu
        | Win16ExportId::UserLoadMenuIndirect
        | Win16ExportId::UserChangeMenu
        | Win16ExportId::UserHiliteMenuItem
        | Win16ExportId::UserEndMenu
        | Win16ExportId::UserGetMenuItemID
        | Win16ExportId::UserSetSystemMenu
        | Win16ExportId::UserIsMenu
        | Win16ExportId::UserSetMenuContextHelpId
        | Win16ExportId::UserGetMenuContextHelpId
        | Win16ExportId::UserModifyMenu
        | Win16ExportId::UserGetMenuCheckMarkDimensions
        | Win16ExportId::UserSetMenuItemBitmaps
        | Win16ExportId::UserMakeMenuRToL
        | Win16ExportId::UserGetMenuItemRect
        | Win16ExportId::UserCheckMenuRadioItem => {
            call_menus::decode(descriptor.id, &arguments, selectors, memory)?
        }
        Win16ExportId::UserCloseWindow
        | Win16ExportId::UserArrangeIconicWindows
        | Win16ExportId::UserOpenIcon
        | Win16ExportId::UserIsIconic
        | Win16ExportId::UserGetWindowRect
        | Win16ExportId::UserGetClientRect
        | Win16ExportId::UserEnableWindow
        | Win16ExportId::UserIsWindowEnabled
        | Win16ExportId::UserBringWindowToTop
        | Win16ExportId::UserGetParent
        | Win16ExportId::UserIsWindow
        | Win16ExportId::UserIsWindowVisible
        | Win16ExportId::UserFindWindow
        | Win16ExportId::UserDestroyWindow
        | Win16ExportId::UserMoveWindow
        | Win16ExportId::UserGetClassName
        | Win16ExportId::UserSetActiveWindow
        | Win16ExportId::UserGetActiveWindow
        | Win16ExportId::UserGetTopWindow
        | Win16ExportId::UserGetNextWindow
        | Win16ExportId::UserRegisterClass
        | Win16ExportId::UserUnregisterClass
        | Win16ExportId::UserCreateWindow
        | Win16ExportId::UserCreateWindowEx
        | Win16ExportId::UserShowWindow
        | Win16ExportId::UserGetClassInfo
        | Win16ExportId::UserSetRect
        | Win16ExportId::UserSetRectEmpty
        | Win16ExportId::UserCopyRect
        | Win16ExportId::UserUnionRect
        | Win16ExportId::UserEqualRect
        | Win16ExportId::UserSubtractRect
        | Win16ExportId::UserIsRectEmpty
        | Win16ExportId::UserPtInRect
        | Win16ExportId::UserOffsetRect
        | Win16ExportId::UserInflateRect
        | Win16ExportId::UserIntersectRect
        | Win16ExportId::UserSetWindowPos
        | Win16ExportId::UserGetWindow
        | Win16ExportId::UserShowOwnedPopups
        | Win16ExportId::UserIsZoomed
        | Win16ExportId::UserGetDlgCtrlID
        | Win16ExportId::UserGetDesktopWindow
        | Win16ExportId::UserGetLastActivePopup
        | Win16ExportId::UserClientToScreen
        | Win16ExportId::UserGetClipCursor
        | Win16ExportId::UserGetCursorPos
        | Win16ExportId::UserCreateCaret
        | Win16ExportId::UserDestroyCaret
        | Win16ExportId::UserSetCaretPos
        | Win16ExportId::UserHideCaret
        | Win16ExportId::UserShowCaret
        | Win16ExportId::UserGetCaretPos
        | Win16ExportId::UserGetWindowPlacement
        | Win16ExportId::UserSetWindowPlacement
        | Win16ExportId::UserScreenToClient
        | Win16ExportId::UserMapWindowPoints
        | Win16ExportId::UserWindowFromPoint => {
            call_window_ops::decode(descriptor.id, &arguments, selectors, memory)?
        }
        Win16ExportId::UserGetTickCount
        | Win16ExportId::UserWNetGetCaps
        | Win16ExportId::UserGetCurrentTime
        | Win16ExportId::UserMessageBeep
        | Win16ExportId::UserGetKeyState
        | Win16ExportId::UserGetSystemMetrics
        | Win16ExportId::UserGetAsyncKeyState
        | Win16ExportId::UserSetMessageQueue => {
            user_system_calls::decode(descriptor.id, &arguments)?
        }
        Win16ExportId::UserMessageBox
        | Win16ExportId::UserInitApp
        | Win16ExportId::UserLoadString
        | Win16ExportId::UserLoadCursor
        | Win16ExportId::UserLoadBitmap
        | Win16ExportId::UserCreateIcon
        | Win16ExportId::UserCreateCursor
        | Win16ExportId::UserLoadIcon => {
            user_resource_calls::decode(descriptor.id, &arguments, selectors, memory)?
        }
        Win16ExportId::UserGlobalAddAtom
        | Win16ExportId::UserGlobalDeleteAtom
        | Win16ExportId::UserGlobalFindAtom
        | Win16ExportId::UserGlobalGetAtomName => {
            user_atom_calls::decode(descriptor.id, &arguments, selectors, memory)?
        }
        Win16ExportId::UserLstrcmp | Win16ExportId::UserLstrcmpi => Win16ApiRequest::Libraries(
            super::Win16LibraryRequest::Strings(super::Win16LibraryStringsRequest::StringCompare {
                left: read_far_string(dword_argument(&arguments, 0)?, selectors, memory)?,
                right: read_far_string(dword_argument(&arguments, 1)?, selectors, memory)?,
                comparison: match descriptor.id {
                    Win16ExportId::KernelReserved5 => Win16StringComparison::Binary,
                    Win16ExportId::UserLstrcmp => Win16StringComparison::Linguistic,
                    Win16ExportId::UserLstrcmpi => Win16StringComparison::LinguisticIgnoreCase,
                    _ => unreachable!("string comparison arm contains only comparison exports"),
                },
            }),
        ),
        Win16ExportId::UserSetDoubleClickTime
        | Win16ExportId::UserGetDoubleClickTime
        | Win16ExportId::UserSetCaretBlinkTime
        | Win16ExportId::UserGetCaretBlinkTime
        | Win16ExportId::UserGetSysColor
        | Win16ExportId::UserGetDialogBaseUnits => {
            win16_service_calls::decode(descriptor.id, &arguments, selectors, memory)?
        }
        _ => return Ok(None),
    };
    Ok(Some(request))
}

#[cfg(test)]
#[path = "call_class_data_tests.rs"]
mod class_data_tests;

#[cfg(test)]
#[path = "call_unregister_class_tests.rs"]
mod unregister_class_tests;

#[cfg(test)]
#[path = "call_child_lookup_tests.rs"]
mod child_lookup_tests;

#[cfg(test)]
#[path = "call_set_window_pos_tests.rs"]
mod set_window_pos_tests;
