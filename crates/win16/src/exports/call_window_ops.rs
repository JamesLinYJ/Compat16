//! Decoder for Win16 USER window and geometry API calls.

use super::{
    Win16ApiRequest, Win16ClassName, Win16ExportId, Win16ResourceName, dword_argument,
    read_far_string, read_nullable_far_string, word_argument,
};
use crate::{SelectorTable, Win16Argument, Win16Error};
use guest_core::GuestMemory;

pub(super) fn decode(
    id: Win16ExportId,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    let request = match id {
        Win16ExportId::UserCreateCaret => Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::CreateCaret {
                window: word_argument(arguments, 0)?,
                bitmap: word_argument(arguments, 1)?,
                width: word_argument(arguments, 2)? as i16,
                height: word_argument(arguments, 3)? as i16,
            }),
        ),
        Win16ExportId::UserDestroyCaret => Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::DestroyCaret),
        ),
        Win16ExportId::UserSetCaretPos => Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::SetCaretPos {
                x: word_argument(arguments, 0)? as i16,
                y: word_argument(arguments, 1)? as i16,
            }),
        ),
        Win16ExportId::UserHideCaret | Win16ExportId::UserShowCaret => {
            let window = word_argument(arguments, 0)?;
            let request = if id == Win16ExportId::UserHideCaret {
                super::Win16UserWindowRequest::HideCaret { window }
            } else {
                super::Win16UserWindowRequest::ShowCaret { window }
            };
            Win16ApiRequest::User(super::Win16UserRequest::Window(request))
        }
        Win16ExportId::UserGetCaretPos => Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::GetCaretPos {
                point: dword_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::UserGetWindowPlacement | Win16ExportId::UserSetWindowPlacement => {
            let window = word_argument(arguments, 0)?;
            let placement = dword_argument(arguments, 1)?;
            let request = if id == Win16ExportId::UserGetWindowPlacement {
                super::Win16UserGeometryRequest::GetWindowPlacement { window, placement }
            } else {
                super::Win16UserGeometryRequest::SetWindowPlacement { window, placement }
            };
            Win16ApiRequest::User(super::Win16UserRequest::Geometry(request))
        }
        Win16ExportId::UserGetCursorPos => Win16ApiRequest::User(
            super::Win16UserRequest::Geometry(super::Win16UserGeometryRequest::GetCursorPos {
                point: dword_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::UserIsIconic => Win16ApiRequest::User(super::Win16UserRequest::Window(
            super::Win16UserWindowRequest::IsIconic {
                window: word_argument(arguments, 0)?,
            },
        )),
        Win16ExportId::UserGetWindowRect | Win16ExportId::UserGetClientRect => {
            let window = word_argument(arguments, 0)?;
            let rect = dword_argument(arguments, 1)?;
            if id == Win16ExportId::UserGetWindowRect {
                Win16ApiRequest::User(super::Win16UserRequest::Geometry(
                    super::Win16UserGeometryRequest::GetWindowRect { window, rect },
                ))
            } else {
                Win16ApiRequest::User(super::Win16UserRequest::Geometry(
                    super::Win16UserGeometryRequest::GetClientRect { window, rect },
                ))
            }
        }
        Win16ExportId::UserUnregisterClass => {
            let far_name = dword_argument(arguments, 0)?;
            let class_name = if far_name >> 16 == 0 {
                Win16ClassName::Atom(far_name as u16)
            } else {
                Win16ClassName::Name(read_far_string(far_name, selectors, memory)?)
            };
            Win16ApiRequest::User(super::Win16UserRequest::Window(
                super::Win16UserWindowRequest::UnregisterClass {
                    class_name, instance: word_argument(arguments, 1)?,
                },
            ))
        }
        Win16ExportId::UserRegisterClass => {
            let far_class = dword_argument(arguments, 0)?;
            let window_class = crate::user_abi::WndClass16::read_from(
                selectors,
                memory,
                selectors.pointer_from_far(far_class)?,
            )?;
            let class_name = if window_class.lpsz_class_name >> 16 == 0 {
                Win16ClassName::Atom(window_class.lpsz_class_name as u16)
            } else {
                Win16ClassName::Name(read_far_string(
                    window_class.lpsz_class_name,
                    selectors,
                    memory,
                )?)
            };
            let menu_name = if window_class.lpsz_menu_name == 0 {
                None
            } else if window_class.lpsz_menu_name >> 16 == 0 {
                Some(Win16ResourceName::Id(window_class.lpsz_menu_name as u16))
            } else {
                Some(Win16ResourceName::Name(read_far_string(
                    window_class.lpsz_menu_name,
                    selectors,
                    memory,
                )?))
            };
            Win16ApiRequest::User(super::Win16UserRequest::Window(
                super::Win16UserWindowRequest::RegisterClass {
                    window_class,
                    class_name,
                    menu_name,
                },
            ))
        }
        Win16ExportId::UserCreateWindow | Win16ExportId::UserCreateWindowEx => {
            let offset = if id == Win16ExportId::UserCreateWindowEx {
                1
            } else {
                0
            };
            let ex_style = if offset == 1 {
                dword_argument(arguments, 0)?
            } else {
                0
            };
            let far_class_name = dword_argument(arguments, offset)?;
            let class_name = if far_class_name >> 16 == 0 {
                Win16ClassName::Atom(far_class_name as u16)
            } else {
                Win16ClassName::Name(read_far_string(far_class_name, selectors, memory)?)
            };
            Win16ApiRequest::User(super::Win16UserRequest::Window(
                super::Win16UserWindowRequest::CreateWindow {
                    class_name,
                    window_name: read_nullable_far_string(
                        dword_argument(arguments, offset + 1)?,
                        selectors,
                        memory,
                    )?,
                    ex_style,
                    style: dword_argument(arguments, offset + 2)?,
                    x: word_argument(arguments, offset + 3)? as i16,
                    y: word_argument(arguments, offset + 4)? as i16,
                    width: word_argument(arguments, offset + 5)? as i16,
                    height: word_argument(arguments, offset + 6)? as i16,
                    parent: word_argument(arguments, offset + 7)?,
                    menu: word_argument(arguments, offset + 8)?,
                    instance: word_argument(arguments, offset + 9)?,
                    parameter: dword_argument(arguments, offset + 10)?,
                },
            ))
        }
        Win16ExportId::UserShowWindow => Win16ApiRequest::User(super::Win16UserRequest::Window(
            super::Win16UserWindowRequest::ShowWindow {
                window: word_argument(arguments, 0)?,
                command: word_argument(arguments, 1)? as i16,
            },
        )),
        Win16ExportId::UserGetClassInfo => {
            let instance = word_argument(arguments, 0)?;
            let far_class_name = dword_argument(arguments, 1)?;
            let class_name = if far_class_name >> 16 == 0 {
                Win16ClassName::Atom(far_class_name as u16)
            } else {
                Win16ClassName::Name(read_far_string(far_class_name, selectors, memory)?)
            };
            Win16ApiRequest::User(super::Win16UserRequest::Window(
                super::Win16UserWindowRequest::GetClassInfo {
                    instance,
                    class_name,
                    class_info: dword_argument(arguments, 2)?,
                },
            ))
        }
        Win16ExportId::UserEnableWindow => Win16ApiRequest::User(super::Win16UserRequest::Window(
            super::Win16UserWindowRequest::EnableWindow {
                window: word_argument(arguments, 0)?,
                enable: word_argument(arguments, 1)?,
            },
        )),
        Win16ExportId::UserIsWindowEnabled => Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::IsWindowEnabled {
                window: word_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::UserBringWindowToTop => Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::BringWindowToTop {
                window: word_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::UserGetParent => Win16ApiRequest::User(super::Win16UserRequest::Window(
            super::Win16UserWindowRequest::GetParent {
                window: word_argument(arguments, 0)?,
            },
        )),
        Win16ExportId::UserIsWindow => Win16ApiRequest::User(super::Win16UserRequest::Window(
            super::Win16UserWindowRequest::IsWindow {
                window: word_argument(arguments, 0)?,
            },
        )),
        Win16ExportId::UserIsWindowVisible => Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::IsWindowVisible {
                window: word_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::UserFindWindow => {
            let class_far = dword_argument(arguments, 0)?;
            let class_name = if class_far == 0 {
                None
            } else if class_far >> 16 == 0 {
                Some(Win16ClassName::Atom(class_far as u16))
            } else {
                Some(Win16ClassName::Name(read_far_string(
                    class_far, selectors, memory,
                )?))
            };
            Win16ApiRequest::User(super::Win16UserRequest::Window(
                super::Win16UserWindowRequest::FindWindow {
                    class_name,
                    window_name: read_nullable_far_string(
                        dword_argument(arguments, 1)?,
                        selectors,
                        memory,
                    )?,
                },
            ))
        }
        Win16ExportId::UserDestroyWindow => Win16ApiRequest::User(super::Win16UserRequest::Window(
            super::Win16UserWindowRequest::DestroyWindow {
                window: word_argument(arguments, 0)?,
            },
        )),
        Win16ExportId::UserMoveWindow => Win16ApiRequest::User(super::Win16UserRequest::Geometry(
            super::Win16UserGeometryRequest::MoveWindow {
                window: word_argument(arguments, 0)?,
                x: word_argument(arguments, 1)? as i16,
                y: word_argument(arguments, 2)? as i16,
                width: word_argument(arguments, 3)? as i16,
                height: word_argument(arguments, 4)? as i16,
                repaint: word_argument(arguments, 5)?,
            },
        )),
        Win16ExportId::UserGetClassName => Win16ApiRequest::User(super::Win16UserRequest::Window(
            super::Win16UserWindowRequest::GetClassName {
                window: word_argument(arguments, 0)?,
                output: dword_argument(arguments, 1)?,
                capacity: word_argument(arguments, 2)? as i16,
            },
        )),
        Win16ExportId::UserSetActiveWindow => Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::SetActiveWindow {
                window: word_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::UserGetActiveWindow => Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::GetActiveWindow),
        ),
        Win16ExportId::UserGetWindow => Win16ApiRequest::User(super::Win16UserRequest::Window(
            super::Win16UserWindowRequest::GetWindow {
                window: word_argument(arguments, 0)?,
                command: word_argument(arguments, 1)?,
            },
        )),
        Win16ExportId::UserGetTopWindow => Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::GetTopWindow {
                window: word_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::UserGetNextWindow => Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::GetNextWindow {
                window: word_argument(arguments, 0)?,
                direction: word_argument(arguments, 1)?,
            }),
        ),
        Win16ExportId::UserShowOwnedPopups => Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::ShowOwnedPopups {
                window: word_argument(arguments, 0)?,
                show: word_argument(arguments, 1)?,
            }),
        ),
        Win16ExportId::UserIsZoomed => Win16ApiRequest::User(super::Win16UserRequest::Window(
            super::Win16UserWindowRequest::IsZoomed {
                window: word_argument(arguments, 0)?,
            },
        )),
        Win16ExportId::UserGetDlgCtrlID => Win16ApiRequest::User(super::Win16UserRequest::Window(
            super::Win16UserWindowRequest::GetDlgCtrlID {
                window: word_argument(arguments, 0)?,
            },
        )),
        Win16ExportId::UserGetDesktopWindow => Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::GetDesktopWindow),
        ),
        Win16ExportId::UserGetLastActivePopup => Win16ApiRequest::User(
            super::Win16UserRequest::Window(super::Win16UserWindowRequest::GetLastActivePopup {
                window: word_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::UserClientToScreen => Win16ApiRequest::User(
            super::Win16UserRequest::Geometry(super::Win16UserGeometryRequest::ClientToScreen {
                window: word_argument(arguments, 0)?,
                point: dword_argument(arguments, 1)?,
            }),
        ),
        Win16ExportId::UserScreenToClient => Win16ApiRequest::User(
            super::Win16UserRequest::Geometry(super::Win16UserGeometryRequest::ScreenToClient {
                window: word_argument(arguments, 0)?,
                point: dword_argument(arguments, 1)?,
            }),
        ),
        Win16ExportId::UserMapWindowPoints => Win16ApiRequest::User(
            super::Win16UserRequest::Geometry(super::Win16UserGeometryRequest::MapWindowPoints {
                from: word_argument(arguments, 0)?,
                to: word_argument(arguments, 1)?,
                points: dword_argument(arguments, 2)?,
                count: word_argument(arguments, 3)?,
            }),
        ),
        Win16ExportId::UserWindowFromPoint => {
            let (x, y) = unpack_point(dword_argument(arguments, 0)?);
            Win16ApiRequest::User(super::Win16UserRequest::Geometry(
                super::Win16UserGeometryRequest::WindowFromPoint { x, y },
            ))
        }
        Win16ExportId::UserSetWindowPos => Win16ApiRequest::User(
            super::Win16UserRequest::Geometry(super::Win16UserGeometryRequest::SetWindowPos {
                window: word_argument(arguments, 0)?,
                insert_after: word_argument(arguments, 1)?,
                x: word_argument(arguments, 2)? as i16,
                y: word_argument(arguments, 3)? as i16,
                width: word_argument(arguments, 4)? as i16,
                height: word_argument(arguments, 5)? as i16,
                flags: word_argument(arguments, 6)?,
            }),
        ),
        Win16ExportId::UserSetRect => Win16ApiRequest::User(super::Win16UserRequest::Geometry(
            super::Win16UserGeometryRequest::SetRect {
                rect: dword_argument(arguments, 0)?,
                left: word_argument(arguments, 1)? as i16,
                top: word_argument(arguments, 2)? as i16,
                right: word_argument(arguments, 3)? as i16,
                bottom: word_argument(arguments, 4)? as i16,
            },
        )),
        Win16ExportId::UserIsRectEmpty => Win16ApiRequest::User(super::Win16UserRequest::Geometry(
            super::Win16UserGeometryRequest::IsRectEmpty {
                rect: dword_argument(arguments, 0)?,
            },
        )),
        Win16ExportId::UserSetRectEmpty => Win16ApiRequest::User(super::Win16UserRequest::Geometry(
            super::Win16UserGeometryRequest::SetRectEmpty { rect: dword_argument(arguments, 0)? },
        )),
        Win16ExportId::UserCopyRect => Win16ApiRequest::User(super::Win16UserRequest::Geometry(
            super::Win16UserGeometryRequest::CopyRect {
                destination: dword_argument(arguments, 0)?, source: dword_argument(arguments, 1)?,
            },
        )),
        Win16ExportId::UserUnionRect => Win16ApiRequest::User(super::Win16UserRequest::Geometry(
            super::Win16UserGeometryRequest::UnionRect {
                destination: dword_argument(arguments, 0)?,
                source1: dword_argument(arguments, 1)?, source2: dword_argument(arguments, 2)?,
            },
        )),
        Win16ExportId::UserEqualRect => Win16ApiRequest::User(super::Win16UserRequest::Geometry(
            super::Win16UserGeometryRequest::EqualRect {
                source1: dword_argument(arguments, 0)?, source2: dword_argument(arguments, 1)?,
            },
        )),
        Win16ExportId::UserSubtractRect => Win16ApiRequest::User(super::Win16UserRequest::Geometry(
            super::Win16UserGeometryRequest::SubtractRect {
                destination: dword_argument(arguments, 0)?,
                source1: dword_argument(arguments, 1)?, source2: dword_argument(arguments, 2)?,
            },
        )),
        Win16ExportId::UserPtInRect => {
            let (x, y) = unpack_point(dword_argument(arguments, 1)?);
            Win16ApiRequest::User(super::Win16UserRequest::Geometry(
                super::Win16UserGeometryRequest::PtInRect {
                    rect: dword_argument(arguments, 0)?,
                    x,
                    y,
                },
            ))
        }
        Win16ExportId::UserOffsetRect => Win16ApiRequest::User(super::Win16UserRequest::Geometry(
            super::Win16UserGeometryRequest::OffsetRect {
                rect: dword_argument(arguments, 0)?,
                x: word_argument(arguments, 1)? as i16,
                y: word_argument(arguments, 2)? as i16,
            },
        )),
        Win16ExportId::UserInflateRect => Win16ApiRequest::User(super::Win16UserRequest::Geometry(
            super::Win16UserGeometryRequest::InflateRect {
                rect: dword_argument(arguments, 0)?,
                x: word_argument(arguments, 1)? as i16,
                y: word_argument(arguments, 2)? as i16,
            },
        )),
        Win16ExportId::UserIntersectRect => Win16ApiRequest::User(
            super::Win16UserRequest::Geometry(super::Win16UserGeometryRequest::IntersectRect {
                destination: dword_argument(arguments, 0)?,
                source1: dword_argument(arguments, 1)?,
                source2: dword_argument(arguments, 2)?,
            }),
        ),
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(request)
}

fn unpack_point(packed: u32) -> (i16, i16) {
    (packed as u16 as i16, (packed >> 16) as u16 as i16)
}
