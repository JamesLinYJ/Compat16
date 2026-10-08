//! Decoder for Win16 USER menu API calls.

use super::{Win16ApiRequest, Win16ExportId, dword_argument, read_far_string, word_argument};
use crate::{SelectorTable, Win16Argument, Win16Error, Win16ResourceName};
use guest_core::GuestMemory;

pub(super) fn decode(
    id: Win16ExportId,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    let request = match id {
        Win16ExportId::UserCreateMenu => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::CreateMenu,
        )),
        Win16ExportId::UserCreatePopupMenu => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::CreatePopupMenu,
        )),
        Win16ExportId::UserLoadMenu => {
            let raw_name = dword_argument(arguments, 1)?;
            let name = if raw_name >> 16 == 0 {
                Win16ResourceName::Id(raw_name as u16)
            } else {
                Win16ResourceName::Name(read_far_string(raw_name, selectors, memory)?)
            };
            Win16ApiRequest::User(super::Win16UserRequest::Menu(
                super::Win16UserMenuRequest::LoadMenu {
                    instance: word_argument(arguments, 0)?,
                    name,
                },
            ))
        }
        Win16ExportId::UserLoadMenuIndirect => Win16ApiRequest::User(
            super::Win16UserRequest::Menu(super::Win16UserMenuRequest::LoadMenuIndirect {
                template: dword_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::UserChangeMenu => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::ChangeMenu {
                menu: word_argument(arguments, 0)?,
                position: word_argument(arguments, 1)?,
                new_item: dword_argument(arguments, 2)?,
                item_id: word_argument(arguments, 3)?,
                flags: word_argument(arguments, 4)?,
            },
        )),
        Win16ExportId::UserHiliteMenuItem => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::HiliteMenuItem {
                window: word_argument(arguments, 0)?,
                menu: word_argument(arguments, 1)?,
                item: word_argument(arguments, 2)?,
                flags: word_argument(arguments, 3)?,
            },
        )),
        Win16ExportId::UserEndMenu => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::EndMenu,
        )),
        Win16ExportId::UserDestroyMenu => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::DestroyMenu {
                menu: word_argument(arguments, 0)?,
            },
        )),
        Win16ExportId::UserCheckMenuItem => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::CheckMenuItem {
                menu: word_argument(arguments, 0)?,
                item: word_argument(arguments, 1)?,
                flags: word_argument(arguments, 2)?,
            },
        )),
        Win16ExportId::UserEnableMenuItem => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::EnableMenuItem {
                menu: word_argument(arguments, 0)?,
                item: word_argument(arguments, 1)?,
                flags: word_argument(arguments, 2)?,
            },
        )),
        Win16ExportId::UserGetSystemMenu => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::GetSystemMenu {
                window: word_argument(arguments, 0)?,
                revert: word_argument(arguments, 1)?,
            },
        )),
        Win16ExportId::UserGetMenu => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::GetMenu {
                window: word_argument(arguments, 0)?,
            },
        )),
        Win16ExportId::UserGetSubMenu => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::GetSubMenu {
                menu: word_argument(arguments, 0)?,
                position: word_argument(arguments, 1)? as i16,
            },
        )),
        Win16ExportId::UserSetMenu => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::SetMenu {
                window: word_argument(arguments, 0)?,
                menu: word_argument(arguments, 1)?,
            },
        )),
        Win16ExportId::UserDrawMenuBar => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::DrawMenuBar {
                window: word_argument(arguments, 0)?,
            },
        )),
        Win16ExportId::UserGetMenuString => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::GetMenuString {
                menu: word_argument(arguments, 0)?,
                item: word_argument(arguments, 1)?,
                output: dword_argument(arguments, 2)?,
                capacity: word_argument(arguments, 3)? as i16,
                flags: word_argument(arguments, 4)?,
            },
        )),
        Win16ExportId::UserGetMenuState => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::GetMenuState {
                menu: word_argument(arguments, 0)?,
                item: word_argument(arguments, 1)?,
                flags: word_argument(arguments, 2)?,
            },
        )),
        Win16ExportId::UserGetMenuItemCount => Win16ApiRequest::User(
            super::Win16UserRequest::Menu(super::Win16UserMenuRequest::GetMenuItemCount {
                menu: word_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::UserGetMenuItemID => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::GetMenuItemID {
                menu: word_argument(arguments, 0)?,
                position: word_argument(arguments, 1)? as i16,
            },
        )),
        Win16ExportId::UserSetSystemMenu => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::SetSystemMenu {
                window: word_argument(arguments, 0)?,
                menu: word_argument(arguments, 1)?,
            },
        )),
        Win16ExportId::UserIsMenu => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::IsMenu {
                menu: word_argument(arguments, 0)?,
            },
        )),
        Win16ExportId::UserSetMenuContextHelpId => Win16ApiRequest::User(
            super::Win16UserRequest::Menu(super::Win16UserMenuRequest::SetMenuContextHelpId {
                menu: word_argument(arguments, 0)?,
                help_id: word_argument(arguments, 1)?,
            }),
        ),
        Win16ExportId::UserGetMenuContextHelpId => Win16ApiRequest::User(
            super::Win16UserRequest::Menu(super::Win16UserMenuRequest::GetMenuContextHelpId {
                menu: word_argument(arguments, 0)?,
            }),
        ),
        Win16ExportId::UserInsertMenu => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::InsertMenu {
                menu: word_argument(arguments, 0)?,
                position: word_argument(arguments, 1)?,
                flags: word_argument(arguments, 2)?,
                item_id: word_argument(arguments, 3)?,
                new_item: dword_argument(arguments, 4)?,
            },
        )),
        Win16ExportId::UserAppendMenu => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::AppendMenu {
                menu: word_argument(arguments, 0)?,
                flags: word_argument(arguments, 1)?,
                item_id: word_argument(arguments, 2)?,
                new_item: dword_argument(arguments, 3)?,
            },
        )),
        Win16ExportId::UserRemoveMenu => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::RemoveMenu {
                menu: word_argument(arguments, 0)?,
                item: word_argument(arguments, 1)?,
                flags: word_argument(arguments, 2)?,
            },
        )),
        Win16ExportId::UserDeleteMenu => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::DeleteMenu {
                menu: word_argument(arguments, 0)?,
                item: word_argument(arguments, 1)?,
                flags: word_argument(arguments, 2)?,
            },
        )),
        Win16ExportId::UserModifyMenu => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::ModifyMenu {
                menu: word_argument(arguments, 0)?,
                position: word_argument(arguments, 1)?,
                flags: word_argument(arguments, 2)?,
                item_id: word_argument(arguments, 3)?,
                new_item: dword_argument(arguments, 4)?,
            },
        )),
        Win16ExportId::UserGetMenuCheckMarkDimensions => Win16ApiRequest::User(
            super::Win16UserRequest::Menu(super::Win16UserMenuRequest::GetMenuCheckMarkDimensions),
        ),
        Win16ExportId::UserSetMenuItemBitmaps => Win16ApiRequest::User(
            super::Win16UserRequest::Menu(super::Win16UserMenuRequest::SetMenuItemBitmaps {
                menu: word_argument(arguments, 0)?,
                position: word_argument(arguments, 1)?,
                flags: word_argument(arguments, 2)?,
                unchecked: word_argument(arguments, 3)?,
                checked: word_argument(arguments, 4)?,
            }),
        ),
        Win16ExportId::UserMakeMenuRToL => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::MakeMenuRToL {
                menu: word_argument(arguments, 0)?,
                flags: word_argument(arguments, 1)?,
            },
        )),
        Win16ExportId::UserGetMenuItemRect => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::GetMenuItemRect {
                window: word_argument(arguments, 0)?,
                menu: word_argument(arguments, 1)?,
                item: word_argument(arguments, 2)?,
                rect: dword_argument(arguments, 3)?,
            },
        )),
        Win16ExportId::UserCheckMenuRadioItem => Win16ApiRequest::User(
            super::Win16UserRequest::Menu(super::Win16UserMenuRequest::CheckMenuRadioItem {
                menu: word_argument(arguments, 0)?,
                first: word_argument(arguments, 1)?,
                last: word_argument(arguments, 2)?,
                check: word_argument(arguments, 3)?,
                by_position: word_argument(arguments, 4)?,
            }),
        ),
        Win16ExportId::UserTrackPopupMenu => Win16ApiRequest::User(super::Win16UserRequest::Menu(
            super::Win16UserMenuRequest::TrackPopupMenu {
                menu: word_argument(arguments, 0)?,
                flags: word_argument(arguments, 1)?,
                x: word_argument(arguments, 2)? as i16,
                y: word_argument(arguments, 3)? as i16,
                reserved: word_argument(arguments, 4)? as i16,
                window: word_argument(arguments, 5)?,
                rect: dword_argument(arguments, 6)?,
            },
        )),
        _ => return Err(Win16Error::InvalidRange),
    };
    Ok(request)
}
