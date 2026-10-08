//! Project-owned USER menu export parameter signatures.
//!
//! Win16 slot widths and prototypes follow the Windows 3.1 SDK Programmer's
//! Reference, Volume 2. The `new_item` values for AppendMenu and InsertMenu
//! remain raw because MF_STRING, MF_POPUP, MF_BITMAP, MF_OWNERDRAW and
//! MF_SEPARATOR assign different meanings to the same stack slot.

use super::*;

pub(super) const USER_MENU_HANDLE_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "menu",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const USER_MENU_WINDOW_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "window",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const USER_DESTROY_MENU_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "menu",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const USER_CHECK_MENU_ITEM_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "item", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_ENABLE_MENU_ITEM_PARAMETERS: &[Win16Parameter] =
    USER_CHECK_MENU_ITEM_PARAMETERS;

pub(super) const USER_GET_SYSTEM_MENU_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "revert", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_SET_MENU_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_GET_SUB_MENU_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "position", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_GET_MENU_STRING_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "item", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_GET_MENU_STATE_PARAMETERS: &[Win16Parameter] =
    USER_CHECK_MENU_ITEM_PARAMETERS;

pub(super) const USER_MENU_ITEM_COUNT_PARAMETERS: &[Win16Parameter] =
    USER_MENU_HANDLE_PARAMETERS;

pub(super) const USER_INSERT_MENU_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "position", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "item_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "new_item", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const USER_APPEND_MENU_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "item_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "new_item", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const USER_REMOVE_MENU_PARAMETERS: &[Win16Parameter] =
    USER_CHECK_MENU_ITEM_PARAMETERS;

pub(super) const USER_DELETE_MENU_PARAMETERS: &[Win16Parameter] =
    USER_CHECK_MENU_ITEM_PARAMETERS;

pub(super) const USER_TRACK_POPUP_MENU_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "reserved", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const USER_LOAD_MENU_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "name", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::ResourceName },
];

pub(super) const USER_LOAD_MENU_INDIRECT_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "template", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER,
}];

pub(super) const USER_CHANGE_MENU_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "position", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "new_item", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "item_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_HILITE_MENU_ITEM_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "item", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_GET_MENU_ITEM_ID_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "position", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_SET_SYSTEM_MENU_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_MENU_CONTEXT_HELP_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "help_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_MODIFY_MENU_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "position", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "item_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "new_item", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const USER_SET_MENU_ITEM_BITMAPS_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "position", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "unchecked", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "checked", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_MENU_HANDLE_FLAGS_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_GET_MENU_ITEM_RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "item", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const USER_MENU_RADIO_ITEM_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "first", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "last", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "check", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "by_position", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
