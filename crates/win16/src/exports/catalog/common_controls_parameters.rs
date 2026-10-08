//! Known Win16 COMMCTRL stack layouts used by the catalog.

use super::*;

pub(super) const MENU_HELP_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "message", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "w_param", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "l_param", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "status_bar", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "help_id_table", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const EFFECTIVE_CLIENT_RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "control_ids", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const CREATE_STATUS_WINDOW_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "style", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "text", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "parent", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "control_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const CREATE_TOOLBAR_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "parent", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "style", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "control_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bitmap_count", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bitmap_instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bitmap_resource", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "buttons", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "button_count", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const CREATE_MAPPED_BITMAP_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bitmap_resource", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "color_map", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "color_map_count", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const PROFILE_STRUCT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "section", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "key", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "data", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "data_size", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "file_name", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
];

pub(super) const CREATE_HEADER_WINDOW_PARAMETERS: &[Win16Parameter] = CREATE_STATUS_WINDOW_PARAMETERS;

pub(super) const MAKE_DRAG_LIST_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "list_box", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const CREATE_TOOLBAR_EX_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "parent", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "style", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "control_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bitmap_count", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bitmap_instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bitmap_resource", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "buttons", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "button_count", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "button_width", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "button_height", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bitmap_width", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bitmap_height", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "button_struct_size", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
