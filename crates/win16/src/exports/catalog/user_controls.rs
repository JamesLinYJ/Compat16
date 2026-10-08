//! Typed USER dialog/control, clipboard, and system-parameter signatures.

use super::*;

pub(super) const USER_DIALOG_RESOURCE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "template", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::ResourceName },
    Win16Parameter { name: "owner", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "procedure", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::FarPointer },
];

pub(super) const USER_DIALOG_END_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dialog", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "result", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_DIALOG_IS_MESSAGE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dialog", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "message", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const USER_DIALOG_CONTROL_ID_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dialog", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "item_id", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_DIALOG_ITEM_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dialog", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "item_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_DIALOG_SET_TEXT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dialog", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "item_id", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "text", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
];

pub(super) const USER_DIALOG_GET_TEXT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dialog", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "item_id", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_DIALOG_SET_INTEGER_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dialog", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "item_id", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "value", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "signed", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_DIALOG_GET_INTEGER_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dialog", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "item_id", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "translated_output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "signed", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_DIALOG_RADIO_BUTTON_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dialog", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "first_item_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "last_item_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "checked_item_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_DIALOG_CHECK_BUTTON_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dialog", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "item_id", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "check_state", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_DIALOG_DIRECTORY_SELECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dialog", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "control_id", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_DIALOG_DIRECTORY_SELECT_EX_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dialog", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "control_id", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_DIALOG_DIRECTORY_LIST_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dialog", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "path_spec", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "list_id", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "path_id", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "file_type", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_ADJUST_WINDOW_RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "style", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "has_menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_MAP_DIALOG_RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dialog", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const USER_CLIPBOARD_OWNER_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "owner", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD,
}];

pub(super) const USER_CLIPBOARD_SET_DATA_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "format", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "global_handle", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_CLIPBOARD_FORMAT_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "format", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD,
}];

pub(super) const USER_CLIPBOARD_PREVIOUS_FORMAT_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "previous_format", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD,
}];

pub(super) const USER_CLIPBOARD_VIEWER_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "viewer", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD,
}];

pub(super) const USER_CLIPBOARD_CHAIN_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "remove_window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "next_window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_CLIPBOARD_PRIORITY_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "formats", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_DIALOG_INDIRECT_GLOBAL_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "template_handle", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "owner", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "procedure", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::FarPointer },
];

pub(super) const USER_DIALOG_INDIRECT_FAR_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "template", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "owner", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "procedure", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::FarPointer },
];

pub(super) const USER_DIALOG_RESOURCE_PARAM_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "template", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::ResourceName },
    Win16Parameter { name: "owner", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "procedure", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::FarPointer },
    Win16Parameter { name: "init_parameter", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const USER_DIALOG_INDIRECT_GLOBAL_PARAM_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "template_handle", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "owner", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "procedure", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::FarPointer },
    Win16Parameter { name: "init_parameter", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const USER_DIALOG_INDIRECT_FAR_PARAM_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "template", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "owner", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "procedure", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::FarPointer },
    Win16Parameter { name: "init_parameter", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const USER_NEXT_DIALOG_ITEM_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dialog", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "control", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "previous", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_ADJUST_WINDOW_RECT_EX_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "style", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "has_menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "extended_style", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const USER_SYSTEM_PARAMETERS_INFO_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "action", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "param", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "data", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
