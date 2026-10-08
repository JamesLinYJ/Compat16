//! Project-owned USER parameter signatures for the export catalog.
//! The catalog is the production declaration source.

use super::*;

pub(super) const USER_CREATE_ICON_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "planes", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bits_per_pixel", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "and_mask", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "xor_mask", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const USER_CREATE_CURSOR_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "x_hotspot", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y_hotspot", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "and_mask", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "xor_mask", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];
pub(super) const USER_PROPERTY_NAME_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "name", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::AtomName },
];

/// Fixed prefix shared by USER.420's CDECL variable argument frame.
pub(super) const USER_WSPRINTF_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "format", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
];

/// USER.421 is Pascal with a FAR pointer to Win16 word-aligned values.
pub(super) const USER_WVSPRINTF_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "format", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "arguments", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const USER_SET_PROPERTY_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "name", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::AtomName },
    Win16Parameter { name: "data", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_ENUM_PROPERTIES_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "callback", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::FarPointer },
];

pub(super) const MESSAGE_BOX_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "owner", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "text", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "caption", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "style", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_KEY_STATE_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "virtual_key",
    kind: ArgumentKind::Word,
    parameter_type: SIGNED_SCALAR,
}];

pub(super) const USER_ANSI_LOWER_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "string_or_char",
    kind: ArgumentKind::Dword,
    parameter_type: FAR_STRING_OR_CHAR,
}];

pub(super) const USER_STRING_COMPARE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "left", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "right", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
];

pub(super) const USER_ANSI_CASE_BUFFER_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "buffer", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "length", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_ANSI_NEXT_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "pointer",
    kind: ArgumentKind::Dword,
    parameter_type: SCALAR_DWORD,
}];

pub(super) const USER_ANSI_PREV_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "start", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "current", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const USER_WINDOW_MESSAGE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "message", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "w_param", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "l_param", kind: ArgumentKind::Dword, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_POST_QUIT_MESSAGE_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "exit_code",
    kind: ArgumentKind::Word,
    parameter_type: SIGNED_SCALAR,
}];

pub(super) const USER_GET_MESSAGE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "message", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "min_message", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "max_message", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_PEEK_MESSAGE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "message", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "min_message", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "max_message", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "remove", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_MESSAGE_POINTER_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "message",
    kind: ArgumentKind::Dword,
    parameter_type: FAR_BUFFER,
}];

pub(super) const USER_FORMAT_NAME_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "name",
    kind: ArgumentKind::Dword,
    parameter_type: NULLABLE_FAR_STRING,
}];

pub(super) const USER_GET_CLIPBOARD_FORMAT_NAME_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "format", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_GET_WINDOW_TEXT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_SET_WINDOW_TEXT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "text", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
];

pub(super) const USER_GET_WINDOW_TEXT_LENGTH_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "window",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const USER_SYSTEM_METRICS_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "index",
    kind: ArgumentKind::Word,
    parameter_type: SIGNED_SCALAR,
}];

pub(super) const USER_SET_TIME_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "milliseconds", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD,
}];

pub(super) const USER_SYS_COLOR_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "index", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD,
}];

pub(super) const USER_BEEP_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "beep_type",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const USER_INIT_APP_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "instance",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const USER_EXIT_WINDOWS_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "return_code", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "reserved", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_EXIT_WINDOWS_EXEC_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "program", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "parameters", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
];

pub(super) const USER_GET_CLASS_INFO_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "class_name", kind: ArgumentKind::Dword, parameter_type: CLASS_NAME },
    Win16Parameter { name: "class_info", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const USER_REGISTER_CLASS_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "window_class",
    kind: ArgumentKind::Dword,
    parameter_type: FAR_BUFFER,
}];

pub(super) const USER_CREATE_WINDOW_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "class_name", kind: ArgumentKind::Dword, parameter_type: CLASS_NAME },
    Win16Parameter { name: "window_name", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "style", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "parent", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter {
        name: "parameter",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::FarPointer,
    },
];

pub(super) const USER_CREATE_WINDOW_EX_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "ex_style", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "class_name", kind: ArgumentKind::Dword, parameter_type: CLASS_NAME },
    Win16Parameter { name: "window_name", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "style", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "parent", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "menu", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter {
        name: "parameter",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::FarPointer,
    },
];

pub(super) const USER_SHOW_WINDOW_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "command", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_LOAD_STRING_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "string_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "buffer", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_WNET_GET_CAPS_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "capability_index", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_LOAD_BITMAP_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bitmap_name_or_id", kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::ResourceName },
];

pub(super) const USER_LOAD_ICON_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter {
        name: "icon_name_or_id",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::ResourceName,
    },
];

pub(super) const USER_LOAD_CURSOR_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter {
        name: "cursor_name_or_id",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::ResourceName,
    },
];

pub(super) const USER_GET_DC_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "window",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const USER_RELEASE_DC_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_SET_MESSAGE_QUEUE_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "message_count",
    kind: ArgumentKind::Word,
    parameter_type: SIGNED_SCALAR,
}];

pub(super) const USER_ATOM_NAME_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "atom_name",
    kind: ArgumentKind::Dword,
    parameter_type: Win16ParameterType::AtomName,
}];

pub(super) const USER_DELETE_ATOM_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "atom",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const USER_GET_ATOM_NAME_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "atom", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "buffer", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_ENUM_WINDOWS_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "callback", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "data", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];
pub(super) const USER_ENUM_SCOPED_WINDOWS_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "scope", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "callback", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "data", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];
