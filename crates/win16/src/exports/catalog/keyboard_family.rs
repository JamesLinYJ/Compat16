//! Confirmed KEYBOARD/WIFEMAN argument layouts backed by direct native calls.

use super::*;

pub(super) const KEYBOARD_TO_ASCII_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "virtual_key", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "scan_code", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "key_state", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const KEYBOARD_ANSI_TO_OEM_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "source", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "destination", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const KEYBOARD_WORD_PARAMETER: &[Win16Parameter] = &[
    Win16Parameter { name: "value", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const KEYBOARD_MAP_VIRTUAL_KEY_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "code", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "map_type", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const KEYBOARD_GET_KEY_NAME_TEXT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "parameter", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const KEYBOARD_CONVERT_BUFFER_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "source", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "destination", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "byte_count", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const KEYBOARD_SET_SPEED_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "speed", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const KEYBOARD_SCREEN_SWITCH_ENABLE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "enable", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const WIFEMAN_DBCS_LEAD_BYTE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "value", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
