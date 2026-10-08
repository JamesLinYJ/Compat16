//! Project-owned USER message, queue, focus, capture, and keyboard signatures.

use super::*;

pub(super) const USER_SET_TIMER_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "timer_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "interval", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "callback", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::FarPointer },
];

pub(super) const USER_WINDOW_TIMER_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "timer_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_SET_WINDOW_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD,
}];

pub(super) const USER_POST_MESSAGE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "message", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "w_param", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "l_param", kind: ArgumentKind::Dword, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_SEND_DLG_ITEM_MESSAGE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dialog", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "id", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "message", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "w_param", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "l_param", kind: ArgumentKind::Dword, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_POST_APP_MESSAGE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "task", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "message", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "w_param", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "l_param", kind: ArgumentKind::Dword, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_CALL_WINDOW_PROC_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "procedure", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::FarPointer },
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "message", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "w_param", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "l_param", kind: ArgumentKind::Dword, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_KEYBOARD_STATE_OUTPUT_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "state", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER,
}];

pub(super) const USER_KEYBOARD_STATE_INPUT_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "state", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER,
}];

pub(super) const USER_QUEUE_STATUS_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD,
}];
