//! USER hook argument signatures from Windows 3.1 USER.spec and SDK WINDOWS.H.

use super::*;

pub(super) const SET_WINDOWS_HOOK_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "hook_type",
        kind: ArgumentKind::Word,
        parameter_type: SIGNED_SCALAR,
    },
    Win16Parameter {
        name: "procedure",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::FarPointer,
    },
];

pub(super) const CALL_MSG_FILTER_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "message",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::FarPointer,
    },
    Win16Parameter {
        name: "code",
        kind: ArgumentKind::Word,
        parameter_type: SIGNED_SCALAR,
    },
];

pub(super) const UNHOOK_WINDOWS_HOOK_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "hook_type",
        kind: ArgumentKind::Word,
        parameter_type: SIGNED_SCALAR,
    },
    Win16Parameter {
        name: "procedure",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::FarPointer,
    },
];

pub(super) const DEF_HOOK_PROC_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "code",
        kind: ArgumentKind::Word,
        parameter_type: SIGNED_SCALAR,
    },
    Win16Parameter {
        name: "w_param",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "l_param",
        kind: ArgumentKind::Dword,
        parameter_type: SIGNED_SCALAR,
    },
    Win16Parameter {
        name: "hook_slot",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::FarPointer,
    },
];

pub(super) const SET_WINDOWS_HOOK_EX_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "hook_type",
        kind: ArgumentKind::Word,
        parameter_type: SIGNED_SCALAR,
    },
    Win16Parameter {
        name: "procedure",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::FarPointer,
    },
    Win16Parameter {
        name: "instance",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "task",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
];

pub(super) const UNHOOK_WINDOWS_HOOK_EX_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "hook",
    kind: ArgumentKind::Dword,
    parameter_type: SCALAR_DWORD,
}];

pub(super) const CALL_NEXT_HOOK_EX_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "hook",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
    Win16Parameter {
        name: "code",
        kind: ArgumentKind::Word,
        parameter_type: SIGNED_SCALAR,
    },
    Win16Parameter {
        name: "w_param",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "l_param",
        kind: ArgumentKind::Dword,
        parameter_type: SIGNED_SCALAR,
    },
];
