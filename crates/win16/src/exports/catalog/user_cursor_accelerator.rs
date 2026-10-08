//! SDK 3.1 USER cursor, accelerator, and WinHelp stack signatures.

use super::*;

pub(super) const SET_CURSOR_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "cursor",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const SHOW_CURSOR_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "show",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const WIN_HELP_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "window",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "help_file",
        kind: ArgumentKind::Dword,
        parameter_type: NULLABLE_FAR_STRING,
    },
    Win16Parameter {
        name: "command",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "data",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
];

pub(super) const LOAD_ACCELERATORS_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "instance",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "name",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::ResourceName,
    },
];

pub(super) const TRANSLATE_ACCELERATOR_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "window",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "accelerator",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "message",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_BUFFER,
    },
];
