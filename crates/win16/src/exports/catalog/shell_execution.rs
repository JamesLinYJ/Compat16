//! Win16 SHELL execution API stack layouts from the Windows 3.1 SDK.

use super::*;

pub(super) const SHELL_EXECUTE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "owner",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "operation",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::NullableFarString,
    },
    Win16Parameter {
        name: "file",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
    Win16Parameter {
        name: "parameters",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::NullableFarString,
    },
    Win16Parameter {
        name: "directory",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::NullableFarString,
    },
    Win16Parameter {
        name: "show",
        kind: ArgumentKind::Word,
        parameter_type: SIGNED_SCALAR,
    },
];

pub(super) const SHELL_FIND_EXECUTABLE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "file",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
    Win16Parameter {
        name: "directory",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::NullableFarString,
    },
    Win16Parameter {
        name: "result_path",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
];

pub(super) const SHELL_ABOUT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "owner",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "app",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
    Win16Parameter {
        name: "other_stuff",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::NullableFarString,
    },
    Win16Parameter {
        name: "icon",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
];
