//! Project-owned TOOLHELP parameter signatures for the export catalog.
//! The catalog is the production declaration source.

use super::*;
pub(super) const TOOLHELP_GLOBAL_HANDLE_TO_SEL_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "handle",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const TOOLHELP_GLOBAL_FIRST_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "output",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const TOOLHELP_GLOBAL_NEXT_PARAMETERS: &[Win16Parameter] =
    TOOLHELP_GLOBAL_FIRST_PARAMETERS;

pub(super) const TOOLHELP_GLOBAL_INFO_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "output",
    kind: ArgumentKind::Dword,
    parameter_type: FAR_OUTPUT_BUFFER,
}];

pub(super) const TOOLHELP_GLOBAL_ENTRY_HANDLE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "output",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
    Win16Parameter { name: "handle", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const TOOLHELP_GLOBAL_ENTRY_MODULE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "output",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
    Win16Parameter { name: "module", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "segment", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const TOOLHELP_INTERRUPT_REGISTER_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "task", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter {
        name: "callback",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::FarPointer,
    },
];

pub(super) const TOOLHELP_INTERRUPT_UNREGISTER_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "task",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];
