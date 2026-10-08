//! Windows 3.1 TOOLHELP notification callback parameter layouts.

use super::*;

pub(super) const NOTIFY_REGISTER: &[Win16Parameter] = &[
    Win16Parameter { name: "task", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter {
        name: "callback",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::FarPointer,
    },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const NOTIFY_UNREGISTER: &[Win16Parameter] = &[Win16Parameter {
    name: "task",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];
