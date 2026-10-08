//! ABI parameter layouts for implemented KERNEL, TOOLHELP, and SYSTEM services.

use super::*;

pub(super) const KERNEL_GET_MODULE_NAME: &[Win16Parameter] = &[
    Win16Parameter { name: "module", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const KERNEL_GET_EXE_PTR: &[Win16Parameter] = &[Win16Parameter {
    name: "handle", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD,
}];

pub(super) const KERNEL_GET_EXP_WIN_VER: &[Win16Parameter] = &[Win16Parameter {
    name: "module", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD,
}];

pub(super) const KERNEL_ANSI_NEXT: &[Win16Parameter] = &[Win16Parameter {
    name: "pointer", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD,
}];

pub(super) const KERNEL_ANSI_PREV: &[Win16Parameter] = &[
    Win16Parameter { name: "start", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "current", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const KERNEL_ANSI_CASE: &[Win16Parameter] = &[Win16Parameter {
    name: "string_or_char", kind: ArgumentKind::Dword, parameter_type: FAR_STRING_OR_CHAR,
}];

pub(super) const KERNEL_IS_TASK: &[Win16Parameter] = &[Win16Parameter {
    name: "task", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD,
}];

pub(super) const KERNEL_BAD_POINTER: &[Win16Parameter] = &[
    Win16Parameter { name: "pointer", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::FarPointer },
    Win16Parameter { name: "length", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const KERNEL_BAD_CODE_POINTER: &[Win16Parameter] = &[Win16Parameter {
    name: "pointer", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::FarPointer,
}];

pub(super) const KERNEL_BAD_STRING_POINTER: &[Win16Parameter] = &[
    Win16Parameter { name: "pointer", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::FarPointer },
    Win16Parameter { name: "maximum", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const KERNEL_BAD_HUGE_POINTER: &[Win16Parameter] = &[
    Win16Parameter { name: "pointer", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::FarPointer },
    Win16Parameter { name: "length", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const KERNEL_LSTRN: &[Win16Parameter] = &[
    Win16Parameter { name: "destination", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::FarPointer },
    Win16Parameter { name: "source", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "limit", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const TOOLHELP_LOCAL_INFO: &[Win16Parameter] = &[
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "heap", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const TOOLHELP_OUTPUT: &[Win16Parameter] = &[Win16Parameter {
    name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER,
}];

pub(super) const TOOLHELP_FIND_NAME: &[Win16Parameter] = &[
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "name", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
];

pub(super) const TOOLHELP_FIND_HANDLE: &[Win16Parameter] = &[
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "handle", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const TOOLHELP_TASK_HANDLE: &[Win16Parameter] = &[Win16Parameter {
    name: "task", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD,
}];

pub(super) const TOOLHELP_TERMINATE_APP: &[Win16Parameter] = &[
    Win16Parameter { name: "task", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "exit_code", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const TOOLHELP_MEMORY_READ: &[Win16Parameter] = &[
    Win16Parameter { name: "selector", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "offset", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "buffer", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const TOOLHELP_MEMORY_WRITE: &[Win16Parameter] = &[
    Win16Parameter { name: "selector", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "offset", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "buffer", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];
