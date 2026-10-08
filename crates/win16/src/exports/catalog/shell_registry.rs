//! Confirmed SHELL registry signatures (SHELL.1 through SHELL.7).

use super::*;

pub(super) const SHELL_REG_OPEN_CREATE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "root", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "subkey", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "result_key", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const SHELL_REG_KEY_PARAMETER: &[Win16Parameter] = &[
    Win16Parameter { name: "key", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const SHELL_REG_DELETE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "root", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "subkey", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
];

pub(super) const SHELL_REG_SET_VALUE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "key", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "subkey", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "value_type", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "value", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "byte_count", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const SHELL_REG_QUERY_VALUE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "key", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "subkey", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "value", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "byte_count", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const SHELL_REG_ENUM_KEY_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "key", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "index", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "name", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];
