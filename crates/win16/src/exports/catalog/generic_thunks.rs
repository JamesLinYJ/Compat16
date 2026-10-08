//! ABI parameter prefixes for the KERNEL generic-thunk exports.
//!
//! The fixed entries use the KERNEL spec widths. The two variadic call
//! descriptors list only their declared DWORD prefix; `VariableStack` keeps
//! this prefix from being mistaken for the complete source argument area.
//! The spec's `varargs` class remains intact on those descriptors. The
//! dedicated frame decoder applies the API-specific Pascal `CallProc32W` and
//! Cdecl `_CallProcEx32W` source stack order.

use super::*;

pub(super) const LOAD_LIBRARY_EX_32W: &[Win16Parameter] = &[
    Win16Parameter {
        name: "library_name",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
    Win16Parameter {
        name: "reserved_hfile",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
    Win16Parameter {
        name: "flags",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
];

pub(super) const FREE_LIBRARY_32W: &[Win16Parameter] = &[Win16Parameter {
    name: "module_handle",
    kind: ArgumentKind::Dword,
    parameter_type: SCALAR_DWORD,
}];

pub(super) const GET_PROC_ADDRESS_32W: &[Win16Parameter] = &[
    Win16Parameter {
        name: "module_handle",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
    Win16Parameter {
        name: "procedure_name",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
];

pub(super) const GET_VDM_POINTER_32W: &[Win16Parameter] = &[
    Win16Parameter {
        name: "address",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::FarPointer,
    },
    Win16Parameter {
        name: "mode",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
];

pub(super) const CALL_PROC_32W: &[Win16Parameter] = &[
    Win16Parameter {
        name: "procedure",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
    Win16Parameter {
        name: "pointer_mask",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
    Win16Parameter {
        name: "encoded_parameter_count",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
];

pub(super) const CALL_PROC_EX_32W: &[Win16Parameter] = &[
    Win16Parameter {
        name: "encoded_parameter_count",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
    Win16Parameter {
        name: "pointer_mask",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
    Win16Parameter {
        name: "procedure",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
];
