//! SDK 3.1 public stack signatures for the KERNEL diagnostic routines.

use super::*;

pub(super) const OUTPUT_DEBUG_STRING: &[Win16Parameter] = &[Win16Parameter {
    name: "message",
    kind: ArgumentKind::Dword,
    parameter_type: FAR_STRING,
}];

pub(super) const FATAL_APP_EXIT: &[Win16Parameter] = &[
    Win16Parameter {
        name: "action",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "message",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
];

pub(super) const FATAL_EXIT: &[Win16Parameter] = &[Win16Parameter {
    name: "error_code",
    kind: ArgumentKind::Word,
    parameter_type: SIGNED_SCALAR,
}];
