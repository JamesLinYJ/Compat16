//! Fixed legacy IME profile parameter layouts.
use super::*;

pub(super) const PROFILE: &[Win16Parameter] = &[Win16Parameter {
    name: "profile",
    kind: ArgumentKind::Dword,
    parameter_type: FAR_BUFFER,
}];
pub(super) const OUTPUT: &[Win16Parameter] = &[Win16Parameter {
    name: "profile",
    kind: ArgumentKind::Dword,
    parameter_type: FAR_OUTPUT_BUFFER,
}];
pub(super) const GET: &[Win16Parameter] = &[
    Win16Parameter {
        name: "window",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "profile",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
];
pub(super) const SET: &[Win16Parameter] = &[
    Win16Parameter {
        name: "window",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "profile",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_BUFFER,
    },
];
pub(super) const MODIFY: &[Win16Parameter] = &[
    Win16Parameter {
        name: "name",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
    Win16Parameter {
        name: "profile",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_BUFFER,
    },
];
