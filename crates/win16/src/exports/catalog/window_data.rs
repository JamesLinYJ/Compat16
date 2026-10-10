//! Shared scalar parameter roles for USER class and window data accessors.

use super::{ArgumentKind, Win16Parameter, Win16ParameterType};

const WINDOW: Win16Parameter = Win16Parameter {
    name: "window", kind: ArgumentKind::Word, parameter_type: Win16ParameterType::Scalar,
};
const INDEX: Win16Parameter = Win16Parameter {
    name: "index", kind: ArgumentKind::Word, parameter_type: Win16ParameterType::SignedScalar,
};
pub(super) const SET_PARENT: &[Win16Parameter] = &[
    WINDOW, Win16Parameter {
        name: "parent", kind: ArgumentKind::Word, parameter_type: Win16ParameterType::Scalar,
    },
];
pub(super) const GET: &[Win16Parameter] = &[WINDOW, INDEX];
pub(super) const SET_WORD: &[Win16Parameter] = &[
    WINDOW, INDEX, Win16Parameter {
        name: "value", kind: ArgumentKind::Word, parameter_type: Win16ParameterType::Scalar,
    },
];
pub(super) const SET_LONG: &[Win16Parameter] = &[
    WINDOW, INDEX, Win16Parameter {
        name: "value", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::SignedScalar,
    },
];
