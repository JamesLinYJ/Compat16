//! PRINT.H priority-queue stack layouts from the Windows 3.1 SDK.

use super::*;

pub(super) const CREATE_PQ: &[Win16Parameter] = &[Win16Parameter {
    name: "capacity",
    kind: ArgumentKind::Word,
    parameter_type: SIGNED_SCALAR,
}];

pub(super) const PQ_HANDLE: &[Win16Parameter] = &[Win16Parameter {
    name: "queue",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const INSERT_PQ: &[Win16Parameter] = &[
    Win16Parameter {
        name: "queue",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "tag",
        kind: ArgumentKind::Word,
        parameter_type: SIGNED_SCALAR,
    },
    Win16Parameter {
        name: "priority",
        kind: ArgumentKind::Word,
        parameter_type: SIGNED_SCALAR,
    },
];

pub(super) const SIZE_PQ: &[Win16Parameter] = &[
    Win16Parameter {
        name: "queue",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "size_change",
        kind: ArgumentKind::Word,
        parameter_type: SIGNED_SCALAR,
    },
];
