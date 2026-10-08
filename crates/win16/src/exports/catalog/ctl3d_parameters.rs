//! Known Win16 CTL3D/CTL3DV2 stack layouts used by the catalog.

use super::*;

pub(super) const ONE_WINDOW: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const TWO_WORDS: &[Win16Parameter] = &[
    Win16Parameter { name: "first", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "second", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const CTL3D_COLOR: &[Win16Parameter] = &[
    Win16Parameter { name: "control", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "message", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const CTL3D_COLOR_EX: &[Win16Parameter] = &[
    Win16Parameter { name: "control", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "message", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "l_param", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const DLG_FRAME_PAINT: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "message", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "w_param", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "l_param", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const CTL3D_SUBCLASS_DLG_EX: &[Win16Parameter] = &[
    Win16Parameter { name: "dialog", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const CTL3D_SUBCLASS_CONTROL_EX: &[Win16Parameter] = &[
    Win16Parameter { name: "control", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "style", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const CTL3D_AUTO_SUBCLASS_EX: &[Win16Parameter] = &[
    Win16Parameter { name: "parent", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];
