//! USER scroll-bar signatures from Windows SDK 3.1 `WINDOWS.H` lines 3918-3923.

use super::*;

pub(super) const SET_POSITION_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bar", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "position", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "redraw", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const GET_POSITION_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bar", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const SET_RANGE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bar", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "minimum", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "maximum", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "redraw", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const GET_RANGE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bar", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "minimum", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "maximum", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const SHOW_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bar", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "show", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const ENABLE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bar", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
