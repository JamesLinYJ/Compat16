//! USER drawing-object signatures from Windows SDK 3.1 `WINDOWS.H`.

use super::*;

pub(super) const RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const FRAME_RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "brush", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const DRAW_ICON_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "icon", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
