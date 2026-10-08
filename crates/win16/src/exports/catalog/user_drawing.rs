//! USER fill and text drawing argument signatures.

use super::*;

pub(super) const USER_FILL_RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "brush", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_DRAW_TEXT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "text", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
