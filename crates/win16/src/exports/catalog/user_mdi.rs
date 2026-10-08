use super::*;

pub(super) const FRAME: &[Win16Parameter] = &[
    Win16Parameter { name: "frame", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "mdi_client", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "message", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "w_param", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "l_param", kind: ArgumentKind::Dword, parameter_type: SIGNED_SCALAR },
];
pub(super) const CHILD: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "message", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "w_param", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "l_param", kind: ArgumentKind::Dword, parameter_type: SIGNED_SCALAR },
];
pub(super) const TRANSLATE: &[Win16Parameter] = &[
    Win16Parameter { name: "mdi_client", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "message", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];
