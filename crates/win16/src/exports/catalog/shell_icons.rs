//! Confirmed Win16 SHELL and USER image-handle stack layouts.

use super::*;

pub(super) const SHELL_EXTRACT_ICON_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "path", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "index", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const SHELL_EXTRACT_ASSOCIATED_ICON_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "icon_path", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "icon_index", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const SHELL_INTERNAL_EXTRACT_ICON_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "path", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "index", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const SHELL_EXTRACT_ICON_EX_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "path", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "index", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "large_icons", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "small_icons", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_IMAGE_HANDLE_PARAMETER: &[Win16Parameter] = &[
    Win16Parameter { name: "image", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
