//! Parameter layouts for additional host-backed KERNEL profile services.

use super::*;

pub(super) const KERNEL_PROFILE_WRITE: &[Win16Parameter] = &[
    Win16Parameter { name: "section", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "key", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "value", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
];

pub(super) const KERNEL_PROFILE_SECTION_NAMES: &[Win16Parameter] = &[
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const KERNEL_PRIVATE_PROFILE_SECTION_NAMES: &[Win16Parameter] = &[
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "filename", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
];
