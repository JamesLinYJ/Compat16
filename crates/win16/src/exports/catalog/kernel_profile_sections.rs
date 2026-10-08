//! ABI parameter layouts for KERNEL profile-section queries.

use super::*;

pub(super) const WRITE_PROFILE_SECTION: &[Win16Parameter] = &[
    Win16Parameter { name: "section", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "entries", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const WRITE_PRIVATE_PROFILE_SECTION: &[Win16Parameter] = &[
    Win16Parameter { name: "section", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "entries", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "filename", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
];

pub(super) const GET_PROFILE_SECTION: &[Win16Parameter] = &[
    Win16Parameter { name: "section", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "output_buffer", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const GET_PRIVATE_PROFILE_SECTION: &[Win16Parameter] = &[
    Win16Parameter { name: "section", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "output_buffer", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "filename", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
];
