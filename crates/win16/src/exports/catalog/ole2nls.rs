//! OLE2NLS parameter layouts for the documented locale and string queries.

use super::*;

pub(super) const GET_USER_DEFAULT_LCID_PARAMETERS: &[Win16Parameter] = &[];
pub(super) const GET_SYSTEM_DEFAULT_LCID_PARAMETERS: &[Win16Parameter] = &[];
pub(super) const GET_USER_DEFAULT_LANG_ID_PARAMETERS: &[Win16Parameter] = &[];
pub(super) const GET_SYSTEM_DEFAULT_LANG_ID_PARAMETERS: &[Win16Parameter] = &[];

pub(super) const GET_LOCALE_INFO_A_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "locale", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "info_type", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "data", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const LC_MAP_STRING_A_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "locale", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "source", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "source_count", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "destination", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "destination_capacity", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const GET_STRING_TYPE_A_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "locale", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "info_type", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "source", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "source_count", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "character_types", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const COMPARE_STRING_A_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "locale", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "left", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "left_count", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "right", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "right_count", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];
