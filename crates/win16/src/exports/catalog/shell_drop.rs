//! Windows 3.1 SHELL drag/drop and Windows 4.x format-drive stack layouts.

use super::*;

pub(super) const SHELL_DRAG_ACCEPT_FILES_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "accept", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const SHELL_DRAG_QUERY_FILE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "drop", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "index", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    // A null output pointer is valid for either the count query or a length query.
    Win16Parameter { name: "file_name", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const SHELL_DRAG_FINISH_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "drop", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const SHELL_DRAG_QUERY_POINT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "drop", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "point", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const SHELL_FORMAT_DRIVE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "owner", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "drive", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "format_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "options", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
