//! Known Win16 COMMDLG stack layouts used by the catalog.

use super::*;

pub(super) const COMMON_DIALOG_STRUCTURE: &[Win16Parameter] = &[
    Win16Parameter { name: "structure", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const GET_FILE_TITLE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "file_name", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "title", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
