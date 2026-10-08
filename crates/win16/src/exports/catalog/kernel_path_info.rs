//! KERNEL path-query ABI layouts from the Windows SDK 3.1 `WINDOWS.H`:
//! GetWindowsDirectory/GetSystemDirectory at lines 262-263 and
//! GetTempFileName at lines 799-802.

use super::*;

pub(super) const GET_WINDOWS_DIRECTORY_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "path", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const GET_SYSTEM_DIRECTORY_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "path", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const GET_TEMP_FILE_NAME_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "drive", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "prefix", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "unique", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "path", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];
