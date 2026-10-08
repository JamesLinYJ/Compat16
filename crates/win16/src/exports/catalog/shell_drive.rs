//! Confirmed SHELL DriveType stack signature.

use super::*;

pub(super) const SHELL_DRIVE_TYPE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "drive", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];
