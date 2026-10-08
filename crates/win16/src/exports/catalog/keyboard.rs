//! Project-owned KEYBOARD parameter signatures for the export catalog.
//! The catalog is the production declaration source.

use super::*;
pub(super) const KEYBOARD_OEM_TO_ANSI_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "source", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "destination", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];
