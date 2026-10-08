//! TIMER driver procedure parameter layout.

use super::*;

pub(super) const DRIVER_PROC: &[Win16Parameter] = &[
    Win16Parameter { name: "device_id", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "driver_handle", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "message", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "parameter1", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "parameter2", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];
