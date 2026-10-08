//! MMSYSTEM timer ABI parameter layouts from the Windows SDK 3.1 MMSYSTEM.H.

use super::*;

pub(super) const GET_SYSTEM_TIME: &[Win16Parameter] = &[
    Win16Parameter { name: "time", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "size", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const GET_DEV_CAPS: &[Win16Parameter] = &[
    Win16Parameter { name: "caps", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "size", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const PERIOD: &[Win16Parameter] = &[
    Win16Parameter { name: "period", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
