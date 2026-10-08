//! Win16 printer-call argument slots; binary outputs are never strings.

use super::*;

pub(super) const DEVICE_CAPABILITIES: &[Win16Parameter] = &[
    Win16Parameter { name: "device", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "port", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "index", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "devmode", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];
