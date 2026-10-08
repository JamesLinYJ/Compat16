//! Win16 parameter layout for `DISPDIB.1 DisplayDib`.

use super::*;

pub(super) const DISPLAY_DIB: &[Win16Parameter] = &[
    Win16Parameter { name: "info", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "bits", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
