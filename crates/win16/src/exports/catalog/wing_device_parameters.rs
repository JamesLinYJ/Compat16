//! Parameter layouts for the WinG exports handled by the GDI-device family.

use super::*;

pub(super) const RECOMMEND_DIB_FORMAT: &[Win16Parameter] = &[
    Win16Parameter { name: "info", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const CREATE_BITMAP: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "info", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "bits_output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const GET_DIB_POINTER: &[Win16Parameter] = &[
    Win16Parameter { name: "bitmap", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "info", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const HALF_TONE_BRUSH: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    // The Microsoft WinG prototype declares COLORREF here (a 32-bit value).
    Win16Parameter { name: "color", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "dither_type", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const BIT_BLT: &[Win16Parameter] = &[
    Win16Parameter { name: "destination", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "destination_x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "destination_y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "source", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "source_x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "source_y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const STRETCH_BLT: &[Win16Parameter] = &[
    Win16Parameter { name: "destination", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "destination_x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "destination_y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "destination_width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "destination_height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "source", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "source_x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "source_y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "source_width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "source_height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];
