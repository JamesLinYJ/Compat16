//! Project-owned USER paint and update-region signatures.
//!
//! FAR buffer metadata keeps the raw 16:16 address, including zero; runtime
//! applies each API's null-pointer and access rules after request decoding.

use super::*;

pub(super) const USER_BEGIN_PAINT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "paint", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const USER_END_PAINT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "paint", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const USER_UPDATE_WINDOW_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_INVALIDATE_RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    // A zero FAR value is retained as the API's nullable RECT pointer.
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "erase", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_INVALIDATE_RGN_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "region", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "erase", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_VALIDATE_RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    // Preserve a zero FAR value so runtime can apply the API's null semantics.
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const USER_VALIDATE_RGN_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "region", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_GET_UPDATE_RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "erase", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_GET_UPDATE_RGN_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "region", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "erase", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_EXCLUDE_UPDATE_RGN_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_REDRAW_WINDOW_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    // A zero FAR value denotes no bounding rectangle.
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "region", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_LOCK_WINDOW_UPDATE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_SCROLL_WINDOW_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "dx", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "dy", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    // Zero retains the API's optional-rectangle meaning for each FAR argument.
    Win16Parameter { name: "scroll_rect", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "clip_rect", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const USER_SCROLL_WINDOW_EX_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "dx", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "dy", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    // These optional FAR values remain raw until runtime applies API rules.
    Win16Parameter { name: "scroll_rect", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "clip_rect", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "update_region", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "update_rect", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
