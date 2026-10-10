//! Project-owned USER window and rectangle parameter signatures.
//!
//! The declarations follow the Windows 3.1 SDK Programmer's Reference,
//! Volume 2. RECT16 and POINT16 pointers stay raw guest FAR values until the
//! runtime can validate the fixed guest structure size and direction.
//! The six void caret signatures are also recorded in Open Watcom's Win16
//! header: https://github.com/open-watcom/open-watcom-v2/blob/08a5064dd9831edf10234844630e605e83606989/bld/w16api/include/win16.mh

use super::*;

pub(super) const USER_CREATE_CARET_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bitmap", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_SET_CARET_POS_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_CLIP_RECT_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "rect",
    kind: ArgumentKind::Dword,
    parameter_type: FAR_OUTPUT_BUFFER,
}];

pub(super) const USER_CURSOR_POINT_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "point",
    kind: ArgumentKind::Dword,
    parameter_type: FAR_OUTPUT_BUFFER,
}];

pub(super) const USER_WINDOW_PLACEMENT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "placement", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const USER_WINDOW_HANDLE_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "window",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const USER_GET_WINDOW_RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const USER_ENABLE_WINDOW_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "enable", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_FIND_WINDOW_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "class_name", kind: ArgumentKind::Dword, parameter_type: CLASS_NAME },
    Win16Parameter { name: "window_name", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
];

pub(super) const USER_GET_CLASS_NAME_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_GET_WINDOW_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "command", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_SHOW_OWNED_POPUPS_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "show", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_WINDOW_POINT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "point", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const USER_MAP_WINDOW_POINTS_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "from", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "to", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "points", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

// Win16 POINT is a four-byte by-value record, never a FAR pointer. Open
// Watcom's Win16 header confirms ChildWindowFromPoint and IsChild prototypes:
// https://github.com/open-watcom/open-watcom-v2/blob/master/bld/w16api/include/win16.mh
// USER.399's ABI comes from the checked-in, Wine-derived USER specification;
// no historical Microsoft Win16 ChildWindowFromPointEx prototype is claimed:
// https://github.com/wine-mirror/wine/blob/master/dlls/user.exe16/user.exe16.spec
// Native USER supplies the current documented Ex hit-test/filter semantics:
// https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-childwindowfrompointex
pub(super) const USER_CHILD_POINT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "parent", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "point", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const USER_CHILD_POINT_EX_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "parent", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "point", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_IS_CHILD_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "parent", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "child", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_POINT_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "point",
    kind: ArgumentKind::Dword,
    parameter_type: SCALAR_DWORD,
}];

pub(super) const USER_WINDOW_MOVE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "repaint", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_SET_WINDOW_POS_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "insert_after", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const USER_SET_RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "left", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "top", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "right", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "bottom", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_RECT_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "rect",
    kind: ArgumentKind::Dword,
    parameter_type: FAR_BUFFER,
}];

pub(super) const USER_POINT_IN_RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "point", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const USER_OFFSET_RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const USER_INTERSECT_RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "destination", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "source1", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "source2", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];
pub(super) const USER_EQUAL_RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "source1", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "source2", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];
pub(super) const USER_OUTPUT_RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];
pub(super) const USER_COPY_RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "destination", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "source", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];
