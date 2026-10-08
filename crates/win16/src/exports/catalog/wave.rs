//! Win16 MMSYSTEM WAVE ABI parameters from the Windows SDK 3.1 prototypes.

use super::*;

pub(super) const OPEN: &[Win16Parameter] = &[
    Win16Parameter {
        name: "handle_out",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
    Win16Parameter {
        name: "device",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "format",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_BUFFER,
    },
    Win16Parameter {
        name: "callback",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
    Win16Parameter {
        name: "instance",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
    Win16Parameter {
        name: "flags",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
];

pub(super) const HEADER: &[Win16Parameter] = &[
    Win16Parameter {
        name: "handle",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "header",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_BUFFER,
    },
    Win16Parameter {
        name: "size",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
];

pub(super) const POSITION: &[Win16Parameter] = &[
    Win16Parameter {
        name: "handle",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "time",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
    Win16Parameter {
        name: "size",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
];

pub(super) const HANDLE: &[Win16Parameter] = &[Win16Parameter {
    name: "handle",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const DEVICE_CAPS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "device",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "capabilities",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
    Win16Parameter {
        name: "size",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
];

pub(super) const ERROR_TEXT: &[Win16Parameter] = &[
    Win16Parameter {
        name: "error",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "text",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
    Win16Parameter {
        name: "size",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
];

pub(super) const GET_PARAMETER: &[Win16Parameter] = &[
    Win16Parameter {
        name: "handle",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "value",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
];

pub(super) const SET_PARAMETER: &[Win16Parameter] = &[
    Win16Parameter {
        name: "handle",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "value",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
];

pub(super) const GET_DEVICE_VOLUME: &[Win16Parameter] = &[
    Win16Parameter {
        name: "device_id",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "value",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
];

pub(super) const SET_DEVICE_VOLUME: &[Win16Parameter] = &[
    Win16Parameter {
        name: "device_id",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "value",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
];

pub(super) const DEVICE_ID: &[Win16Parameter] = &[
    Win16Parameter {
        name: "handle",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "device_id",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
];

pub(super) const MESSAGE: &[Win16Parameter] = &[
    Win16Parameter {
        name: "device_or_handle",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "message",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "parameter1",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
    Win16Parameter {
        name: "parameter2",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
];
