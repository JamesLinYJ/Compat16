//! Parameter layouts for the Windows 3.1 MMSYSTEM MIDI entry points.

use super::*;

pub(super) const CAPS: &[Win16Parameter] = &[
    Win16Parameter { name: "device_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "caps", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "size", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
pub(super) const ERROR_TEXT: &[Win16Parameter] = &[
    Win16Parameter { name: "error", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "text", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "size", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
pub(super) const OPEN: &[Win16Parameter] = &[
    Win16Parameter { name: "handle", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "device_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "callback", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "instance", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];
pub(super) const DEVICE: &[Win16Parameter] = &[
    Win16Parameter { name: "device", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
pub(super) const HEADER: &[Win16Parameter] = &[
    Win16Parameter { name: "device", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "header", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "size", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
pub(super) const SHORT_MESSAGE: &[Win16Parameter] = &[
    Win16Parameter { name: "device", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "message", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];
pub(super) const GET_VOLUME: &[Win16Parameter] = &[
    Win16Parameter { name: "device", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "volume", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];
pub(super) const SET_VOLUME: &[Win16Parameter] = &[
    Win16Parameter { name: "device", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "volume", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];
pub(super) const CACHE_PATCHES: &[Win16Parameter] = &[
    Win16Parameter { name: "device", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bank", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "patches", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
pub(super) const CACHE_DRUM_PATCHES: &[Win16Parameter] = &[
    Win16Parameter { name: "device", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "patch", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "keys", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
pub(super) const GET_ID: &[Win16Parameter] = &[
    Win16Parameter { name: "device", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "device_id", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];
pub(super) const DRIVER_MESSAGE: &[Win16Parameter] = &[
    Win16Parameter { name: "device", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "message", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "parameter1", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "parameter2", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];
// The 250–257 stream declarations are retained by the project ABI inventory,
// but are absent from the Windows 3.1 SDK 3.1 MMSYSTEM.H contract.
pub(super) const STREAM_PROPERTY: &[Win16Parameter] = &[
    Win16Parameter { name: "stream", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "property", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "flags", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];
pub(super) const STREAM_OPEN: &[Win16Parameter] = &[
    Win16Parameter { name: "stream", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "devices", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "callback", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "instance", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];
pub(super) const STREAM_POSITION: &[Win16Parameter] = &[
    Win16Parameter { name: "stream", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "time", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "size", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
pub(super) const STREAM_OUT: &[Win16Parameter] = &[
    Win16Parameter { name: "stream", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "header", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "size", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
