//! MCI stack contracts from the Win16 module specification and SDK 3.1.

use super::*;

pub(super) const SEND_COMMAND: &[Win16Parameter] = &[
    Win16Parameter { name: "device_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "message", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "parameters", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];
pub(super) const SEND_STRING: &[Win16Parameter] = &[
    Win16Parameter { name: "command", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "callback", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
pub(super) const DEVICE_NAME: &[Win16Parameter] = &[
    Win16Parameter { name: "name", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
];
pub(super) const LOAD_COMMAND_RESOURCE: &[Win16Parameter] = &[
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "resource", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::ResourceName },
    Win16Parameter { name: "resource_type", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
pub(super) const ERROR_STRING: &[Win16Parameter] = &[
    Win16Parameter { name: "error", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "buffer", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
pub(super) const SET_DRIVER_DATA: &[Win16Parameter] = &[
    Win16Parameter { name: "device_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "data", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];
pub(super) const DEVICE_ID: &[Win16Parameter] = &[
    Win16Parameter { name: "device_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
pub(super) const DRIVER_NOTIFY: &[Win16Parameter] = &[
    Win16Parameter { name: "window", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "device_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "status", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
pub(super) const COMMAND_STRING: &[Win16Parameter] = &[
    Win16Parameter { name: "command", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
];
pub(super) const SET_YIELD_PROC: &[Win16Parameter] = &[
    Win16Parameter { name: "device_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "procedure", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::FarPointer },
    Win16Parameter { name: "data", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];
pub(super) const ELEMENT_ID: &[Win16Parameter] = &[
    Win16Parameter { name: "element_id", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "device_type", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
];
pub(super) const GET_YIELD_PROC: &[Win16Parameter] = &[
    Win16Parameter { name: "device_id", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "data", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];
