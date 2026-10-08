//! KERNEL instance/code query layouts from the Windows SDK 3.1 `WINDOWS.H`.

use super::*;

pub(super) const GET_INSTANCE_DATA_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "previous_instance",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "current_instance_buffer_offset",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "byte_count",
        kind: ArgumentKind::Word,
        parameter_type: SIGNED_SCALAR,
    },
];

pub(super) const GET_CODE_HANDLE_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "procedure",
    kind: ArgumentKind::Dword,
    parameter_type: Win16ParameterType::FarPointer,
}];

pub(super) const GET_CODE_INFO_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "procedure_or_module_segment",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
    Win16Parameter {
        name: "output",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
];
