//! USER/WFW network redirector parameter declarations.

use super::*;

pub(super) const WNET_ERROR_TEXT: &[Win16Parameter] = &[
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
        name: "capacity",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
];
pub(super) const WNET_OPEN_JOB: &[Win16Parameter] = &[
    Win16Parameter {
        name: "queue",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
    Win16Parameter {
        name: "job_name",
        kind: ArgumentKind::Dword,
        parameter_type: NULLABLE_FAR_STRING,
    },
    Win16Parameter {
        name: "copies",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "hfile_output",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
];
pub(super) const WNET_CLOSE_JOB: &[Win16Parameter] = &[
    Win16Parameter {
        name: "hfile",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "job_id_output",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_BUFFER,
    },
    Win16Parameter {
        name: "queue_name_output",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_BUFFER,
    },
];
pub(super) const WNET_QUEUE_JOB: &[Win16Parameter] = &[
    Win16Parameter {
        name: "queue",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
    Win16Parameter {
        name: "job_id",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
];
pub(super) const WNET_ABORT_JOB: &[Win16Parameter] = &[
    Win16Parameter {
        name: "queue",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
    Win16Parameter {
        name: "hfile",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
];
pub(super) const WNET_SET_JOB_COPIES: &[Win16Parameter] = &[
    Win16Parameter {
        name: "queue",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
    Win16Parameter {
        name: "job_id",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "copies",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
];
pub(super) const WNET_WATCH_QUEUE: &[Win16Parameter] = &[
    Win16Parameter {
        name: "owner",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "local_device",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
    Win16Parameter {
        name: "user",
        kind: ArgumentKind::Dword,
        parameter_type: NULLABLE_FAR_STRING,
    },
    Win16Parameter {
        name: "n_queue",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
];
pub(super) const WNET_QUEUE_NAME: &[Win16Parameter] = &[Win16Parameter {
    name: "queue",
    kind: ArgumentKind::Dword,
    parameter_type: FAR_STRING,
}];
pub(super) const WNET_LOCAL_DEVICE: &[Win16Parameter] = &[Win16Parameter {
    name: "local_device",
    kind: ArgumentKind::Dword,
    parameter_type: FAR_STRING,
}];
pub(super) const WNET_LOCK_QUEUE_DATA: &[Win16Parameter] = &[
    Win16Parameter {
        name: "queue",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
    Win16Parameter {
        name: "user",
        kind: ArgumentKind::Dword,
        parameter_type: NULLABLE_FAR_STRING,
    },
    Win16Parameter {
        name: "queue_data_output",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
];
pub(super) const WNET_GET_CONNECTION: &[Win16Parameter] = &[
    Win16Parameter {
        name: "local_name",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
    Win16Parameter {
        name: "remote_name_output",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
    Win16Parameter {
        name: "length_inout",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_BUFFER,
    },
];
pub(super) const WNET_WORD: &[Win16Parameter] = &[Win16Parameter {
    name: "value",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];
pub(super) const WNET_OWNER_TYPE: &[Win16Parameter] = &[
    Win16Parameter {
        name: "owner",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "resource_type",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
];
pub(super) const WNET_BROWSE_DIALOG: &[Win16Parameter] = &[
    Win16Parameter {
        name: "owner",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "resource_type",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "path_output",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
];
pub(super) const WNET_GET_USER: &[Win16Parameter] = &[
    Win16Parameter {
        name: "user_output",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
    Win16Parameter {
        name: "length_inout",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_BUFFER,
    },
];
pub(super) const WNET_ADD_CONNECTION: &[Win16Parameter] = &[
    Win16Parameter {
        name: "remote_name",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
    Win16Parameter {
        name: "password",
        kind: ArgumentKind::Dword,
        parameter_type: NULLABLE_FAR_STRING,
    },
    Win16Parameter {
        name: "local_name",
        kind: ArgumentKind::Dword,
        parameter_type: NULLABLE_FAR_STRING,
    },
];
pub(super) const WNET_CANCEL_CONNECTION: &[Win16Parameter] = &[
    Win16Parameter {
        name: "local_name",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
    Win16Parameter {
        name: "force",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
];
pub(super) const WNET_ERROR_OUTPUT: &[Win16Parameter] = &[Win16Parameter {
    name: "error_output",
    kind: ArgumentKind::Dword,
    parameter_type: FAR_OUTPUT_BUFFER,
}];
pub(super) const WNET_GET_ERROR_TEXT: &[Win16Parameter] = &[
    Win16Parameter {
        name: "error",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "text_output",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
    Win16Parameter {
        name: "length_inout",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_BUFFER,
    },
];
pub(super) const WNET_RESTORE_CONNECTION: &[Win16Parameter] = &[
    Win16Parameter {
        name: "owner",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "local_name",
        kind: ArgumentKind::Dword,
        parameter_type: NULLABLE_FAR_STRING,
    },
];
pub(super) const WNET_WRITE_JOB: &[Win16Parameter] = &[
    Win16Parameter {
        name: "hfile",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "data_far",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::FarPointer,
    },
    Win16Parameter {
        name: "length_far",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::FarPointer,
    },
];
pub(super) const WNET_VIEW_QUEUE: &[Win16Parameter] = &[
    Win16Parameter {
        name: "owner",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "queue",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
];
pub(super) const WNET_PROPERTY_DIALOG: &[Win16Parameter] = &[
    Win16Parameter {
        name: "owner",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "button",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "property",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "name",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
    Win16Parameter {
        name: "resource_type",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
];
pub(super) const WNET_DIRECTORY_TYPE: &[Win16Parameter] = &[
    Win16Parameter {
        name: "path",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
    Win16Parameter {
        name: "type_output",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
];
pub(super) const WNET_DIRECTORY_NOTIFY: &[Win16Parameter] = &[
    Win16Parameter {
        name: "owner",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "path",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
    Win16Parameter {
        name: "notification",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
];
pub(super) const WNET_GET_PROPERTY_TEXT: &[Win16Parameter] = &[
    Win16Parameter {
        name: "button",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "property",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "name",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
    Win16Parameter {
        name: "button_name_output",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
    Win16Parameter {
        name: "capacity",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "resource_type",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
];
