//! Windows 3.1 KERNEL file-system export stack layouts.

use super::*;

pub(super) const FILE_CDR: &[Win16Parameter] = &[Win16Parameter {
    name: "procedure",
    kind: ArgumentKind::Dword,
    parameter_type: Win16ParameterType::FarPointer,
}];

pub(super) const CREATE_DIRECTORY: &[Win16Parameter] = &[
    Win16Parameter {
        name: "path",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
    Win16Parameter {
        name: "security_attributes",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::FarPointer,
    },
];

pub(super) const REMOVE_DIRECTORY: &[Win16Parameter] = &[Win16Parameter {
    name: "path",
    kind: ArgumentKind::Dword,
    parameter_type: FAR_STRING,
}];

pub(super) const DELETE_FILE: &[Win16Parameter] = &[Win16Parameter {
    name: "path",
    kind: ArgumentKind::Dword,
    parameter_type: FAR_STRING,
}];

pub(super) const GET_CURRENT_DIRECTORY: &[Win16Parameter] = &[
    Win16Parameter {
        name: "capacity",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
    Win16Parameter {
        name: "output",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
];

pub(super) const SET_CURRENT_DIRECTORY: &[Win16Parameter] = &[Win16Parameter {
    name: "path",
    kind: ArgumentKind::Dword,
    parameter_type: FAR_STRING,
}];

pub(super) const FIND_FIRST_FILE: &[Win16Parameter] = &[
    Win16Parameter {
        name: "search_file",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
    Win16Parameter {
        name: "find_data",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
];

pub(super) const FIND_NEXT_FILE: &[Win16Parameter] = &[
    Win16Parameter {
        name: "search_handle",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "find_data",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
];

pub(super) const FIND_CLOSE: &[Win16Parameter] = &[Win16Parameter {
    name: "search_handle",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const GET_FILE_ATTRIBUTES: &[Win16Parameter] = &[Win16Parameter {
    name: "path",
    kind: ArgumentKind::Dword,
    parameter_type: FAR_STRING,
}];

pub(super) const SET_FILE_ATTRIBUTES: &[Win16Parameter] = &[
    Win16Parameter {
        name: "path",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_STRING,
    },
    Win16Parameter {
        name: "attributes",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
];

pub(super) const GET_DISK_FREE_SPACE: &[Win16Parameter] = &[
    Win16Parameter {
        name: "root_path",
        kind: ArgumentKind::Dword,
        parameter_type: NULLABLE_FAR_STRING,
    },
    Win16Parameter {
        name: "sectors_per_cluster",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
    Win16Parameter {
        name: "bytes_per_sector",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
    Win16Parameter {
        name: "free_clusters",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
    Win16Parameter {
        name: "total_clusters",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
];
