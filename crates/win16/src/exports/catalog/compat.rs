//! Project-owned Win16 COMPOBJ, VER, LZEXPAND, and SHELL stack signatures.

use super::*;

pub(super) const COM_GUID_COMPARE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "left", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "right", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const VER_RESOURCE_SIZE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "path", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "resource_type", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::ResourceName },
    Win16Parameter { name: "name", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::ResourceName },
    Win16Parameter { name: "size_output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const VER_GET_RESOURCE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "path", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "resource_type", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::ResourceName },
    Win16Parameter { name: "name", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::ResourceName },
    Win16Parameter { name: "offset", kind: ArgumentKind::Dword, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "count", kind: ArgumentKind::Dword, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const VER_VERSION_INFO_SIZE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "path", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "handle_output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const VER_VERSION_INFO_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "path", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "handle", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const VER_FIND_FILE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "file", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "windows_dir", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "app_dir", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "dir_output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "dir_capacity_output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "file_output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "file_capacity_output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const VER_INSTALL_FILE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "source", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "destination", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "source_dir", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "destination_dir", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "current_dir", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "scratch_output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "scratch_capacity_output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const VER_LANGUAGE_NAME_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "language", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const VER_QUERY_VALUE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "block", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "sub_block", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "value_output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "length_output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const LZ_COPY_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "source", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "destination", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const LZ_OPEN_FILE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "path", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "ofstruct", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "style", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const LZ_FILE_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "file", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR,
}];

pub(super) const LZ_SEEK_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "file", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "offset", kind: ArgumentKind::Dword, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "origin", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const LZ_READ_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "file", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const LZ_GET_EXPANDED_NAME_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "source", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const SHELL_DO_ENVIRONMENT_SUBST_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "buffer", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const SHELL_FIND_ENVIRONMENT_STRING_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "query", kind: ArgumentKind::Dword, parameter_type: FAR_STRING,
}];
