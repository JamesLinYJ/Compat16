//! Project-owned KERNEL parameter signatures for the export catalog.
//! The catalog is the production declaration source.

use super::*;

// Win16 signatures and KERNEL ordinals: Open Watcom win16.mh and kernel.def,
// revision 08a5064dd9831edf10234844630e605e83606989. Win16 int is signed
// 16-bit; LPCSTR/LPSTR use four-byte FAR slots, and all six results use AX.
pub(super) const INIT_ATOM_TABLE_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "buckets",
    kind: ArgumentKind::Word,
    parameter_type: SIGNED_SCALAR,
}];

pub(super) const ATOM_NAME_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "name",
    kind: ArgumentKind::Dword,
    parameter_type: Win16ParameterType::AtomName,
}];

pub(super) const ATOM_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "atom",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const GET_ATOM_NAME_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "atom",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "buffer",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
    Win16Parameter {
        name: "capacity",
        kind: ArgumentKind::Word,
        parameter_type: SIGNED_SCALAR,
    },
];

pub(super) const LCLOSE_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "file_handle",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const LOPEN_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "path", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "mode", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];
pub(super) const OPEN_FILE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "path", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "reopen", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "style", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
pub(super) const WIN_EXEC_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "command_line", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "show", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const LREAD_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "file_handle", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "buffer", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const LLSEEK_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "file_handle", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "offset", kind: ArgumentKind::Dword, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "origin", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GLOBAL_ALLOC_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "size", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const GLOBAL_REALLOC_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "handle", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "size", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const GLOBAL_COMPACT_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "minimum_free", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD,
}];

pub(super) const GLOBAL_DOS_ALLOC_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "size", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD,
}];

pub(super) const GLOBAL_CHANGE_LOCK_COUNT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "handle", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "delta", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GLOBAL_OWNER_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "handle", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "owner", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const GLOBAL_HANDLE_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "handle",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const GLOBAL_SELECTOR_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "selector",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const LONG_SELECTOR_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "guest_linear",
    kind: ArgumentKind::Dword,
    parameter_type: SCALAR_DWORD,
}];

pub(super) const FAR_SELECTOR_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "far_pointer",
    kind: ArgumentKind::Dword,
    parameter_type: Win16ParameterType::FarPointer,
}];

pub(super) const GLOBAL_SEGMENT_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "segment", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD,
}];

pub(super) const GET_FREE_SPACE_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD,
}];

pub(super) const LOCAL_INIT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "selector", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "start", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "end", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const LOCAL_ALLOC_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "size", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const LOCAL_REALLOC_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "handle", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "size", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "flags", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const LOCAL_HANDLE_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "handle",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const LOCAL_OFFSET_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "offset",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const LOCAL_HANDLE_DELTA_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "delta",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const LOCAL_MINIMUM_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "minimum",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const LCREAT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "path", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "attributes", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const LWRITE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "file_handle", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "buffer", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const HREAD_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "file_handle", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "buffer", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Dword, parameter_type: SIGNED_SCALAR },
];

pub(super) const HWRITE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "file_handle", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "buffer", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Dword, parameter_type: SIGNED_SCALAR },
];

pub(super) const HMEMCPY_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "destination", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "source", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Dword, parameter_type: SIGNED_SCALAR },
];

pub(super) const EXIT_PROCESS_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "status",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const TASK_EVENT_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "task_handle",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const SET_HANDLE_COUNT_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "requested_count",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const SET_ERROR_MODE_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "mode",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const GET_DRIVE_TYPE_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "drive",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const PRESTO_CHANGO_SELECTOR_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "source_selector", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "destination_selector", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const ALLOC_CS_TO_DS_ALIAS_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "source_selector",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const ALLOC_SELECTOR_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "source_selector",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const FREE_SELECTOR_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "selector",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const SELECTOR_LIMIT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "selector", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "limit", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const SELECTOR_BASE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "selector", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "base", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const SELECTOR_ACCESS_RIGHTS_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "selector", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "operation", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "value", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const SELECTOR_ARRAY_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "count", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD,
}];

pub(super) const LONG_PTR_ADD_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "pointer", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "add", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];


pub(super) const GET_MODULE_FILE_NAME_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "module", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter {
        name: "output_buffer",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GET_MODULE_HANDLE_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    // This is a far-string slot, but the comparison implementation also interprets a selector-zero
    // value as an HINSTANCE16. The decoder discriminates on the high word.
    name: "module_or_name",
    kind: ArgumentKind::Dword,
    parameter_type: SCALAR_DWORD,
}];

pub(super) const GET_MODULE_USAGE_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "module",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const GET_PROC_ADDRESS_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "module", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter {
        // A FARPROC name is a FAR string; a selector-zero slot carries an ordinal.
        name: "procedure_name_or_ordinal",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
];

pub(super) const LOAD_LIBRARY_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "library_name",
    kind: ArgumentKind::Dword,
    parameter_type: FAR_STRING,
}];

pub(super) const FREE_LIBRARY_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "module",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const FIND_RESOURCE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "module", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter {
        name: "name",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::ResourceName,
    },
    Win16Parameter {
        name: "resource_type",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::ResourceName,
    },
];

pub(super) const RESOURCE_MODULE_INFO_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "module", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "info", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const RESOURCE_DATA_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "data",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const ALLOC_RESOURCE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "module", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "info", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "size", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const SET_RESOURCE_HANDLER_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "module", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter {
        name: "type_name",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::ResourceName,
    },
    Win16Parameter {
        name: "handler",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::FarPointer,
    },
];

pub(super) const DEF_RESOURCE_HANDLER_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "data", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "module", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "info", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const MAKE_PROC_INSTANCE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "procedure", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::FarPointer },
    Win16Parameter { name: "instance", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const FREE_PROC_INSTANCE_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "procedure",
    kind: ArgumentKind::Dword,
    parameter_type: Win16ParameterType::FarPointer,
}];

pub(super) const PROFILE_INT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "section", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "key", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "default_value", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "filename", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
];

pub(super) const PROFILE_GET_INT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "section", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "key", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "default_value", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const PROFILE_STRING_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "section", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "key", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "default_value", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "output_buffer", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "filename", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
];

pub(super) const PROFILE_GET_STRING_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "section", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "key", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "default_value", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "output_buffer", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "capacity", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const PROFILE_WRITE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "section", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "key", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "value", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "filename", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
];

pub(super) const STRING_COMPARE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "left", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
    Win16Parameter { name: "right", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
];

pub(super) const STRING_LENGTH_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "text",
    kind: ArgumentKind::Dword,
    parameter_type: NULLABLE_FAR_STRING,
}];

pub(super) const STRING_COPY_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "destination", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "source", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
];

pub(super) const STRING_CONCAT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "destination", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "source", kind: ArgumentKind::Dword, parameter_type: FAR_STRING },
];
