//! Parameter layouts for GDI bounds, font metrics, and object queries.

use super::*;

// SDK 3.1 Volume 2 allows lprcBounds to be NULL for SetBoundsRect; FarBuffer
// preserves the pointer slot while the dedicated decoder keeps NULL distinct.
pub(super) const GDI_SET_BOUNDS_RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "dc",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "bounds_rect",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_BUFFER,
    },
    Win16Parameter {
        name: "flags",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
];

pub(super) const GDI_GET_BOUNDS_RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "dc",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "bounds_rect",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
    Win16Parameter {
        name: "flags",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
];

pub(super) const GDI_SET_MAPPER_FLAGS_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "dc",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "flags",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
];

pub(super) const GDI_GET_ASPECT_RATIO_FILTER_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "dc",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const GDI_GET_ASPECT_RATIO_FILTER_EX_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "dc",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "aspect_ratio",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
];

pub(super) const GDI_IS_GDI_OBJECT_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "object",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

// The SDK also permits the low word of lpszFilename to carry a loaded-module
// handle; the export's dedicated decoder handles that case before path decode.
pub(super) const GDI_ADD_FONT_RESOURCE_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "filename_or_module",
    kind: ArgumentKind::Dword,
    parameter_type: FAR_STRING,
}];

pub(super) const GDI_REMOVE_FONT_RESOURCE_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "filename_or_module",
    kind: ArgumentKind::Dword,
    parameter_type: FAR_STRING,
}];

// Microsoft Windows 3.1 SDK Disk 03: INC/WINDOWS.H declares
// BOOL WINAPI GetCharWidth(HDC, UINT, UINT, int FAR*), with 16-bit UINT/int.
// WLIB/LIBW.LIB independently records GETCHARWIDTH -> GDI ordinal 350 in its
// OMF IMPDEF at offset 0x4cb1. Source disk and expanded-library SHA-256:
// https://diskettes.pcjs.org/pcx86/sdk/windows/3.10/WIN31SDK-DISK03.json
// 234101bae0f50884a6e2f5f932ac2a53dd79c017ce174772b449a9d98e049c06
// Both queries have identical argument slots; their output element layouts
// differ and are handled by separate typed requests/runtime encoders.
pub(super) const GDI_GET_CHAR_WIDTH_PARAMETERS: &[Win16Parameter] =
    GDI_GET_CHAR_ABC_WIDTHS_PARAMETERS;

pub(super) const GDI_GET_CHAR_ABC_WIDTHS_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "dc",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "first_character",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "last_character",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "widths",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
];

// A NULL lpvBuffer or zero cbData requests the table size (SDK 3.1 Volume 2).
pub(super) const GDI_GET_FONT_DATA_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "dc",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "table",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
    Win16Parameter {
        name: "offset",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
    Win16Parameter {
        name: "buffer",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
    Win16Parameter {
        name: "byte_count",
        kind: ArgumentKind::Dword,
        parameter_type: SCALAR_DWORD,
    },
];

pub(super) const GDI_GET_RASTERIZER_CAPS_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "status",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
    Win16Parameter {
        name: "byte_count",
        kind: ArgumentKind::Word,
        parameter_type: SIGNED_SCALAR,
    },
];

// The SDK permits NULL lpkrnpair to query the total count, independent of
// cPairs; the dedicated decoder retains that nullable output pointer.
pub(super) const GDI_GET_KERNING_PAIRS_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter {
        name: "dc",
        kind: ArgumentKind::Word,
        parameter_type: SCALAR_WORD,
    },
    Win16Parameter {
        name: "pair_count",
        kind: ArgumentKind::Word,
        parameter_type: SIGNED_SCALAR,
    },
    Win16Parameter {
        name: "pairs",
        kind: ArgumentKind::Dword,
        parameter_type: FAR_OUTPUT_BUFFER,
    },
];
