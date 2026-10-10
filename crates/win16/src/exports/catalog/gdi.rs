//! Project-owned GDI parameter signatures for the export catalog.
//! The catalog is the production declaration source.

use super::*;

pub(super) const GDI_GET_OBJECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "object", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];
pub(super) const GDI_CREATE_COMPATIBLE_DC_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "source",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const GDI_DELETE_DC_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "dc",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const GDI_OBJECT_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "object",
    kind: ArgumentKind::Word,
    parameter_type: SCALAR_WORD,
}];

pub(super) const GDI_GET_DEVICE_CAPS_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "index", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_GET_STOCK_OBJECT_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "index",
    kind: ArgumentKind::Word,
    parameter_type: SIGNED_SCALAR,
}];

pub(super) const GDI_ENUM_FONTS_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "face_name", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter {
        name: "callback",
        kind: ArgumentKind::Dword,
        parameter_type: Win16ParameterType::FarPointer,
    },
    Win16Parameter { name: "parameter", kind: ArgumentKind::Dword, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_MUL_DIV_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "multiplicand", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "multiplier", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "divisor", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_LINE_DDA_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "x_start", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y_start", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "x_end", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y_end", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "callback", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::FarPointer },
    Win16Parameter { name: "data", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const GDI_SELECT_OBJECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "object", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const GDI_DC_COLOR_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "color", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const GDI_DC_MODE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "mode", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_DC_POINT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_RECTANGLE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "left", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "top", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "right", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "bottom", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_TEXT_OUTPUT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "text", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_BIT_BLT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "destination", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "destination_x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "destination_y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "source", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "source_x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "source_y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "rop", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const GDI_BRUSH_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "color",
    kind: ArgumentKind::Dword,
    parameter_type: SCALAR_DWORD,
}];

pub(super) const GDI_GET_TEXT_EXTENT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "text", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

/// The `init_data` FAR slot accepts null to request the default device mode;
/// its raw guest value is preserved for runtime-side DEVMODE16 decoding.
pub(super) const GDI_CREATE_DC_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "driver", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "device", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
    Win16Parameter { name: "init_data", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const GDI_CREATE_PEN_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "style", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "color", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const GDI_INDIRECT_PEN_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "logpen", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER,
}];

pub(super) const GDI_CREATE_FONT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "escapement", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "orientation", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "weight", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "italic", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "underline", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "strikeout", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "char_set", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "out_precision", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "clip_precision", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "quality", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "pitch_and_family", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "face_name", kind: ArgumentKind::Dword, parameter_type: NULLABLE_FAR_STRING },
];

pub(super) const GDI_INDIRECT_FONT_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "logfont", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER,
}];

pub(super) const GDI_CREATE_BITMAP_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "planes", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bits_per_pixel", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bits", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const GDI_INDIRECT_BITMAP_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "bitmap", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER,
}];

pub(super) const GDI_INDIRECT_BRUSH_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "logbrush", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER,
}];

pub(super) const GDI_COMPATIBLE_BITMAP_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_DC_HANDLE_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD,
}];

pub(super) const GDI_DC_RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "left", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "top", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "right", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "bottom", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_PAT_BLT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "rop", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const GDI_PIXEL_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_SET_PIXEL_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "color", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const GDI_STRETCH_BLT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "destination", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "destination_x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "destination_y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "source", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "source_x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "source_y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "source_width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "source_height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "rop", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const GDI_POINTS_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "points", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_POINTS_OUTPUT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "points", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_CLIP_BOX_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const GDI_RECT_VISIBLE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const GDI_DC_ALIGNMENT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "alignment", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const GDI_EXT_TEXT_OUT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "options", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "text", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "spacing", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const GDI_TEXT_EXTENT_POINT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "text", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "size", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const GDI_DC_OUTPUT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const GDI_DC_POINT_OUTPUT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const GDI_DC_SCALE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "x_numerator", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "x_denominator", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y_numerator", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y_denominator", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_DC_SCALE_OUTPUT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "x_numerator", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "x_denominator", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y_numerator", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y_denominator", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const GDI_DC_EXTRA_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "extra", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_RESTORE_DC_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "saved", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_TEXT_JUSTIFICATION_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "extra", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "breaks", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_GET_TEXT_METRICS_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const GDI_GET_TEXT_FACE_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const GDI_ARC_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "left", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "top", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "right", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "bottom", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "start_x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "start_y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "end_x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "end_y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_ROUND_RECT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "left", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "top", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "right", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "bottom", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "ellipse_width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "ellipse_height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_FLOOD_FILL_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "color", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const GDI_EXT_FLOOD_FILL_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "color", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "fill_type", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const GDI_REGION_PAIR_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "first", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "second", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const GDI_REGION_OFFSET_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "region", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_RECT_REGION_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "region", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "left", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "top", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "right", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "bottom", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_REGION_BOX_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "region", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const GDI_RECT_IN_REGION_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "region", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const GDI_FRAME_REGION_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "region", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "brush", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_REGION_OPERATION_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "region", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const GDI_FILL_REGION_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "region", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "brush", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const GDI_COMBINE_REGION_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "destination", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "source1", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "source2", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "mode", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_POLYGON_RGN_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "points", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "fill_mode", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_POLYGON_POLYGON_RGN_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "points", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "polygon_counts", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "polygon_count", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "fill_mode", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_POLY_POLYGON_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "points", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "counts", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "polygon_count", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const GDI_GET_PATH_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "points", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "types", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_SELECT_CLIP_PATH_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "mode", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const GDI_EXT_SELECT_CLIP_REGION_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "region", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "mode", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_RECT_COORDINATES_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "left", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "top", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "right", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "bottom", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_INDIRECT_RECT_PARAMETERS: &[Win16Parameter] = &[Win16Parameter {
    name: "rect", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER,
}];

pub(super) const GDI_ROUND_RECT_COORDINATES_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "left", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "top", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "right", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "bottom", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "ellipse_width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "ellipse_height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const GDI_REGION_POINT_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "region", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

// GDI.58/60/445: Pascal WORD handles/styles, DWORD COLORREF, WORD HBRUSH.
pub(super) const GDI_HATCH_BRUSH_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "hatch", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "color", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const GDI_PATTERN_BRUSH_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "bitmap", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const GDI_DIB_PATTERN_BRUSH_PARAMETERS: &[Win16Parameter] = &[
    Win16Parameter { name: "dib", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "color_usage", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];
