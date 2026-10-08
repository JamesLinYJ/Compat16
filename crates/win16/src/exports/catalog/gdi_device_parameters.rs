//! Parameter layouts for the GDI bitmap, DIB, palette, and print records.
//!
//! Active descriptors are registered in `catalog/declarations.rs`; retaining
//! a signature here does not itself expose an implementation to the guest.

use super::*;

pub(super) const GET_BITMAP_BITS: &[Win16Parameter] = &[
    Win16Parameter { name: "bitmap", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "byte_count", kind: ArgumentKind::Dword, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "output", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const SET_BITMAP_BITS: &[Win16Parameter] = &[
    Win16Parameter { name: "bitmap", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "byte_count", kind: ArgumentKind::Dword, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "bits", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const CREATE_DISCARDABLE_BITMAP: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const CREATE_PALETTE: &[Win16Parameter] = &[
    Win16Parameter { name: "log_palette", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const SELECT_PALETTE: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "palette", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "force_background", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const DC_HANDLE: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const PALETTE_ENTRIES: &[Win16Parameter] = &[
    Win16Parameter { name: "palette", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "start", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "entries", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const PALETTE_ENTRIES_OUTPUT: &[Win16Parameter] = &[
    Win16Parameter { name: "palette", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "start", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "entries", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const RESIZE_PALETTE: &[Win16Parameter] = &[
    Win16Parameter { name: "palette", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const NEAREST_PALETTE_INDEX: &[Win16Parameter] = &[
    Win16Parameter { name: "palette", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "color", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const SYSTEM_PALETTE_USE: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "use_mode", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const SYSTEM_PALETTE_ENTRIES: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "start", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "entries", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const RESET_DC: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "devmode", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const START_DOC: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "doc_info", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const SET_ABORT_PROC: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "callback", kind: ArgumentKind::Dword, parameter_type: Win16ParameterType::FarPointer },
];

// Microsoft Windows 3.1 SDK Programmer's Reference, Volume 2:
// StretchDIBits takes lpvBits before lpbmi; Set/GetDIBits take hdc before
// hbitmap. Equal-width ABI slots do not reveal an accidental semantic swap.
// https://www.bitsavers.org/pdf/microsoft/windows_3.1/Microsoft_Windows_3.1_SDK_1992/PC28916-0492_Programmers_Reference_Volume_2_199204.pdf
pub(super) const STRETCH_DIBITS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "destination_x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "destination_y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "destination_width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "destination_height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "source_x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "source_y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "source_width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "source_height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "bits", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "info", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "usage", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "rop", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
];

pub(super) const SET_DIBITS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bitmap", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "start_scan", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "scan_lines", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bits", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "info", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "color_usage", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const GET_DIBITS: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bitmap", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "start_scan", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "scan_lines", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bits", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
    // BITMAPINFO supplies requested format fields and receives the resolved
    // format, so the current catalog's generic buffer kind describes its input.
    Win16Parameter { name: "info", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "color_usage", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const CREATE_DIBITMAP: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "header", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "init_flags", kind: ArgumentKind::Dword, parameter_type: SCALAR_DWORD },
    Win16Parameter { name: "bits", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "info", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "color_usage", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const DIBITS_TO_DEVICE: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "destination_x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "destination_y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "source_x", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "source_y", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "start_scan", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "scan_lines", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "bits", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "info", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
    Win16Parameter { name: "color_usage", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const BITMAP_DIMENSION: &[Win16Parameter] = &[
    Win16Parameter { name: "bitmap", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const SET_BITMAP_DIMENSION: &[Win16Parameter] = &[
    Win16Parameter { name: "bitmap", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
];

pub(super) const BITMAP_DIMENSION_EX: &[Win16Parameter] = &[
    Win16Parameter { name: "bitmap", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "size", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const SET_BITMAP_DIMENSION_EX: &[Win16Parameter] = &[
    Win16Parameter { name: "bitmap", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "width", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "height", kind: ArgumentKind::Word, parameter_type: SIGNED_SCALAR },
    Win16Parameter { name: "size", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];

pub(super) const CREATE_HALFTONE_PALETTE: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
];

pub(super) const DIB_COLOR_TABLE_SET: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "start", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "colors", kind: ArgumentKind::Dword, parameter_type: FAR_BUFFER },
];

pub(super) const DIB_COLOR_TABLE_GET: &[Win16Parameter] = &[
    Win16Parameter { name: "dc", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "start", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "count", kind: ArgumentKind::Word, parameter_type: SCALAR_WORD },
    Win16Parameter { name: "colors", kind: ArgumentKind::Dword, parameter_type: FAR_OUTPUT_BUFFER },
];
