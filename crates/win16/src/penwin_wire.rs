//! Fixed Windows 3.1 Pen Windows guest layouts.
//!
//! These records use packed little-endian 16-bit guest fields. Host Windows
//! structures use different widths/alignment, and far pointers here are only
//! guest selector:offset values. `zerocopy` supplies checked fixed-layout byte
//! access; it does not validate guest ranges, handles, or callback identities.

use core::mem::{align_of, offset_of, size_of};

use zerocopy::byteorder::little_endian::{I16, I32, U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct Point16Wire {
    pub(crate) x: I16,
    pub(crate) y: I16,
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct Rect16Wire {
    pub(crate) left: I16,
    pub(crate) top: I16,
    pub(crate) right: I16,
    pub(crate) bottom: I16,
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct OemPenInfoWire {
    pub(crate) data_type: U16,
    pub(crate) value_max: U16,
    pub(crate) distinct: U16,
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct PenInfoWire {
    pub(crate) raw_width: U16,
    pub(crate) raw_height: U16,
    pub(crate) distinct_width: U16,
    pub(crate) distinct_height: U16,
    pub(crate) sampling_rate: I16,
    pub(crate) sampling_distance: I16,
    pub(crate) capabilities: I32,
    pub(crate) pens: I16,
    pub(crate) oem_data_bytes: I16,
    pub(crate) oem_pen_info: [OemPenInfoWire; 6],
    pub(crate) reserved: [U16; 8],
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct PenPacketWire {
    pub(crate) tablet_x: U16,
    pub(crate) tablet_y: U16,
    pub(crate) pen_data_kind: U16,
    pub(crate) oem_data: [U16; 6],
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct StrokeInfoWire {
    pub(crate) point_count: U16,
    pub(crate) point_bytes: U16,
    pub(crate) pen_data_kind: U16,
    pub(crate) tick: U32,
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct CalibrationWire {
    pub(crate) offset_x: I16,
    pub(crate) offset_y: I16,
    pub(crate) distinct_width: I16,
    pub(crate) distinct_height: I16,
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct GuideWire {
    pub(crate) values: [I16; 9],
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct RecognizerContextWire {
    pub(crate) recognizer_handle: U16,
    pub(crate) window: U16,
    pub(crate) event_ref: U16,
    pub(crate) preferences: U16,
    pub(crate) options: I32,
    pub(crate) yield_callback: U32,
    pub(crate) user_data: [u8; 32],
    pub(crate) country: U16,
    pub(crate) international_preferences: U16,
    pub(crate) language: [u8; 44],
    pub(crate) dictionaries: [U32; 16],
    pub(crate) try_dictionary: U16,
    pub(crate) error_level: I16,
    pub(crate) allowed_characters: I32,
    pub(crate) priority_characters: I32,
    pub(crate) character_flags: [u8; 32],
    pub(crate) result_mode: U16,
    pub(crate) timeout: U16,
    pub(crate) pen_collection_mode: I32,
    pub(crate) bound: Rect16Wire,
    pub(crate) exclude: Rect16Wire,
    pub(crate) guide: GuideWire,
    pub(crate) orientation: U16,
    pub(crate) direction: U16,
    pub(crate) ink_width: I16,
    pub(crate) ink_color: U32,
    pub(crate) app_parameter: U32,
    pub(crate) dictionary_parameter: U32,
    pub(crate) recognizer_parameter: U32,
    pub(crate) reserved: [U16; 8],
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct SycWire {
    pub(crate) values: [U16; 4],
    pub(crate) last_segment: I16,
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct SyeWire {
    pub(crate) symbol: I32,
    pub(crate) recognition_value: I32,
    pub(crate) confidence: I16,
    pub(crate) segment_index: I16,
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct SygWire {
    pub(crate) hot_spots: [Point16Wire; 8],
    pub(crate) hot_spot_count: I16,
    pub(crate) first_box: I16,
    pub(crate) recognition_value: I32,
    pub(crate) symbol_entries: U32,
    pub(crate) symbol_entry_count: I16,
    pub(crate) segments: U32,
    pub(crate) segment_count: I16,
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct RecognitionResultWire {
    pub(crate) graph: SygWire,
    pub(crate) result_type: U16,
    pub(crate) symbol_count: I16,
    pub(crate) symbols: U32,
    pub(crate) symbol_handle: U16,
    pub(crate) baseline: I16,
    pub(crate) midline: I16,
    pub(crate) pen_data_handle: U16,
    pub(crate) ink_bounds: Rect16Wire,
    pub(crate) end_point: Point16Wire,
    pub(crate) context: U32,
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct PenDataHeaderWire {
    pub(crate) version: U16,
    pub(crate) bytes_used: U16,
    pub(crate) stroke_count: U16,
    pub(crate) point_count: U16,
    pub(crate) max_points_per_stroke: U16,
    pub(crate) bounds: Rect16Wire,
    pub(crate) scale_kind: U16,
    pub(crate) ink_width: I16,
    pub(crate) ink_color: U32,
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct RectOffsetWire {
    pub(crate) values: [I16; 4],
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct BoxLayoutWire {
    pub(crate) cusp_height: I16,
    pub(crate) end_cusp_height: I16,
    pub(crate) style: U16,
    pub(crate) colors: [U32; 3],
}

#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct ScreenKeyboardInfoWire {
    pub(crate) window: U16,
    pub(crate) pad: U16,
    pub(crate) visible: I16,
    pub(crate) minimized: I16,
    pub(crate) bounds: Rect16Wire,
    pub(crate) reserved: U32,
}

const _: () = {
    assert!(size_of::<Point16Wire>() == 4);
    assert!(align_of::<Point16Wire>() == 1);
    assert!(offset_of!(Point16Wire, y) == 2);
    assert!(size_of::<Rect16Wire>() == 8);
    assert!(align_of::<Rect16Wire>() == 1);
    assert!(offset_of!(Rect16Wire, right) == 4);
    assert!(offset_of!(Rect16Wire, bottom) == 6);
    assert!(size_of::<OemPenInfoWire>() == 6);
    assert!(size_of::<PenInfoWire>() == 72);
    assert!(offset_of!(PenInfoWire, capabilities) == 12);
    assert!(offset_of!(PenInfoWire, oem_pen_info) == 20);
    assert!(size_of::<PenPacketWire>() == 18);
    assert!(size_of::<StrokeInfoWire>() == 10);
    assert!(offset_of!(StrokeInfoWire, tick) == 6);
    assert!(size_of::<CalibrationWire>() == 8);
    assert!(size_of::<GuideWire>() == 18);
    assert!(size_of::<RecognizerContextWire>() == 284);
    assert!(offset_of!(RecognizerContextWire, dictionaries) == 96);
    assert!(offset_of!(RecognizerContextWire, bound) == 212);
    assert!(size_of::<SycWire>() == 10);
    assert!(size_of::<SyeWire>() == 12);
    assert!(size_of::<SygWire>() == 52);
    assert!(offset_of!(SygWire, symbol_entries) == 40);
    assert!(size_of::<RecognitionResultWire>() == 84);
    assert!(offset_of!(RecognitionResultWire, ink_bounds) == 68);
    assert!(size_of::<PenDataHeaderWire>() == 26);
    assert!(offset_of!(PenDataHeaderWire, scale_kind) == 18);
    assert!(size_of::<RectOffsetWire>() == 8);
    assert!(size_of::<BoxLayoutWire>() == 18);
    assert!(size_of::<ScreenKeyboardInfoWire>() == 20);
};
