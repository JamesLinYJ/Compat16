//! Private byte-aligned representations of Windows 3.1 owner-draw records.

use zerocopy::byteorder::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::user_abi::wire::Rect16Wire;

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct DrawItemStruct16Wire {
    pub(super) ctl_type: U16,
    pub(super) ctl_id: U16,
    pub(super) item_id: U16,
    pub(super) item_action: U16,
    pub(super) item_state: U16,
    pub(super) hwnd_item: U16,
    pub(super) hdc: U16,
    pub(super) rc_item: Rect16Wire,
    pub(super) item_data: U32,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct MeasureItemStruct16Wire {
    pub(super) ctl_type: U16,
    pub(super) ctl_id: U16,
    pub(super) item_id: U16,
    pub(super) item_width: U16,
    pub(super) item_height: U16,
    pub(super) item_data: U32,
}

/// The only bytes the Win16 owner may return from WM_MEASUREITEM.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct MeasureItemOutputs16Wire {
    pub(super) item_width: U16,
    pub(super) item_height: U16,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct DeleteItemStruct16Wire {
    pub(super) ctl_type: U16,
    pub(super) ctl_id: U16,
    pub(super) item_id: U16,
    pub(super) hwnd_item: U16,
    pub(super) item_data: U32,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(super) struct CompareItemStruct16Wire {
    pub(super) ctl_type: U16,
    pub(super) ctl_id: U16,
    pub(super) hwnd_item: U16,
    pub(super) item_id1: U16,
    pub(super) item_data1: U32,
    pub(super) item_id2: U16,
    pub(super) item_data2: U32,
}

const _: () = {
    use super::{
        compare_item_struct16_offsets as compare,
        delete_item_struct16_offsets as delete,
        draw_item_struct16_offsets as draw,
        measure_item_struct16_offsets as measure,
    };

    assert!(core::mem::size_of::<DrawItemStruct16Wire>() == draw::SIZE);
    assert!(core::mem::align_of::<DrawItemStruct16Wire>() == 1);
    assert!(core::mem::offset_of!(DrawItemStruct16Wire, ctl_type) == draw::CTL_TYPE);
    assert!(core::mem::offset_of!(DrawItemStruct16Wire, ctl_id) == draw::CTL_ID);
    assert!(core::mem::offset_of!(DrawItemStruct16Wire, item_id) == draw::ITEM_ID);
    assert!(core::mem::offset_of!(DrawItemStruct16Wire, item_action) == draw::ITEM_ACTION);
    assert!(core::mem::offset_of!(DrawItemStruct16Wire, item_state) == draw::ITEM_STATE);
    assert!(core::mem::offset_of!(DrawItemStruct16Wire, hwnd_item) == draw::HWND_ITEM);
    assert!(core::mem::offset_of!(DrawItemStruct16Wire, hdc) == draw::HDC);
    assert!(core::mem::offset_of!(DrawItemStruct16Wire, rc_item) == draw::RC_ITEM);
    assert!(core::mem::size_of::<Rect16Wire>() == crate::window_geometry::Rect16::SIZE);
    assert!(draw::RC_ITEM + crate::window_geometry::Rect16::SIZE == draw::ITEM_DATA);
    assert!(core::mem::offset_of!(DrawItemStruct16Wire, item_data) == draw::ITEM_DATA);

    assert!(core::mem::size_of::<MeasureItemStruct16Wire>() == measure::SIZE);
    assert!(core::mem::align_of::<MeasureItemStruct16Wire>() == 1);
    assert!(core::mem::offset_of!(MeasureItemStruct16Wire, ctl_type) == measure::CTL_TYPE);
    assert!(core::mem::offset_of!(MeasureItemStruct16Wire, ctl_id) == measure::CTL_ID);
    assert!(core::mem::offset_of!(MeasureItemStruct16Wire, item_id) == measure::ITEM_ID);
    assert!(core::mem::offset_of!(MeasureItemStruct16Wire, item_width) == measure::ITEM_WIDTH);
    assert!(core::mem::offset_of!(MeasureItemStruct16Wire, item_height) == measure::ITEM_HEIGHT);
    assert!(measure::ITEM_WIDTH + measure::OUTPUT_SIZE == measure::ITEM_DATA);
    assert!(core::mem::offset_of!(MeasureItemStruct16Wire, item_data) == measure::ITEM_DATA);
    assert!(core::mem::size_of::<MeasureItemOutputs16Wire>() == measure::OUTPUT_SIZE);
    assert!(core::mem::align_of::<MeasureItemOutputs16Wire>() == 1);
    assert!(core::mem::offset_of!(MeasureItemOutputs16Wire, item_width) == 0);
    assert!(core::mem::offset_of!(MeasureItemOutputs16Wire, item_height) == 2);

    assert!(core::mem::size_of::<DeleteItemStruct16Wire>() == delete::SIZE);
    assert!(core::mem::align_of::<DeleteItemStruct16Wire>() == 1);
    assert!(core::mem::offset_of!(DeleteItemStruct16Wire, ctl_type) == delete::CTL_TYPE);
    assert!(core::mem::offset_of!(DeleteItemStruct16Wire, ctl_id) == delete::CTL_ID);
    assert!(core::mem::offset_of!(DeleteItemStruct16Wire, item_id) == delete::ITEM_ID);
    assert!(core::mem::offset_of!(DeleteItemStruct16Wire, hwnd_item) == delete::HWND_ITEM);
    assert!(core::mem::offset_of!(DeleteItemStruct16Wire, item_data) == delete::ITEM_DATA);

    assert!(core::mem::size_of::<CompareItemStruct16Wire>() == compare::SIZE);
    assert!(core::mem::align_of::<CompareItemStruct16Wire>() == 1);
    assert!(core::mem::offset_of!(CompareItemStruct16Wire, ctl_type) == compare::CTL_TYPE);
    assert!(core::mem::offset_of!(CompareItemStruct16Wire, ctl_id) == compare::CTL_ID);
    assert!(core::mem::offset_of!(CompareItemStruct16Wire, hwnd_item) == compare::HWND_ITEM);
    assert!(core::mem::offset_of!(CompareItemStruct16Wire, item_id1) == compare::ITEM_ID1);
    assert!(core::mem::offset_of!(CompareItemStruct16Wire, item_data1) == compare::ITEM_DATA1);
    assert!(core::mem::offset_of!(CompareItemStruct16Wire, item_id2) == compare::ITEM_ID2);
    assert!(core::mem::offset_of!(CompareItemStruct16Wire, item_data2) == compare::ITEM_DATA2);
};
