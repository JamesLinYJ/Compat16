//! Private, byte-aligned representations for fixed Win16 USER wire layouts.

use zerocopy::byteorder::little_endian::{I16, U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

// SDK 3.1 WINDOWPLACEMENT uses 16-bit UINT, POINT and RECT fields;
// the native binding has different widths and cannot describe this wire ABI.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WindowPlacement16Wire {
    pub(crate) length: U16,
    pub(crate) flags: U16,
    pub(crate) show_command: U16,
    pub(crate) minimum: [I16; 2],
    pub(crate) maximum: [I16; 2],
    pub(crate) normal: [I16; 4],
}

const _: () = {
    assert!(core::mem::size_of::<WindowPlacement16Wire>() == 22);
    assert!(core::mem::align_of::<WindowPlacement16Wire>() == 1);
    assert!(core::mem::offset_of!(WindowPlacement16Wire, length) == 0);
    assert!(core::mem::offset_of!(WindowPlacement16Wire, flags) == 2);
    assert!(core::mem::offset_of!(WindowPlacement16Wire, show_command) == 4);
    assert!(core::mem::offset_of!(WindowPlacement16Wire, minimum) == 6);
    assert!(core::mem::offset_of!(WindowPlacement16Wire, maximum) == 10);
    assert!(core::mem::offset_of!(WindowPlacement16Wire, normal) == 14);
};

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct Point16Wire {
    pub(crate) x: I16,
    pub(crate) y: I16,
}

const _: () = {
    assert!(core::mem::size_of::<Point16Wire>() == super::Point16::SIZE);
    assert!(core::mem::align_of::<Point16Wire>() == 1);
    assert!(core::mem::offset_of!(Point16Wire, x) == 0);
    assert!(core::mem::offset_of!(Point16Wire, y) == 2);
};

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WndClass16Wire {
    pub(crate) style: U16,
    pub(crate) lpfn_wnd_proc: U32,
    pub(crate) cb_cls_extra: I16,
    pub(crate) cb_wnd_extra: I16,
    pub(crate) h_instance: U16,
    pub(crate) h_icon: U16,
    pub(crate) h_cursor: U16,
    pub(crate) hbr_background: U16,
    pub(crate) lpsz_menu_name: U32,
    pub(crate) lpsz_class_name: U32,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct Msg16Wire {
    pub(crate) hwnd: U16,
    pub(crate) message: U16,
    pub(crate) w_param: U16,
    pub(crate) l_param: U32,
    pub(crate) time: U32,
    pub(crate) pt_x: I16,
    pub(crate) pt_y: I16,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct CreateStruct16Wire {
    pub(crate) lp_create_params: U32,
    pub(crate) h_instance: U16,
    pub(crate) h_menu: U16,
    pub(crate) hwnd_parent: U16,
    pub(crate) cy: I16,
    pub(crate) cx: I16,
    pub(crate) y: I16,
    pub(crate) x: I16,
    pub(crate) style: U32,
    pub(crate) lpsz_name: U32,
    pub(crate) lpsz_class: U32,
    pub(crate) dw_ex_style: U32,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct Rect16Wire {
    pub(crate) left: I16,
    pub(crate) top: I16,
    pub(crate) right: I16,
    pub(crate) bottom: I16,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct MinMaxInfo16Wire {
    pub(crate) pt_reserved_x: I16,
    pub(crate) pt_reserved_y: I16,
    pub(crate) pt_max_size_x: I16,
    pub(crate) pt_max_size_y: I16,
    pub(crate) pt_max_position_x: I16,
    pub(crate) pt_max_position_y: I16,
    pub(crate) pt_min_track_size_x: I16,
    pub(crate) pt_min_track_size_y: I16,
    pub(crate) pt_max_track_size_x: I16,
    pub(crate) pt_max_track_size_y: I16,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub(crate) struct WindowPos16Wire {
    pub(crate) hwnd: U16,
    pub(crate) hwnd_insert_after: U16,
    pub(crate) x: I16,
    pub(crate) y: I16,
    pub(crate) cx: I16,
    pub(crate) cy: I16,
    pub(crate) flags: U16,
}

const _: () = {
    use crate::user_abi::{
        createstruct16_offsets as create, msg16_offsets as msg,
        wndclass16_offsets as wndclass,
    };
    use crate::window_geometry::{
        minmaxinfo16_offsets as minmax, rect16_offsets as rect,
        windowpos16_offsets as windowpos,
    };

    assert!(core::mem::size_of::<WndClass16Wire>() == wndclass::SIZE);
    assert!(core::mem::align_of::<WndClass16Wire>() == 1);
    assert!(core::mem::offset_of!(WndClass16Wire, style) == wndclass::STYLE);
    assert!(core::mem::offset_of!(WndClass16Wire, lpfn_wnd_proc) == wndclass::LPFN_WND_PROC);
    assert!(core::mem::offset_of!(WndClass16Wire, cb_cls_extra) == wndclass::CB_CLS_EXTRA);
    assert!(core::mem::offset_of!(WndClass16Wire, cb_wnd_extra) == wndclass::CB_WND_EXTRA);
    assert!(core::mem::offset_of!(WndClass16Wire, h_instance) == wndclass::H_INSTANCE);
    assert!(core::mem::offset_of!(WndClass16Wire, h_icon) == wndclass::H_ICON);
    assert!(core::mem::offset_of!(WndClass16Wire, h_cursor) == wndclass::H_CURSOR);
    assert!(core::mem::offset_of!(WndClass16Wire, hbr_background) == wndclass::HBR_BACKGROUND);
    assert!(core::mem::offset_of!(WndClass16Wire, lpsz_menu_name) == wndclass::LPSZ_MENU_NAME);
    assert!(core::mem::offset_of!(WndClass16Wire, lpsz_class_name) == wndclass::LPSZ_CLASS_NAME);

    assert!(core::mem::size_of::<Msg16Wire>() == msg::SIZE);
    assert!(core::mem::align_of::<Msg16Wire>() == 1);
    assert!(core::mem::offset_of!(Msg16Wire, hwnd) == msg::HWND);
    assert!(core::mem::offset_of!(Msg16Wire, message) == msg::MESSAGE);
    assert!(core::mem::offset_of!(Msg16Wire, w_param) == msg::W_PARAM);
    assert!(core::mem::offset_of!(Msg16Wire, l_param) == msg::L_PARAM);
    assert!(core::mem::offset_of!(Msg16Wire, time) == msg::TIME);
    assert!(core::mem::offset_of!(Msg16Wire, pt_x) == msg::PT_X);
    assert!(core::mem::offset_of!(Msg16Wire, pt_y) == msg::PT_Y);

    assert!(core::mem::size_of::<CreateStruct16Wire>() == create::SIZE);
    assert!(core::mem::align_of::<CreateStruct16Wire>() == 1);
    assert!(core::mem::offset_of!(CreateStruct16Wire, lp_create_params) == create::LP_CREATE_PARAMS);
    assert!(core::mem::offset_of!(CreateStruct16Wire, h_instance) == create::H_INSTANCE);
    assert!(core::mem::offset_of!(CreateStruct16Wire, h_menu) == create::H_MENU);
    assert!(core::mem::offset_of!(CreateStruct16Wire, hwnd_parent) == create::HWND_PARENT);
    assert!(core::mem::offset_of!(CreateStruct16Wire, cy) == create::CY);
    assert!(core::mem::offset_of!(CreateStruct16Wire, cx) == create::CX);
    assert!(core::mem::offset_of!(CreateStruct16Wire, y) == create::Y);
    assert!(core::mem::offset_of!(CreateStruct16Wire, x) == create::X);
    assert!(core::mem::offset_of!(CreateStruct16Wire, style) == create::STYLE);
    assert!(core::mem::offset_of!(CreateStruct16Wire, lpsz_name) == create::LPSZ_NAME);
    assert!(core::mem::offset_of!(CreateStruct16Wire, lpsz_class) == create::LPSZ_CLASS);
    assert!(core::mem::offset_of!(CreateStruct16Wire, dw_ex_style) == create::DW_EX_STYLE);

    assert!(core::mem::size_of::<Rect16Wire>() == rect::SIZE);
    assert!(core::mem::align_of::<Rect16Wire>() == 1);
    assert!(core::mem::offset_of!(Rect16Wire, left) == rect::LEFT);
    assert!(core::mem::offset_of!(Rect16Wire, top) == rect::TOP);
    assert!(core::mem::offset_of!(Rect16Wire, right) == rect::RIGHT);
    assert!(core::mem::offset_of!(Rect16Wire, bottom) == rect::BOTTOM);

    assert!(core::mem::size_of::<MinMaxInfo16Wire>() == minmax::SIZE);
    assert!(core::mem::align_of::<MinMaxInfo16Wire>() == 1);
    assert!(core::mem::offset_of!(MinMaxInfo16Wire, pt_reserved_x) == minmax::PT_RESERVED_X);
    assert!(core::mem::offset_of!(MinMaxInfo16Wire, pt_reserved_y) == minmax::PT_RESERVED_Y);
    assert!(core::mem::offset_of!(MinMaxInfo16Wire, pt_max_size_x) == minmax::PT_MAX_SIZE_X);
    assert!(core::mem::offset_of!(MinMaxInfo16Wire, pt_max_size_y) == minmax::PT_MAX_SIZE_Y);
    assert!(core::mem::offset_of!(MinMaxInfo16Wire, pt_max_position_x) == minmax::PT_MAX_POSITION_X);
    assert!(core::mem::offset_of!(MinMaxInfo16Wire, pt_max_position_y) == minmax::PT_MAX_POSITION_Y);
    assert!(core::mem::offset_of!(MinMaxInfo16Wire, pt_min_track_size_x) == minmax::PT_MIN_TRACK_SIZE_X);
    assert!(core::mem::offset_of!(MinMaxInfo16Wire, pt_min_track_size_y) == minmax::PT_MIN_TRACK_SIZE_Y);
    assert!(core::mem::offset_of!(MinMaxInfo16Wire, pt_max_track_size_x) == minmax::PT_MAX_TRACK_SIZE_X);
    assert!(core::mem::offset_of!(MinMaxInfo16Wire, pt_max_track_size_y) == minmax::PT_MAX_TRACK_SIZE_Y);

    assert!(core::mem::size_of::<WindowPos16Wire>() == windowpos::SIZE);
    assert!(core::mem::align_of::<WindowPos16Wire>() == 1);
    assert!(core::mem::offset_of!(WindowPos16Wire, hwnd) == windowpos::HWND);
    assert!(core::mem::offset_of!(WindowPos16Wire, hwnd_insert_after) == windowpos::HWND_INSERT_AFTER);
    assert!(core::mem::offset_of!(WindowPos16Wire, x) == windowpos::X);
    assert!(core::mem::offset_of!(WindowPos16Wire, y) == windowpos::Y);
    assert!(core::mem::offset_of!(WindowPos16Wire, cx) == windowpos::CX);
    assert!(core::mem::offset_of!(WindowPos16Wire, cy) == windowpos::CY);
    assert!(core::mem::offset_of!(WindowPos16Wire, flags) == windowpos::FLAGS);
};
