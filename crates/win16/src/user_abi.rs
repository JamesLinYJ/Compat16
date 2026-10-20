//! Checked codecs for fixed-layout Win16 USER structures.
//!
//! `WNDCLASS16`, `MSG16`, and `CREATESTRUCT16` use fixed Win16 field widths
//! and one-byte alignment. Guest pointer fields stay as raw 32-bit values here.
//! Callers must validate a pointer with `SelectorTable` before dereferencing
//! it; these codecs never
//! create a host pointer. Private wire structs use alignment-one little-endian
//! fields, with their sizes and offsets checked against the named ABI offsets.

use crate::{SegmentedPointer, SelectorTable, Win16Error};
use guest_core::GuestMemory;

#[path = "user_abi_wire.rs"]
pub(crate) mod wire;

/// Windows 3.1 `WINDOWPLACEMENT`. Positions are screen coordinates, the same
/// space as `GetWindowRect`. The host converts Win32 workspace coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowPlacement16 {
    pub length: u16,
    pub flags: u16,
    pub show_command: u16,
    pub minimum: Point16,
    pub maximum: Point16,
    pub normal: crate::Rect16,
}

impl WindowPlacement16 {
    pub const SIZE: usize = 22;

    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        let value: wire::WindowPlacement16Wire = zerocopy::transmute!(*bytes);
        Self {
            length: value.length.get(), flags: value.flags.get(),
            show_command: value.show_command.get(),
            minimum: Point16 { x: value.minimum[0].get(), y: value.minimum[1].get() },
            maximum: Point16 { x: value.maximum[0].get(), y: value.maximum[1].get() },
            normal: crate::Rect16 {
                left: value.normal[0].get(), top: value.normal[1].get(),
                right: value.normal[2].get(), bottom: value.normal[3].get(),
            },
        }
    }

    pub fn encode(self) -> [u8; Self::SIZE] {
        use zerocopy::byteorder::little_endian::{I16, U16};
        zerocopy::transmute!(wire::WindowPlacement16Wire {
            length: U16::new(self.length), flags: U16::new(self.flags),
            show_command: U16::new(self.show_command),
            minimum: [I16::new(self.minimum.x), I16::new(self.minimum.y)],
            maximum: [I16::new(self.maximum.x), I16::new(self.maximum.y)],
            normal: [I16::new(self.normal.left), I16::new(self.normal.top),
                I16::new(self.normal.right), I16::new(self.normal.bottom)],
        })
    }
}

/// Byte offsets in the packed Win16 `WNDCLASS16` ABI representation.
pub mod wndclass16_offsets {
    pub const STYLE: usize = 0;
    pub const LPFN_WND_PROC: usize = 2;
    pub const CB_CLS_EXTRA: usize = 6;
    pub const CB_WND_EXTRA: usize = 8;
    pub const H_INSTANCE: usize = 10;
    pub const H_ICON: usize = 12;
    pub const H_CURSOR: usize = 14;
    pub const HBR_BACKGROUND: usize = 16;
    pub const LPSZ_MENU_NAME: usize = 18;
    pub const LPSZ_CLASS_NAME: usize = 22;
    pub const SIZE: usize = 26;
}

/// Byte offsets in the packed Win16 `MSG16` ABI representation.
pub mod msg16_offsets {
    pub const HWND: usize = 0;
    pub const MESSAGE: usize = 2;
    pub const W_PARAM: usize = 4;
    pub const L_PARAM: usize = 6;
    pub const TIME: usize = 10;
    pub const PT_X: usize = 14;
    pub const PT_Y: usize = 16;
    pub const SIZE: usize = 18;
}

/// Byte offsets in the packed Win16 `CREATESTRUCT16` ABI representation.
pub mod createstruct16_offsets {
    pub const LP_CREATE_PARAMS: usize = 0;
    pub const H_INSTANCE: usize = 4;
    pub const H_MENU: usize = 6;
    pub const HWND_PARENT: usize = 8;
    pub const CY: usize = 10;
    pub const CX: usize = 12;
    pub const Y: usize = 14;
    pub const X: usize = 16;
    pub const STYLE: usize = 18;
    pub const LPSZ_NAME: usize = 22;
    pub const LPSZ_CLASS: usize = 26;
    pub const DW_EX_STYLE: usize = 30;
    pub const SIZE: usize = 34;
}

/// The Win16 `POINT16` coordinates embedded in `MSG16`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct Point16 {
    pub x: i16,
    pub y: i16,
}

impl Point16 {
    pub const SIZE: usize = 4;

    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        let value: wire::Point16Wire = zerocopy::transmute!(*bytes);
        Self { x: value.x.get(), y: value.y.get() }
    }

    pub fn encode(self) -> [u8; Self::SIZE] {
        use zerocopy::byteorder::little_endian::I16;
        zerocopy::transmute!(wire::Point16Wire {
            x: I16::new(self.x), y: I16::new(self.y),
        })
    }
}

/// Logical fields of the packed, 26-byte Win16 `WNDCLASS16` structure.
///
/// `lpfn_wnd_proc`, `lpsz_menu_name`, and `lpsz_class_name` retain their raw
/// guest `SEGPTR` bits. In particular, `lpfn_wnd_proc` must not be cast to or
/// called as a host function pointer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct WndClass16 {
    pub style: u16,
    pub lpfn_wnd_proc: u32,
    pub cb_cls_extra: i16,
    pub cb_wnd_extra: i16,
    pub h_instance: u16,
    pub h_icon: u16,
    pub h_cursor: u16,
    pub hbr_background: u16,
    pub lpsz_menu_name: u32,
    pub lpsz_class_name: u32,
}

impl WndClass16 {
    pub const SIZE: usize = wndclass16_offsets::SIZE;

    /// Decodes exactly one packed Win16 `WNDCLASS16` byte sequence.
    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        let wire: wire::WndClass16Wire = zerocopy::transmute!(*bytes);

        Self {
            style: wire.style.get(),
            lpfn_wnd_proc: wire.lpfn_wnd_proc.get(),
            cb_cls_extra: wire.cb_cls_extra.get(),
            cb_wnd_extra: wire.cb_wnd_extra.get(),
            h_instance: wire.h_instance.get(),
            h_icon: wire.h_icon.get(),
            h_cursor: wire.h_cursor.get(),
            hbr_background: wire.hbr_background.get(),
            lpsz_menu_name: wire.lpsz_menu_name.get(),
            lpsz_class_name: wire.lpsz_class_name.get(),
        }
    }

    /// Encodes this value as exactly 26 guest-format bytes.
    pub fn encode(self) -> [u8; Self::SIZE] {
        use zerocopy::byteorder::little_endian::{I16, U16, U32};

        let wire = wire::WndClass16Wire {
            style: U16::new(self.style),
            lpfn_wnd_proc: U32::new(self.lpfn_wnd_proc),
            cb_cls_extra: I16::new(self.cb_cls_extra),
            cb_wnd_extra: I16::new(self.cb_wnd_extra),
            h_instance: U16::new(self.h_instance),
            h_icon: U16::new(self.h_icon),
            h_cursor: U16::new(self.h_cursor),
            hbr_background: U16::new(self.hbr_background),
            lpsz_menu_name: U32::new(self.lpsz_menu_name),
            lpsz_class_name: U32::new(self.lpsz_class_name),
        };
        zerocopy::transmute!(wire)
    }

    /// Reads one structure after validating the guest selector, rights, and
    /// complete structure range.
    pub fn read_from(
        selectors: &SelectorTable,
        memory: &impl GuestMemory,
        pointer: SegmentedPointer,
    ) -> Result<Self, Win16Error> {
        Ok(Self::decode(&read_guest::<{ Self::SIZE }>(selectors, memory, pointer)?))
    }

    /// Writes one structure after validating the guest selector, rights, and
    /// complete structure range.
    pub fn write_to(
        self,
        selectors: &SelectorTable,
        memory: &mut impl GuestMemory,
        pointer: SegmentedPointer,
    ) -> Result<(), Win16Error> {
        write_guest(selectors, memory, pointer, &self.encode())
    }
}

/// Logical fields of the packed, 18-byte Win16 `MSG16` structure.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct Msg16 {
    pub hwnd: u16,
    pub message: u16,
    pub w_param: u16,
    /// Raw 32-bit `LPARAM16` bits, which may encode a guest far pointer.
    pub l_param: u32,
    pub time: u32,
    pub pt: Point16,
}

/// Logical fields of the packed, 34-byte Win16 `CREATESTRUCT16` structure.
///
/// The byte representation retains Win16 field order and widths. Microsoft documents the
/// corresponding creation-data, instance, menu, parent, geometry, style, title,
/// and class semantics for `CREATESTRUCT` in its Win32 API contract
/// ([Microsoft documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-createstructa)).
/// Pointer-shaped fields remain raw guest values; `lpsz_class` may also carry
/// a low-word class atom. They are never host pointers, and FAR pointers must
/// be validated by the caller before dereferencing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct CreateStruct16 {
    /// Application-supplied `CreateWindow` data, retained as raw guest bits.
    pub lp_create_params: u32,
    pub h_instance: u16,
    pub h_menu: u16,
    pub hwnd_parent: u16,
    pub cy: i16,
    pub cx: i16,
    pub y: i16,
    pub x: i16,
    pub style: u32,
    /// Guest FAR pointer to the window title, or a null FAR pointer.
    pub lpsz_name: u32,
    /// Guest FAR pointer to the class name, or a low-word class atom.
    pub lpsz_class: u32,
    pub dw_ex_style: u32,
}

impl CreateStruct16 {
    pub const SIZE: usize = createstruct16_offsets::SIZE;

    /// Decodes exactly one packed Win16 `CREATESTRUCT16` byte sequence.
    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        let wire: wire::CreateStruct16Wire = zerocopy::transmute!(*bytes);

        Self {
            lp_create_params: wire.lp_create_params.get(),
            h_instance: wire.h_instance.get(),
            h_menu: wire.h_menu.get(),
            hwnd_parent: wire.hwnd_parent.get(),
            cy: wire.cy.get(),
            cx: wire.cx.get(),
            y: wire.y.get(),
            x: wire.x.get(),
            style: wire.style.get(),
            lpsz_name: wire.lpsz_name.get(),
            lpsz_class: wire.lpsz_class.get(),
            dw_ex_style: wire.dw_ex_style.get(),
        }
    }

    /// Encodes this value as exactly 34 guest-format bytes.
    pub fn encode(self) -> [u8; Self::SIZE] {
        use zerocopy::byteorder::little_endian::{I16, U16, U32};

        let wire = wire::CreateStruct16Wire {
            lp_create_params: U32::new(self.lp_create_params),
            h_instance: U16::new(self.h_instance),
            h_menu: U16::new(self.h_menu),
            hwnd_parent: U16::new(self.hwnd_parent),
            cy: I16::new(self.cy),
            cx: I16::new(self.cx),
            y: I16::new(self.y),
            x: I16::new(self.x),
            style: U32::new(self.style),
            lpsz_name: U32::new(self.lpsz_name),
            lpsz_class: U32::new(self.lpsz_class),
            dw_ex_style: U32::new(self.dw_ex_style),
        };
        zerocopy::transmute!(wire)
    }

    /// Reads one structure after validating the guest selector, rights, and
    /// complete structure range.
    pub fn read_from(
        selectors: &SelectorTable,
        memory: &impl GuestMemory,
        pointer: SegmentedPointer,
    ) -> Result<Self, Win16Error> {
        Ok(Self::decode(&read_guest::<{ Self::SIZE }>(selectors, memory, pointer)?))
    }

    /// Writes one structure after validating the guest selector, rights, and
    /// complete structure range.
    pub fn write_to(
        self,
        selectors: &SelectorTable,
        memory: &mut impl GuestMemory,
        pointer: SegmentedPointer,
    ) -> Result<(), Win16Error> {
        write_guest(selectors, memory, pointer, &self.encode())
    }
}

impl Msg16 {
    pub const SIZE: usize = msg16_offsets::SIZE;

    /// Decodes exactly one packed Win16 `MSG16` byte sequence.
    pub fn decode(bytes: &[u8; Self::SIZE]) -> Self {
        let wire: wire::Msg16Wire = zerocopy::transmute!(*bytes);

        Self {
            hwnd: wire.hwnd.get(),
            message: wire.message.get(),
            w_param: wire.w_param.get(),
            l_param: wire.l_param.get(),
            time: wire.time.get(),
            pt: Point16 {
                x: wire.pt_x.get(),
                y: wire.pt_y.get(),
            },
        }
    }

    /// Encodes this value as exactly 18 guest-format bytes.
    pub fn encode(self) -> [u8; Self::SIZE] {
        use zerocopy::byteorder::little_endian::{I16, U16, U32};

        let wire = wire::Msg16Wire {
            hwnd: U16::new(self.hwnd),
            message: U16::new(self.message),
            w_param: U16::new(self.w_param),
            l_param: U32::new(self.l_param),
            time: U32::new(self.time),
            pt_x: I16::new(self.pt.x),
            pt_y: I16::new(self.pt.y),
        };
        zerocopy::transmute!(wire)
    }

    /// Reads one structure after validating the guest selector, rights, and
    /// complete structure range.
    pub fn read_from(
        selectors: &SelectorTable,
        memory: &impl GuestMemory,
        pointer: SegmentedPointer,
    ) -> Result<Self, Win16Error> {
        Ok(Self::decode(&read_guest::<{ Self::SIZE }>(selectors, memory, pointer)?))
    }

    /// Writes one structure after validating the guest selector, rights, and
    /// complete structure range.
    pub fn write_to(
        self,
        selectors: &SelectorTable,
        memory: &mut impl GuestMemory,
        pointer: SegmentedPointer,
    ) -> Result<(), Win16Error> {
        write_guest(selectors, memory, pointer, &self.encode())
    }
}

fn read_guest<const SIZE: usize>(
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
    pointer: SegmentedPointer,
) -> Result<[u8; SIZE], Win16Error> {
    let mut bytes = [0; SIZE];
    selectors.read(memory, pointer, &mut bytes)?;
    Ok(bytes)
}

fn write_guest<const SIZE: usize>(
    selectors: &SelectorTable,
    memory: &mut impl GuestMemory,
    pointer: SegmentedPointer,
    bytes: &[u8; SIZE],
) -> Result<(), Win16Error> {
    selectors.write(memory, pointer, bytes)
}
