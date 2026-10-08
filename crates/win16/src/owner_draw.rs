//! Checked Win16 owner-draw structure codecs and list-box message packing.
//!
//! The fixed layouts follow the Windows 3.1 SDK 3.10 `WINDOWS.H` declarations
//! on SDK Disk 3: `DRAWITEMSTRUCT` (lines 4381–4396), `MEASUREITEMSTRUCT`
//! (4398–4410), `DELETEITEMSTRUCT` (4412–4423), and `COMPAREITEMSTRUCT`
//! (4425–4438). The corresponding message descriptions and structures are in
//! the 1992 *Programmer's Reference, Volume 3*: messages pp. 92, 98–99,
//! 119, 122–123, and 153; structure entries pp. 254, 274, 282–283, 316–317.
//! `WINDOWSX.H` lines 866–876 defines the `WM_VKEYTOITEM` and `WM_CHARTOITEM`
//! word packing. The local source artifact and hash records are in
//! `work/reference/windows-sdk/manifest.json` (`WIN31SDK-DISK03.json`,
//! SHA-256 `898b908d9f3a9d13a8c37040ffd00b28e76fd977da452243c51b89a4d19b8e8b`;
//! Volume 3 PDF SHA-256 `f07a526d692810dc1d9fdc720d75c4e96999a1428f9ee96d4652257c91e469e7`).
//!
//! SDK `UINT`, `HWND`, and `HDC` fields remain 16-bit guest values; `DWORD`
//! item data remains 32-bit. These logical types never contain host pointers.
//! `WINDOWS.H` defines `UINT`/`DWORD` at lines 133–137, `RECT` at 1070–1076,
//! and declares `HDC`, `HWND`, and `HMENU` at lines 1051, 2622, and 2626
//! (with `HANDLE`/`DECLARE_HANDLE` at 208–218). The owner-draw records have
//! no separately declared `HMENU` field: `hwndItem` keeps its 16-bit layout,
//! but DRAWITEMSTRUCT with `CtlType == ODT_MENU` carries a guest HMENU there
//! (Volume 3 p.283). Callback marshalling must select the HWND/HMENU namespace
//! from CtlType rather than treating every hwndItem as a window handle.
//! Win16 `COMPAREITEMSTRUCT` ends with `itemData2`; the later Win32
//! `dwLocaleId` field is absent from the Windows 3.1 declaration. In
//! `WM_MEASUREITEM`, only `itemWidth` and `itemHeight` are outputs, so use
//! [`MeasureItemStruct16::write_outputs`] to preserve every input field.

use crate::window_geometry::Rect16;
use crate::Win16Error;
use zerocopy::byteorder::little_endian::{U16, U32};

#[path = "owner_draw/wire.rs"]
mod wire;

/// Byte offsets in the Windows 3.1 `DRAWITEMSTRUCT` representation.
pub mod draw_item_struct16_offsets {
    pub const CTL_TYPE: usize = 0;
    pub const CTL_ID: usize = 2;
    pub const ITEM_ID: usize = 4;
    pub const ITEM_ACTION: usize = 6;
    pub const ITEM_STATE: usize = 8;
    pub const HWND_ITEM: usize = 10;
    pub const HDC: usize = 12;
    pub const RC_ITEM: usize = 14;
    pub const ITEM_DATA: usize = 22;
    pub const SIZE: usize = 26;
}

/// Byte offsets in the Windows 3.1 `MEASUREITEMSTRUCT` representation.
pub mod measure_item_struct16_offsets {
    pub const CTL_TYPE: usize = 0;
    pub const CTL_ID: usize = 2;
    pub const ITEM_ID: usize = 4;
    pub const ITEM_WIDTH: usize = 6;
    pub const ITEM_HEIGHT: usize = 8;
    pub const ITEM_DATA: usize = 10;
    pub const OUTPUT_SIZE: usize = 4;
    pub const SIZE: usize = 14;
}

/// Byte offsets in the Windows 3.1 `DELETEITEMSTRUCT` representation.
pub mod delete_item_struct16_offsets {
    pub const CTL_TYPE: usize = 0;
    pub const CTL_ID: usize = 2;
    pub const ITEM_ID: usize = 4;
    pub const HWND_ITEM: usize = 6;
    pub const ITEM_DATA: usize = 8;
    pub const SIZE: usize = 12;
}

/// Byte offsets in the Windows 3.1 `COMPAREITEMSTRUCT` representation.
pub mod compare_item_struct16_offsets {
    pub const CTL_TYPE: usize = 0;
    pub const CTL_ID: usize = 2;
    pub const HWND_ITEM: usize = 4;
    pub const ITEM_ID1: usize = 6;
    pub const ITEM_DATA1: usize = 8;
    pub const ITEM_ID2: usize = 12;
    pub const ITEM_DATA2: usize = 14;
    pub const SIZE: usize = 18;
}

/// Input fields delivered by Win16 `WM_DRAWITEM` (26 bytes).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct DrawItemStruct16 {
    pub ctl_type: u16,
    pub ctl_id: u16,
    pub item_id: u16,
    pub item_action: u16,
    pub item_state: u16,
    /// Guest HWND, or HMENU when ctl_type is ODT_MENU. Never a native handle.
    pub hwnd_item: u16,
    /// Guest HDC word. It is not a native pointer or host HDC.
    pub hdc: u16,
    pub rc_item: Rect16,
    /// The application-supplied 32-bit `DWORD` item value.
    pub item_data: u32,
}

impl DrawItemStruct16 {
    pub const SIZE: usize = draw_item_struct16_offsets::SIZE;

    /// Decodes exactly one Windows 3.1 Win16 `DRAWITEMSTRUCT`.
    pub fn decode(bytes: &[u8]) -> Result<Self, Win16Error> {
        let bytes: &[u8; Self::SIZE] = bytes.try_into().map_err(|_| Win16Error::InvalidSize)?;
        let wire: wire::DrawItemStruct16Wire = zerocopy::transmute!(*bytes);
        let rect_bytes: [u8; Rect16::SIZE] = zerocopy::transmute!(wire.rc_item);
        Ok(Self {
            ctl_type: wire.ctl_type.get(),
            ctl_id: wire.ctl_id.get(),
            item_id: wire.item_id.get(),
            item_action: wire.item_action.get(),
            item_state: wire.item_state.get(),
            hwnd_item: wire.hwnd_item.get(),
            hdc: wire.hdc.get(),
            rc_item: Rect16::decode(&rect_bytes),
            item_data: wire.item_data.get(),
        })
    }

    /// Encodes this record as exactly 26 Win16 bytes.
    pub fn encode(self) -> [u8; Self::SIZE] {
        let wire = wire::DrawItemStruct16Wire {
            ctl_type: U16::new(self.ctl_type),
            ctl_id: U16::new(self.ctl_id),
            item_id: U16::new(self.item_id),
            item_action: U16::new(self.item_action),
            item_state: U16::new(self.item_state),
            hwnd_item: U16::new(self.hwnd_item),
            hdc: U16::new(self.hdc),
            rc_item: zerocopy::transmute!(self.rc_item.encode()),
            item_data: U32::new(self.item_data),
        };
        zerocopy::transmute!(wire)
    }
}

/// Fields supplied to the owner for Win16 `WM_MEASUREITEM` (14 bytes).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct MeasureItemStruct16 {
    pub ctl_type: u16,
    pub ctl_id: u16,
    pub item_id: u16,
    /// The only writable output fields in `WM_MEASUREITEM`.
    pub item_width: u16,
    /// The only writable output fields in `WM_MEASUREITEM`.
    pub item_height: u16,
    pub item_data: u32,
}

impl MeasureItemStruct16 {
    pub const SIZE: usize = measure_item_struct16_offsets::SIZE;
    pub const OUTPUT_SIZE: usize = measure_item_struct16_offsets::OUTPUT_SIZE;

    /// Decodes exactly one Windows 3.1 Win16 `MEASUREITEMSTRUCT`.
    pub fn decode(bytes: &[u8]) -> Result<Self, Win16Error> {
        let bytes: &[u8; Self::SIZE] = bytes.try_into().map_err(|_| Win16Error::InvalidSize)?;
        let wire: wire::MeasureItemStruct16Wire = zerocopy::transmute!(*bytes);
        Ok(Self {
            ctl_type: wire.ctl_type.get(),
            ctl_id: wire.ctl_id.get(),
            item_id: wire.item_id.get(),
            item_width: wire.item_width.get(),
            item_height: wire.item_height.get(),
            item_data: wire.item_data.get(),
        })
    }

    /// Encodes a standalone record as exactly 14 Win16 bytes.
    pub fn encode(self) -> [u8; Self::SIZE] {
        let wire = wire::MeasureItemStruct16Wire {
            ctl_type: U16::new(self.ctl_type),
            ctl_id: U16::new(self.ctl_id),
            item_id: U16::new(self.item_id),
            item_width: U16::new(self.item_width),
            item_height: U16::new(self.item_height),
            item_data: U32::new(self.item_data),
        };
        zerocopy::transmute!(wire)
    }

    /// Writes only `itemWidth` and `itemHeight` to an existing full record.
    /// All other input bytes, including `itemData`, are preserved.
    pub fn write_outputs(self, bytes: &mut [u8]) -> Result<(), Win16Error> {
        if bytes.len() != Self::SIZE {
            return Err(Win16Error::InvalidSize);
        }
        let wire = wire::MeasureItemOutputs16Wire {
            item_width: U16::new(self.item_width),
            item_height: U16::new(self.item_height),
        };
        let output: [u8; Self::OUTPUT_SIZE] = zerocopy::transmute!(wire);
        let start = measure_item_struct16_offsets::ITEM_WIDTH;
        bytes[start..start + Self::OUTPUT_SIZE].copy_from_slice(&output);
        Ok(())
    }
}

/// Input fields delivered by Win16 `WM_DELETEITEM` (12 bytes).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct DeleteItemStruct16 {
    pub ctl_type: u16,
    pub ctl_id: u16,
    pub item_id: u16,
    /// Guest HWND word. The SDK declares this as HWND, never as HMENU.
    pub hwnd_item: u16,
    pub item_data: u32,
}

impl DeleteItemStruct16 {
    pub const SIZE: usize = delete_item_struct16_offsets::SIZE;

    /// Decodes exactly one Windows 3.1 Win16 `DELETEITEMSTRUCT`.
    pub fn decode(bytes: &[u8]) -> Result<Self, Win16Error> {
        let bytes: &[u8; Self::SIZE] = bytes.try_into().map_err(|_| Win16Error::InvalidSize)?;
        let wire: wire::DeleteItemStruct16Wire = zerocopy::transmute!(*bytes);
        Ok(Self {
            ctl_type: wire.ctl_type.get(),
            ctl_id: wire.ctl_id.get(),
            item_id: wire.item_id.get(),
            hwnd_item: wire.hwnd_item.get(),
            item_data: wire.item_data.get(),
        })
    }

    /// Encodes this record as exactly 12 Win16 bytes.
    pub fn encode(self) -> [u8; Self::SIZE] {
        let wire = wire::DeleteItemStruct16Wire {
            ctl_type: U16::new(self.ctl_type),
            ctl_id: U16::new(self.ctl_id),
            item_id: U16::new(self.item_id),
            hwnd_item: U16::new(self.hwnd_item),
            item_data: U32::new(self.item_data),
        };
        zerocopy::transmute!(wire)
    }
}

/// Input fields delivered by Win16 `WM_COMPAREITEM` (18 bytes).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct CompareItemStruct16 {
    pub ctl_type: u16,
    pub ctl_id: u16,
    /// Guest HWND word; it is not a native pointer or HMENU.
    pub hwnd_item: u16,
    pub item_id1: u16,
    pub item_data1: u32,
    pub item_id2: u16,
    pub item_data2: u32,
}

impl CompareItemStruct16 {
    pub const SIZE: usize = compare_item_struct16_offsets::SIZE;

    /// Decodes exactly one Windows 3.1 Win16 `COMPAREITEMSTRUCT`.
    pub fn decode(bytes: &[u8]) -> Result<Self, Win16Error> {
        let bytes: &[u8; Self::SIZE] = bytes.try_into().map_err(|_| Win16Error::InvalidSize)?;
        let wire: wire::CompareItemStruct16Wire = zerocopy::transmute!(*bytes);
        Ok(Self {
            ctl_type: wire.ctl_type.get(),
            ctl_id: wire.ctl_id.get(),
            hwnd_item: wire.hwnd_item.get(),
            item_id1: wire.item_id1.get(),
            item_data1: wire.item_data1.get(),
            item_id2: wire.item_id2.get(),
            item_data2: wire.item_data2.get(),
        })
    }

    /// Encodes this record as exactly 18 Win16 bytes.
    pub fn encode(self) -> [u8; Self::SIZE] {
        let wire = wire::CompareItemStruct16Wire {
            ctl_type: U16::new(self.ctl_type),
            ctl_id: U16::new(self.ctl_id),
            hwnd_item: U16::new(self.hwnd_item),
            item_id1: U16::new(self.item_id1),
            item_data1: U32::new(self.item_data1),
            item_id2: U16::new(self.item_id2),
            item_data2: U32::new(self.item_data2),
        };
        zerocopy::transmute!(wire)
    }
}

/// Packed Win16 fields for `WM_VKEYTOITEM`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct VKeyToItem16 {
    pub virtual_key: u16,
    /// Low word of LPARAM: guest list-box HWND, not a native pointer.
    pub list_box_hwnd: u16,
    /// Signed high word of LPARAM, preserving the SDK `int` bit pattern.
    pub caret_index: i16,
}

impl VKeyToItem16 {
    pub fn decode(w_param: u16, l_param: u32) -> Self {
        let (list_box_hwnd, caret_index) = decode_list_box_l_param(l_param);
        Self { virtual_key: w_param, list_box_hwnd, caret_index }
    }

    pub fn encode(self) -> (u16, u32) {
        (self.virtual_key, encode_list_box_l_param(self.list_box_hwnd, self.caret_index))
    }
}

/// Packed Win16 fields for `WM_CHARTOITEM`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct CharToItem16 {
    pub character: u16,
    /// Low word of LPARAM: guest list-box HWND, not a native pointer.
    pub list_box_hwnd: u16,
    /// Signed high word of LPARAM, preserving the SDK `int` bit pattern.
    pub caret_index: i16,
}

impl CharToItem16 {
    pub fn decode(w_param: u16, l_param: u32) -> Self {
        let (list_box_hwnd, caret_index) = decode_list_box_l_param(l_param);
        Self { character: w_param, list_box_hwnd, caret_index }
    }

    pub fn encode(self) -> (u16, u32) {
        (self.character, encode_list_box_l_param(self.list_box_hwnd, self.caret_index))
    }
}

// This is the Windows 3.1 `MAKELPARAM` guest wire contract. A generic
// serialization library does not define its low/high WORD meaning or retain
// the signed Win16 caret-index interpretation, so keep this narrow codec
// explicit at the message boundary.
fn decode_list_box_l_param(l_param: u32) -> (u16, i16) {
    (l_param as u16, (l_param >> 16) as u16 as i16)
}

fn encode_list_box_l_param(list_box_hwnd: u16, caret_index: i16) -> u32 {
    u32::from(list_box_hwnd) | (u32::from(caret_index as u16) << 16)
}
