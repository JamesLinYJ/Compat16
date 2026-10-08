//! Pointer-free common-control operations owned by the native UI worker.

use crate::{Win16HostRect, Win16HostWindow};
use crate::{Win16HostDib, Win16HostGdiObject, Win16HostMenu};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostToolbarButton {
    pub image_index: i16,
    pub command_id: i16,
    pub state: u8,
    pub style: u8,
    /// Win16 `idsHelp` is signed INT; convert its old DWORD bit pattern to a
    /// zero-extended native pointer-sized `TBBUTTON::dwData` value.
    pub help_data: i16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostToolbarBitmap {
    None,
    GuestObject(Win16HostGdiObject),
    OwnedDib(Win16HostDib),
    /// SDK HINST_COMMCTRL sentinel plus a standard-control bitmap resource ID.
    CommonControlResource(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostDragListKind { BeginDrag, Dragging, Dropped, CancelDrag }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostDragListNotification {
    pub message: u16,
    pub control_id: u16,
    pub list_box: Win16HostWindow,
    /// The original checked HWND16 alias is retained across this exact native
    /// callback; runtime revalidates it before putting it in DRAGLISTINFO16.
    pub guest_list_box: u16,
    pub kind: Win16HostDragListKind,
    pub cursor_x: i16,
    pub cursor_y: i16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostMenuHelpResolution { NoChange, Close, String(u16) }

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostCommonControlsOperation {
    Init,
    CreateStatusWindow { style: u32, text: Vec<u8>, parent: Option<Win16HostWindow>, id: u16 },
    CreateHeaderWindow { style: u32, text: Vec<u8>, parent: Win16HostWindow, id: u16 },
    CreateToolbar {
        style: u32,
        parent: Win16HostWindow,
        id: u16,
        bitmap_count: i16,
        bitmap: Win16HostToolbarBitmap,
        buttons: Vec<Win16HostToolbarButton>,
        button_width: i16,
        button_height: i16,
        bitmap_width: i16,
        bitmap_height: i16,
        guest_button_size: u16,
    },
    MenuHelpResolve {
        message: u16,
        w_param: u16,
        flags: u16,
        main_menu: Option<Win16HostMenu>,
        selected_menu: Option<Win16HostMenu>,
        status_bar: Win16HostWindow,
        command_id_offset: u16,
        menu_id_offset: u16,
        popup_ids: Vec<(u16, Win16HostMenu)>,
    },
    MenuHelpApply { status_bar: Win16HostWindow, simple: bool, text: Option<Vec<u8>> },
    MakeDragList { list_box: Win16HostWindow, guest_list_box: u16 },
    /// Exact Win16 `INT` array, including its zero terminator and the leading
    /// menu pair, after the runtime has checked the complete bounded span.
    GetEffectiveClientRect { window: Win16HostWindow, layout_info: Vec<i32> },
    WritePrivateProfileStruct {
        section: Option<Vec<u8>>,
        key: Option<Vec<u8>>,
        data: Option<Vec<u8>>,
        data_size: u16,
        file_name: Option<Vec<u8>>,
    },
    GetPrivateProfileStruct {
        section: Vec<u8>, key: Vec<u8>, capacity: u16, file_name: Vec<u8>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostCommonControlsResult {
    Initialized,
    /// USER's current relationship after synchronous creation callbacks.
    /// The parent is an opaque identity, never the requested guest handle.
    CreatedWindow { window: Option<Win16HostWindow>, parent: Option<Win16HostWindow> },
    MenuHelp(Win16HostMenuHelpResolution),
    MenuHelpApplied,
    Rect(Option<Win16HostRect>),
    Bool(bool),
    ProfileData { succeeded: bool, data: Vec<u8> },
}
