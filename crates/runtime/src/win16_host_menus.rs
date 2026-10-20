//! Owned menu payloads crossing the Win16 runtime and Windows host boundary.
//!
//! A menu handle is an opaque identity owned by the host adapter. Menu item
//! text, popup handles, bitmaps, and owner-draw data remain distinct values;
//! none of these variants carries a guest or host pointer.

use crate::{Win16HostGdiObject, Win16HostMenu, Win16HostRect, Win16HostWindow};

/// The identifier portion of an InsertMenu/AppendMenu item. A popup item
/// carries its submenu handle separately from the item label/content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16MenuItemIdentity {
    Command(u16),
    Submenu(Win16HostMenu),
}

/// The content portion of an InsertMenu/AppendMenu item. Strings are owned
/// ANSI bytes without a trailing NUL. `OwnerDraw` is the Win16 32-bit
/// application value, never a host pointer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16MenuItemContent {
    /// `None` preserves a null FAR pointer; `Some(Vec::new())` is a non-null
    /// pointer to an empty string.
    Text(Option<Vec<u8>>),
    /// `None` preserves a null HBITMAP; a guest handle is translated before
    /// entering this host payload.
    Bitmap(Option<Win16HostGdiObject>),
    OwnerDraw(u32),
    Separator,
}

/// A fully marshalled menu item. Identity and content are orthogonal because
/// normal command and popup entries have both an ID/handle and a label.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16MenuItem {
    pub identity: Win16MenuItemIdentity,
    pub content: Win16MenuItemContent,
}

/// Owned Win16 RT_MENU or LoadMenuIndirect template after parsing. Popup
/// submenus are represented recursively, so no guest HGLOBAL/FAR pointer is
/// needed by the host while Windows builds the native menu tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win16MenuTemplate {
    pub items: Vec<Win16MenuTemplateItem>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16MenuTemplateItem {
    Command { flags: u16, id: u16, text: Vec<u8> },
    Popup { flags: u16, text: Vec<u8>, submenu: Win16MenuTemplate },
    Separator { flags: u16, id: u16 },
}

/// A typed native USER menu operation. Flags retain their Win16 WORD width;
/// the host passes their documented native meanings to Windows after only
/// the pointer/handle conversion represented by these owned payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16MenuOperation {
    Create { popup: bool },
    CreateFromTemplate { template: Win16MenuTemplate },
    Destroy { menu: Win16HostMenu },
    CheckItem { menu: Win16HostMenu, item: u16, flags: u16 },
    EnableItem { menu: Win16HostMenu, item: u16, flags: u16 },
    HiliteItem {
        window: Win16HostWindow,
        menu: Win16HostMenu,
        item: u16,
        flags: u16,
    },
    EndMenu,
    IsMenu { menu: Win16HostMenu },
    GetMenuItemId { menu: Win16HostMenu, position: i16 },
    SetSystemMenu { window: Win16HostWindow, menu: Option<Win16HostMenu> },
    SetMenuContextHelpId { menu: Win16HostMenu, help_id: u16 },
    GetMenuContextHelpId { menu: Win16HostMenu },
    GetMenuCheckMarkDimensions,
    MakeMenuRToL { menu: Win16HostMenu, right_to_left: bool },
    CheckRadioItem {
        menu: Win16HostMenu,
        first: u16,
        last: u16,
        check: u16,
        by_position: bool,
    },
    GetSystemMenu { window: Win16HostWindow, revert: bool },
    GetMenu { window: Win16HostWindow },
    GetSubMenu { menu: Win16HostMenu, position: i16 },
    SetMenu { window: Win16HostWindow, menu: Option<Win16HostMenu> },
    DrawMenuBar { window: Win16HostWindow },
    GetMenuString { menu: Win16HostMenu, item: u16, flags: u16, capacity: i16 },
    GetMenuState { menu: Win16HostMenu, item: u16, flags: u16 },
    GetMenuItemCount { menu: Win16HostMenu },
    GetMenuItemRect {
        window: Option<Win16HostWindow>,
        menu: Win16HostMenu,
        item: u16,
    },
    /// `position` is the native UINT. `MF_BYPOSITION` with Win16 -1 is
    /// `u32::MAX`; other positions are the zero-extended guest word.
    InsertMenu { menu: Win16HostMenu, position: u32, flags: u16, item: Win16MenuItem },
    AppendMenu { menu: Win16HostMenu, flags: u16, item: Win16MenuItem },
    ModifyMenu { menu: Win16HostMenu, position: u16, flags: u16, item: Win16MenuItem },
    SetMenuItemBitmaps {
        menu: Win16HostMenu,
        position: u16,
        flags: u16,
        unchecked: Option<Win16HostGdiObject>,
        checked: Option<Win16HostGdiObject>,
    },
    RemoveMenu { menu: Win16HostMenu, item: u16, flags: u16 },
    DeleteMenu { menu: Win16HostMenu, item: u16, flags: u16 },
    TrackPopupMenu {
        menu: Win16HostMenu,
        flags: u16,
        x: i16,
        y: i16,
        reserved: i16,
        owner: Option<Win16HostWindow>,
        rect: Option<Win16HostRect>,
    },
}

/// The native API result plus menu tokens invalidated by native lifetime
/// changes. The runtime removes those tokens from its guest HMENU table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16MenuResult {
    Created(Option<Win16HostMenu>),
    Menu {
        menu: Option<Win16HostMenu>,
        invalidated: Vec<Win16HostMenu>,
    },
    Boolean {
        succeeded: bool,
        invalidated: Vec<Win16HostMenu>,
    },
    /// DrawMenuBar has a void Win16 ABI result; the host records completion
    /// without inventing a guest success value.
    Drawn,
    /// CheckMenuItem and EnableMenuItem return the item's previous state;
    /// 0xffff remains the native failure sentinel.
    ItemFlags(u16),
    ItemId(u16),
    ItemCount(i16),
    ContextHelpId(u32),
    CheckMarkDimensions(u32),
    MenuRect { succeeded: bool, rect: Option<Win16HostRect> },
    MenuString { count: i16, buffer: Vec<u8> },
    /// Win16 TrackPopupMenu returns an INT16. Depending on its flags, the
    /// native value can be a BOOL or the selected command ID.
    Popup { value: u16, invalidated: Vec<Win16HostMenu> },
}
