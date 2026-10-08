//! Owned request values for this Win16 API family.

use super::super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16UserMenuRequest {
    /// Create a native USER menu and return its mapped guest HMENU.
    CreateMenu,

    /// Create a native USER popup menu and return its mapped guest HMENU.
    CreatePopupMenu,

    LoadMenu {
        instance: u16,
        name: Win16ResourceName,
    },

    /// The guest MENU template remains a raw FAR pointer for bounded runtime parsing.
    LoadMenuIndirect {
        template: u32,
    },

    ChangeMenu {
        menu: u16,
        position: u16,
        new_item: u32,
        item_id: u16,
        flags: u16,
    },

    HiliteMenuItem {
        window: u16,
        menu: u16,
        item: u16,
        flags: u16,
    },

    EndMenu,

    GetMenuItemID {
        menu: u16,
        position: i16,
    },

    SetSystemMenu {
        window: u16,
        menu: u16,
    },

    IsMenu {
        menu: u16,
    },

    SetMenuContextHelpId {
        menu: u16,
        help_id: u16,
    },

    /// The current declared ABI marks USER.385 `-ret16`; a header return-width
    /// discrepancy remains tracked separately for guest-version review.
    GetMenuContextHelpId {
        menu: u16,
    },

    ModifyMenu {
        menu: u16,
        position: u16,
        flags: u16,
        item_id: u16,
        new_item: u32,
    },

    GetMenuCheckMarkDimensions,

    SetMenuItemBitmaps {
        menu: u16,
        position: u16,
        flags: u16,
        unchecked: u16,
        checked: u16,
    },

    MakeMenuRToL {
        menu: u16,
        flags: u16,
    },

    GetMenuItemRect {
        window: u16,
        menu: u16,
        item: u16,
        rect: u32,
    },

    CheckMenuRadioItem {
        menu: u16,
        first: u16,
        last: u16,
        check: u16,
        by_position: u16,
    },

    /// Destroy a mapped menu through native USER and invalidate its guest handle on success.
    DestroyMenu {
        menu: u16,
    },

    /// Preserve the raw menu selector, item selector, and MF_* flags.
    CheckMenuItem {
        menu: u16,
        item: u16,
        flags: u16,
    },

    /// Preserve the raw menu selector, item selector, and MF_* flags.
    EnableMenuItem {
        menu: u16,
        item: u16,
        flags: u16,
    },

    /// Get or reset a window's native system menu.
    GetSystemMenu {
        window: u16,
        revert: u16,
    },

    /// Return the menu attached to a window as a mapped guest HMENU.
    GetMenu {
        window: u16,
    },

    /// Return a mapped submenu by its signed Win16 INT16 position.
    GetSubMenu {
        menu: u16,
        position: i16,
    },

    /// Attach or remove a mapped menu on a window.
    SetMenu {
        window: u16,
        menu: u16,
    },

    /// Redraw a window's native menu bar. Win16 USER.160 returns no value.
    DrawMenuBar {
        window: u16,
    },

    /// Keep the output FAR pointer raw so runtime can honor the signed count
    /// and flags before validating or writing the caller's buffer.
    GetMenuString {
        menu: u16,
        item: u16,
        output: u32,
        capacity: i16,
        flags: u16,
    },

    /// Query the native flags/state for a menu item.
    GetMenuState {
        menu: u16,
        item: u16,
        flags: u16,
    },

    /// Return a menu's item count using its signed Win16 INT16 bit pattern.
    GetMenuItemCount {
        menu: u16,
    },

    /// The meaning of `new_item` depends on flags; both it and the ID remain raw.
    InsertMenu {
        menu: u16,
        position: u16,
        flags: u16,
        item_id: u16,
        new_item: u32,
    },

    /// The meaning of `new_item` depends on flags; both it and the ID remain raw.
    AppendMenu {
        menu: u16,
        flags: u16,
        item_id: u16,
        new_item: u32,
    },

    /// Remove a menu item, preserving whether the selector is an ID or position.
    RemoveMenu {
        menu: u16,
        item: u16,
        flags: u16,
    },

    /// Delete a menu item, preserving whether the selector is an ID or position.
    DeleteMenu {
        menu: u16,
        item: u16,
        flags: u16,
    },

    /// Track a native popup menu with signed coordinates and a raw optional RECT16 FAR pointer.
    TrackPopupMenu {
        menu: u16,
        flags: u16,
        x: i16,
        y: i16,
        reserved: i16,
        window: u16,
        rect: u32,
    },
}
