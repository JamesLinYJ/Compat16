//! Owner-safe mutations of native menu trees.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use runtime::{
    RuntimeError, Win16HostGdiObject, Win16HostMenu, Win16MenuItem, Win16MenuItemIdentity,
    Win16MenuOperation, Win16MenuResult,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, DeleteMenu, InsertMenuW, MF_BYPOSITION, MF_POPUP, ModifyMenuW, RemoveMenu,
};

use super::super::win16_menu_attachment as attachment;
use super::super::win16_window_worker::WorkerState;

pub(super) fn set_system_menu(
    state: &Rc<RefCell<WorkerState>>,
    window: runtime::Win16HostWindow,
    menu: Option<Win16HostMenu>,
) -> Result<Win16MenuResult, RuntimeError> {
    let Some(hwnd) = super::native_window(state, window) else {
        return Ok(super::boolean(false));
    };
    let hmenu = match menu {
        Some(menu) => super::native_menu(state, menu),
        None => Some(std::ptr::null_mut()),
    };
    let Some(hmenu) = hmenu else {
        return Ok(super::boolean(false));
    };
    let old = { state.borrow().system_menus.get(&window).copied() };
    if old.is_some_and(|old| attachment::cached_menu_tree_is_retiring(state, old)) {
        return Ok(super::boolean(false));
    }
    let identity_cookie = state
        .borrow()
        .window_identity_cookies
        .get(&window)
        .filter(|binding| binding.hwnd == hwnd as usize)
        .map(|binding| binding.value);
    let old_tree = match old.filter(|old| Some(*old) != menu) {
        Some(old) => {
            let Some(old_native) = super::native_menu(state, old) else {
                return Ok(super::boolean(false));
            };
            let Some(tree) = attachment::preflight_replace_system_menu(
                state,
                window,
                hwnd,
                old,
                old_native,
                identity_cookie,
            )?
            else {
                return Ok(super::boolean(false));
            };
            Some(tree)
        }
        None => None,
    };
    let new_tree = if let Some(menu) = menu {
        if attachment::cached_menu_tree_is_retiring(state, menu) {
            return Ok(super::boolean(false));
        }
        let tree = attachment::refresh_menu_tree(state, menu)?;
        if attachment::menu_tree_is_retiring(state, &tree) {
            return Ok(super::boolean(false));
        }
        Some(tree)
    } else {
        None
    };
    if old_tree
        .as_ref()
        .zip(new_tree.as_ref())
        .is_some_and(|(old, new)| attachment::menu_identity_sets_intersect(old, new))
    {
        // The success path may retire identities from the prior system-menu tree.
        // Reject shared generations before entry; do not assume USER accepts or
        // completes an overlapping replacement.
        return Ok(super::boolean(false));
    }
    let native_succeeded = {
        let roots = old.into_iter().chain(menu).collect::<Vec<_>>();
        let _menu_owners = attachment::retain_menu_call_owners(state, &roots)?;
        let _reservation = match old_tree.as_ref() {
            Some(tree) => Some(attachment::reserve_menu_retirement(state, tree)?),
            None => None,
        };
        super::set_system_menu_native(hwnd, hmenu).unwrap_or(false)
    };
    // USER may run callbacks while setting a system menu. Attribute publication
    // only to the original HWND cookie and exact menu generation that entered.
    let same_window = super::super::win16_window_identity::resolve_user_window(state, window)
        == Some(hwnd)
        && state
            .borrow()
            .window_identity_cookies
            .get(&window)
            .filter(|binding| binding.hwnd == hwnd as usize)
            .map(|binding| binding.value)
            == identity_cookie;
    let same_menu = menu.map_or(true, |menu| {
        attachment::menu_token_matches(state, menu, hmenu)
            && (crate::windows::win32_safe::is_menu(hmenu) != 0)
    });
    let same_ledger = state.borrow().system_menus.get(&window).copied() == old;
    let publish = native_succeeded && same_window && same_menu && same_ledger;
    let invalidated = old_tree.as_ref().map_or_else(Vec::new, |tree| {
        if old != menu {
            attachment::invalidate_menu_identities(state, tree, false)
        } else {
            Vec::new()
        }
    });
    if publish {
        let mut worker = state.borrow_mut();
        if let Some(menu) = menu {
            worker.system_menus.insert(window, menu);
        } else {
            worker.system_menus.remove(&window);
        }
    }
    Ok(Win16MenuResult::Boolean {
        succeeded: native_succeeded,
        invalidated,
    })
}

pub(super) fn destroy_menu(
    state: &Rc<RefCell<WorkerState>>,
    menu: Win16HostMenu,
) -> Result<Win16MenuResult, RuntimeError> {
    let Some(native) = super::native_menu(state, menu) else {
        return Ok(super::boolean(false));
    };
    if state
        .borrow()
        .retiring_menu_native_handles
        .contains(&(menu, native as usize))
    {
        return Ok(super::boolean(false));
    }
    if attachment::cached_menu_tree_is_retiring(state, menu) {
        return Ok(super::boolean(false));
    }
    let Some(tree) = attachment::preflight_destroy_menu_tree(state, menu, native)? else {
        return Ok(super::boolean(false));
    };
    let _owners = attachment::retain_menu_call_owners(state, &[menu])?;
    let _reservation = attachment::reserve_menu_retirement(state, &tree)?;
    let succeeded = crate::windows::win32_safe::destroy_menu(native) != 0;
    drop(_reservation);
    let invalidated = attachment::invalidate_menu_identities(state, &tree, succeeded);
    Ok(Win16MenuResult::Boolean {
        succeeded,
        invalidated,
    })
}

pub(super) fn execute(
    state: &Rc<RefCell<WorkerState>>,
    bitmaps: &BTreeMap<Win16HostGdiObject, Option<usize>>,
    operation: Win16MenuOperation,
) -> Result<Win16MenuResult, RuntimeError> {
    match operation {
        Win16MenuOperation::InsertMenu {
            menu,
            position,
            flags,
            item,
        } => insert_item(state, bitmaps, menu, u32::from(position), flags, item, true)
            .map(super::boolean),
        Win16MenuOperation::AppendMenu { menu, flags, item } => {
            insert_item(state, bitmaps, menu, 0, flags, item, false).map(super::boolean)
        }
        Win16MenuOperation::ModifyMenu {
            menu,
            position,
            flags,
            item,
        } => modify_item(state, bitmaps, menu, u32::from(position), flags, item),
        Win16MenuOperation::RemoveMenu { menu, item, flags } => {
            remove_item(state, menu, u32::from(item), flags)
        }
        Win16MenuOperation::DeleteMenu { menu, item, flags } => {
            delete_item(state, menu, u32::from(item), flags)
        }
        _ => unreachable!("only menu mutations are routed here"),
    }
}

fn insert_item(
    state: &Rc<RefCell<WorkerState>>,
    bitmaps: &BTreeMap<Win16HostGdiObject, Option<usize>>,
    menu: Win16HostMenu,
    position: u32,
    flags: u16,
    item: Win16MenuItem,
    insert: bool,
) -> Result<bool, RuntimeError> {
    let Some(native) = super::native_menu(state, menu) else {
        return Ok(false);
    };
    if attachment::cached_menu_tree_is_retiring(state, menu) {
        return Ok(false);
    }
    let parent_tree = attachment::refresh_menu_tree(state, menu)?;
    if attachment::menu_tree_is_retiring(state, &parent_tree) {
        return Ok(false);
    }
    let submenu = if has_menu_flag(flags, MF_POPUP) {
        match item.identity {
            Win16MenuItemIdentity::Submenu(token) => Some(token),
            Win16MenuItemIdentity::Command(_) => None,
        }
    } else {
        None
    };
    if let Some(child) = submenu {
        let Some(native_child) = super::native_menu(state, child) else {
            return Ok(false);
        };
        if attachment::cached_menu_tree_is_retiring(state, child) {
            return Ok(false);
        }
        let child_tree = attachment::refresh_menu_tree(state, child)?;
        if child_tree.contains_key(&menu) || attachment::menu_tree_is_retiring(state, &child_tree) {
            return Ok(false);
        }
        if !attachment::menu_token_matches(state, child, native_child) {
            return Ok(false);
        }
    }
    let Some(item) = super::text::native_item(state, bitmaps, item)? else {
        return Ok(false);
    };
    let mut roots = vec![menu];
    if let Some(child) = submenu {
        roots.push(child);
    }
    let _owners = attachment::retain_menu_call_owners(state, &roots)?;
    // SAFETY: InsertMenuW reads an optional caller-owned string. AppendMenuW reads an optional caller-owned string.
    let succeeded = unsafe {
        if insert {
            InsertMenuW(
                native,
                position,
                u32::from(flags),
                item.value,
                item.pointer(),
            )
        } else {
            AppendMenuW(native, u32::from(flags), item.value, item.pointer())
        }
    } != 0;
    // A failure return can still follow callback reentry. Reconcile either
    // result, while preserving the native BOOL in any typed inspection error.
    reconcile_after_native(
        state,
        menu,
        if insert { "InsertMenuW" } else { "AppendMenuW" },
        succeeded,
    )?;
    Ok(succeeded)
}

fn modify_item(
    state: &Rc<RefCell<WorkerState>>,
    bitmaps: &BTreeMap<Win16HostGdiObject, Option<usize>>,
    menu: Win16HostMenu,
    position: u32,
    flags: u16,
    item: Win16MenuItem,
) -> Result<Win16MenuResult, RuntimeError> {
    let Some(native) = super::native_menu(state, menu) else {
        return Ok(super::boolean(false));
    };
    if attachment::cached_menu_tree_is_retiring(state, menu) {
        return Ok(super::boolean(false));
    }
    let parent_tree = attachment::refresh_menu_tree(state, menu)?;
    if attachment::menu_tree_is_retiring(state, &parent_tree) {
        return Ok(super::boolean(false));
    }
    let previous =
        super::query_submenu(state, native, position, has_menu_flag(flags, MF_BYPOSITION))?;
    let next = if has_menu_flag(flags, MF_POPUP) {
        match item.identity {
            Win16MenuItemIdentity::Submenu(token) => Some(token),
            Win16MenuItemIdentity::Command(_) => None,
        }
    } else {
        None
    };
    let next_tree = match next {
        Some(next) => {
            let Some(next_native) = super::native_menu(state, next) else {
                return Ok(super::boolean(false));
            };
            if attachment::cached_menu_tree_is_retiring(state, next) {
                return Ok(super::boolean(false));
            }
            let next_tree = attachment::refresh_menu_tree(state, next)?;
            if attachment::menu_tree_is_retiring(state, &next_tree)
                || (Some(next) != previous && next_tree.contains_key(&menu))
                || !attachment::menu_token_matches(state, next, next_native)
            {
                return Ok(super::boolean(false));
            }
            // Keep this refreshed token-to-native generation snapshot alive for
            // the old/new overlap check below; reconstructing it would admit a
            // different generation after callback reentry.
            Some(next_tree)
        }
        None => None,
    };
    let Some(item) = super::text::native_item(state, bitmaps, item)? else {
        return Ok(super::boolean(false));
    };
    let old_tree = match previous.filter(|old| Some(*old) != next) {
        Some(previous) => match attachment::preflight_consume_submenu(state, menu, previous)? {
            Some(tree) => Some(tree),
            None => return Ok(super::boolean(false)),
        },
        None => None,
    };
    if old_tree
        .as_ref()
        .zip(next_tree.as_ref())
        .is_some_and(|(old, next)| attachment::menu_identity_sets_intersect(old, next))
    {
        // ModifyMenu consumes the removed submenu on success. Do not let its
        // retirement invalidate an exact native generation also supplied anew.
        return Ok(super::boolean(false));
    }
    let mut roots = vec![menu];
    roots.extend(previous);
    roots.extend(next);
    let _owners = attachment::retain_menu_call_owners(state, &roots)?;
    let _reservation = match old_tree.as_ref() {
        Some(tree) => Some(attachment::reserve_menu_retirement(state, tree)?),
        None => None,
    };
    // SAFETY: ModifyMenuW reads an optional caller-owned string.
    let succeeded = unsafe {
        ModifyMenuW(
            native,
            position,
            u32::from(flags),
            item.value,
            item.pointer(),
        ) != 0
    };
    drop(_reservation);
    let reconciliation = reconcile_after_native(state, menu, "ModifyMenuW", succeeded);
    let invalidated = old_tree.as_ref().map_or_else(Vec::new, |tree| {
        attachment::invalidate_menu_identities(state, tree, succeeded)
    });
    reconciliation?;
    Ok(Win16MenuResult::Boolean {
        succeeded,
        invalidated,
    })
}

fn remove_item(
    state: &Rc<RefCell<WorkerState>>,
    menu: Win16HostMenu,
    item: u32,
    flags: u16,
) -> Result<Win16MenuResult, RuntimeError> {
    let Some(native) = super::native_menu(state, menu) else {
        return Ok(super::boolean(false));
    };
    if attachment::cached_menu_tree_is_retiring(state, menu) {
        return Ok(super::boolean(false));
    }
    let parent_tree = attachment::refresh_menu_tree(state, menu)?;
    if attachment::menu_tree_is_retiring(state, &parent_tree) {
        return Ok(super::boolean(false));
    }
    let child = super::query_submenu(state, native, item, has_menu_flag(flags, MF_BYPOSITION))?;
    let mut roots = vec![menu];
    roots.extend(child);
    let _owners = attachment::retain_menu_call_owners(state, &roots)?;
    // SAFETY: RemoveMenu takes a menu handle and integer parameters.
    let succeeded = unsafe { RemoveMenu(native, item, u32::from(flags)) != 0 };
    reconcile_after_native(state, menu, "RemoveMenu", succeeded)?;
    // RemoveMenu detaches the submenu without consuming it; refreshed native
    // edges mark it as a root only if no other parent still owns it.
    Ok(super::boolean(succeeded))
}

fn delete_item(
    state: &Rc<RefCell<WorkerState>>,
    menu: Win16HostMenu,
    item: u32,
    flags: u16,
) -> Result<Win16MenuResult, RuntimeError> {
    let Some(native) = super::native_menu(state, menu) else {
        return Ok(super::boolean(false));
    };
    if attachment::cached_menu_tree_is_retiring(state, menu) {
        return Ok(super::boolean(false));
    }
    let parent_tree = attachment::refresh_menu_tree(state, menu)?;
    if attachment::menu_tree_is_retiring(state, &parent_tree) {
        return Ok(super::boolean(false));
    }
    let child = super::query_submenu(state, native, item, has_menu_flag(flags, MF_BYPOSITION))?;
    let old_tree = match child {
        Some(child) => match attachment::preflight_consume_submenu(state, menu, child)? {
            Some(tree) => Some(tree),
            None => return Ok(super::boolean(false)),
        },
        None => None,
    };
    let mut roots = vec![menu];
    roots.extend(child);
    let _owners = attachment::retain_menu_call_owners(state, &roots)?;
    let _reservation = match old_tree.as_ref() {
        Some(tree) => Some(attachment::reserve_menu_retirement(state, tree)?),
        None => None,
    };
    // SAFETY: DeleteMenu takes a menu handle and integer parameters.
    let succeeded = unsafe { DeleteMenu(native, item, u32::from(flags)) != 0 };
    drop(_reservation);
    let reconciliation = reconcile_after_native(state, menu, "DeleteMenu", succeeded);
    let invalidated = old_tree.as_ref().map_or_else(Vec::new, |tree| {
        attachment::invalidate_menu_identities(state, tree, succeeded)
    });
    reconciliation?;
    Ok(Win16MenuResult::Boolean {
        succeeded,
        invalidated,
    })
}

fn reconcile_after_native(
    state: &Rc<RefCell<WorkerState>>,
    menu: Win16HostMenu,
    operation: &str,
    native_result: bool,
) -> Result<(), RuntimeError> {
    attachment::refresh_menu_tree(state, menu)
        .map(|_| ())
        .map_err(|error| {
            RuntimeError::with_source(
                error.kind(),
                format!(
                    "{operation} returned BOOL {native_result}; refresh its native owner graph"
                ),
                error,
            )
        })
}

fn has_menu_flag(flags: u16, native_flag: u32) -> bool {
    u32::from(flags) & native_flag != 0
}
