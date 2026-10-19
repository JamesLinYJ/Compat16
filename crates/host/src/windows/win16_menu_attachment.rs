//! Exact menu/window identity checks around USER calls that can reenter.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;
use std::sync::atomic::AtomicU64;

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostMenu, Win16HostWindow};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{GetMenuItemCount, GetSubMenu, HMENU};

use super::win16_window_worker::WorkerState;

static NEXT_MENU_RETIREMENT_ID: AtomicU64 = AtomicU64::new(1);

#[path = "win16_menu_retirement.rs"]
mod retirement;

pub(super) use retirement::{
    begin_window_menu_retirement, capture_window_menu_retirement, finish_window_menu_retirement,
    flush_deferred_menu_retirements, invalidate_menu_identities, latch_retirement_failure,
    publish_fresh_menu_generation, reserve_menu_retirement, retire_destroyed_window_menu_snapshot,
};

/// The submenu graph is also the resource owner graph used by SetMenu and
/// window teardown, so every call site shares one exact token traversal.
pub(super) fn menu_tree(
    state: &Rc<RefCell<WorkerState>>,
    root: Win16HostMenu,
) -> Vec<Win16HostMenu> {
    fn visit(state: &WorkerState, current: Win16HostMenu, seen: &mut BTreeSet<Win16HostMenu>) {
        if !seen.insert(current) {
            return;
        }
        if let Some(children) = state.menu_children.get(&current) {
            for child in children {
                visit(state, *child, seen);
            }
        }
    }
    let state = state.borrow();
    let mut seen = BTreeSet::new();
    visit(&state, root, &mut seen);
    seen.into_iter().collect()
}

/// Refresh native submenu edges before pinning or consuming a tree. The
/// ledger can be reentered between USER calls, so this snapshot follows the
/// HMENU handles Windows currently exposes rather than trusting old edges.
pub(super) fn refresh_menu_tree(
    state: &Rc<RefCell<WorkerState>>,
    root: Win16HostMenu,
) -> Result<std::collections::BTreeMap<Win16HostMenu, usize>, RuntimeError> {
    fn visit(
        state: &Rc<RefCell<WorkerState>>,
        native: HMENU,
        menus: &mut std::collections::BTreeMap<Win16HostMenu, usize>,
        edges: &mut std::collections::BTreeMap<Win16HostMenu, BTreeSet<Win16HostMenu>>,
    ) -> Result<Win16HostMenu, RuntimeError> {
        let token =
            super::win16_menu_worker::intern_menu(state, native, false)?.ok_or_else(|| {
                RuntimeError::new(
                    Kind::HostFailure,
                    "native submenu disappeared while reading its owner tree",
                )
            })?;
        if let Some(previous) = menus.get(&token) {
            if *previous != native as usize {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "one menu token resolved to two native generations",
                ));
            }
            return Ok(token);
        }
        if (crate::windows::win32_safe::is_menu(native)) == 0
            || !menu_token_matches(state, token, native)
        {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "native menu identity changed while reading its owner tree",
            ));
        }
        menus.insert(token, native as usize);
        // SAFETY: GetMenuItemCount takes a menu handle and no pointers.
        let count = unsafe { GetMenuItemCount(native) };
        if count < 0 {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "read native menu entries before owner-sensitive cleanup",
            ));
        }
        let mut children = BTreeSet::new();
        for position in 0..count {
            // SAFETY: GetSubMenu returns a submenu handle, or null.
            let child = unsafe { GetSubMenu(native, position) };
            if !child.is_null() {
                let child_token = visit(state, child, menus, edges)?;
                children.insert(child_token);
            }
        }
        edges.insert(token, children);
        Ok(token)
    }

    let native = state.borrow().menus.get(&root).copied().ok_or_else(|| {
        RuntimeError::new(
            Kind::InternalInvariant,
            "menu tree root disappeared before native ownership inspection",
        )
    })?;
    let mut menus = std::collections::BTreeMap::new();
    let mut edges = std::collections::BTreeMap::new();
    visit(state, native, &mut menus, &mut edges)?;
    apply_menu_edges(state, edges);
    Ok(menus)
}

fn apply_menu_edges(
    state: &Rc<RefCell<WorkerState>>,
    edges: std::collections::BTreeMap<Win16HostMenu, BTreeSet<Win16HostMenu>>,
) {
    let mut state = state.borrow_mut();
    for (parent, children) in edges {
        let previous = state
            .menu_children
            .insert(parent, children.clone())
            .unwrap_or_default();
        for child in previous.difference(&children) {
            if state.owned_menus.contains(child)
                && !state
                    .menu_children
                    .values()
                    .any(|items| items.contains(child))
            {
                state.owned_menu_roots.insert(*child);
            }
        }
        for child in children {
            state.owned_menu_roots.remove(&child);
        }
    }
    state.owned_menu_roots = state
        .owned_menus
        .iter()
        .copied()
        .filter(|menu| {
            !state
                .menu_children
                .values()
                .any(|children| children.contains(menu))
        })
        .collect();
}

fn refresh_all_menu_graph(state: &Rc<RefCell<WorkerState>>) -> Result<(), RuntimeError> {
    let roots = {
        let state = state.borrow();
        state
            .menus
            .iter()
            .map(|(token, native)| (*token, *native))
            .collect::<Vec<_>>()
    };
    for (token, native) in roots {
        if !cached_menu_tree_is_retiring(state, token)
            && (crate::windows::win32_safe::is_menu(native)) != 0
            && menu_token_matches(state, token, native)
        {
            refresh_menu_tree(state, token)?;
        }
    }
    Ok(())
}

fn tree_has_pinned_identity(
    state: &Rc<RefCell<WorkerState>>,
    tree: &std::collections::BTreeMap<Win16HostMenu, usize>,
) -> bool {
    let state = state.borrow();
    tree.iter().any(|(token, native)| {
        state
            .pending_window_menu_retirements
            .iter()
            .any(|pending| pending.menu_tokens.get(token) == Some(native))
            || state
                .active_menu_call_owners
                .iter()
                .any(|owners| owners.get(token) == Some(native))
    })
}

fn tree_has_external_parent(
    state: &Rc<RefCell<WorkerState>>,
    tree: &std::collections::BTreeMap<Win16HostMenu, usize>,
    allowed_parent: Option<(Win16HostMenu, Win16HostMenu)>,
) -> bool {
    state
        .borrow()
        .menu_children
        .iter()
        .any(|(parent, children)| {
            children.iter().any(|child| {
                if !tree.contains_key(child) || tree.contains_key(parent) {
                    return false;
                }
                allowed_parent != Some((*parent, *child))
            })
        })
}

fn tree_has_conflicting_live_owner(
    state: &Rc<RefCell<WorkerState>>,
    tree: &std::collections::BTreeMap<Win16HostMenu, usize>,
    allowed_parent: Option<Win16HostMenu>,
) -> Result<bool, RuntimeError> {
    let mut windows = {
        let state = state.borrow();
        state
            .windows
            .iter()
            .map(|(window, hwnd)| (*window, *hwnd))
            .collect::<Vec<_>>()
    };
    windows.sort_unstable_by_key(|(window, _)| *window);
    for (window, hwnd) in windows {
        if super::win16_window_identity::resolve_user_window(state, window) != Some(hwnd) {
            continue;
        }
        for root in current_window_menu_roots(state, window, hwnd) {
            let owner_tree = refresh_menu_tree(state, root)?;
            if owner_tree.keys().any(|token| tree.contains_key(token))
                && !allowed_parent.is_some_and(|parent| owner_tree.contains_key(&parent))
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Return the exact live tree only when destroying it cannot consume a menu
/// still owned by a window, another submenu edge, or an in-flight USER call.
pub(super) fn preflight_destroy_menu_tree(
    state: &Rc<RefCell<WorkerState>>,
    root: Win16HostMenu,
    native: HMENU,
) -> Result<Option<std::collections::BTreeMap<Win16HostMenu, usize>>, RuntimeError> {
    refresh_all_menu_graph(state)?;
    let tree = refresh_menu_tree(state, root)?;
    if tree.get(&root) != Some(&(native as usize)) {
        return Ok(None);
    }
    if tree_has_pinned_identity(state, &tree)
        || tree_has_external_parent(state, &tree, None)
        || tree_has_conflicting_live_owner(state, &tree, None)?
    {
        return Ok(None);
    }
    Ok(Some(tree))
}

/// A successful DeleteMenu/ModifyMenu consumes the old submenu. Permit the
/// requested parent edge to be removed only when it is the sole external
/// owner; other live roots and in-flight frames keep the complete child tree.
pub(super) fn preflight_consume_submenu(
    state: &Rc<RefCell<WorkerState>>,
    parent: Win16HostMenu,
    child: Win16HostMenu,
) -> Result<Option<std::collections::BTreeMap<Win16HostMenu, usize>>, RuntimeError> {
    refresh_all_menu_graph(state)?;
    let tree = refresh_menu_tree(state, child)?;
    if tree.contains_key(&parent)
        || !state
            .borrow()
            .menu_children
            .get(&parent)
            .is_some_and(|children| children.contains(&child))
    {
        return Ok(None);
    }
    let parent_native = state.borrow().menus.get(&parent).copied();
    let child_native = state.borrow().menus.get(&child).copied();
    let (Some(parent_native), Some(child_native)) = (parent_native, child_native) else {
        return Ok(None);
    };
    if native_submenu_occurrences(parent_native, child_native) != Some(1) {
        return Ok(None);
    }
    if tree_has_pinned_identity(state, &tree)
        || tree_has_external_parent(state, &tree, Some((parent, child)))
        || tree_has_conflicting_live_owner(state, &tree, Some(parent))?
    {
        return Ok(None);
    }
    Ok(Some(tree))
}

/// Revert consumes the system-menu copy owned by one exact window. Permit its
/// own ledger root, while refusing a shared tree held by another live owner.
pub(super) fn preflight_revert_system_menu(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: HWND,
    root: Win16HostMenu,
    native: HMENU,
) -> Result<Option<std::collections::BTreeMap<Win16HostMenu, usize>>, RuntimeError> {
    refresh_all_menu_graph(state)?;
    let tree = refresh_menu_tree(state, root)?;
    if tree.get(&root) != Some(&(native as usize))
        || state.borrow().system_menus.get(&window) != Some(&root)
        || super::win16_window_identity::resolve_user_window(state, window) != Some(hwnd)
        || tree_has_pinned_identity(state, &tree)
        || tree_has_external_parent(state, &tree, None)
    {
        return Ok(None);
    }
    if tree_has_other_live_window_owner(state, &tree, Some((window, hwnd, root)))? {
        return Ok(None);
    }
    Ok(Some(tree))
}

/// Find live HWND/system-menu owners of any descendant, preserving graph
/// inspection failures as typed errors instead of treating them as conflicts.
fn tree_has_other_live_window_owner(
    state: &Rc<RefCell<WorkerState>>,
    tree: &std::collections::BTreeMap<Win16HostMenu, usize>,
    allowed_owner: Option<(Win16HostWindow, HWND, Win16HostMenu)>,
) -> Result<bool, RuntimeError> {
    let mut windows = {
        let state = state.borrow();
        state
            .windows
            .iter()
            .map(|(window, hwnd)| (*window, *hwnd))
            .collect::<Vec<_>>()
    };
    windows.sort_unstable_by_key(|(window, _)| *window);
    for (owner, owner_hwnd) in windows {
        if super::win16_window_identity::resolve_user_window(state, owner) != Some(owner_hwnd) {
            continue;
        }
        for owner_root in current_window_menu_roots(state, owner, owner_hwnd) {
            let owner_tree = refresh_menu_tree(state, owner_root)?;
            if owner_tree.keys().any(|token| tree.contains_key(token))
                && allowed_owner != Some((owner, owner_hwnd, owner_root))
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Preflight replacing one exact window's old system-menu root. Every owner in
/// the consumed subtree must be the receiver's own exact HWND/root identity.
pub(super) fn preflight_replace_system_menu(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: HWND,
    root: Win16HostMenu,
    native: HMENU,
    identity_cookie: Option<usize>,
) -> Result<Option<std::collections::BTreeMap<Win16HostMenu, usize>>, RuntimeError> {
    refresh_all_menu_graph(state)?;
    let tree = refresh_menu_tree(state, root)?;
    let current_cookie = state
        .borrow()
        .window_identity_cookies
        .get(&window)
        .filter(|binding| binding.hwnd == hwnd as usize)
        .map(|binding| binding.value);
    if tree.get(&root) != Some(&(native as usize))
        || state.borrow().system_menus.get(&window) != Some(&root)
        || current_cookie != identity_cookie
        || super::win16_window_identity::resolve_user_window(state, window) != Some(hwnd)
        || tree_has_pinned_identity(state, &tree)
        || tree_has_external_parent(state, &tree, None)
        || tree_has_other_live_window_owner(state, &tree, Some((window, hwnd, root)))?
    {
        return Ok(None);
    }
    Ok(Some(tree))
}

pub(super) fn menu_tree_is_retiring(
    state: &Rc<RefCell<WorkerState>>,
    tree: &std::collections::BTreeMap<Win16HostMenu, usize>,
) -> bool {
    state
        .borrow()
        .retiring_menu_native_handles
        .iter()
        .any(|identity| {
            tree.iter()
                .any(|(token, native)| identity == &(*token, *native))
        })
}

/// Compare exact token/native generations after each live graph is refreshed
/// from USER; a stale token must not alias a later generation of the same bits.
pub(super) fn menu_identity_sets_intersect(
    left: &std::collections::BTreeMap<Win16HostMenu, usize>,
    right: &std::collections::BTreeMap<Win16HostMenu, usize>,
) -> bool {
    left.iter()
        .any(|(token, native)| right.get(token) == Some(native))
}

pub(super) fn cached_menu_tree_is_retiring(
    state: &Rc<RefCell<WorkerState>>,
    root: Win16HostMenu,
) -> bool {
    let tree = menu_tree(state, root);
    let state = state.borrow();
    tree.iter().any(|token| {
        state.menus.get(token).is_some_and(|native| {
            state
                .retiring_menu_native_handles
                .contains(&(*token, *native as usize))
        })
    })
}

fn native_submenu_occurrences(parent: HMENU, child: HMENU) -> Option<usize> {
    // SAFETY: GetMenuItemCount takes a menu handle and no pointers.
    let count = unsafe { GetMenuItemCount(parent) };
    if count < 0 {
        return None;
    }
    // SAFETY: GetSubMenu returns a submenu handle, or null.
    Some(
        (0..count)
            .filter(|position| unsafe { GetSubMenu(parent, *position) == child })
            .count(),
    )
}

pub(super) fn mark_owned(state: &Rc<RefCell<WorkerState>>, token: Win16HostMenu) {
    let mut state = state.borrow_mut();
    state.owned_menus.insert(token);
    if !state
        .menu_children
        .values()
        .any(|children| children.contains(&token))
    {
        state.owned_menu_roots.insert(token);
    }
}

pub(super) fn menu_token_matches(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostMenu,
    native: HMENU,
) -> bool {
    if native.is_null() {
        return false;
    }
    let state = state.borrow();
    state.menus.get(&token).copied() == Some(native)
        && state.menus_by_native.get(&(native as usize)).copied() == Some(token)
}

pub(super) fn token_for_native(
    state: &Rc<RefCell<WorkerState>>,
    native: HMENU,
) -> Option<Win16HostMenu> {
    if native.is_null() {
        return None;
    }
    let state = state.borrow();
    let token = state.menus_by_native.get(&(native as usize)).copied()?;
    (state.menus.get(&token).copied() == Some(native)).then_some(token)
}

pub(super) fn dialog_attachment_is_current(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: HWND,
    token: Win16HostMenu,
    native: HMENU,
) -> bool {
    if !menu_token_matches(state, token, native)
        || super::win16_window_identity::resolve(state, window) != Some(hwnd)
    {
        return false;
    }
    crate::windows::win32_safe::is_window(hwnd) != 0
        && crate::windows::win32_safe::is_menu(native) != 0
        && crate::windows::win32_safe::get_menu(hwnd) == native
}

pub(super) fn publish_dialog_attachment(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: HWND,
    token: Win16HostMenu,
    native: HMENU,
) -> bool {
    if !dialog_attachment_is_current(state, window, hwnd, token, native) {
        return false;
    }
    state.borrow_mut().window_menus.insert(window, token);
    reconcile_window_menu_ledger(state);
    true
}

pub(super) fn clear_dialog_attachment(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: HWND,
    token: Win16HostMenu,
    native: HMENU,
) -> bool {
    if !menu_token_matches(state, token, native)
        || super::win16_window_identity::resolve(state, window) != Some(hwnd)
        || {
            crate::windows::win32_safe::is_window(hwnd) == 0
                || !crate::windows::win32_safe::get_menu(hwnd).is_null()
        }
    {
        return false;
    }
    let mut state_guard = state.borrow_mut();
    if state_guard.menus.get(&token).copied() != Some(native)
        || state_guard.menus_by_native.get(&(native as usize)).copied() != Some(token)
    {
        return false;
    }
    if state_guard.window_menus.get(&window) == Some(&token) {
        state_guard.window_menus.remove(&window);
    }
    drop(state_guard);
    reconcile_window_menu_ledger(state);
    true
}

pub(super) fn record_requested_attachment(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: HWND,
    token: Option<Win16HostMenu>,
    native: HMENU,
) -> bool {
    if super::win16_window_identity::resolve_user_window(state, window) != Some(hwnd) {
        return false;
    }
    match token {
        Some(token) => {
            if !menu_token_matches(state, token, native) || {
                crate::windows::win32_safe::is_window(hwnd) == 0
                    || crate::windows::win32_safe::is_menu(native) == 0
                    || crate::windows::win32_safe::get_menu(hwnd) != native
            } {
                return false;
            }
            state.borrow_mut().window_menus.insert(window, token);
        }
        None => {
            if !native.is_null() || {
                crate::windows::win32_safe::is_window(hwnd) == 0
                    || !crate::windows::win32_safe::get_menu(hwnd).is_null()
            } {
                return false;
            }
            state.borrow_mut().window_menus.remove(&window);
        }
    }
    reconcile_window_menu_ledger(state);
    true
}

pub(super) fn reconcile_window_menu_ledger(state: &Rc<RefCell<WorkerState>>) {
    let owners = {
        let state = state.borrow();
        state
            .window_menus
            .iter()
            .map(|(window, token)| (*window, state.windows.get(window).copied(), *token))
            .collect::<Vec<_>>()
    };
    for (window, hwnd, token) in owners {
        let current = hwnd.is_some_and(|hwnd| {
            super::win16_window_identity::resolve_user_window(state, window) == Some(hwnd)
                && state
                    .borrow()
                    .menus
                    .get(&token)
                    .copied()
                    .is_some_and(|native| {
                        menu_token_matches(state, token, native)
                            && (crate::windows::win32_safe::is_window(hwnd) != 0
                                && crate::windows::win32_safe::get_menu(hwnd) == native)
                    })
        });
        if !current {
            let mut state = state.borrow_mut();
            if state.window_menus.get(&window) == Some(&token) {
                state.window_menus.remove(&window);
            }
        }
    }
}

pub(super) fn menu_attached_to_live_window(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostMenu,
    native: HMENU,
) -> Result<bool, RuntimeError> {
    // Treat mapped root menus and their submenu trees as window owners; a
    // submenu need not equal GetMenu(hwnd) to remain owned by that HWND.
    if !menu_token_matches(state, token, native) {
        return Ok(false);
    }
    let mut windows = {
        let state = state.borrow();
        if state
            .pending_window_menu_retirements
            .iter()
            .any(|pending| pending.menu_tokens.get(&token) == Some(&(native as usize)))
        {
            return Ok(true);
        }
        state
            .windows
            .iter()
            .map(|(window, hwnd)| {
                (
                    *window,
                    *hwnd,
                    state.window_menus.get(window).copied(),
                    state.system_menus.get(window).copied(),
                )
            })
            .collect::<Vec<_>>()
    };
    windows.sort_unstable_by_key(|(window, _, _, _)| *window);
    for (window, hwnd, _, _) in windows {
        for root in current_window_menu_roots(state, window, hwnd) {
            if refresh_menu_tree(state, root)?.get(&token) == Some(&(native as usize)) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn current_window_menu_roots(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: HWND,
) -> BTreeSet<Win16HostMenu> {
    if super::win16_window_identity::resolve_user_window(state, window) != Some(hwnd) {
        return BTreeSet::new();
    }
    let (window_menu, system_menu) = {
        let state = state.borrow();
        (
            state.window_menus.get(&window).copied(),
            state.system_menus.get(&window).copied(),
        )
    };
    let native = crate::windows::win32_safe::get_menu(hwnd);
    let mut roots = BTreeSet::new();
    if let Some(token) = window_menu {
        if menu_token_matches(state, token, native) {
            roots.insert(token);
        }
    }
    if let Some(token) = system_menu {
        if state
            .borrow()
            .menus
            .get(&token)
            .copied()
            .is_some_and(|native| {
                menu_token_matches(state, token, native)
                    && (crate::windows::win32_safe::is_menu(native) != 0)
            })
        {
            roots.insert(token);
        }
    }
    if let Some(token) = token_for_native(state, native) {
        roots.insert(token);
    }
    roots
}

pub(super) struct MenuCallOwnerGuard {
    state: Rc<RefCell<WorkerState>>,
    owners: std::collections::BTreeMap<Win16HostMenu, usize>,
}

/// Pin a complete native menu tree before SetMenu/DrawMenuBar can reenter
/// guest code and mutate the HWND ledger or request DestroyMenu.
pub(super) fn retain_menu_call_owners(
    state: &Rc<RefCell<WorkerState>>,
    roots: &[Win16HostMenu],
) -> Result<MenuCallOwnerGuard, RuntimeError> {
    let mut owners = std::collections::BTreeMap::new();
    for root in roots {
        if cached_menu_tree_is_retiring(state, *root) {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "native menu owner is being consumed by an active USER call",
            ));
        }
        owners.extend(refresh_menu_tree(state, *root)?);
    }
    let mut borrowed = state.borrow_mut();
    borrowed
        .active_menu_call_owners
        .try_reserve(1)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve an in-flight native menu owner frame",
                error,
            )
        })?;
    // A nested DestroyWindow may report invalid aliases before this outer USER
    // call returns, so reserve space for every exact identity pinned here.
    borrowed
        .deferred_menu_retirements
        .try_reserve(owners.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve deferred native menu retirement records",
                error,
            )
        })?;
    borrowed.active_menu_call_owners.push(owners.clone());
    drop(borrowed);
    Ok(MenuCallOwnerGuard {
        state: Rc::clone(state),
        owners,
    })
}

impl Drop for MenuCallOwnerGuard {
    fn drop(&mut self) {
        let mut state = self.state.borrow_mut();
        if let Some(index) = state
            .active_menu_call_owners
            .iter()
            .rposition(|owners| owners == &self.owners)
        {
            state.active_menu_call_owners.remove(index);
        }
        drop(state);
        // A nested call has already returned any dead guest aliases. Drop only
        // releases its native sidecars when their exact HMENU is now invalid.
        flush_deferred_menu_retirements(&self.state);
    }
}
