//! Menu identity retirement after confirmed native consumption.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::atomic::Ordering;

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostMenu, Win16HostWindow};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::HMENU;

use super::super::win16_window_worker::WorkerState;

pub(in crate::windows::win16_windows) struct MenuRetirementReservation {
    state: Rc<RefCell<WorkerState>>,
    identities: Vec<(Win16HostMenu, usize)>,
}

/// Keep old numeric handles reserved across a consuming USER call. A nested
/// CreateMenu must not bind a recycled value to the retiring guest token.
pub(in crate::windows::win16_windows) fn reserve_menu_retirement(
    state: &Rc<RefCell<WorkerState>>,
    tree: &BTreeMap<Win16HostMenu, usize>,
) -> Result<MenuRetirementReservation, RuntimeError> {
    let mut identities = Vec::new();
    identities.try_reserve_exact(tree.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "copy exact native menu generations for retirement",
            error,
        )
    })?;
    identities.extend(tree.iter().map(|(token, native)| (*token, *native)));
    let shared = Rc::clone(state);
    let mut state = state.borrow_mut();
    state
        .retiring_menu_native_handles
        .try_reserve(identities.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native menu generations before recursive destruction",
                error,
            )
        })?;
    state
        .retiring_menu_native_handles
        .extend(identities.iter().copied());
    drop(state);
    Ok(MenuRetirementReservation {
        state: shared,
        identities,
    })
}

impl Drop for MenuRetirementReservation {
    fn drop(&mut self) {
        let mut state = self.state.borrow_mut();
        for identity in &self.identities {
            if let Some(index) = state
                .retiring_menu_native_handles
                .iter()
                .rposition(|item| item == identity)
            {
                state.retiring_menu_native_handles.remove(index);
            }
        }
    }
}

pub(in crate::windows::win16_windows) fn invalidate_menu_identities(
    state: &Rc<RefCell<WorkerState>>,
    identities: &BTreeMap<Win16HostMenu, usize>,
    explicitly_destroyed: bool,
) -> Vec<Win16HostMenu> {
    let confirmed = identities
        .iter()
        .filter_map(|(token, raw)| {
            let native = *raw as HMENU;
            let current = {
                let state = state.borrow();
                state.menus.get(token).copied() == Some(native)
            };
            let replaced = {
                let state = state.borrow();
                current
                    && state
                        .menus_by_native
                        .get(raw)
                        .is_some_and(|active| active != token)
            };
            (current
                && (explicitly_destroyed || replaced || {
                    crate::windows::win32_safe::is_menu(native)
                } == 0))
                .then_some((*token, *raw))
        })
        .collect::<BTreeMap<_, _>>();
    if confirmed.is_empty() {
        return Vec::new();
    }
    let mut state = state.borrow_mut();
    let mut invalidated = BTreeSet::new();
    for (token, raw) in &confirmed {
        let retained = state
            .pending_window_menu_retirements
            .iter()
            .any(|pending| pending.menu_tokens.get(token) == Some(raw))
            || state
                .active_menu_call_owners
                .iter()
                .any(|owners| owners.get(token) == Some(raw));
        if retained {
            if !state.deferred_menu_retirements.contains(&(*token, *raw)) {
                state.deferred_menu_retirements.push((*token, *raw));
            }
            // Runtime aliases retire after this confirmed native destruction;
            // the exact host sidecar waits for its callback owner to unwind.
            invalidated.insert(*token);
            continue;
        }
        if state.menus.get(token).copied() != Some(*raw as HMENU) {
            continue;
        }
        state.menus.remove(token);
        if state.menus_by_native.get(raw) == Some(token) {
            state.menus_by_native.remove(raw);
        }
        state.owned_menus.remove(token);
        state.owned_menu_roots.remove(token);
        state.menu_children.remove(token);
        invalidated.insert(*token);
    }
    for children in state.menu_children.values_mut() {
        children.retain(|child| !invalidated.contains(child));
    }
    state
        .system_menus
        .retain(|_, menu| !invalidated.contains(menu));
    state
        .window_menus
        .retain(|_, menu| !invalidated.contains(menu));
    let roots = state
        .owned_menus
        .iter()
        .copied()
        .filter(|menu| {
            !state
                .menu_children
                .values()
                .any(|children| children.contains(menu))
        })
        .collect::<BTreeSet<_>>();
    state.owned_menu_roots = roots;
    invalidated.into_iter().collect()
}

pub(in crate::windows::win16_windows) fn retire_destroyed_window_menu_snapshot(
    state: &Rc<RefCell<WorkerState>>,
    identities: &BTreeMap<Win16HostMenu, usize>,
) -> Vec<Win16HostMenu> {
    invalidate_menu_identities(state, identities, false)
}

pub(in crate::windows::win16_windows) fn flush_deferred_menu_retirements(
    state: &Rc<RefCell<WorkerState>>,
) {
    let candidates = {
        let state = state.borrow();
        state
            .deferred_menu_retirements
            .iter()
            .copied()
            .filter(|(token, native)| {
                !state
                    .pending_window_menu_retirements
                    .iter()
                    .any(|pending| pending.menu_tokens.get(token) == Some(native))
                    && !state
                        .active_menu_call_owners
                        .iter()
                        .any(|owners| owners.get(token) == Some(native))
            })
            .collect::<Vec<_>>()
    };
    if candidates.is_empty() {
        return;
    }
    let mut dead = BTreeMap::new();
    for (token, native) in &candidates {
        let current = state.borrow().menus.get(token).copied() == Some(*native as HMENU);
        // A deferred identity was already confirmed consumed before it was
        // queued. Do not reinterpret a recycled numeric HMENU as that object.
        if current {
            dead.insert(*token, *native);
        }
    }
    if !dead.is_empty() {
        let _ = invalidate_menu_identities(state, &dead, true);
    }
    let mut state = state.borrow_mut();
    state
        .deferred_menu_retirements
        .retain(|identity| !candidates.contains(identity));
}

pub(in crate::windows::win16_windows) fn begin_window_menu_retirement(
    state: &Rc<RefCell<WorkerState>>,
    windows: &[(Win16HostWindow, HWND)],
) -> Result<Vec<u64>, RuntimeError> {
    // Reserve the callback-side error sink first, so later capacity and graph
    // inspection failures can be latched without replacing their typed cause.
    state
        .borrow_mut()
        .terminal_failures
        .try_reserve(windows.len().max(1))
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve typed window-menu retirement failure records",
                error,
            )
        })?;
    let mut retirement_ids = Vec::new();
    retirement_ids
        .try_reserve_exact(windows.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve window menu retirement generation IDs",
                error,
            )
        })?;
    for _ in windows {
        let id = super::NEXT_MENU_RETIREMENT_ID
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| {
                RuntimeError::new(
                    Kind::ResourceExhausted,
                    "window menu retirement generation space exhausted",
                )
            })?;
        retirement_ids.push(id);
    }
    let mut snapshots = Vec::new();
    snapshots
        .try_reserve_exact(windows.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve exact window menu retirement snapshots",
                error,
            )
        })?;
    for (window, hwnd) in windows {
        let mut menus = BTreeMap::new();
        for root in super::current_window_menu_roots(state, *window, *hwnd) {
            menus.extend(super::refresh_menu_tree(state, root)?);
        }
        snapshots.push((
            menus,
            state
                .borrow()
                .window_identity_cookies
                .get(window)
                .filter(|binding| binding.hwnd == *hwnd as usize)
                .map(|binding| binding.value),
        ));
    }
    let mut state_guard = state.borrow_mut();
    state_guard
        .pending_window_menu_retirements
        .try_reserve(windows.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve pending window menu retirement records",
                error,
            )
        })?;
    let menu_count = snapshots.iter().try_fold(0usize, |count, (menus, _)| {
        count.checked_add(menus.len()).ok_or_else(|| {
            RuntimeError::new(
                Kind::ResourceExhausted,
                "window menu retirement snapshot count overflow",
            )
        })
    })?;
    state_guard
        .deferred_menu_retirements
        .try_reserve(menu_count)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve deferred identities for a DestroyWindow callback stack",
                error,
            )
        })?;
    drop(state_guard);
    for (((window, hwnd), (menu_tokens, identity_cookie)), retirement_id) in
        windows.iter().zip(snapshots).zip(&retirement_ids)
    {
        state.borrow_mut().pending_window_menu_retirements.push(
            super::super::win16_window_worker::PendingWindowMenuRetirement {
                retirement_id: *retirement_id,
                window: *window,
                hwnd: *hwnd as usize,
                identity_cookie,
                menu_tokens,
            },
        );
    }
    Ok(retirement_ids)
}

pub(in crate::windows::win16_windows) fn capture_window_menu_retirement(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: HWND,
) -> Result<(), RuntimeError> {
    let identity_cookie = state
        .borrow()
        .window_identity_cookies
        .get(&window)
        .filter(|binding| binding.hwnd == hwnd as usize)
        .map(|binding| binding.value);
    let mut menu_tokens = BTreeMap::new();
    for root in super::current_window_menu_roots(state, window, hwnd) {
        menu_tokens.extend(super::refresh_menu_tree(state, root)?);
    }
    let mut state = state.borrow_mut();
    for pending in state
        .pending_window_menu_retirements
        .iter_mut()
        .filter(|pending| {
            pending.window == window
                && pending.hwnd == hwnd as usize
                && pending.identity_cookie == identity_cookie
        })
    {
        pending
            .menu_tokens
            .extend(menu_tokens.iter().map(|(token, native)| (*token, *native)));
    }
    Ok(())
}

pub(in crate::windows::win16_windows) fn finish_window_menu_retirement(
    state: &Rc<RefCell<WorkerState>>,
    retirement_ids: &[u64],
) -> BTreeMap<Win16HostMenu, usize> {
    let mut retired = BTreeMap::new();
    let mut state = state.borrow_mut();
    for retirement_id in retirement_ids {
        if let Some(index) = state
            .pending_window_menu_retirements
            .iter()
            .rposition(|pending| pending.retirement_id == *retirement_id)
        {
            retired.extend(
                state
                    .pending_window_menu_retirements
                    .remove(index)
                    .menu_tokens,
            );
        }
    }
    retired
}

/// A fresh CreateMenu result is a new native incarnation even when USER has
/// recycled a numeric HMENU still present in an older callback snapshot.
/// Retire that exact token generation before publishing the new token; pending
/// and active frames retain their old sidecar until their normal unwind.
fn retire_replaced_menu_generation(
    state: &Rc<RefCell<WorkerState>>,
    native: HMENU,
) -> Result<Vec<Win16HostMenu>, RuntimeError> {
    if native.is_null() {
        return Ok(Vec::new());
    }
    let raw = native as usize;
    let token = { state.borrow().menus_by_native.get(&raw).copied() };
    let Some(token) = token else {
        return Ok(Vec::new());
    };
    if state.borrow().menus.get(&token).copied() != Some(native) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "fresh menu creation collided with an inconsistent native-generation index",
        ));
    }
    let identities = {
        let tokens = super::menu_tree(state, token);
        let state = state.borrow();
        tokens
            .into_iter()
            .filter_map(|token| {
                state
                    .menus
                    .get(&token)
                    .map(|native| (token, *native as usize))
            })
            .collect::<BTreeMap<_, _>>()
    };
    let root_identity = BTreeMap::from([(token, raw)]);
    let mut invalidated = invalidate_menu_identities(state, &root_identity, true)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let descendants = identities
        .iter()
        .filter(|(candidate, _)| **candidate != token)
        .map(|(token, native)| (*token, *native))
        .collect::<BTreeMap<_, _>>();
    invalidated.extend(invalidate_menu_identities(state, &descendants, false));
    let mut state = state.borrow_mut();
    // The old token may remain in pending/active snapshots, but the reverse
    // lookup must name the fresh object now returned for this raw HMENU.
    if state.menus_by_native.get(&raw) == Some(&token) {
        state.menus_by_native.remove(&raw);
    }
    Ok(invalidated.into_iter().collect())
}

/// Publish an HMENU returned by a fresh native creation API under a new host
/// token. This is deliberately separate from `intern_menu`, which resolves
/// handles observed through existing attachments and submenu edges.
pub(in crate::windows::win16_windows) fn publish_fresh_menu_generation(
    state: &Rc<RefCell<WorkerState>>,
    native: HMENU,
    token: Win16HostMenu,
) -> Result<(Option<Win16HostMenu>, Vec<Win16HostMenu>), RuntimeError> {
    if native.is_null() || { crate::windows::win32_safe::is_menu(native) } == 0 {
        return Ok((None, Vec::new()));
    }
    let raw = native as usize;
    let invalidated = match retire_replaced_menu_generation(state, native) {
        Ok(invalidated) => invalidated,
        Err(error) => {
            // The native creation already succeeded. Keep its owner by
            // dropping only the corrupt reverse-index entry, recording the
            // original invariant, and publishing it under its fresh token.
            latch_retirement_failure(state, error);
            let mut state = state.borrow_mut();
            if let Some(stale) = state.menus_by_native.get(&raw).copied() {
                if state.menus.get(&stale).copied() != Some(native) {
                    state.menus_by_native.remove(&raw);
                }
            }
            Vec::new()
        }
    };
    let mut state = state.borrow_mut();
    if state.menus.contains_key(&token) {
        drop(state);
        // A fresh native owner cannot be published under a reused host token.
        // Release the untracked USER object before returning its invariant.
        (crate::windows::win32_safe::destroy_menu(native));
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "fresh native menu token was already present in the owner ledger",
        ));
    }
    if state.menus_by_native.contains_key(&raw) {
        drop(state);
        // Do not leak the new object or steal another generation's reverse
        // lookup if retirement failed to clear the collided raw handle.
        (crate::windows::win32_safe::destroy_menu(native));
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "fresh native menu generation remained indexed after retirement",
        ));
    }
    state.menus.insert(token, native);
    state.menus_by_native.insert(raw, token);
    state.owned_menus.insert(token);
    state.owned_menu_roots.insert(token);
    Ok((Some(token), invalidated))
}

/// Fail-stop after a typed menu-retirement failure and preserve its cause. The
/// native callback ABI cannot return RuntimeError, so report it through the
/// innermost active operation response and keep it for terminal aggregation.
pub(in crate::windows::win16_windows) fn latch_retirement_failure(
    state: &Rc<RefCell<WorkerState>>,
    error: RuntimeError,
) {
    let (response, failure) = {
        let mut state = state.borrow_mut();
        let initiates_terminal_transition = !state.aborted;
        state.callbacks_enabled = false;
        state.aborted = true;
        let failure = std::sync::Arc::new(error);
        state
            .terminal_failures
            .push(std::sync::Arc::clone(&failure));
        let response = initiates_terminal_transition
            .then(|| {
                state
                    .active_operations
                    .last()
                    .map(|operation| operation.response.clone())
            })
            .flatten();
        (response, failure)
    };
    if let Some(response) = response {
        // A WndProc cannot return RuntimeError through USER's ABI. Complete the
        // innermost live operation with the same typed cause before its ordinary
        // BOOL/result path can publish a misleading success or failure value.
        let _ = response.send(Err(RuntimeError::with_source(
            failure.kind(),
            "Win16 USER operation encountered a menu retirement failure",
            failure,
        )));
    }
}
