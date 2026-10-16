//! Exact native window subtree identity and destruction retirement lifecycle.
//!
//! Both DestroyWindow and typed WM_MDIDESTROY use this scope so maps, menu
//! pins, and post-USER invalidation are retired from the same exact snapshot.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostMenu, Win16HostWindow,
    Win16HostWindowRetirementReceipt,
};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{GetAncestor, GetWindow, GA_PARENT, GW_OWNER, IsWindow};

use super::{NativeWindowIdentity, WorkerState, remove_window_maps, retire_clipboard_viewer};

pub(in crate::windows) struct WindowRetirementScope {
    pub(in crate::windows) candidates: Vec<NativeWindowRetirementCandidate>,
    pub(in crate::windows) receipts: Vec<Win16HostWindowRetirementReceipt>,
    menu_retirement_ids: Vec<u64>,
}

pub(in crate::windows) struct WindowRetirementPreparation {
    pub(in crate::windows) scope: WindowRetirementScope,
    pub(in crate::windows) ready: bool,
}

impl WindowRetirementPreparation {
    pub(in crate::windows) fn candidate_for(
        &self,
        window: Win16HostWindow,
        hwnd: HWND,
    ) -> Option<NativeWindowRetirementCandidate> {
        self.scope.candidates.iter().copied().find(|candidate| {
            candidate.window == window && candidate.hwnd == hwnd
        })
    }
}

pub(in crate::windows) struct WindowRetirementFinish {
    pub(in crate::windows) receipts: Vec<Win16HostWindowRetirementReceipt>,
    pub(in crate::windows) invalidated_menus: Vec<Win16HostMenu>,
}

/// Pin every menu currently attached to the exact native subtree before any
/// clipboard callback or USER call can reenter guest code.
pub(in crate::windows) fn prepare_window_retirement(
    state: &Rc<RefCell<WorkerState>>,
    root: Win16HostWindow,
    root_hwnd: HWND,
) -> Result<Option<WindowRetirementPreparation>, RuntimeError> {
    let Some(mut scope) = begin_window_retirement(state, root, root_hwnd)? else {
        return Ok(None);
    };
    for candidate in scope.candidates.iter().copied() {
        retire_clipboard_viewer(state, candidate.window);
    }
    let ready = match extend_window_retirement(state, &mut scope, root, root_hwnd) {
        Ok(ready) => ready,
        Err(error) => {
            let _ = finish_window_retirement(state, scope, false);
            return Err(error);
        }
    };
    Ok(Some(WindowRetirementPreparation { scope, ready }))
}

fn begin_window_retirement(
    state: &Rc<RefCell<WorkerState>>,
    root: Win16HostWindow,
    root_hwnd: HWND,
) -> Result<Option<WindowRetirementScope>, RuntimeError> {
    begin_window_retirement_scope(state, root, root_hwnd, true)
}

/// Begin an observation scope around a USER dispatch which may destroy a
/// mapped subtree. It pins attached menu identities but deliberately does not
/// retire clipboard viewers or reject an existing DC: DispatchMessage/close
/// semantics are observed, not vetoed by this scope.
pub(in crate::windows) fn begin_window_retirement_observation(
    state: &Rc<RefCell<WorkerState>>,
    root: Win16HostWindow,
    root_hwnd: HWND,
) -> Result<Option<WindowRetirementScope>, RuntimeError> {
    begin_window_retirement_scope(state, root, root_hwnd, false)
}

fn begin_window_retirement_scope(
    state: &Rc<RefCell<WorkerState>>,
    root: Win16HostWindow,
    root_hwnd: HWND,
    reject_active_dc: bool,
) -> Result<Option<WindowRetirementScope>, RuntimeError> {
    if unsafe { IsWindow(root_hwnd) } == 0
        || !super::native_windows::native_window_is_destruction_target(state, root, root_hwnd)
    {
        return Ok(None);
    }
    let candidates = snapshot_window_retirement_candidates(state, root, root_hwnd)?;
    if candidates.is_empty()
        || (reject_active_dc && subtree_has_active_dc(state, &candidates))
    {
        return Ok(None);
    }
    let mut windows = Vec::new();
    windows.try_reserve_exact(candidates.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve exact native window owners before menu retirement begins",
            error,
        )
    })?;
    windows.extend(candidates.iter().map(|candidate| (candidate.window, candidate.hwnd)));
    let mut receipts = Vec::new();
    receipts.try_reserve_exact(candidates.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve exact window retirement receipts before USER teardown",
            error,
        )
    })?;
    let menu_retirement_ids = super::super::win16_menu_attachment::
        begin_window_menu_retirement(state, &windows)?;
    Ok(Some(WindowRetirementScope {
        candidates,
        receipts,
        menu_retirement_ids,
    }))
}

/// Merge any exact child generations created or moved into the subtree while
/// reentrant callbacks ran, and reject a target with a live DC.
fn extend_window_retirement(
    state: &Rc<RefCell<WorkerState>>,
    scope: &mut WindowRetirementScope,
    root: Win16HostWindow,
    root_hwnd: HWND,
) -> Result<bool, RuntimeError> {
    if unsafe { IsWindow(root_hwnd) } == 0
        || !super::native_windows::native_window_is_destruction_target(state, root, root_hwnd)
    {
        return Ok(false);
    }
    let candidates = snapshot_window_retirement_candidates(state, root, root_hwnd)?;
    if candidates.is_empty() || subtree_has_active_dc(state, &candidates) {
        return Ok(false);
    }
    let root_is_current = candidates.iter().any(|candidate| {
        candidate.window == root && candidate.hwnd == root_hwnd
    });
    let mut windows = Vec::new();
    windows.try_reserve_exact(candidates.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve current exact window owners before extending menu pins",
            error,
        )
    })?;
    windows.extend(candidates.iter().map(|candidate| (candidate.window, candidate.hwnd)));
    let additions = candidates.iter().copied().filter(|candidate| {
        !scope.candidates.iter().any(|existing| same_candidate(*existing, *candidate))
    }).collect::<Vec<_>>();
    scope.candidates.try_reserve(additions.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve newly observed exact window identities before USER teardown",
            error,
        )
    })?;
    let receipt_capacity = scope.candidates.len().checked_add(additions.len()).ok_or_else(|| {
        RuntimeError::new(Kind::ResourceExhausted,
            "native window retirement receipt capacity overflow")
    })?;
    // Receipts remain empty until USER returns. Reserve the whole candidate
    // set, not only additions relative to the still-empty receipt vector.
    scope.receipts.try_reserve(receipt_capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve receipts for newly observed exact window identities",
            error,
        )
    })?;
    scope.menu_retirement_ids.try_reserve(candidates.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve menu retirement pins before extending the native subtree snapshot",
            error,
        )
    })?;
    let menu_ids = super::super::win16_menu_attachment::
        begin_window_menu_retirement(state, &windows)?;
    scope.menu_retirement_ids.extend(menu_ids);
    scope.candidates.extend(additions);
    Ok(root_is_current)
}

fn subtree_has_active_dc(
    state: &Rc<RefCell<WorkerState>>,
    candidates: &[NativeWindowRetirementCandidate],
) -> bool {
    let dcs = state.borrow().dcs.clone();
    candidates.iter().any(|candidate| dcs.window_has_active_dc(candidate.window))
}

pub(in crate::windows) fn finish_window_retirement(
    state: &Rc<RefCell<WorkerState>>,
    mut scope: WindowRetirementScope,
    probe_consumed_menus: bool,
) -> WindowRetirementFinish {
    for candidate in scope.candidates.iter().copied() {
        if retire_dead_window_candidate(state, candidate) {
            scope.receipts.push(Win16HostWindowRetirementReceipt {
                window: candidate.window,
            });
        }
    }
    let menu_snapshot = super::super::win16_menu_attachment::finish_window_menu_retirement(
        state, &scope.menu_retirement_ids,
    );
    // HWND destruction can consume menus even when a callback has already
    // removed the window maps. This exact snapshot is invalidated only when
    // IsMenu/native generation evidence confirms consumption or reuse.
    let invalidated_menus = if probe_consumed_menus {
        super::super::win16_menu_attachment::
            retire_destroyed_window_menu_snapshot(state, &menu_snapshot)
    } else {
        Vec::new()
    };
    super::super::win16_menu_attachment::flush_deferred_menu_retirements(state);
    WindowRetirementFinish {
        receipts: scope.receipts,
        invalidated_menus,
    }
}

pub(in crate::windows) fn same_candidate(
    left: NativeWindowRetirementCandidate,
    right: NativeWindowRetirementCandidate,
) -> bool {
    left.window == right.window
        && left.hwnd == right.hwnd
        && left.identity.window == right.identity.window
        && left.identity.class == right.identity.class
        && left.identity.creation == right.identity.creation
        && left.identity.process_id == right.identity.process_id
        && left.identity.thread_id == right.identity.thread_id
        && left.identity.owned == right.identity.owned
}

#[derive(Clone, Copy)]
pub(in crate::windows::win16_windows) struct NativeWindowRetirementCandidate {
    pub(in crate::windows::win16_windows) window: Win16HostWindow,
    pub(in crate::windows::win16_windows) hwnd: HWND,
    pub(in crate::windows::win16_windows) identity: NativeWindowIdentity,
}

/// Snapshot the exact mapped identities in one live native window subtree.
/// Call before a USER operation that may synchronously destroy the tree.
pub(in crate::windows::win16_windows) fn snapshot_window_retirement_candidates(
    state: &Rc<RefCell<WorkerState>>,
    root: Win16HostWindow,
    root_hwnd: HWND,
) -> Result<Vec<NativeWindowRetirementCandidate>, RuntimeError> {
    let descendants = descendants_of(state, root, root_hwnd)?;
    let mut candidates = Vec::new();
    candidates.try_reserve_exact(descendants.len()).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve exact native window identities before a USER teardown call",
            error,
        )
    })?;
    let borrowed = state.try_borrow().map_err(|_| RuntimeError::new(
        Kind::InternalInvariant,
        "snapshot exact native window identities without a conflicting worker borrow",
    ))?;
    for (window, hwnd) in descendants {
        let Some(identity) = borrowed.windows_by_native.get(&(hwnd as usize)).copied()
            .filter(|identity| identity.window == window)
        else {
            continue;
        };
        if borrowed.windows.get(&window).copied() == Some(hwnd) {
            candidates.push(NativeWindowRetirementCandidate { window, hwnd, identity });
        }
    }
    Ok(candidates)
}

/// Capture one exact mapped token/HWND generation for a synchronous destroy.
pub(in crate::windows::win16_windows) fn capture_window_retirement_candidate(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: HWND,
) -> Option<NativeWindowRetirementCandidate> {
    let borrowed = state.borrow();
    if borrowed.windows.get(&window).copied() != Some(hwnd) {
        return None;
    }
    let identity = borrowed.windows_by_native.get(&(hwnd as usize)).copied()
        .filter(|identity| identity.window == window)?;
    Some(NativeWindowRetirementCandidate { window, hwnd, identity })
}

/// Retire a candidate only after USER confirms the HWND is dead, the native
/// index has handed its bits to another identity, or a callback already
/// recorded the exact token's lifecycle tombstone.
pub(in crate::windows::win16_windows) fn retire_dead_window_candidate(
    state: &Rc<RefCell<WorkerState>>,
    candidate: NativeWindowRetirementCandidate,
) -> bool {
    let (already_retired, token_still_maps_candidate, native_owner) = {
        let borrowed = state.borrow();
        let retired = borrowed.retired_window_tokens.contains(&candidate.window)
            && !borrowed.windows.contains_key(&candidate.window);
        let token_still_maps_candidate =
            borrowed.windows.get(&candidate.window).copied() == Some(candidate.hwnd);
        let native_owner = borrowed
            .windows_by_native
            .get(&(candidate.hwnd as usize))
            .copied();
        (retired, token_still_maps_candidate, native_owner)
    };
    if already_retired {
        return true;
    }
    if !token_still_maps_candidate {
        return false;
    }
    match native_owner {
        Some(current) if current.window == candidate.window => {
            // The token still owns this exact native generation. USER must
            // confirm its HWND is dead before we clear its native sidecars.
            if !same_window_identity(current, candidate.identity)
                || unsafe { IsWindow(candidate.hwnd) } != 0
            {
                return false;
            }
        }
        // The old token-to-HWND record survived, but USER has already handed
        // those HWND bits to another identity (or removed the native index).
        // remove_window_maps retires only the old token and preserves a newer
        // owner found at the same address.
        Some(_) | None => {}
    }
    remove_window_maps(state, candidate.window, candidate.hwnd);
    let borrowed = state.borrow();
    borrowed.retired_window_tokens.contains(&candidate.window)
        && !borrowed.windows.contains_key(&candidate.window)
        && borrowed.windows_by_native.get(&(candidate.hwnd as usize))
            .is_none_or(|identity| identity.window != candidate.window)
}

fn same_window_identity(left: NativeWindowIdentity, right: NativeWindowIdentity) -> bool {
    left.window == right.window
        && left.class == right.class
        && left.creation == right.creation
        && left.process_id == right.process_id
        && left.thread_id == right.thread_id
        && left.owned == right.owned
}

pub(super) fn descendants_of(
    state: &Rc<RefCell<WorkerState>>,
    root: Win16HostWindow,
    root_hwnd: HWND,
) -> Result<Vec<(Win16HostWindow, HWND)>, RuntimeError> {
    let windows = {
        let state = state.borrow();
        state.windows.iter().map(|(token, hwnd)| (*token, *hwnd)).collect::<Vec<_>>()
    };
    let mut descendants = Vec::new();
    for (token, hwnd) in windows {
        let exact_retained_root = token == root && hwnd == root_hwnd
            && super::native_windows::native_window_is_destruction_target(state, root, root_hwnd);
        if !exact_retained_root
            && super::super::win16_window_identity::resolve(state, token) != Some(hwnd)
        {
            continue;
        }
        // Both actual-parent and owner relationships can cause destruction.
        // Foreign intermediate HWNDs need not have guest aliases. Exhaustion
        // is an error before USER, never evidence that a candidate is outside
        // the native destruction closure.
        let reaches_root = token == root || hwnd == root_hwnd
            || reaches_destruction_root(hwnd as usize, root_hwnd as usize, 65_536, |current| {
                [unsafe { GetAncestor(current as HWND, GA_PARENT) } as usize,
                    unsafe { GetWindow(current as HWND, GW_OWNER) } as usize]
            })?;
        if reaches_root { descendants.push((token, hwnd)); }
    }
    Ok(descendants)
}

fn reaches_destruction_root(
    start: usize,
    root: usize,
    maximum_nodes: usize,
    mut links: impl FnMut(usize) -> [usize; 2],
) -> Result<bool, RuntimeError> {
    let mut pending = vec![start];
    let mut visited = BTreeSet::new();
    while let Some(current) = pending.pop() {
        if current == root { return Ok(true); }
        if current == 0 || visited.contains(&current) { continue; }
        if visited.len() >= maximum_nodes {
            return Err(RuntimeError::new(Kind::ResourceExhausted,
                "native parent/owner destruction graph exceeds its bounded traversal"));
        }
        visited.insert(current);
        for parent in links(current) {
            if parent == root && parent != 0 { return Ok(true); }
            if parent != 0 && !visited.contains(&parent) { pending.push(parent); }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod destruction_graph_tests {
    use super::*;

    #[test]
    fn both_actual_parent_and_owner_paths_reach_the_root() {
        for reverse in [false, true] {
            let reached = reaches_destruction_root(1, 9, 8, |node| {
                let edges = match node { 1 => [2, 3], 2 => [4, 0], 3 => [0, 9], _ => [0, 0] };
                if reverse { [edges[1], edges[0]] } else { edges }
            }).unwrap();
            assert!(reached);
        }
    }

    #[test]
    fn cycles_and_shared_ancestors_terminate_without_false_retirement_evidence() {
        let mut queries = 0;
        assert!(!reaches_destruction_root(1, 9, 3, |node| {
            queries += 1;
            match node { 1 => [2, 3], 2 => [1, 3], _ => [2, 1] }
        }).unwrap());
        assert_eq!(queries, 3);
    }

    #[test]
    fn traversal_bound_is_an_error_not_an_absent_relationship() {
        let error = reaches_destruction_root(1, 9, 2, |node| [node + 1, 0]).unwrap_err();
        assert_eq!(error.kind(), Kind::ResourceExhausted);
        assert!(reaches_destruction_root(1, 3, 2, |node| [node + 1, 0]).unwrap());
    }
}
