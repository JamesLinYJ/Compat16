//! Template-owned STATIC icons. Identity observation does not publish a DLGPROC
//! route: the guest's first dialog callback remains WM_INITDIALOG.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use runtime::{DiagnosticKind as Kind, RuntimeError, Win16CreationId, Win16HostDialogAtom as Atom,
    Win16HostDialogTemplate, Win16HostWindow};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyWindow, EndDialog, GetParent, IsWindow};
use crate::windows::win16_dialog_icon_retention::{self as retention, DialogIconOwner};
use super::win16_window_worker::{self as worker, WorkerState};

#[path = "win16_dialog_icon_observer.rs"]
mod observer;
pub(super) use observer::CreationScope;
#[path = "win16_dialog_icon_subclass.rs"]
mod subclass;

#[path = "win16_dialog_icon_index.rs"]
mod index;
pub(super) type IconSidecars = index::IndexedSidecars<IconSidecar>;

impl index::IndexedSidecars<IconSidecar> {
    pub(super) fn unbound_count(&self) -> usize { self.iter().filter(|sidecar| sidecar.hwnd.is_none()).count() }
    fn push(&mut self, sidecar: IconSidecar) -> Result<(), IconSidecar> {
        self.insert(sidecar.window, sidecar.operation, sidecar.creation, sidecar.size_pointer, sidecar)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Phase { Prepared, Bound, NonclientCreating, NonclientCreated, Creating, Installing, Ready, Failed }

pub(super) struct IconSidecar {
    operation: u64,
    creation: Win16CreationId,
    window: Win16HostWindow,
    hwnd: Option<usize>,
    size_pointer: usize,
    control_id: u16,
    owner: Arc<DialogIconOwner>,
    phase: Phase,
    subclass_installed: bool,
    initial_set_pending: bool,
    replacement_seen: bool,
}

pub(super) fn eligible(template: &Win16HostDialogTemplate) -> bool {
    if !template.items.iter().any(|item| item.initial_icon.is_some()) { return true; }
    matches!(template.class, Atom::None | Atom::Ordinal(0x8002))
        && template.guest_class_name.is_none()
        && template.style & 0x0010 == 0 // DS_NOFAILCREATE cannot hide a rejected child.
        && template.items.iter().all(|item|
            matches!(item.class, Atom::Ordinal(0x80..=0x85)) && item.guest_class_name.is_none()
                && (item.initial_icon.is_none() || (matches!(item.class, Atom::Ordinal(0x82))
                    && item.style & 0x1f == 3 && item.creation_data.is_empty()
                    && matches!(item.title, Atom::None))))
}

pub(super) fn prepare(
    state: &Rc<RefCell<WorkerState>>, template: &Win16HostDialogTemplate,
    offsets: &[Option<(usize, usize)>], base: usize, operation: u64,
    creation: Win16CreationId, modal: bool,
) -> Result<Option<CreationScope>, RuntimeError> {
    let count = template.items.iter().filter(|item| item.initial_icon.is_some()).count();
    if count == 0 { return Ok(None); }
    if !eligible(template) { return Err(error("unsupported template-owned STATIC icon form")); }
    state.borrow_mut().dialog_icon_sidecars.try_reserve(count).map_err(|source|
        RuntimeError::with_source(Kind::ResourceExhausted, "reserve dialog icon sidecars", source))?;
    let staged = (|| {
        for (index, item) in template.items.iter().enumerate() {
            let Some(icon) = item.initial_icon else { continue; };
            let offset = offsets.get(index).and_then(|offset| *offset)
                .ok_or_else(|| error("dialog icon item lost its owned creation payload"))?.0;
            let size_pointer = base.checked_add(offset)
                .ok_or_else(|| error("dialog icon creation pointer overflow"))?;
            let window = worker::allocate_window_token(state)?;
            let (lease, worker_id) = {
                let state = state.borrow();
                (state.images.lease_icon(icon)?.ok_or_else(|| error("dialog icon token is no longer live"))?,
                    state.worker_retirement_id)
            };
            let owner = retention::stage(worker_id, lease)?;
            let inserted = state.borrow_mut().dialog_icon_sidecars.push(IconSidecar {
                operation, creation, window, hwnd: None, size_pointer,
                control_id: item.id, owner, phase: Phase::Prepared,
                subclass_installed: false, initial_set_pending: false, replacement_seen: false,
            });
            if let Err(sidecar) = inserted {
                retention::cancel_unbound(&sidecar.owner);
                return Err(error("dialog icon sidecar index reservation or uniqueness failed"));
            }
        }
        CreationScope::enter(state, operation, creation, count, modal).map(Some)
    })();
    if staged.is_err() { retire_after_call(state); }
    staged
}

/// Invoked before any guest INIT callback or template menu attachment.
pub(super) fn before_init(
    state: &Rc<RefCell<WorkerState>>, operation: u64, creation: Win16CreationId, hwnd: HWND,
) -> Result<(), RuntimeError> {
    let Some((expected, modal, failed)) = observer::active_contract(operation, creation) else { return Ok(()); };
    let (root, root_token, ready) = {
        let borrowed = state.borrow();
        let pending = borrowed.pending_dialog_routes.iter().find(|pending|
            pending.operation == operation && pending.creation == creation)
            .ok_or_else(|| error("dialog icon INIT lost its pending root"))?;
        let ready = borrowed.dialog_icon_sidecars.iter().filter(|sidecar|
            sidecar.operation == operation && sidecar.creation == creation
                && sidecar.phase == Phase::Ready).count();
        (pending.root_window, pending.root_token, ready)
    };
    let mut exact_children = 0;
    let count = state.borrow().dialog_icon_sidecars.len();
    for index in 0..count {
        let candidate = {
            let borrowed = state.borrow();
            borrowed.dialog_icon_sidecars.get(index).filter(|sidecar|
                sidecar.operation == operation && sidecar.creation == creation && sidecar.phase == Phase::Ready)
                .map(|sidecar| (sidecar.window, sidecar.hwnd))
        };
        if let Some((window, Some(child))) = candidate {
            if super::win16_window_identity::resolve(state, window) == Some(child as HWND)
                && unsafe { GetParent(child as HWND) } == hwnd
                && state.borrow().windows_by_native.get(&child).is_some_and(|identity|
                    identity.window == window && identity.creation == Some(creation))
            { exact_children += 1; }
        }
    }
    if !failed && ready == expected && exact_children == expected && root == Some(hwnd as usize)
        && super::win16_window_identity::resolve(state, root_token) == Some(hwnd)
    { return Ok(()); }
    // An unrecognized payload must not leave DialogBox in its modal loop. The
    // INIT cookie/operation was verified by the caller; never destroy a pinned
    // different root or a replacement incarnation.
    let safe_root = root.is_none() || (root == Some(hwnd as usize)
        && super::win16_window_identity::resolve(state, root_token) == Some(hwnd));
    if safe_root {
        if modal { unsafe { EndDialog(hwnd, -1); } }
        else { unsafe { DestroyWindow(hwnd); } }
    }
    observer::report(operation, creation, error("dialog icon creation did not complete before WM_INITDIALOG"));
    Err(error("dialog icon creation did not complete before WM_INITDIALOG"))
}

/// Only native-call return plus HWND absence retires a bound owner. Synthetic
/// NCDESTROY and removed identity properties leave the process owner retained.
pub(super) fn retire_after_call(state: &Rc<RefCell<WorkerState>>) {
    let mut index = 0;
    loop {
        let candidate = {
            let state = state.borrow();
            state.dialog_icon_sidecars.get(index).map(|sidecar|
                (Arc::clone(&sidecar.owner), sidecar.hwnd, sidecar.operation, sidecar.creation, sidecar.window))
        };
        let Some((owner, hwnd, operation, creation, window)) = candidate else { break; };
        let dead = match hwnd {
            None => !observer::has_frame(operation, creation) && retention::cancel_unbound(&owner),
            Some(hwnd) => (unsafe { IsWindow(hwnd as HWND) } == 0) && retention::retire_if_absent(&owner),
        };
        if dead {
            if let Some(hwnd) = hwnd { worker::remove_window_maps(state, window, hwnd as HWND); }
            let removed = state.borrow_mut().dialog_icon_sidecars.swap_remove(index);
            drop(removed);
        } else { index += 1; }
    }
}

fn error(message: &'static str) -> RuntimeError { RuntimeError::new(Kind::HostFailure, message) }

#[cfg(test)]
#[path = "win16_dialog_icon_controls_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "win16_dialog_icon_native_tests.rs"]
mod native_tests;
