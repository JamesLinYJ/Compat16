//! Immutable Win16 creation provenance for native dialog template controls.

use super::win16_window_worker::WorkerState;
use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostWindow};
use std::{cell::RefCell, rc::Rc};
use windows_sys::Win32::{
    Foundation::HWND,
    UI::WindowsAndMessaging::{GW_CHILD, GW_HWNDNEXT},
};

pub(super) fn query(state: &Rc<RefCell<WorkerState>>, window: Win16HostWindow) -> Option<u16> {
    let hwnd = super::win16_window_identity::resolve(state, window)?;
    let state = state.borrow();
    state
        .window_creation_instances
        .get(&window)
        .copied()
        .or_else(|| {
            state
                .dialog_creation_data
                .get(&(hwnd as usize))
                .map(|(_, data)| data.guest_instance)
        })
}

/// Called before WM_INITDIALOG enters guest code. Adopt the live template
/// descendants once; subsequent GetParent/SetParent observations never alter
/// this record. Tokens include HWND incarnation, so recycled values cannot
/// inherit a former control's instance.
pub(super) fn capture_dialog(
    state: &Rc<RefCell<WorkerState>>,
    root: HWND,
    instance: u16,
) -> Result<(), RuntimeError> {
    let mut parents = Vec::new();
    parents.try_reserve(1).map_err(capacity_error)?;
    parents.push(root);
    while let Some(parent) = parents.pop() {
        let token = super::win16_window_identity::adopt(state, parent)?;
        super::win16_window_identity::associate_dialog_child(state, parent);
        {
            let mut state = state.borrow_mut();
            state
                .window_creation_instances
                .try_reserve(1)
                .map_err(capacity_error)?;
            state
                .window_creation_instances
                .entry(token)
                .or_insert(instance);
        }
        let mut child = crate::windows::win32_safe::get_window(parent, GW_CHILD);
        while !child.is_null() {
            parents.try_reserve(1).map_err(capacity_error)?;
            parents.push(child);
            child = crate::windows::win32_safe::get_window(child, GW_HWNDNEXT);
        }
    }
    Ok(())
}

fn capacity_error(error: std::collections::TryReserveError) -> RuntimeError {
    RuntimeError::with_source(
        Kind::ResourceExhausted,
        "retain native control creation provenance",
        error,
    )
}
