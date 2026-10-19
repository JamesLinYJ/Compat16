//! Capability for one live private-class WM_INITDIALOG default invocation.
use std::cell::RefCell;
use std::rc::Rc;

use runtime::{DiagnosticKind, RuntimeError, Win16CreationId, Win16HostWindow};
use windows_sys::Win32::Foundation::HWND;

use super::super::win16_window_worker::{DialogRoute, WorkerState};

pub(super) struct DefaultInitScope {
    state: Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    route: DialogRoute,
    consumer: u64,
    previous: Option<u64>,
}

impl DefaultInitScope {
    pub(super) fn begin(
        state: &Rc<RefCell<WorkerState>>,
        hwnd: HWND,
        window: Win16HostWindow,
        creation: Option<Win16CreationId>,
        source_operation: u64,
    ) -> Result<Option<Self>, RuntimeError> {
        let mut borrowed = state.borrow_mut();
        let Some(route) = borrowed
            .dialog_routes_by_native
            .get(&(hwnd as usize))
            .copied()
            .filter(|route| route.class_init_in_progress)
        else {
            return Ok(None);
        };
        if route.window != window
            || Some(route.creation) != creation
            || route.operation != source_operation
            || !borrowed
                .active_operations
                .iter()
                .any(|active| active.id == source_operation)
        {
            return Err(RuntimeError::new(
                DiagnosticKind::InternalInvariant,
                "private dialog default initialization lost its live creation callback",
            ));
        }
        let consumer = borrowed
            .active_operations
            .last()
            .ok_or_else(|| {
                RuntimeError::new(
                    DiagnosticKind::InternalInvariant,
                    "private dialog default initialization has no active invocation",
                )
            })?
            .id;
        let previous = route.class_init_default_operation;
        let current = borrowed
            .dialog_routes_by_native
            .get_mut(&(hwnd as usize))
            .ok_or_else(|| {
                RuntimeError::new(
                    DiagnosticKind::InternalInvariant,
                    "private dialog default initialization lost its retained route",
                )
            })?;
        current.class_init_default_operation = Some(consumer);
        Ok(Some(Self {
            state: Rc::clone(state),
            hwnd,
            route,
            consumer,
            previous,
        }))
    }
}

impl Drop for DefaultInitScope {
    fn drop(&mut self) {
        if let Some(current) = self
            .state
            .borrow_mut()
            .dialog_routes_by_native
            .get_mut(&(self.hwnd as usize))
            .filter(|current| {
                current.operation == self.route.operation
                    && current.creation == self.route.creation
                    && current.cookie == self.route.cookie
                    && current.window == self.route.window
                    && current.class_init_default_operation == Some(self.consumer)
            })
        {
            current.class_init_default_operation = self.previous;
        }
    }
}
