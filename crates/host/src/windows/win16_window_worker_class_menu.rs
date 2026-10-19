//! Materialize and retire copied default class menus on the HWND owner thread.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::rc::Rc;
use std::sync::Arc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostMenu, Win16MenuOperation, Win16MenuResult,
    Win16MenuTemplate,
};

use super::WorkerState;

pub(super) fn create(
    state: &Rc<RefCell<WorkerState>>,
    template: &Win16MenuTemplate,
) -> Result<Option<Win16HostMenu>, RuntimeError> {
    let result = super::super::win16_menu_worker::execute(
        state,
        Win16MenuOperation::CreateFromTemplate {
            template: template.clone(),
        },
        &BTreeMap::new(),
    )?;
    match result {
        Win16MenuResult::Created(Some(menu)) if menu.0 != 0 => Ok(Some(menu)),
        Win16MenuResult::Created(None) => Ok(None),
        Win16MenuResult::Created(Some(_)) => Err(RuntimeError::new(
            Kind::InternalInvariant,
            "native class-menu materializer returned a zero host identity",
        )),
        _ => Err(RuntimeError::new(
            Kind::InternalInvariant,
            "native class-menu materializer returned a non-creation result",
        )),
    }
}

pub(super) fn retire_unattached_class_menu(
    state: &Rc<RefCell<WorkerState>>,
    menu: Win16HostMenu,
) -> Result<(), RuntimeError> {
    // A failed CreateWindowEx can destroy its attached class menu during
    // synchronous rollback. Retire that confirmed dead generation before
    // attempting a live-tree traversal for DestroyMenu.
    if retire_dead_class_menu(state, menu) {
        return Ok(());
    }
    let result = super::super::win16_menu_worker::execute(
        state,
        Win16MenuOperation::Destroy { menu },
        &BTreeMap::new(),
    );
    match result {
        Ok(Win16MenuResult::Boolean {
            succeeded: true, ..
        }) => Ok(()),
        Ok(Win16MenuResult::Boolean {
            succeeded: false, ..
        }) => {
            if retire_dead_class_menu(state, menu) {
                return Ok(());
            }
            Err(RuntimeError::with_source(
                Kind::HostFailure,
                "unattached class-menu owner remains live after its window lifecycle ended",
                RetainedClassMenuOwner { menu, cause: None },
            ))
        }
        Ok(_) => Err(RuntimeError::new(
            Kind::InternalInvariant,
            "class-menu cleanup returned a non-Boolean DestroyMenu result",
        )),
        Err(error) => Err(RuntimeError::with_source(
            error.kind(),
            "unattached class-menu cleanup failed with its owner retained",
            RetainedClassMenuOwner {
                menu,
                cause: Some(error),
            },
        )),
    }
}

fn retire_dead_class_menu(state: &Rc<RefCell<WorkerState>>, menu: Win16HostMenu) -> bool {
    let native = state.borrow().menus.get(&menu).copied();
    if !native.is_some_and(|native| crate::windows::win32_safe::is_menu(native) == 0) {
        return false;
    }
    let identities = super::super::win16_menu_attachment::menu_tree(state, menu)
        .into_iter()
        .filter_map(|token| {
            state
                .borrow()
                .menus
                .get(&token)
                .copied()
                .map(|native| (token, native as usize))
        })
        .collect::<BTreeMap<_, _>>();
    let _ = super::super::win16_menu_attachment::retire_destroyed_window_menu_snapshot(
        state,
        &identities,
    );
    !state.borrow().menus.contains_key(&menu)
}

pub(super) fn record_retained_owner_failure(state: &Rc<RefCell<WorkerState>>, error: RuntimeError) {
    state.borrow_mut().terminal_failures.push(Arc::new(error));
}

#[derive(Debug)]
struct RetainedClassMenuOwner {
    menu: Win16HostMenu,
    cause: Option<RuntimeError>,
}

impl fmt::Display for RetainedClassMenuOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "retained class-menu owner {:?}", self.menu)?;
        if let Some(cause) = &self.cause {
            write!(formatter, ": {cause}")?;
        }
        Ok(())
    }
}

impl Error for RetainedClassMenuOwner {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cause
            .as_ref()
            .map(|cause| cause as &(dyn Error + 'static))
    }
}
