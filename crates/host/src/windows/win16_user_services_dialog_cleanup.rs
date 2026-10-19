//! Roll back dialog-owned HWND, route, and menu state after native USER returns.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostWindow, Win16WindowCreationRejection,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{DrawMenuBar, SetMenu};

use super::super::win16_window_worker::WorkerState;

pub(super) fn destroy_dialog_menu(
    state: &Rc<RefCell<WorkerState>>,
    token: runtime::Win16HostMenu,
) -> Result<(), RuntimeError> {
    let native = state.borrow().menus.get(&token).copied();
    let Some(native) = native else {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "dialog menu token disappeared before rollback",
        ));
    };
    if !super::super::win16_menu_attachment::menu_token_matches(state, token, native) || {
        crate::windows::win32_safe::is_menu(native) == 0
    } {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "DestroyMenu could not retire a detached dialog menu",
        ));
    }
    let Some(tree) =
        super::super::win16_menu_attachment::preflight_destroy_menu_tree(state, token, native)?
    else {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "dialog menu tree is still owned by a window, submenu, or suspended USER call",
        ));
    };
    let _owners = super::super::win16_menu_attachment::retain_menu_call_owners(state, &[token])?;
    let _reservation = super::super::win16_menu_attachment::reserve_menu_retirement(state, &tree)?;
    let destroyed = crate::windows::win32_safe::destroy_menu(native) != 0;
    drop(_reservation);
    let _ =
        super::super::win16_menu_attachment::invalidate_menu_identities(state, &tree, destroyed);
    drop(_owners);
    if !destroyed
        && super::super::win16_menu_attachment::menu_token_matches(state, token, native)
        && (crate::windows::win32_safe::is_menu(native) != 0)
    {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "DestroyMenu could not retire a detached dialog menu",
        ));
    }
    Ok(())
}

pub(super) fn cleanup_dialog_route(
    state: &Rc<RefCell<WorkerState>>,
    route: super::super::win16_window_worker::PendingDialogRoute,
) -> Result<(), RuntimeError> {
    cleanup_dialog_resources(
        state,
        route.root_token,
        route.controls.iter().map(|control| control.window_token),
        route.menu,
    )
}

pub(super) fn cleanup_dialog_resources(
    state: &Rc<RefCell<WorkerState>>,
    root: Win16HostWindow,
    controls: impl Iterator<Item = Win16HostWindow>,
    menu: Option<runtime::Win16HostMenu>,
) -> Result<(), RuntimeError> {
    let mut failure = None;
    let detach_result = menu.map(|menu| detach_dialog_menu(state, root, menu));
    let root_result = retire_dialog_route_window(state, root);
    record_cleanup_failure(&mut failure, root_result);
    for control in controls {
        record_cleanup_failure(&mut failure, retire_dialog_route_window(state, control));
    }
    if let Some(menu) = menu {
        match dialog_menu_attached(state, root, menu) {
            Ok(true) => {
                let cleanup = match detach_result {
                    Some(Err(error)) => error,
                    _ => RuntimeError::new(
                        Kind::HostFailure,
                        "dialog menu remains attached to its live HWND during rollback",
                    ),
                };
                record_cleanup_failure(&mut failure, Err(cleanup));
            }
            Ok(false) => {
                // A failed detach is superseded only when exact root destruction
                // or a later USER change has ended this attachment. Until then the
                // HMENU ledger remains available to the next rollback attempt.
                record_cleanup_failure(
                    &mut failure,
                    destroy_detached_dialog_menu(state, root, menu),
                );
            }
            Err(error) => {
                // An uncertain attachment must keep its native owner. Retain this
                // inspection failure and any earlier detach error alongside
                // accumulated root/control cleanup failures.
                if let Some(Err(detach_error)) = detach_result {
                    record_cleanup_failure(&mut failure, Err(detach_error));
                }
                record_cleanup_failure(&mut failure, Err(error));
            }
        }
    }
    failure.map_or(Ok(()), Err)
}

fn detach_dialog_menu(
    state: &Rc<RefCell<WorkerState>>,
    root: Win16HostWindow,
    token: runtime::Win16HostMenu,
) -> Result<(), RuntimeError> {
    let native = state.borrow().menus.get(&token).copied();
    let Some(native) = native else {
        // DestroyWindow invalidates a menu token when USER has already
        // retired the attached dialog's menu tree.
        return Ok(());
    };
    if native.is_null() {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "dialog menu token resolved to a null native HMENU",
        ));
    }

    let Some(hwnd) = super::super::win16_window_identity::resolve(state, root) else {
        return Ok(());
    };
    if crate::windows::win32_safe::is_window(hwnd) == 0
        || crate::windows::win32_safe::get_menu(hwnd) != native
    {
        return Ok(());
    }
    if !super::super::win16_menu_attachment::dialog_attachment_is_current(
        state, root, hwnd, token, native,
    ) {
        return Ok(());
    }
    let _menu_owners =
        super::super::win16_menu_attachment::retain_menu_call_owners(state, &[token])?;
    // SAFETY: SetMenu attaches a menu this process owns to a window.
    let _detach_reported_success = unsafe { SetMenu(hwnd, std::ptr::null_mut()) } != 0;
    if !super::super::win16_menu_attachment::clear_dialog_attachment(
        state, root, hwnd, token, native,
    ) {
        if super::super::win16_menu_attachment::dialog_attachment_is_current(
            state, root, hwnd, token, native,
        ) {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "SetMenu could not detach the dialog menu during rollback",
            ));
        }
        return Ok(());
    }
    // SAFETY: DrawMenuBar redraws the menu of a window this thread owns.
    let redrawn = unsafe { DrawMenuBar(hwnd) } != 0;
    if super::super::win16_window_identity::resolve(state, root) != Some(hwnd) {
        return Ok(());
    }
    if !super::super::win16_menu_attachment::menu_token_matches(state, token, native) {
        return Ok(());
    }
    if (crate::windows::win32_safe::get_menu(hwnd)) == native {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "guest code reattached the dialog menu during rollback",
        ));
    }
    if !redrawn && (crate::windows::win32_safe::get_menu(hwnd)).is_null() {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "DrawMenuBar could not update the dialog after menu rollback",
        ));
    }
    Ok(())
}

fn dialog_menu_attached(
    state: &Rc<RefCell<WorkerState>>,
    root: Win16HostWindow,
    token: runtime::Win16HostMenu,
) -> Result<bool, RuntimeError> {
    let native_menu = state.borrow().menus.get(&token).copied();
    let Some(native_menu) = native_menu.filter(|menu| !menu.is_null()) else {
        return Ok(false);
    };
    let attached_to_root =
        super::super::win16_window_identity::resolve(state, root).is_some_and(|hwnd| {
            super::super::win16_menu_attachment::dialog_attachment_is_current(
                state,
                root,
                hwnd,
                token,
                native_menu,
            )
        });
    if attached_to_root {
        return Ok(true);
    }
    super::super::win16_menu_attachment::menu_attached_to_live_window(state, token, native_menu)
}

fn destroy_detached_dialog_menu(
    state: &Rc<RefCell<WorkerState>>,
    root: Win16HostWindow,
    token: runtime::Win16HostMenu,
) -> Result<(), RuntimeError> {
    let native = state.borrow().menus.get(&token).copied();
    let Some(native) = native else {
        return Ok(());
    };
    if native.is_null() {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "dialog menu token resolved to a null native HMENU",
        ));
    }
    if dialog_menu_attached(state, root, token)? {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "refused to destroy a dialog menu still owned by a live HWND or USER call",
        ));
    }
    if !super::super::win16_menu_attachment::menu_token_matches(state, token, native) || {
        crate::windows::win32_safe::is_menu(native)
    } == 0
    {
        return Ok(());
    }
    let Some(tree) =
        super::super::win16_menu_attachment::preflight_destroy_menu_tree(state, token, native)?
    else {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "dialog menu tree acquired another owner before native retirement",
        ));
    };
    let _owners = super::super::win16_menu_attachment::retain_menu_call_owners(state, &[token])?;
    let _reservation = super::super::win16_menu_attachment::reserve_menu_retirement(state, &tree)?;
    let destroyed = crate::windows::win32_safe::destroy_menu(native) != 0;
    drop(_reservation);
    let _ =
        super::super::win16_menu_attachment::invalidate_menu_identities(state, &tree, destroyed);
    drop(_owners);
    if !destroyed
        && super::super::win16_menu_attachment::menu_token_matches(state, token, native)
        && (crate::windows::win32_safe::is_menu(native) != 0)
    {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "DestroyMenu could not retire the detached dialog menu",
        ));
    }
    Ok(())
}

fn retire_dialog_route_window(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostWindow,
) -> Result<(), RuntimeError> {
    let Some(hwnd) = state.borrow().windows.get(&token).copied() else {
        return Ok(());
    };
    if super::super::win16_window_identity::resolve(state, token) == Some(hwnd)
        && (crate::windows::win32_safe::is_window(hwnd)) != 0
    {
        if !super::super::win16_window_worker::destroy_quiet(state, token) {
            return Err(RuntimeError::new(
                Kind::HostFailure,
                "DestroyWindow could not retire an abandoned dialog route",
            ));
        }
    } else {
        super::super::win16_window_worker::remove_window_maps(state, token, hwnd);
    }
    Ok(())
}

fn record_cleanup_failure(failure: &mut Option<RuntimeError>, cleanup: Result<(), RuntimeError>) {
    if let Err(cleanup) = cleanup {
        *failure = Some(match failure.take() {
            Some(primary) => super::combine_dialog_cleanup_failure(
                primary,
                cleanup,
                "multiple native dialog resources could not be fully retired",
            ),
            None => cleanup,
        });
    }
}

pub(super) fn cleanup_menu_after_error(
    state: &Rc<RefCell<WorkerState>>,
    menu: Option<runtime::Win16HostMenu>,
    primary: RuntimeError,
) -> RuntimeError {
    let Some(menu) = menu else {
        return primary;
    };
    match destroy_dialog_menu(state, menu) {
        Ok(()) => primary,
        Err(cleanup) => super::combine_dialog_cleanup_failure(
            primary,
            cleanup,
            "dialog creation failed and its menu rollback also failed",
        ),
    }
}

pub(super) fn reject_after_menu(
    state: &Rc<RefCell<WorkerState>>,
    menu: Option<runtime::Win16HostMenu>,
    modal: bool,
    rejection: Win16WindowCreationRejection,
) -> Result<runtime::Win16HostDialogResult, RuntimeError> {
    if let Some(menu) = menu {
        destroy_dialog_menu(state, menu)?;
    }
    Ok(super::create_failure(modal, rejection))
}
