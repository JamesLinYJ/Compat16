//! Exact CREATESTRUCT provenance for custom guest dialog roots and controls.
//!
//! Native dialog templates carry host-owned creation-data addresses. They are
//! used only as opaque route keys; this module never dereferences
//! `lpCreateParams` or treats it as a guest FAR value.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16CreationId, Win16HostCreationData,
    Win16HostWindow,
};
use windows_sys::Win32::Foundation::{HWND, LPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CREATESTRUCTW, DrawMenuBar, GetClassNameW, GetMenu, SetMenu, WM_CREATE, WM_NCCREATE,
};

use super::win16_window_worker::{
    self as worker, DialogRoute, NativeWindowIdentity, WorkerState,
};

const MAX_NATIVE_CLASS_NAME: usize = 256;

pub(super) fn identify(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    message: u32,
    l_param: LPARAM,
) -> Result<Option<(
    NativeWindowIdentity,
    Option<Win16HostCreationData>,
    usize,
    Option<Win16CreationId>,
)>, RuntimeError> {
    if !matches!(message, WM_NCCREATE | WM_CREATE) || l_param == 0 {
        return Ok(None);
    }
    // USER supplies CREATESTRUCTW only during these synchronous creation
    // messages. The nested lpCreateParams remains opaque until compared with
    // addresses calculated from our own live template allocation.
    let native = unsafe { &*(l_param as *const CREATESTRUCTW) };
    let creation_pointer = native.lpCreateParams as usize;
    let native_id = hwnd as usize;

    let candidate = {
        let state = state.borrow();
        let active_operation = state.active_operations.last().map(|operation| operation.id);
        let mut candidate = None;
        for pending in state.pending_dialog_routes.iter().rev() {
            // A route belongs only to the native CreateDialog/DialogBox call
            // that installed it. Nested guest CreateWindow calls run under a
            // different active operation and must not adopt a same-class HWND.
            if active_operation != Some(pending.operation) {
                continue;
            }
            let root = pending.root.as_ref().filter(|root| {
                pending.root_window.is_none()
                    && native.hwndParent == pending.owner
                    && native_class_matches(&state, hwnd, native, root.data.class)
            });
            if let Some(root) = root {
                candidate = Some((
                    pending.operation,
                    pending.creation,
                    pending.guest_instance,
                    pending.owner,
                    None,
                    pending.root_token,
                    pending.root.as_ref().map(|root| root.data.class),
                    pending.cookie,
                    pending.init_parameter,
                    pending.menu,
                    pending.root_token,
                    RouteCandidate::Root(copy_creation_data(&root.data)?),
                ));
                break;
            }

            let root_window = match pending.root_window {
                Some(root_window) => root_window,
                None if pending.root.is_none()
                    && native_class_name_is(native.hwndParent, b"#32770") =>
                {
                    native.hwndParent as usize
                }
                None => continue,
            };
            if native.hwndParent as usize != root_window {
                continue;
            }
            let Some(control) = pending.controls.iter().find(|control| {
                (creation_pointer == control.size_pointer
                    || creation_pointer == control.data_pointer)
                    && native.hMenu as usize == usize::from(
                        control.data.child_id.unwrap_or_default(),
                    )
                    && native_class_matches(&state, hwnd, native, control.data.class)
            }) else {
                continue;
            };
            candidate = Some((
                pending.operation,
                pending.creation,
                pending.guest_instance,
                pending.owner,
                Some(root_window),
                pending.root_token,
                pending.root.as_ref().map(|root| root.data.class),
                pending.cookie,
                pending.init_parameter,
                pending.menu,
                control.window_token,
                RouteCandidate::Control(copy_creation_data(&control.data)?),
            ));
            break;
        }
        candidate
    };
    let Some((operation, creation, guest_instance, owner, root_window, root_token,
        root_class, cookie, init_parameter, menu, token, route)) = candidate else {
        return Ok(None);
    };

    if state.borrow().windows_by_native.contains_key(&native_id) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "custom dialog creation HWND already belongs to a different USER identity",
        ));
    }
    let (mut data, is_root, menu) = match route {
        RouteCandidate::Root(data) => (data, true, menu),
        RouteCandidate::Control(data) => (data, false, None),
    };
    if data.guest_instance != guest_instance || data.dialog_root != is_root {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "custom dialog route changed its instance or root/control role"));
    }
    let root_token = if !is_root && root_class.is_none() {
        let root = root_window.ok_or_else(|| RuntimeError::new(Kind::InternalInvariant,
            "custom dialog control route omitted its standard root HWND"))?;
        super::win16_dialog_root_identity::bind_standard_root(
            state, operation, creation, root as HWND,
        )?
    } else { root_token };
    if !is_root {
        if root_window.is_none() {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "custom dialog control route omitted its root HWND"));
        }
        data.parent = Some(root_token);
    } else {
        // Dialog template roots use the owning window as CREATESTRUCT parent.
        data.parent = if owner.is_null() {
            None
        } else {
            state.borrow().windows_by_native.get(&(owner as usize))
                .map(|identity| identity.window)
        };
    }
    let (process_id, thread_id) =
        super::win16_window_identity::native_owner_identity(hwnd).ok_or_else(|| {
            RuntimeError::new(Kind::HostFailure,
                "read the live native process and thread identity for a custom dialog HWND")
        })?;

    let retained_data = copy_creation_data(&data)?;
    let (route_index, previous_root_window) = {
        let mut state = state.borrow_mut();
        let Some(index) = state.pending_dialog_routes.iter().position(|pending| {
            pending.operation == operation && pending.creation == creation
        })
        else {
            return Err(RuntimeError::new(Kind::InternalInvariant,
                "custom dialog CREATESTRUCT lost its exact pending operation"));
        };
        state.dialog_creation_data.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve custom dialog CREATESTRUCT metadata",
                error,
            )
        })?;
        state.windows_by_native.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve custom dialog native HWND identity",
                error,
            )
        })?;
        state.window_identity_cookies.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve custom dialog HWND identity cookie",
                error,
            )
        })?;
        state.dialog_children_by_native.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve custom dialog child identity metadata",
                error,
            )
        })?;
        if is_root {
            state.dialog_routes_by_native.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve custom dialog DLGPROC route",
                    error,
                )
            })?;
        }
        (index, state.pending_dialog_routes[index].root_window)
    };
    let identity = NativeWindowIdentity {
        window: token,
        class: Some(data.class),
        creation: Some(creation),
        process_id,
        thread_id,
        owned: true,
    };

    // All potentially fallible route copies and capacity reservations happen
    // before native USER identity is published. If menu setup or a later
    // identity step fails, retire only the newly adopted token/HWND pair and
    // restore this creation's prior root slot.
    let mut newly_bound_root = None;
    let mut newly_bound_window = None;
    let install = (|| -> Result<(), RuntimeError> {
        if !is_root {
            let root = root_window.ok_or_else(|| RuntimeError::new(
                Kind::InternalInvariant,
                "custom dialog control route lost its validated root HWND",
            ))? as HWND;
            let existing_root = state.borrow().windows_by_native
                .get(&(root as usize)).copied();
            let root_was_bound = existing_root.is_some_and(|current|
                current.window == root_token)
                && super::win16_window_identity::resolve(state, root_token) == Some(root);
            super::win16_window_identity::bind_dialog_root(
                state, root_token, root, root_class, Some(creation),
            )?;
            if !root_was_bound {
                newly_bound_root = Some((root_token, root));
            }
        }
        super::win16_window_identity::bind(state, token, hwnd)?;
        newly_bound_window = Some((token, hwnd));
        {
            let mut state = state.borrow_mut();
            state.windows.insert(token, hwnd);
            state.windows_by_native.insert(native_id, identity);
            state.dialog_creation_data.insert(native_id, (creation, retained_data));
            state.pending_dialog_routes[route_index].root_window = if is_root {
                Some(native_id)
            } else {
                root_window
            };
            if is_root {
                state.dialog_routes_by_native.insert(native_id, DialogRoute {
                    operation,
                    creation,
                    cookie,
                    window: token,
                    init_parameter,
                    menu,
                    class_init_in_progress: false,
                    class_init_default_called: false,
                });
            }
        }
        super::win16_window_identity::associate_dialog_child(state, hwnd);
        if is_root {
            if let Some(menu) = menu {
                attach_menu(state, token, hwnd, menu)?;
                data.menu = Some(menu);
                let retained_data = copy_creation_data(&data)?;
                state.borrow_mut().dialog_creation_data
                    .insert(native_id, (creation, retained_data));
            }
        }
        Ok(())
    })();
    if let Err(error) = install {
        {
            let mut state = state.borrow_mut();
            for children in state.dialog_children_by_native.values_mut() {
                if children.get(&native_id) == Some(&token) {
                    children.remove(&native_id);
                }
            }
            if let Some(pending) = state.pending_dialog_routes.iter_mut()
                .find(|pending| pending.operation == operation && pending.creation == creation)
            {
                pending.root_window = previous_root_window;
            }
        }
        if let Some((window, native)) = newly_bound_window {
            worker::remove_window_maps(state, window, native);
        }
        if let Some((window, native)) = newly_bound_root {
            worker::remove_window_maps(state, window, native);
        }
        return Err(error);
    }
    Ok(Some((identity, Some(data), 0, Some(creation))))
}

enum RouteCandidate {
    Root(Win16HostCreationData),
    Control(Win16HostCreationData),
}

fn native_class_matches(
    state: &WorkerState,
    hwnd: HWND,
    create: &CREATESTRUCTW,
    token: runtime::Win16HostClass,
) -> bool {
    let Some(class) = state.classes.get(&token) else { return false; };
    if class.system_class || create.hInstance != class.instance || class.name.last() != Some(&0) {
        return false;
    }
    let mut name = [0_u16; MAX_NATIVE_CLASS_NAME];
    let length = unsafe { GetClassNameW(hwnd, name.as_mut_ptr(), MAX_NATIVE_CLASS_NAME as i32) };
    let expected = class.name[..class.name.len() - 1]
        .iter().map(|byte| u16::from(*byte)).collect::<Vec<_>>();
    length > 0
        && name[..length as usize].len() == expected.len()
        && name[..length as usize].iter().zip(&expected)
            .all(|(actual, expected)| ascii_upper_wide(*actual) == ascii_upper_wide(*expected))
}

fn native_class_name_is(hwnd: HWND, expected: &[u8]) -> bool {
    if hwnd.is_null() { return false; }
    let mut name = [0_u16; MAX_NATIVE_CLASS_NAME];
    let copied = unsafe { GetClassNameW(hwnd, name.as_mut_ptr(), MAX_NATIVE_CLASS_NAME as i32) };
    let expected = expected.iter().map(|byte| u16::from(*byte)).collect::<Vec<_>>();
    copied > 0
        && name[..copied as usize].len() == expected.len()
        && name[..copied as usize].iter().zip(&expected)
            .all(|(actual, expected)| ascii_upper_wide(*actual) == ascii_upper_wide(*expected))
}

fn ascii_upper_wide(value: u16) -> u16 {
    if (u16::from(b'a')..=u16::from(b'z')).contains(&value) {
        value - u16::from(b'a' - b'A')
    } else {
        value
    }
}

fn copy_creation_data(data: &Win16HostCreationData) -> Result<Win16HostCreationData, RuntimeError> {
    if data.class_menu_template.is_some() {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "class RT_MENU template cannot be copied into a dialog-created window route",
        ));
    }
    Ok(Win16HostCreationData {
        class: data.class,
        guest_instance: data.guest_instance,
        guest_class_name: match &data.guest_class_name {
            runtime::Win16HostClassName::Atom(atom) => runtime::Win16HostClassName::Atom(*atom),
            runtime::Win16HostClassName::Name(name) => {
                runtime::Win16HostClassName::Name(copy_bytes(name, "custom dialog class name")?)
            }
        },
        guest_menu: data.guest_menu,
        class_menu_template: None,
        create_parameter: data.create_parameter,
        mdi_client: data.mdi_client,
        creation_data: data.creation_data.as_ref().map(|bytes|
            copy_bytes(bytes, "custom dialog control creation data")).transpose()?,
        dialog_root: data.dialog_root,
        menu: data.menu,
        title: data.title.as_ref().map(|bytes| copy_bytes(bytes, "custom dialog title"))
            .transpose()?,
        style: data.style,
        ex_style: data.ex_style,
        x: data.x,
        y: data.y,
        width: data.width,
        height: data.height,
        parent: data.parent,
        child_id: data.child_id,
    })
}

fn copy_bytes(bytes: &[u8], what: &'static str) -> Result<Vec<u8>, RuntimeError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len()).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted, format!("allocate {what}"), error))?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

fn attach_menu(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: HWND,
    token: runtime::Win16HostMenu,
) -> Result<(), RuntimeError> {
    let Some(menu) = state.borrow().menus.get(&token).copied() else {
        return Err(RuntimeError::new(Kind::InternalInvariant,
            "custom dialog template menu token disappeared before attachment"));
    };
    if !super::win16_menu_attachment::menu_token_matches(state, token, menu)
        || unsafe { windows_sys::Win32::UI::WindowsAndMessaging::IsMenu(menu) } == 0
        || super::win16_menu_attachment::cached_menu_tree_is_retiring(state, token)
    {
        return Err(RuntimeError::new(Kind::HostFailure,
            "custom dialog template menu is no longer a live native HMENU"));
    }
    if super::win16_window_identity::resolve(state, window) != Some(hwnd) {
        return Err(RuntimeError::new(Kind::HostFailure,
            "custom dialog root identity changed before menu attachment"));
    }
    let previous = unsafe { GetMenu(hwnd) };
    if previous != menu {
        let mut owner_roots = vec![token];
        if let Some(previous_token) = super::win16_menu_attachment::token_for_native(
            state, previous,
        ) {
            owner_roots.push(previous_token);
        }
        let _menu_owners = super::win16_menu_attachment::retain_menu_call_owners(
            state, &owner_roots,
        )?;
        let installed = unsafe { SetMenu(hwnd, menu) } != 0;
        if !installed {
            // A failed native call may still have reentered and attached this
            // exact menu. Retain that owner only when the original dialog
            // incarnation and native attachment are both still present.
            super::win16_menu_attachment::publish_dialog_attachment(
                state, window, hwnd, token, menu,
            );
            return Err(RuntimeError::new(Kind::HostFailure,
                "SetMenu rejected the converted Win16 dialog menu"));
        }
        // SetMenu can dispatch frame messages before returning. Publish only
        // after proving the same cookie-bound dialog still owns this HMENU.
        if !super::win16_menu_attachment::publish_dialog_attachment(
            state, window, hwnd, token, menu,
        ) {
            return Err(RuntimeError::new(Kind::HostFailure,
                "SetMenu completed after the dialog or menu attachment changed"));
        }
        if unsafe { DrawMenuBar(hwnd) } == 0 {
            // Redraw can also dispatch guest code. Never compensate through a
            // cached HWND unless the original owner and its menu still match.
            if !super::win16_menu_attachment::dialog_attachment_is_current(
                state, window, hwnd, token, menu,
            ) {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "DrawMenuBar failed after guest code changed the dialog attachment"));
            }
            let previous_token = super::win16_menu_attachment::token_for_native(state, previous);
            let previous_is_safe = if previous.is_null() {
                true
            } else if let Some(previous_token) = previous_token {
                super::win16_menu_attachment::menu_token_matches(
                    state, previous_token, previous,
                ) && unsafe { windows_sys::Win32::UI::WindowsAndMessaging::IsMenu(previous) != 0 }
                    && !super::win16_menu_attachment::menu_attached_to_live_window(
                        state, previous_token, previous,
                    )?
            } else {
                false
            };
            if !previous_is_safe {
                return Err(RuntimeError::new(Kind::HostFailure,
                    "DrawMenuBar failed; the prior menu no longer has a safe restore identity"));
            }
            let _restore_reported_success = unsafe { SetMenu(hwnd, previous) } != 0;
            let restored = if let Some(previous_token) = previous_token {
                super::win16_menu_attachment::dialog_attachment_is_current(
                    state, window, hwnd, previous_token, previous,
                )
            } else {
                super::win16_window_identity::resolve(state, window) == Some(hwnd)
                    && unsafe {
                        windows_sys::Win32::UI::WindowsAndMessaging::IsWindow(hwnd) != 0
                            && GetMenu(hwnd).is_null()
                    }
            };
            if !restored {
                // If our menu remains attached, keep its owner visible to
                // common cleanup. A reentrant replacement keeps its own map.
                super::win16_menu_attachment::publish_dialog_attachment(
                    state, window, hwnd, token, menu,
                );
                return Err(RuntimeError::new(Kind::HostFailure,
                    "DrawMenuBar failed and the prior menu could not be safely restored"));
            }
            if let Some(previous_token) = previous_token {
                state.borrow_mut().window_menus.insert(window, previous_token);
            } else {
                let mut state = state.borrow_mut();
                if state.window_menus.get(&window) == Some(&token) {
                    state.window_menus.remove(&window);
                }
            }
            super::win16_menu_attachment::reconcile_window_menu_ledger(state);
            let restored_bar = unsafe { DrawMenuBar(hwnd) } != 0;
            let still_restored = if let Some(previous_token) = previous_token {
                super::win16_menu_attachment::dialog_attachment_is_current(
                    state, window, hwnd, previous_token, previous,
                )
            } else {
                super::win16_window_identity::resolve(state, window) == Some(hwnd)
                    && unsafe {
                        windows_sys::Win32::UI::WindowsAndMessaging::IsWindow(hwnd) != 0
                            && GetMenu(hwnd).is_null()
                    }
            };
            if still_restored {
                if let Some(previous_token) = previous_token {
                    state.borrow_mut().window_menus.insert(window, previous_token);
                    super::win16_menu_attachment::reconcile_window_menu_ledger(state);
                }
            }
            return Err(RuntimeError::new(Kind::HostFailure,
                if restored_bar && still_restored {
                    "DrawMenuBar could not update the converted Win16 dialog menu; prior menu was restored"
                } else {
                    "DrawMenuBar failed while the dialog menu rollback was reentered"
                }));
        }
        if !super::win16_menu_attachment::dialog_attachment_is_current(
            state, window, hwnd, token, menu,
        ) {
            return Err(RuntimeError::new(Kind::HostFailure,
                "DrawMenuBar returned after guest code changed the dialog attachment"));
        }
        return Ok(());
    }
    if !super::win16_menu_attachment::publish_dialog_attachment(state, window, hwnd, token, menu) {
        return Err(RuntimeError::new(Kind::HostFailure,
            "custom dialog menu is not attached to its exact root HWND"));
    }
    Ok(())
}

pub(super) fn attach_template_menu(
    state: &Rc<RefCell<WorkerState>>,
    route: DialogRoute,
    hwnd: HWND,
) -> Result<(), RuntimeError> {
    let Some(menu) = route.menu else { return Ok(()); };
    attach_menu(state, route.window, hwnd, menu)
}
