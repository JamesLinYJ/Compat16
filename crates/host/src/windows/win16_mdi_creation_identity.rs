//! Exact native identity validation and token claiming for MDI children.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16CreationId, Win16HostCallback, Win16HostMdiCreate,
    Win16HostWindow,
};
use windows_sys::Win32::Foundation::{HWND, LPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CREATESTRUCTW, GWL_EXSTYLE, GetWindowLongPtrW, WM_CREATE, WM_NCCREATE, WS_EX_MDICHILD,
};

use super::super::win16_window_worker::{NativeWindowIdentity, WorkerState, remove_window_maps};
use super::PendingMdiCreation;
#[path = "win16_mdi_callback_mcs.rs"]
mod callback_mcs;
pub(super) use callback_mcs::{
    native_callback_candidate_matches, native_class_matches, read_callback_mdi_struct,
    validate_native_candidate, write_callback_mdi_struct,
};

pub(super) fn bind_pending_mdi_child_identity(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    pending: &PendingMdiCreation,
) -> Result<NativeWindowIdentity, RuntimeError> {
    let existing = {
        let borrowed = state.try_borrow().map_err(|_| {
            super::mdi_route_error(
                Kind::InternalInvariant,
                "inspect the exact MDI child identity without a conflicting borrow",
            )
        })?;
        let native_identity = borrowed.windows_by_native.get(&(hwnd as usize)).copied();
        if let Some(identity) = native_identity {
            if identity.window != pending.child
                || identity.class != Some(pending.class)
                || identity.creation != Some(pending.creation)
                || borrowed.windows.get(&pending.child) != Some(&hwnd)
            {
                return Err(super::mdi_route_error(
                    Kind::HostFailure,
                    "native MDI child HWND already belongs to another identity",
                ));
            }
            Some(identity)
        } else {
            if borrowed.windows.contains_key(&pending.child)
                || borrowed.retired_window_tokens.contains(&pending.child)
                || pending.actual_child.is_some_and(|actual| actual != hwnd)
            {
                return Err(super::mdi_route_error(
                    Kind::HostFailure,
                    "preallocated MDI child token was already mapped or retired",
                ));
            }
            None
        }
    };

    let identity = if let Some(identity) = existing {
        identity
    } else {
        {
            let mut borrowed = state.try_borrow_mut().map_err(|_| {
                super::mdi_route_error(
                    Kind::InternalInvariant,
                    "reserve exact MDI HWND identity without a conflicting worker borrow",
                )
            })?;
            borrowed.windows.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve MDI child HWND identity before binding",
                    error,
                )
            })?;
            borrowed.windows_by_native.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve MDI child native-HWND index before binding",
                    error,
                )
            })?;
        }
        super::super::win16_window_identity::bind(state, pending.child, hwnd)?;
        let (process_id, thread_id) =
            super::super::win16_window_identity::native_owner_identity(hwnd).ok_or_else(|| {
                super::mdi_route_error(
                    Kind::HostFailure,
                    "read the MDI child owner identity after binding",
                )
            })?;
        if process_id != pending.owner_process || thread_id != pending.owner_thread {
            remove_window_maps(state, pending.child, hwnd);
            return Err(super::mdi_route_error(
                Kind::HostFailure,
                "native MDI child owner differs from its exact client thread",
            ));
        }
        let identity = NativeWindowIdentity {
            window: pending.child,
            class: Some(pending.class),
            creation: Some(pending.creation),
            process_id,
            thread_id,
            owned: true,
        };
        let route_updated = {
            let mut borrowed = state.borrow_mut();
            borrowed.windows.insert(pending.child, hwnd);
            borrowed.windows_by_native.insert(hwnd as usize, identity);
            let route = borrowed
                .pending_mdi_creations
                .iter_mut()
                .rev()
                .find(|route| {
                    route.native_mdi_struct == pending.native_mdi_struct
                        && route.creation == pending.creation
                        && route.operation == pending.operation
                });
            if let Some(route) = route {
                route.actual_child = Some(hwnd);
                true
            } else {
                false
            }
        };
        if !route_updated {
            remove_window_maps(state, pending.child, hwnd);
            return Err(super::mdi_route_error(
                Kind::InternalInvariant,
                "exact pending MDI route disappeared while binding its child",
            ));
        }
        identity
    };

    if existing.is_some() {
        let mut borrowed = state.try_borrow_mut().map_err(|_| {
            super::mdi_route_error(
                Kind::InternalInvariant,
                "refresh the exact MDI child route without a conflicting borrow",
            )
        })?;
        let route = borrowed
            .pending_mdi_creations
            .iter_mut()
            .rev()
            .find(|route| {
                route.native_mdi_struct == pending.native_mdi_struct
                    && route.creation == pending.creation
                    && route.operation == pending.operation
            })
            .ok_or_else(|| {
                super::mdi_route_error(
                    Kind::InternalInvariant,
                    "exact pending MDI route disappeared before WM_CREATE",
                )
            })?;
        if route.actual_child.is_some_and(|actual| actual != hwnd) {
            return Err(super::mdi_route_error(
                Kind::HostFailure,
                "one MDI creation route attempted to claim two native HWNDs",
            ));
        }
        route.actual_child = Some(hwnd);
    }

    Ok(identity)
}

pub(super) fn suppresses_unproven_mdi_candidate(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
) -> bool {
    if hwnd.is_null()
        ||  { crate::windows::win32_safe::is_window(hwnd) } == 0
        // SAFETY: GetWindowLongPtrW reads one window-long slot. The HWND is a window this thread created or was given by Windows.
        || unsafe { GetWindowLongPtrW(hwnd, GWL_EXSTYLE) as u32 } & WS_EX_MDICHILD == 0
    {
        return false;
    }
    let client = crate::windows::win32_safe::get_parent(hwnd);
    let Some((process_id, thread_id)) =
        super::super::win16_window_identity::native_owner_identity(hwnd)
    else {
        return false;
    };
    let candidates = {
        let Ok(borrowed) = state.try_borrow() else {
            return false;
        };
        borrowed
            .pending_mdi_creations
            .iter()
            .rev()
            .filter(|pending| {
                pending.client == client
                    && pending.owner_process == process_id
                    && pending.owner_thread == thread_id
                    && borrowed
                        .active_operations
                        .iter()
                        .any(|active| active.id == pending.operation)
            })
            .map(|pending| pending.native_class_name.clone())
            .collect::<Vec<_>>()
    };
    candidates
        .into_iter()
        .any(|class_name| native_class_matches(hwnd, &class_name))
}

pub(super) fn checked_live_mdi_create_parameter(
    state: &Rc<RefCell<WorkerState>>,
    callback: runtime::Win16HostCallback,
    expected_window: Win16HostWindow,
    expected_creation: Win16CreationId,
) -> Result<LPARAM, RuntimeError> {
    let (hwnd, creation, identity, message, callback_mdi_struct, l_param, operation) = {
        let borrowed = state.try_borrow().map_err(|_| {
            super::mdi_route_error(
                Kind::InternalInvariant,
                "inspect the live MDI callback without a conflicting worker borrow",
            )
        })?;
        let live = borrowed
            .live_callbacks
            .iter()
            .rev()
            .find(|live| live.callback == callback)
            .ok_or_else(|| {
                super::mdi_route_error(Kind::InvalidInput, "MDI default callback is no longer live")
            })?;
        // Copy identity metadata, not the callback's continuation ownership,
        // before releasing the worker borrow for subsequent validation.
        (
            live.hwnd,
            live.creation,
            live.identity,
            live.message,
            live.mdi_create_struct,
            live.l_param,
            live.operation,
        )
    };
    if callback_mdi_struct.is_none()
        || creation != Some(expected_creation)
        || identity.is_none_or(|identity| {
            identity.window != expected_window || identity.creation != Some(expected_creation)
        })
        || hwnd.is_null()
        || !matches!(message, Some(WM_NCCREATE | WM_CREATE))
    {
        return Err(super::mdi_route_error(
            Kind::InvalidInput,
            "MDI default callback does not match its live child creation identity",
        ));
    }
    let callback_mdi_struct = callback_mdi_struct.unwrap();
    let l_param = l_param.ok_or_else(|| {
        super::mdi_route_error(
            Kind::InvalidInput,
            "live MDI creation callback has no native CREATESTRUCTW",
        )
    })?;
    if l_param == 0 {
        return Err(super::mdi_route_error(
            Kind::InvalidInput,
            "live MDI creation callback has a null native CREATESTRUCTW",
        ));
    }
    // SAFETY: this exact CREATESTRUCTW belongs to the still-suspended native
    // WM_NCCREATE/WM_CREATE callback retained in `live_callbacks`.
    let create = unsafe { &*(l_param as *const CREATESTRUCTW) };
    if create.lpCreateParams as usize != callback_mdi_struct {
        return Err(super::mdi_route_error(
            Kind::HostFailure,
            "live native CREATESTRUCTW no longer references its callback MCS copy",
        ));
    }
    let pending = {
        let borrowed = state.try_borrow().map_err(|_| {
            super::mdi_route_error(
                Kind::InternalInvariant,
                "validate the live MDI creation route without a conflicting borrow",
            )
        })?;
        borrowed
            .pending_mdi_creations
            .iter()
            .rev()
            .find(|pending| {
                pending.creation == expected_creation
                    && pending.child == expected_window
                    && pending.actual_child == Some(hwnd)
                    && pending.operation == operation
            })
            .map(PendingMdiCreation::snapshot)
            .ok_or_else(|| {
                super::mdi_route_error(
                    Kind::InvalidInput,
                    "live MDI callback lost its exact pending creation route",
                )
            })?
    };
    validate_pending_operation(state, &pending)?;
    validate_native_candidate(state, hwnd, create, callback_mdi_struct, &pending)?;
    Ok(callback_mdi_struct as LPARAM)
}

/// Apply guest-edited, non-identity fields to the exact native MCS retained by
/// the outer MDICREATE guard. Every replacement string is owned by that
/// pending record until the native call unwinds, including older generations
/// that a reentrant native call may still be borrowing.
pub(super) fn apply_live_mdi_create_fields(
    state: &Rc<RefCell<WorkerState>>,
    callback: Win16HostCallback,
    expected_window: Win16HostWindow,
    data: &Win16HostMdiCreate,
) -> Result<LPARAM, RuntimeError> {
    let callback_parameter =
        checked_live_mdi_create_parameter(state, callback, expected_window, data.creation)?;
    if callback_parameter == 0 {
        return Err(super::mdi_route_error(
            Kind::InternalInvariant,
            "exact live MDI callback resolved to a null callback MCS copy",
        ));
    }
    let callback_mdi_struct = callback_parameter as usize;

    let (operation, live_hwnd, native_mdi_struct, native_class, title, updated_title) = {
        let borrowed = state.try_borrow().map_err(|_| {
            super::mdi_route_error(
                Kind::InternalInvariant,
                "inspect the live MDI callback before forwarding guest fields",
            )
        })?;
        let live = borrowed
            .live_callbacks
            .iter()
            .rev()
            .find(|live| live.callback == callback)
            .ok_or_else(|| {
                super::mdi_route_error(
                    Kind::InvalidInput,
                    "MDI field forwarding callback is no longer live",
                )
            })?;
        if live.mdi_create_struct != Some(callback_mdi_struct)
            || live.creation != Some(data.creation)
            || live.identity.is_none_or(|identity| {
                identity.window != expected_window || identity.creation != Some(data.creation)
            })
        {
            return Err(super::mdi_route_error(
                Kind::InvalidInput,
                "MDI field forwarding does not match the exact live callback identity",
            ));
        }
        let pending = borrowed
            .pending_mdi_creations
            .iter()
            .rev()
            .find(|pending| {
                pending.creation == data.creation
                    && pending.child == expected_window
                    && pending.actual_child == Some(live.hwnd)
                    && pending.operation == live.operation
            })
            .ok_or_else(|| {
                super::mdi_route_error(
                    Kind::InvalidInput,
                    "MDI field forwarding lost its exact pending child route",
                )
            })?;
        if !borrowed
            .active_operations
            .iter()
            .any(|active| active.id == pending.operation)
            || pending.system_class_kind.is_some()
            || data.creation != pending.creation
            || data.class != pending.class
            || data.guest_class_name != pending.mdi.guest_class_name
            || data.owner_instance != pending.mdi.owner_instance
        {
            return Err(super::mdi_route_error(
                Kind::InvalidInput,
                "guest MDI fields attempted to replace the native class, owner, or creation identity",
            ));
        }
        let native_class = borrowed
            .classes
            .get(&pending.class)
            .cloned()
            .ok_or_else(|| {
                super::mdi_route_error(
                    Kind::InvalidInput,
                    "MDI child native class is no longer registered",
                )
            })?;
        if native_class.system_class || native_class.system_class_kind.is_some() {
            return Err(super::mdi_route_error(
                Kind::InvalidInput,
                "guest MDI fields cannot be forwarded through a predefined system class",
            ));
        }
        let class_bytes = native_class.name.strip_suffix(&[0]).ok_or_else(|| {
            super::mdi_route_error(
                Kind::InternalInvariant,
                "registered MDI child native class name has no final NUL",
            )
        })?;
        if class_bytes.is_empty() || class_bytes.contains(&0) {
            return Err(super::mdi_route_error(
                Kind::InternalInvariant,
                "registered MDI child native class name is empty or malformed",
            ));
        }
        let codec = borrowed.text_codec;
        let class_name = codec.to_wide_z(class_bytes)?;
        if class_name.last() != Some(&0)
            || class_name[..class_name.len() - 1] != pending.native_class_name[..]
        {
            return Err(super::mdi_route_error(
                Kind::HostFailure,
                "registered native MDI class changed during creation",
            ));
        }
        let title = data
            .title
            .as_deref()
            .map(|bytes| codec.to_wide_z(bytes))
            .transpose()?;
        let updated_title = match data.title.as_deref() {
            None => None,
            Some(bytes) => {
                let mut owned = Vec::new();
                owned.try_reserve_exact(bytes.len()).map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "retain updated guest MDI title for a later creation callback",
                        error,
                    )
                })?;
                owned.extend_from_slice(bytes);
                Some(owned)
            }
        };
        (
            pending.operation,
            live.hwnd,
            pending.native_mdi_struct,
            native_class,
            title,
            updated_title,
        )
    };

    let original_before = read_callback_mdi_struct(native_mdi_struct).ok_or_else(|| {
        super::mdi_route_error(
            Kind::HostFailure,
            "read the host-owned canonical MDI create structure",
        )
    })?;
    let copied_before = read_callback_mdi_struct(callback_mdi_struct).ok_or_else(|| {
        super::mdi_route_error(
            Kind::HostFailure,
            "read USER's copied MDI structure during the suspended callback",
        )
    })?;
    if original_before.hOwner != native_class.instance
        || copied_before.hOwner != native_class.instance
    {
        return Err(super::mdi_route_error(
            Kind::HostFailure,
            "canonical or copied MDI owner no longer matches its registered host class",
        ));
    }

    let mut borrowed = state.try_borrow_mut().map_err(|_| {
        super::mdi_route_error(
            Kind::InternalInvariant,
            "retain native MDI forwarding strings without a conflicting worker borrow",
        )
    })?;
    let index = borrowed
        .pending_mdi_creations
        .iter()
        .rposition(|pending| {
            pending.native_mdi_struct == native_mdi_struct
                && pending.creation == data.creation
                && pending.child == expected_window
                && pending.operation == operation
                && pending.actual_child == Some(live_hwnd)
        })
        .ok_or_else(|| {
            super::mdi_route_error(
                Kind::InvalidInput,
                "exact MDI child route disappeared before native field update",
            )
        })?;
    if index + 1 != borrowed.pending_mdi_creations.len()
        || !borrowed
            .active_operations
            .iter()
            .any(|active| active.id == operation)
        || borrowed
            .classes
            .get(&data.class)
            .is_none_or(|current| !std::rc::Rc::ptr_eq(current, &native_class))
    {
        return Err(super::mdi_route_error(
            Kind::InvalidInput,
            "MDI field update no longer belongs to the active native creation route",
        ));
    }
    let pending = &mut borrowed.pending_mdi_creations[index];
    let buffer_count = if title.is_some() { 1 } else { 0 };
    pending
        .retained_forwarded_strings
        .try_reserve(buffer_count)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "retain forwarded MDI title through native reentry",
                error,
            )
        })?;

    let title_pointer = if let Some(title) = title {
        let pointer = title.as_ptr();
        pending.retained_forwarded_strings.push(title);
        pointer
    } else {
        std::ptr::null()
    };

    let mut original_after = original_before;
    let mut copied_after = copied_before;
    for mdi in [&mut original_after, &mut copied_after] {
        // Keep each structure's szClass pointer and hOwner unchanged. USER may
        // own a distinct class-string copy; neither pointer is an identity.
        mdi.szTitle = title_pointer;
        mdi.x = mdi_coordinate(data.x);
        mdi.y = mdi_coordinate(data.y);
        mdi.cx = mdi_coordinate(data.cx);
        mdi.cy = mdi_coordinate(data.cy);
        mdi.style = data.style;
        mdi.lParam = data.parameter as i32 as LPARAM;
    }

    // Write USER's active copy first. If the host-owned original then fails,
    // restore the copy best-effort before returning the host error.
    if callback_mdi_struct != native_mdi_struct {
        write_callback_mdi_struct(callback_mdi_struct, &copied_after)?;
        if let Err(error) = write_callback_mdi_struct(native_mdi_struct, &original_after) {
            let _ = write_callback_mdi_struct(callback_mdi_struct, &copied_before);
            return Err(error);
        }
    } else {
        write_callback_mdi_struct(native_mdi_struct, &original_after)?;
    }

    // The USER copy and canonical input now contain the same current fields.
    pending.mdi.x = data.x;
    pending.mdi.y = data.y;
    pending.mdi.cx = data.cx;
    pending.mdi.cy = data.cy;
    pending.mdi.style = data.style;
    pending.mdi.parameter = data.parameter;
    pending.mdi.title = updated_title;
    Ok(callback_parameter)
}

fn mdi_coordinate(value: i16) -> i32 {
    if value == i16::MIN {
        i32::MIN
    } else {
        i32::from(value)
    }
}

pub(super) fn validate_pending_operation(
    state: &Rc<RefCell<WorkerState>>,
    pending: &PendingMdiCreation,
) -> Result<(), RuntimeError> {
    let borrowed = state.try_borrow().map_err(|_| {
        super::mdi_route_error(
            Kind::InternalInvariant,
            "validate the active MDI operation generation without a conflicting borrow",
        )
    })?;
    let client_identity = borrowed
        .windows_by_native
        .get(&(pending.client as usize))
        .copied();
    let frame_identity = borrowed
        .windows_by_native
        .get(&(pending.frame as usize))
        .copied();
    let client_is_exact = borrowed.windows.get(&pending.client_window) == Some(&pending.client)
        && client_identity.is_some_and(|identity| {
            identity.window == pending.client_window
                && identity.process_id == pending.owner_process
                && identity.thread_id == pending.owner_thread
                && identity.class.is_some_and(|class| {
                    borrowed.classes.get(&class).is_some_and(|class| {
                        class.system_class
                            && class.system_class_kind
                                == Some(runtime::Win16HostSystemClass::MdiClient)
                    })
                })
        });
    let frame_is_exact = (crate::windows::win32_safe::is_window(pending.frame)) != 0
        && (crate::windows::win32_safe::get_parent(pending.client)) == pending.frame
        && borrowed.windows.get(&pending.frame_window) == Some(&pending.frame)
        && super::super::win16_window_identity::native_owner_identity(pending.frame)
            == Some((pending.owner_process, pending.owner_thread))
        && frame_identity.is_some_and(|identity| {
            identity.window == pending.frame_window
                && identity.process_id == pending.owner_process
                && identity.thread_id == pending.owner_thread
        });
    // A guest default-procedure call pushes a nested worker operation while
    // the original MDICREATE is suspended. Its exact owner must remain active,
    // but need not be the stack top; callback and MCS identities are checked
    // separately before forwarding any guest fields.
    if !client_is_exact
        || !frame_is_exact
        || !borrowed
            .active_operations
            .iter()
            .any(|active| active.id == pending.operation)
        || !borrowed.pending_mdi_creations.iter().any(|current| {
            current.native_mdi_struct == pending.native_mdi_struct
                && current.creation == pending.creation
                && current.child == pending.child
                && current.operation == pending.operation
        })
    {
        return Err(super::mdi_route_error(
            Kind::InvalidInput,
            "MDI child callback does not belong to the current native operation generation",
        ));
    }
    Ok(())
}

/// Validate the only supported no-callback result: a live HWND created by
/// this active MDICREATE for an exact predefined USER class. Guest classes
/// never use this post-return path; they must first claim WM_NCCREATE through
/// their exact synchronous operation/client/frame route.
pub(super) fn validate_native_system_result(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    pending: &PendingMdiCreation,
) -> Result<(), RuntimeError> {
    validate_pending_operation(state, pending)?;
    let system_kind = pending.system_class_kind.ok_or_else(|| {
        super::mdi_route_error(
            Kind::CompatibilityGap,
            "native MDI result without a guest callback is not a predefined system class",
        )
    })?;

    if hwnd.is_null()
        ||  { crate::windows::win32_safe::is_window(hwnd) } == 0
        ||  { crate::windows::win32_safe::get_parent(hwnd) } != pending.client
        // SAFETY: GetWindowLongPtrW reads one window-long slot. The HWND is a window this thread created or was given by Windows.
        || unsafe { GetWindowLongPtrW(hwnd, GWL_EXSTYLE) as u32 } & WS_EX_MDICHILD == 0
        || !native_class_matches(hwnd, &pending.native_class_name)
    {
        return Err(super::mdi_route_error(
            Kind::HostFailure,
            "native MDI system-class result failed HWND, parent, class, or WS_EX_MDICHILD validation",
        ));
    }

    let registered_identity_matches = {
        let borrowed = state.try_borrow().map_err(|_| {
            super::mdi_route_error(
                Kind::InternalInvariant,
                "validate the returned MDI system class without a conflicting worker borrow",
            )
        })?;
        let child_class = borrowed.classes.get(&pending.class).ok_or_else(|| {
            super::mdi_route_error(
                Kind::HostFailure,
                "returned MDI system class is no longer registered",
            )
        })?;
        if !child_class.system_class || child_class.system_class_kind != Some(system_kind) {
            return Err(super::mdi_route_error(
                Kind::HostFailure,
                "returned MDI class no longer matches its exact predefined system-class identity",
            ));
        }
        let class_bytes = child_class.name.strip_suffix(&[0]).ok_or_else(|| {
            super::mdi_route_error(
                Kind::InternalInvariant,
                "registered MDI system class name has no final NUL",
            )
        })?;
        if borrowed.text_codec.to_wide(class_bytes)? != pending.native_class_name {
            return Err(super::mdi_route_error(
                Kind::HostFailure,
                "returned native class name differs from the active registered system class",
            ));
        }
        if pending.mdi.class != pending.class || pending.mdi.creation != pending.creation {
            return Err(super::mdi_route_error(
                Kind::InternalInvariant,
                "returned MDI child no longer matches its exact class and creation plan",
            ));
        }
        let client_identity = borrowed
            .windows_by_native
            .get(&(pending.client as usize))
            .copied();
        let client_class_is_mdi = client_identity
            .and_then(|identity| identity.class)
            .and_then(|class| borrowed.classes.get(&class))
            .is_some_and(|class| {
                class.system_class
                    && class.system_class_kind == Some(runtime::Win16HostSystemClass::MdiClient)
            });
        borrowed.windows.get(&pending.client_window) == Some(&pending.client)
            && client_identity.is_some_and(|identity| {
                identity.window == pending.client_window
                    && identity.process_id == pending.owner_process
                    && identity.thread_id == pending.owner_thread
            })
            && client_class_is_mdi
    };
    if !registered_identity_matches {
        return Err(super::mdi_route_error(
            Kind::HostFailure,
            "returned MDI system child no longer belongs to its exact registered client",
        ));
    }

    let (process_id, thread_id) = super::super::win16_window_identity::native_owner_identity(hwnd)
        .ok_or_else(|| {
            super::mdi_route_error(
                Kind::HostFailure,
                "read returned MDI system child process and thread identity",
            )
        })?;
    if process_id != pending.owner_process || thread_id != pending.owner_thread {
        return Err(super::mdi_route_error(
            Kind::HostFailure,
            "returned MDI system child belongs to a different process or owner thread",
        ));
    }
    Ok(())
}
