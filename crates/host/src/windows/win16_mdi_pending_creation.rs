//! Exact reentrant identity for a child created by one synchronous WM_MDICREATE.
//!
//! USER may copy both the MDICREATESTRUCTW and its strings while processing
//! WM_MDICREATE. This record therefore binds a child to the exact synchronous
//! operation/client/frame scope and validates copied MCS contents, not pointers.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16CreationId, Win16HostClass, Win16HostCreationData,
    Win16HostMdiChildCreation, Win16HostMdiCreate, Win16HostWindow,
};
use windows_sys::Win32::Foundation::{HWND, LPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CREATESTRUCTW, GWL_EXSTYLE, GetWindowLongPtrW, MDICREATESTRUCTW, WM_CREATE, WM_NCCREATE,
    WS_EX_MDICHILD,
};

use super::win16_window_worker::{
    NativeWindowIdentity, WorkerState, allocate_window_token, remove_window_maps,
};

#[path = "win16_mdi_creation_identity.rs"]
mod identity;

pub(super) struct PendingMdiCreation {
    native_mdi_struct: usize,
    client: HWND,
    client_window: Win16HostWindow,
    frame: HWND,
    frame_window: Win16HostWindow,
    child: Win16HostWindow,
    class: Win16HostClass,
    creation: Win16CreationId,
    operation: u64,
    owner_process: u32,
    owner_thread: u32,
    native_class_name: Vec<u16>,
    /// Present only for a predefined system class backed by USER. Such a
    /// child has no guest WndProc callback, so its returned HWND can be
    /// claimed only after the same exact request and native identity checks.
    system_class_kind: Option<runtime::Win16HostSystemClass>,
    /// Native W strings forwarded from a live guest create callback. Retain
    /// every generation until this outer MDICREATE guard unwinds because a
    /// nested native call may still be borrowing an earlier pointer.
    retained_forwarded_strings: Vec<Vec<u16>>,
    mdi: Win16HostMdiCreate,
    actual_child: Option<HWND>,
}

impl PendingMdiCreation {
    /// Copy the route metadata without duplicating native strings whose
    /// pointers remain owned by the canonical pending record.
    fn snapshot(&self) -> Self {
        Self {
            native_mdi_struct: self.native_mdi_struct,
            client: self.client,
            client_window: self.client_window,
            frame: self.frame,
            frame_window: self.frame_window,
            child: self.child,
            class: self.class,
            creation: self.creation,
            operation: self.operation,
            owner_process: self.owner_process,
            owner_thread: self.owner_thread,
            native_class_name: self.native_class_name.clone(),
            system_class_kind: self.system_class_kind,
            retained_forwarded_strings: Vec::new(),
            mdi: self.mdi.clone(),
            actual_child: self.actual_child,
        }
    }
}

/// Exact callback result. The native MCS address is host-only and is pinned
/// onto the live callback solely for checked default reconstruction.
pub(in crate::windows::win16_windows) struct MdiCreationCallback {
    pub(in crate::windows::win16_windows) identity: NativeWindowIdentity,
    pub(in crate::windows::win16_windows) data: Win16HostMdiChildCreation,
    /// USER's actual MCS copy referenced by this suspended CREATESTRUCT.
    /// It is valid only for this callback's lifetime.
    pub(in crate::windows::win16_windows) callback_mdi_struct: usize,
}

pub(in crate::windows::win16_windows) struct PendingMdiCreationGuard {
    state: Rc<RefCell<WorkerState>>,
    native_mdi_struct: usize,
    creation: Win16CreationId,
    operation: u64,
    armed: bool,
}

impl PendingMdiCreationGuard {
    pub(in crate::windows::win16_windows) fn register(
        state: &Rc<RefCell<WorkerState>>,
        client: HWND,
        frame: HWND,
        mdi_struct: *const MDICREATESTRUCTW,
        mdi: &Win16HostMdiCreate,
    ) -> Result<Self, RuntimeError> {
        if client.is_null() || mdi_struct.is_null() || mdi.creation.0 == 0 {
            return Err(mdi_route_error(
                Kind::InvalidInput,
                "register WM_MDICREATE with a live client, native MCS, and creation identity",
            ));
        }
        let native_mdi_struct = mdi_struct as usize;
        if (crate::windows::win32_safe::get_parent(client)) != frame {
            return Err(mdi_route_error(
                Kind::InvalidInput,
                "WM_MDICREATE frame is not the exact native parent of its MDI client",
            ));
        }
        let (
            client_window,
            frame_window,
            owner_process,
            owner_thread,
            operation,
            class_name,
            system_class_kind,
        ) = {
            let borrowed = state.try_borrow().map_err(|_| {
                mdi_route_error(
                    Kind::InternalInvariant,
                    "inspect the MDI client without a conflicting worker borrow",
                )
            })?;
            let identity = borrowed
                .windows_by_native
                .get(&(client as usize))
                .copied()
                .filter(|identity| borrowed.windows.get(&identity.window) == Some(&client))
                .ok_or_else(|| {
                    mdi_route_error(
                        Kind::InvalidInput,
                        "WM_MDICREATE client has no exact native window identity",
                    )
                })?;
            let frame_identity = borrowed
                .windows_by_native
                .get(&(frame as usize))
                .copied()
                .filter(|identity| borrowed.windows.get(&identity.window) == Some(&frame))
                .ok_or_else(|| {
                    mdi_route_error(
                        Kind::InvalidInput,
                        "WM_MDICREATE frame has no exact native window identity",
                    )
                })?;
            if (crate::windows::win32_safe::is_window(frame)) == 0 {
                return Err(mdi_route_error(
                    Kind::HostFailure,
                    "WM_MDICREATE frame HWND is no longer live",
                ));
            }
            if identity
                .class
                .and_then(|class| borrowed.classes.get(&class))
                .is_none_or(|class| {
                    class.system_class_kind != Some(runtime::Win16HostSystemClass::MdiClient)
                })
            {
                return Err(mdi_route_error(
                    Kind::InvalidInput,
                    "WM_MDICREATE target is not the registered MDI client",
                ));
            }
            let (owner_process, owner_thread) =
                super::win16_window_identity::native_owner_identity(client).ok_or_else(|| {
                    mdi_route_error(
                        Kind::HostFailure,
                        "read the native MDI client owner identity",
                    )
                })?;
            if owner_thread != (crate::windows::win32_safe::current_thread_id()) {
                return Err(mdi_route_error(
                    Kind::InvalidInput,
                    "WM_MDICREATE is not running on its MDI client owner thread",
                ));
            }
            if frame_identity.process_id != owner_process
                || frame_identity.thread_id != owner_thread
                || super::win16_window_identity::native_owner_identity(frame)
                    != Some((owner_process, owner_thread))
            {
                return Err(mdi_route_error(
                    Kind::InvalidInput,
                    "WM_MDICREATE frame and client have different native owners",
                ));
            }
            let operation = borrowed
                .active_operations
                .last()
                .map(|active| active.id)
                .ok_or_else(|| {
                    mdi_route_error(
                        Kind::InternalInvariant,
                        "WM_MDICREATE has no active native operation generation",
                    )
                })?;
            let class = borrowed.classes.get(&mdi.class).ok_or_else(|| {
                mdi_route_error(
                    Kind::InvalidInput,
                    "WM_MDICREATE target class is not registered",
                )
            })?;
            let class_bytes = class.name.strip_suffix(&[0]).ok_or_else(|| {
                mdi_route_error(
                    Kind::InternalInvariant,
                    "registered MDI child class name has no final NUL",
                )
            })?;
            if class_bytes.is_empty() || class_bytes.contains(&0) {
                return Err(mdi_route_error(
                    Kind::InternalInvariant,
                    "registered MDI child class name is empty or contains an embedded NUL",
                ));
            }
            let system_class_kind = match (class.system_class, class.system_class_kind) {
                (true, Some(kind)) => Some(kind),
                (false, None) => None,
                _ => {
                    return Err(mdi_route_error(
                        Kind::InternalInvariant,
                        "registered MDI child class has inconsistent system-class identity",
                    ));
                }
            };
            let codec = borrowed.text_codec;
            (
                identity.window,
                frame_identity.window,
                owner_process,
                owner_thread,
                operation,
                codec.to_wide(class_bytes)?,
                system_class_kind,
            )
        };
        let child = allocate_window_token(state)?;
        if class_name.is_empty() || class_name.contains(&0) {
            return Err(mdi_route_error(
                Kind::InternalInvariant,
                "registered MDI child class has no native UTF-16 name",
            ));
        }

        {
            let mut borrowed = state.try_borrow_mut().map_err(|_| {
                mdi_route_error(
                    Kind::InternalInvariant,
                    "reserve exact MDI creation ownership without a conflicting worker borrow",
                )
            })?;
            let outstanding = borrowed
                .windows
                .len()
                .checked_add(borrowed.pending_creations.len())
                .and_then(|count| count.checked_add(borrowed.pending_mdi_creations.len()))
                .and_then(|count| count.checked_add(1))
                .ok_or_else(|| {
                    mdi_route_error(
                        Kind::ResourceExhausted,
                        "native window retirement capacity is exhausted",
                    )
                })?;
            borrowed
                .retired_window_tokens
                .try_reserve(outstanding)
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve MDI child retirement identity before native creation",
                        error,
                    )
                })?;
            borrowed
                .pending_mdi_creations
                .try_reserve(1)
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve the exact pending MDI creation record",
                        error,
                    )
                })?;
            borrowed.windows.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve the MDI child native-window identity",
                    error,
                )
            })?;
            borrowed.windows_by_native.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve the MDI child native-HWND index",
                    error,
                )
            })?;
            borrowed
                .window_identity_cookies
                .try_reserve(1)
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve the MDI child identity property",
                        error,
                    )
                })?;
            if borrowed.pending_mdi_creations.iter().any(|pending| {
                pending.operation == operation
                    || pending.native_mdi_struct == native_mdi_struct
                    || pending.creation == mdi.creation
                    || pending.child == child
            }) {
                return Err(mdi_route_error(
                    Kind::InternalInvariant,
                    "WM_MDICREATE reused an active operation, MCS address, or creation identity",
                ));
            }
            borrowed.pending_mdi_creations.push(PendingMdiCreation {
                native_mdi_struct,
                client,
                client_window,
                frame,
                frame_window,
                child,
                class: mdi.class,
                creation: mdi.creation,
                operation,
                owner_process,
                owner_thread,
                native_class_name: class_name,
                system_class_kind,
                retained_forwarded_strings: Vec::new(),
                mdi: mdi.clone(),
                actual_child: None,
            });
        }
        Ok(Self {
            state: Rc::clone(state),
            native_mdi_struct,
            creation: mdi.creation,
            operation,
            armed: true,
        })
    }

    /// Retire this exact pending record after the native MDI call unwinds.
    /// A failed call also retires any child identity claimed during reentry.
    pub(in crate::windows::win16_windows) fn finish(
        mut self,
        result: HWND,
    ) -> Result<(), RuntimeError> {
        let pending_before_return = {
            let borrowed = self.state.try_borrow().map_err(|_| {
                mdi_route_error(
                    Kind::InternalInvariant,
                    "inspect exact MDI creation before native return without a conflicting borrow",
                )
            })?;
            let index = borrowed
                .pending_mdi_creations
                .iter()
                .rposition(|pending| {
                    pending.native_mdi_struct == self.native_mdi_struct
                        && pending.creation == self.creation
                        && pending.operation == self.operation
                })
                .ok_or_else(|| {
                    mdi_route_error(
                        Kind::InternalInvariant,
                        "exact pending MDI creation disappeared before native return",
                    )
                })?;
            if index + 1 != borrowed.pending_mdi_creations.len() {
                return Err(mdi_route_error(
                    Kind::InternalInvariant,
                    "nested MDI creation guards did not unwind in LIFO order",
                ));
            }
            borrowed.pending_mdi_creations[index].snapshot()
        };

        // Predefined USER classes have no host_window_proc and therefore no
        // reentrant guest callback. Allow only the exact, registered system
        // class case to claim the synchronous result HWND after native checks.
        if !result.is_null()
            && pending_before_return.actual_child.is_none()
            && pending_before_return.system_class_kind.is_some()
        {
            identity::validate_native_system_result(&self.state, result, &pending_before_return)?;
            identity::bind_pending_mdi_child_identity(&self.state, result, &pending_before_return)?;
        }

        let pending = {
            let mut borrowed = self.state.try_borrow_mut().map_err(|_| {
                mdi_route_error(
                    Kind::InternalInvariant,
                    "finish exact MDI creation without a conflicting worker borrow",
                )
            })?;
            let index = borrowed
                .pending_mdi_creations
                .iter()
                .rposition(|pending| {
                    pending.native_mdi_struct == self.native_mdi_struct
                        && pending.creation == self.creation
                        && pending.operation == self.operation
                })
                .ok_or_else(|| {
                    mdi_route_error(
                        Kind::InternalInvariant,
                        "exact pending MDI creation disappeared before native return",
                    )
                })?;
            if index + 1 != borrowed.pending_mdi_creations.len() {
                return Err(mdi_route_error(
                    Kind::InternalInvariant,
                    "nested MDI creation guards did not unwind in LIFO order",
                ));
            }
            self.armed = false;
            borrowed.pending_mdi_creations.remove(index)
        };

        match (result.is_null(), pending.actual_child) {
            (true, Some(hwnd)) => {
                remove_window_maps(&self.state, pending.child, hwnd);
                Ok(())
            }
            (false, Some(hwnd)) if hwnd != result => {
                remove_window_maps(&self.state, pending.child, hwnd);
                Err(mdi_route_error(
                    Kind::HostFailure,
                    "WM_MDICREATE returned an HWND different from its exact child callback",
                ))
            }
            (false, Some(hwnd)) => {
                let borrowed = self.state.try_borrow().map_err(|_| {
                    mdi_route_error(
                        Kind::InternalInvariant,
                        "verify the completed MDI child identity without a conflicting borrow",
                    )
                })?;
                let identity = borrowed.windows_by_native.get(&(hwnd as usize)).copied();
                if borrowed.windows.get(&pending.child) != Some(&hwnd)
                    || identity.is_none_or(|identity| {
                        identity.window != pending.child
                            || identity.class != Some(pending.class)
                            || identity.creation != Some(pending.creation)
                    })
                {
                    Err(mdi_route_error(
                        Kind::InternalInvariant,
                        "completed MDI child lost its exact native identity",
                    ))
                } else {
                    Ok(())
                }
            }
            (false, None) => Err(mdi_route_error(
                Kind::CompatibilityGap,
                "native WM_MDICREATE returned a child without an exact reentrant creation route",
            )),
            (true, None) => Ok(()),
        }
    }
}

impl Drop for PendingMdiCreationGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(mut state) = self.state.try_borrow_mut()
            && let Some(index) = state.pending_mdi_creations.iter().rposition(|pending| {
                pending.native_mdi_struct == self.native_mdi_struct
                    && pending.creation == self.creation
                    && pending.operation == self.operation
            })
        {
            state.pending_mdi_creations.remove(index);
        }
        self.armed = false;
    }
}

/// Claim the child created by the exact synchronous WM_MDICREATE operation.
/// USER may copy the MCS and its strings, so route selection uses the unique
/// active operation/client/frame guard and then validates copied field values.
pub(in crate::windows::win16_windows) fn identify_mdi_child_creation(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    message: u32,
    l_param: LPARAM,
) -> Result<Option<MdiCreationCallback>, RuntimeError> {
    if !matches!(message, WM_NCCREATE | WM_CREATE) || hwnd.is_null() {
        return Ok(None);
    }
    if l_param == 0 {
        let exact_operation_is_active = {
            let borrowed = state.try_borrow().map_err(|_| {
                mdi_route_error(
                    Kind::InternalInvariant,
                    "check the exact MDI frame for a missing CREATESTRUCTW",
                )
            })?;
            borrowed.active_operations.last().is_some_and(|active| {
                borrowed
                    .pending_mdi_creations
                    .iter()
                    .any(|pending| pending.operation == active.id)
            })
        };
        return if exact_operation_is_active {
            Err(mdi_route_error(
                Kind::HostFailure,
                "exact WM_MDICREATE callback has no native CREATESTRUCTW",
            ))
        } else {
            Ok(None)
        };
    }
    // SAFETY: USER supplies CREATESTRUCTW in LPARAM for exactly WM_NCCREATE
    // and WM_CREATE; this helper is called only from the synchronous WndProc.
    let create = unsafe { &*(l_param as *const CREATESTRUCTW) };
    let callback_mdi_struct = create.lpCreateParams as usize;
    let callback_owner = super::win16_window_identity::native_owner_identity(hwnd);
    let scoped = {
        let borrowed = state.try_borrow().map_err(|_| {
            mdi_route_error(
                Kind::InternalInvariant,
                "match native MDI creation without a conflicting worker borrow",
            )
        })?;
        let current_operation = borrowed.active_operations.last().map(|active| active.id);
        borrowed
            .pending_mdi_creations
            .iter()
            .filter(|pending| {
                Some(pending.operation) == current_operation
                    && borrowed
                        .active_operations
                        .iter()
                        .any(|active| active.id == pending.operation)
            })
            .map(PendingMdiCreation::snapshot)
            .collect::<Vec<_>>()
    };
    if scoped.is_empty() {
        return Ok(None);
    }
    if scoped.len() != 1 {
        return Err(mdi_route_error(
            Kind::InternalInvariant,
            "one active WM_MDICREATE operation matched multiple pending invocation frames",
        ));
    }
    let pending = scoped.into_iter().next().unwrap();
    {
        let borrowed = state.try_borrow().map_err(|_| {
            mdi_route_error(
                Kind::InternalInvariant,
                "validate the top MDI invocation frame without a conflicting worker borrow",
            )
        })?;
        if !borrowed
            .pending_mdi_creations
            .last()
            .is_some_and(|current| {
                current.native_mdi_struct == pending.native_mdi_struct
                    && current.creation == pending.creation
                    && current.operation == pending.operation
                    && current.client_window == pending.client_window
                    && current.frame_window == pending.frame_window
            })
        {
            return Err(mdi_route_error(
                Kind::InternalInvariant,
                "MDI child callback did not arrive through the top synchronous invocation frame",
            ));
        }
    }
    // A normal child window may be created reentrantly on the same thread, but
    // it is not this route unless it is the MDI child the exact call is creating.
    if hwnd.is_null() {
        return Ok(None);
    }
    let callback_is_mdi_child = create.dwExStyle & WS_EX_MDICHILD != 0;
    if (crate::windows::win32_safe::is_window(hwnd)) == 0 {
        return if callback_is_mdi_child {
            Err(mdi_route_error(
                Kind::HostFailure,
                "exact WM_MDICREATE callback has no live native HWND",
            ))
        } else {
            Ok(None)
        };
    }
    let native_is_mdi_child =
        // SAFETY: GetWindowLongPtrW reads one window-long slot. The HWND is a window this thread created or was given by Windows.
        unsafe { GetWindowLongPtrW(hwnd, GWL_EXSTYLE) as u32 } & WS_EX_MDICHILD != 0;
    if !callback_is_mdi_child && !native_is_mdi_child {
        return Ok(None);
    }
    if callback_is_mdi_child != native_is_mdi_child {
        return Err(mdi_route_error(
            Kind::HostFailure,
            "WM_MDICREATE callback and native HWND disagree about WS_EX_MDICHILD",
        ));
    }
    let Some((process_id, thread_id)) = callback_owner else {
        return Err(mdi_route_error(
            Kind::HostFailure,
            "read the native owner of the exact WM_MDICREATE callback HWND",
        ));
    };
    if pending.owner_process != process_id || pending.owner_thread != thread_id {
        return Err(mdi_route_error(
            Kind::HostFailure,
            "exact WM_MDICREATE callback HWND belongs to a different process or thread",
        ));
    }
    if create.hwndParent != pending.client || { crate::windows::win32_safe::get_parent(hwnd) }
        != pending.client
    {
        return Err(mdi_route_error(
            Kind::HostFailure,
            "exact WM_MDICREATE callback HWND has the wrong native client parent",
        ));
    }
    if !identity::native_callback_candidate_matches(hwnd, create, &pending) {
        return Err(mdi_route_error(
            Kind::HostFailure,
            "WM_MDICREATE callback HWND failed exact native class, owner, or parent validation",
        ));
    }
    match message {
        WM_NCCREATE if pending.actual_child.is_none() => {}
        WM_CREATE if pending.actual_child == Some(hwnd) => {}
        WM_NCCREATE => {
            return Err(mdi_route_error(
                Kind::HostFailure,
                "WM_NCCREATE attempted to claim an already-claimed MDI invocation",
            ));
        }
        WM_CREATE => {
            return Err(mdi_route_error(
                Kind::HostFailure,
                "WM_CREATE arrived before the exact WM_NCCREATE MDI claim",
            ));
        }
        _ => return Ok(None),
    }
    identity::validate_pending_operation(state, &pending)?;
    identity::validate_native_candidate(state, hwnd, create, callback_mdi_struct, &pending)?;

    let identity = identity::bind_pending_mdi_child_identity(state, hwnd, &pending)?;

    let child_id = (crate::windows::win32_safe::get_dlg_ctrl_id(hwnd)) as u16;
    let data = Win16HostCreationData {
        class: pending.class,
        guest_instance: pending.mdi.owner_instance,
        guest_class_name: pending.mdi.guest_class_name.clone(),
        guest_menu: child_id,
        class_menu_template: None,
        create_parameter: pending.mdi.parameter,
        creation_data: None,
        mdi_client: None,
        dialog_root: false,
        menu: None,
        title: pending.mdi.title.clone(),
        style: create.style as u32,
        ex_style: create.dwExStyle,
        x: create.x as i16,
        y: create.y as i16,
        width: create.cx as i16,
        height: create.cy as i16,
        parent: Some(pending.client_window),
        child_id: Some(child_id),
    };
    Ok(Some(MdiCreationCallback {
        identity,
        data: Win16HostMdiChildCreation {
            creation: data,
            mdi: pending.mdi,
        },
        callback_mdi_struct,
    }))
}

/// Prevent ordinary CreateWindowEx cookie fallback from assigning an MDI child
/// before its exact CREATESTRUCTW.lpCreateParams route reaches the WndProc.
/// This predicate suppresses fallback only; it never creates or returns identity.
pub(in crate::windows::win16_windows) fn suppresses_unproven_mdi_candidate(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
) -> bool {
    identity::suppresses_unproven_mdi_candidate(state, hwnd)
}

pub(in crate::windows::win16_windows) fn apply_live_mdi_create_fields(
    state: &Rc<RefCell<WorkerState>>,
    callback: runtime::Win16HostCallback,
    expected_window: Win16HostWindow,
    data: &Win16HostMdiCreate,
) -> Result<LPARAM, RuntimeError> {
    identity::apply_live_mdi_create_fields(state, callback, expected_window, data)
}

fn mdi_route_error(kind: Kind, message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(kind, message)
}
