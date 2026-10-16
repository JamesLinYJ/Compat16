//! Native EnumPropsW continuation and nested-mutation handling.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostWindow, Win16WindowStep,
    Win16WindowTarget,
};
use windows_sys::Win32::Foundation::{HANDLE, HWND};
use windows_sys::Win32::UI::WindowsAndMessaging::EnumPropsW;

use super::{EnumPropertySnapshot, SharedWorker};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EnumPropertyIdentity {
    atom: u16,
    generation: u64,
}

struct EnumContext {
    state: SharedWorker,
    window: Win16HostWindow,
    hwnd: HWND,
    identity_cookie: Option<usize>,
    snapshot: BTreeMap<u16, EnumPropertySnapshot>,
    current: Option<EnumPropertyIdentity>,
    stopped_by_other_removal: bool,
    window_retired: bool,
    callbacks_seen: usize,
    last_guest_result: i16,
}

struct ActiveEnumGuard {
    context: *mut EnumContext,
}

impl ActiveEnumGuard {
    fn push(context: &mut EnumContext) -> Self {
        let context = context as *mut EnumContext;
        ACTIVE_ENUMS.with(|stack| stack.borrow_mut().push(context));
        Self { context }
    }
}

impl Drop for ActiveEnumGuard {
    fn drop(&mut self) {
        ACTIVE_ENUMS.with(|stack| {
            let mut stack = stack.borrow_mut();
            if let Some(index) = stack.iter().rposition(|context| *context == self.context) {
                stack.remove(index);
            }
        });
    }
}

thread_local! {
    /// EnumPropsW has no user-data parameter. The worker thread is synchronous,
    /// so a scoped stack associates nested native callbacks with their frame.
    static ACTIVE_ENUMS: RefCell<Vec<*mut EnumContext>> = const { RefCell::new(Vec::new()) };
}

pub(super) fn enumerate(
    state: &SharedWorker,
    target: Win16WindowTarget,
) -> Result<i16, RuntimeError> {
    let Some((window, hwnd, identity_cookie)) = super::resolve_window(state, target) else {
        return Ok(-1);
    };
    let snapshot = {
        let worker = state.borrow();
        worker.window_properties.entries.get(&window)
            .into_iter().flat_map(|properties| properties.iter())
            .filter(|(_, property)| property.hwnd == hwnd as usize
                && property.identity_cookie == identity_cookie)
            .map(|(atom, property)| (*atom, EnumPropertySnapshot {
                generation: property.generation,
                native_key_atom: property.native_key_atom,
            }))
            .collect::<BTreeMap<_, _>>()
    };
    if !super::identity_matches(state, window, hwnd, identity_cookie) {
        return Ok(-1);
    }

    let mut context = Box::new(EnumContext {
        state: Rc::clone(state),
        window,
        hwnd,
        identity_cookie,
        snapshot,
        current: None,
        stopped_by_other_removal: false,
        window_retired: false,
        callbacks_seen: 0,
        last_guest_result: -1,
    });
    let _active = ActiveEnumGuard::push(&mut context);
    // SAFETY: `hwnd` is validated on the USER worker. The callback copies
    // values before suspending; its scoped context remains alive for this call.
    let _native_result = unsafe { EnumPropsW(hwnd, Some(property_enum_callback)) };
    if context.callbacks_seen == 0 {
        Ok(-1)
    } else {
        Ok(context.last_guest_result)
    }
}

unsafe extern "system" fn property_enum_callback(
    hwnd: HWND,
    name: windows_sys::core::PCWSTR,
    marker: HANDLE,
) -> windows_sys::core::BOOL {
    match catch_unwind(AssertUnwindSafe(|| {
        property_enum_callback_inner(hwnd, name, marker)
    })) {
        Ok(result) => result,
        Err(_) => {
            if let Some(context) = current_enum_context() {
                // SAFETY: The scoped frame remains alive until EnumPropsW
                // returns; no reference to it is held across guest callbacks.
                unsafe { (*context).window_retired = true; }
                let state = unsafe { Rc::clone(&(*context).state) };
                super::super::win16_window_callbacks::fail_worker(&state,
                    RuntimeError::new(Kind::InternalInvariant,
                        "Win16 EnumProps callback panicked; native callbacks were canceled"));
            }
            0
        }
    }
}

fn property_enum_callback_inner(
    hwnd: HWND,
    name: windows_sys::core::PCWSTR,
    marker: HANDLE,
) -> windows_sys::core::BOOL {
    let Some(context_pointer) = current_enum_context() else { return 1; };
    let atom = {
        let context = unsafe { &*context_pointer };
        super::native::property_atom(name, &context.snapshot)
    };
    let Some(atom) = atom else { return 1; };
    let (state, window, identity_cookie, retired) = unsafe {
        let context = &*context_pointer;
        (Rc::clone(&context.state), context.window,
            context.identity_cookie, context.window_retired)
    };
    if unsafe { (*context_pointer).hwnd } != hwnd || retired {
        return 1;
    }
    let snapshot = unsafe {
        (&(*context_pointer).snapshot).get(&atom).copied()
    };
    let Some(snapshot) = snapshot else { return 1; };
    let Some(property) = super::entry(&state, window, atom) else { return 1; };
    let native_marker = marker as usize;
    if property.generation != snapshot.generation
        || property.native_key_atom != snapshot.native_key_atom
        || property.hwnd != hwnd as usize
        || property.identity_cookie != identity_cookie
        || property.marker != native_marker
        || !super::identity_matches(&state, window, hwnd, identity_cookie)
    {
        return 1;
    }

    let active = {
        let worker = state.borrow();
        if worker.callbacks_enabled && !worker.aborted {
            worker.active_operations.last().cloned()
        } else {
            None
        }
    };
    let Some(active) = active else {
        unsafe { (*context_pointer).window_retired = true; }
        super::super::win16_window_callbacks::fail_worker(&state,
            RuntimeError::new(Kind::InternalInvariant,
                "native EnumProps callback has no active Win16 operation"));
        return 0;
    };
    let identity = state.borrow().windows_by_native.get(&(hwnd as usize))
        .copied().filter(|identity| identity.window == window);
    let Some(identity) = identity else {
        unsafe { (*context_pointer).window_retired = true; }
        super::super::win16_window_callbacks::fail_worker(&state,
            RuntimeError::new(Kind::InternalInvariant,
                "native EnumProps callback lost its exact window identity"));
        return 0;
    };
    let live_callback_reservation = state.borrow_mut().live_callbacks.try_reserve(1);
    if let Err(error) = live_callback_reservation {
        unsafe { (*context_pointer).window_retired = true; }
        super::super::win16_window_callbacks::fail_worker(&state,
            RuntimeError::with_source(Kind::ResourceExhausted,
                "reserve terminal identity for native EnumProps callback", error));
        return 0;
    }
    let Some(callback) = super::super::win16_window_worker::allocate_callback_id(&state) else {
        unsafe { (*context_pointer).window_retired = true; }
        super::super::win16_window_callbacks::fail_worker(&state,
            RuntimeError::new(Kind::ResourceExhausted,
                "Win16 native callback identity exhausted"));
        return 0;
    };

    unsafe {
        (*context_pointer).current = Some(EnumPropertyIdentity {
            atom,
            generation: snapshot.generation,
        });
    }
    let source = runtime::Win16NativeCallbackSource::PropertyEnumeration {
        window,
        class: identity.class,
        atom,
        generation: snapshot.generation,
    };
    state.borrow_mut().live_callbacks.push(
        super::super::win16_window_worker::LiveCallback {
        callback,
        operation: active.id,
        source,
        creation: None,
        identity: Some(identity),
        message: None,
        hwnd,
        w_param: None,
        l_param: None,
        native_message_context: None,
        creation_cookie: None,
        mdi_create_struct: None,
    });
    crate::windows::win16_gdi::flush_thread_batch();
    if active.response.send(Ok(Win16WindowStep::WindowPropertyCallback {
        operation_id: runtime::Win16HostWindowOperationId(active.id),
        callback,
        window,
        name: property.callback_name,
        data: property.data,
        source,
    })).is_err() {
        unsafe {
            (*context_pointer).current = None;
            (*context_pointer).window_retired = true;
        }
        super::super::win16_window_callbacks::remove_live_callback(&state, callback);
        super::super::win16_window_callbacks::fail_worker(&state,
            RuntimeError::new(Kind::HostFailure,
                "Win16 runtime dropped a suspended EnumProps callback"));
        return 0;
    }

    let reply = super::super::win16_window_callbacks::wait_for_guest_reply(
        &state, &active, callback,
    );
    super::super::win16_window_callbacks::remove_live_callback(&state, callback);
    unsafe { (*context_pointer).current = None; }
    let Some(reply) = reply else {
        unsafe { (*context_pointer).window_retired = true; }
        return 0;
    };
    if reply.native_control_color_result.is_some() {
        unsafe { (*context_pointer).window_retired = true; }
        super::super::win16_window_callbacks::fail_worker(&state,
            RuntimeError::new(Kind::InternalInvariant,
                "native HBRUSH sidecar escaped a Win16 EnumProps callback"));
        return 0;
    }

    let guest_result = reply.result.value as u16 as i16;
    unsafe {
        (*context_pointer).callbacks_seen = (*context_pointer).callbacks_seen.saturating_add(1);
        (*context_pointer).last_guest_result = guest_result;
    }
    let must_stop = unsafe {
        (*context_pointer).stopped_by_other_removal || (*context_pointer).window_retired
    } || !super::identity_matches(&state, window, hwnd, identity_cookie);
    if must_stop { return 0; }
    i32::from(guest_result)
}

fn current_enum_context() -> Option<*mut EnumContext> {
    ACTIVE_ENUMS.with(|stack| stack.borrow().last().copied())
}

/// A deletion of the current property is supported. Removing another property
/// stops every affected nested enumeration before Windows advances its table.
pub(super) fn mark_property_removed(
    window: Win16HostWindow,
    atom: u16,
    generation: u64,
) {
    ACTIVE_ENUMS.with(|stack| {
        let contexts = stack.borrow().clone();
        for pointer in contexts {
            // SAFETY: Frames are live on this worker thread. Guest waits retain
            // no Rust reference, so nested operations may mutate each frame.
            let context = unsafe { &mut *pointer };
            if context.window != window { continue; }
            let removed = EnumPropertyIdentity { atom, generation };
            if context.current != Some(removed) {
                context.stopped_by_other_removal = true;
            }
        }
    });
}

pub(super) fn mark_window_retired(window: Win16HostWindow) {
    ACTIVE_ENUMS.with(|stack| {
        let contexts = stack.borrow().clone();
        for pointer in contexts {
            // SAFETY: These are live scoped frames; no guest wait holds a
            // mutable reference while retirement occurs.
            let context = unsafe { &mut *pointer };
            if context.window == window { context.window_retired = true; }
        }
    });
}
