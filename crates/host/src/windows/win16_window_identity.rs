//! Stable identity for native HWNDs owned by the Win16 USER worker.
//!
//! HWND values are recyclable. Same-thread windows adopted by this worker
//! therefore carry a private USER property whose opaque integer value is also
//! recorded beside the guest-facing token. The value is an identity cookie,
//! never a pointer or guest-visible host address.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16CreationId, Win16HostWindow, Win16HostWindowLiveness,
};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetPropW, GetWindowThreadProcessId, RemovePropW, SetPropW,
};

use super::win16_window_worker::{
    NativeWindowIdentity, WorkerState, allocate_window_token, remove_window_maps,
};

const IDENTITY_PROPERTY: windows_sys::core::PCWSTR =
    windows_sys::core::w!("Win16.WindowIdentity.57EDE69F-7DB5-42D1-9CED-6096DD23FE54");

static NEXT_COOKIE: AtomicUsize = AtomicUsize::new(1);

pub(super) fn native_owner_identity(hwnd: HWND) -> Option<(u32, u32)> {
    if hwnd.is_null() || { crate::windows::win32_safe::is_window(hwnd) } == 0 {
        return None;
    }
    let mut process_id = 0;
    // SAFETY: GetWindowThreadProcessId optionally writes a caller-owned process id.
    let thread_id = unsafe { GetWindowThreadProcessId(hwnd, &mut process_id) };
    (process_id != 0 && thread_id != 0).then_some((process_id, thread_id))
}

#[derive(Clone, Copy)]
pub(super) struct NativeWindowCreationOwner {
    window: Win16HostWindow,
    creation: Win16CreationId,
    process_id: u32,
    thread_id: u32,
}

impl NativeWindowCreationOwner {
    pub(super) fn matches(&self, window: Win16HostWindow, creation: Win16CreationId) -> bool {
        self.window == window && self.creation == creation
    }

    pub(super) fn identity(&self) -> (u32, u32) {
        (self.process_id, self.thread_id)
    }
}

pub(super) fn reserve_creation_owner_capacity(
    state: &Rc<RefCell<WorkerState>>,
    needs_creation_cookie: bool,
) -> Result<(), RuntimeError> {
    let mut state = state.try_borrow_mut().map_err(|_| {
        identity_error(
            Kind::InternalInvariant,
            "reserve native HWND identity capacity without a conflicting worker borrow",
        )
    })?;
    state.windows_by_native.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve the native HWND identity before CreateWindowEx",
            error,
        )
    })?;
    state.windows.try_reserve(1).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve the native HWND token mapping before CreateWindowEx",
            error,
        )
    })?;
    state
        .window_identity_cookies
        .try_reserve(1)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve the HWND identity cookie before CreateWindowEx",
                error,
            )
        })?;
    if needs_creation_cookie {
        state.pending_creations.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve the pending creation record before CreateWindowEx",
                error,
            )
        })?;
    }
    Ok(())
}

/// Capture the actual caller identity for one synchronous native creation.
/// CreateWindowEx creates its HWND on this calling thread; retain this exact
/// invocation identity and creation token if a later owner query transiently
/// fails, rather than inventing PID/TID values after the call.
pub(super) fn native_creation_owner_identity(
    window: Win16HostWindow,
    creation: Win16CreationId,
) -> Result<NativeWindowCreationOwner, RuntimeError> {
    let process_id = crate::windows::win32_safe::current_process_id();
    let thread_id = crate::windows::win32_safe::current_thread_id();
    if process_id == 0 || thread_id == 0 {
        return Err(identity_error(
            Kind::HostFailure,
            "capture the actual native process and thread before CreateWindowEx",
        ));
    }
    Ok(NativeWindowCreationOwner {
        window,
        creation,
        process_id,
        thread_id,
    })
}

/// One native HWND incarnation bound to one host-only Win16 token.
#[derive(Clone, Copy)]
pub(super) struct WindowCookieBinding {
    pub(super) hwnd: usize,
    pub(super) value: usize,
}

/// Bind a newly adopted, same-process, worker-thread HWND to its token.
///
/// Existing properties are never overwritten. An already recorded binding is
/// accepted only when both its HWND and live property still match.
pub(super) fn bind(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostWindow,
    hwnd: HWND,
) -> Result<(), RuntimeError> {
    if hwnd.is_null() || belongs_to_worker(hwnd) != Some(true) {
        return Err(identity_error(
            Kind::InvalidInput,
            "bind a Win16 window identity to a same-thread native window",
        ));
    }
    let native = hwnd as usize;

    let existing = {
        let state = state.borrow();
        if state
            .windows
            .get(&token)
            .is_some_and(|mapped| *mapped != hwnd)
            || state
                .windows_by_native
                .get(&native)
                .is_some_and(|identity| identity.window != token)
        {
            return Err(identity_error(
                Kind::HostFailure,
                "bind a Win16 window identity without replacing another mapping",
            ));
        }
        state.window_identity_cookies.get(&token).copied()
    };

    if let Some(binding) = existing {
        if binding.hwnd == native && binding.value != 0 && property_value(hwnd) == binding.value {
            return Ok(());
        }
        return Err(identity_error(
            Kind::HostFailure,
            "verify an existing Win16 native window identity cookie",
        ));
    }

    let already_mapped = {
        let state = state.borrow();
        state.windows.contains_key(&token) || state.windows_by_native.contains_key(&native)
    };
    if already_mapped {
        return Err(identity_error(
            Kind::HostFailure,
            "bind a Win16 window identity only when first adopting its HWND",
        ));
    }

    // Reserve the identity ledger before mutating native USER state. HashMap
    // insertion after SetPropW must not lose the cookie if allocation fails.
    state
        .borrow_mut()
        .window_identity_cookies
        .try_reserve(1)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve a Win16 native window identity cookie record",
                error,
            )
        })?;

    // SetPropW replaces an existing property with the same name, so inspect
    // first and refuse to claim any property installed by another owner.
    if property_value(hwnd) != 0 {
        return Err(identity_error(
            Kind::HostFailure,
            "bind a Win16 window identity without replacing an existing property",
        ));
    }
    let value = NEXT_COOKIE
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            next.checked_add(1)
        })
        .map_err(|_| {
            identity_error(
                Kind::ResourceExhausted,
                "allocate a Win16 native window identity cookie",
            )
        })?;
    if value == 0 {
        return Err(identity_error(
            Kind::ResourceExhausted,
            "allocate a nonzero Win16 native window identity cookie",
        ));
    }

    // SAFETY: `hwnd` was confirmed live on this worker thread, the property
    // name is static and NUL-terminated, and `value` is an opaque nonzero
    // integer cookie rather than an address.
    if unsafe { SetPropW(hwnd, IDENTITY_PROPERTY, value as *mut std::ffi::c_void) } == 0 {
        return Err(identity_error(
            Kind::HostFailure,
            "install a private Win16 native window identity cookie",
        ));
    }
    if property_value(hwnd) != value {
        remove_property_if_matches(hwnd, value);
        return Err(identity_error(
            Kind::HostFailure,
            "verify an installed Win16 native window identity cookie",
        ));
    }

    let inserted = {
        let mut state = state.borrow_mut();
        if state.window_identity_cookies.contains_key(&token)
            || state
                .windows
                .get(&token)
                .is_some_and(|mapped| *mapped != hwnd)
            || state
                .windows_by_native
                .get(&native)
                .is_some_and(|identity| identity.window != token)
        {
            false
        } else {
            state.window_identity_cookies.insert(
                token,
                WindowCookieBinding {
                    hwnd: native,
                    value,
                },
            );
            true
        }
    };
    if !inserted {
        remove_property_if_matches(hwnd, value);
        return Err(identity_error(
            Kind::HostFailure,
            "record a Win16 native window identity without replacing another mapping",
        ));
    }
    Ok(())
}

/// Bind a dialog root to the host token reserved for its exact creation call.
/// Standard `#32770` roots have no guest WndProc, while custom roots acquire
/// this identity from their synchronous `WM_NCCREATE` route.
pub(super) fn bind_dialog_root(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostWindow,
    hwnd: HWND,
    class: Option<runtime::Win16HostClass>,
    creation: Option<Win16CreationId>,
) -> Result<(), RuntimeError> {
    if hwnd.is_null() || belongs_to_worker(hwnd) != Some(true) {
        return Err(identity_error(
            Kind::InvalidInput,
            "bind the exact dialog root on the owning USER worker",
        ));
    }
    let (process_id, thread_id) = native_owner_identity(hwnd).ok_or_else(|| {
        identity_error(
            Kind::HostFailure,
            "read the live native process and thread identity for the dialog root",
        )
    })?;
    let native = hwnd as usize;
    let existing = {
        let borrowed = state.borrow();
        if borrowed
            .windows_by_native
            .get(&native)
            .is_some_and(|identity| identity.window != token)
            || borrowed
                .windows
                .get(&token)
                .is_some_and(|mapped| *mapped != hwnd)
        {
            return Err(identity_error(
                Kind::HostFailure,
                "bind a dialog root without replacing another HWND generation",
            ));
        }
        borrowed.windows_by_native.get(&native).copied()
    };
    if let Some(identity) = existing {
        if identity.class != class
            || identity
                .creation
                .is_some_and(|current| Some(current) != creation)
            || resolve(state, token) != Some(hwnd)
        {
            return Err(identity_error(
                Kind::HostFailure,
                "verify the reserved dialog root identity and class",
            ));
        }
        let mut state = state.borrow_mut();
        let identity = state
            .windows_by_native
            .get_mut(&native)
            .filter(|current| current.window == token)
            .ok_or_else(|| {
                identity_error(
                    Kind::HostFailure,
                    "retain the reserved dialog root identity",
                )
            })?;
        identity.owned = true;
        if creation.is_some() {
            identity.creation = creation;
        }
        return Ok(());
    }
    state
        .borrow_mut()
        .windows_by_native
        .try_reserve(1)
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve a dialog root HWND identity",
                error,
            )
        })?;
    bind(state, token, hwnd)?;
    let mut borrowed = state.borrow_mut();
    if borrowed.windows_by_native.contains_key(&native)
        || borrowed
            .windows
            .get(&token)
            .is_some_and(|mapped| *mapped != hwnd)
    {
        drop(borrowed);
        retire(state, token, hwnd);
        return Err(identity_error(
            Kind::HostFailure,
            "record the reserved dialog root without replacing another identity",
        ));
    }
    borrowed.windows.insert(token, hwnd);
    borrowed.windows_by_native.insert(
        native,
        super::win16_window_worker::NativeWindowIdentity {
            window: token,
            class,
            creation,
            process_id,
            thread_id,
            owned: true,
        },
    );
    Ok(())
}

/// Return an HWND only while its token maps to the exact live property-bound
/// incarnation on this process's current worker thread.
pub(super) fn resolve(state: &Rc<RefCell<WorkerState>>, token: Win16HostWindow) -> Option<HWND> {
    let (hwnd, value) = {
        let state = state.borrow();
        let binding = state.window_identity_cookies.get(&token).copied()?;
        if binding.hwnd == 0 || binding.value == 0 {
            return None;
        }
        let hwnd = binding.hwnd as HWND;
        if state.windows.get(&token).copied()? != hwnd
            || state
                .windows_by_native
                .get(&binding.hwnd)
                .is_none_or(|identity| identity.window != token)
        {
            return None;
        }
        (hwnd, binding.value)
    };

    if belongs_to_worker(hwnd) != Some(true) || property_value(hwnd) != value {
        return None;
    }
    Some(hwnd)
}

/// Resolve a token for ordinary USER operations. Cookie-bound and current
/// worker-thread windows require strict identity validation. A mapped HWND on
/// another process/thread keeps its prior IsWindow-based USER semantics, but
/// this path must never be used to query or call a window procedure or to
/// destroy a window owned by the guest.
pub(super) fn resolve_user_window(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostWindow,
) -> Option<HWND> {
    let (hwnd, has_cookie, owned) = {
        let state = state.borrow();
        let hwnd = state.windows.get(&token).copied()?;
        let native = hwnd as usize;
        let identity = state.windows_by_native.get(&native)?;
        if identity.window != token {
            return None;
        }
        (
            hwnd,
            state.window_identity_cookies.contains_key(&token),
            identity.owned,
        )
    };

    if has_cookie {
        return resolve(state, token);
    }
    if owned {
        return None;
    }
    match belongs_to_worker(hwnd) {
        Some(true) | None => None,
        Some(false) => Some(hwnd),
    }
}

/// Query one exact host token without adopting, rebranding, or destroying an
/// HWND. A retired token is returned only from the worker's exact lifecycle
/// tombstone or the still-retained exact token/HWND record proving that HWND
/// is no longer a window.
pub(super) fn liveness(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostWindow,
) -> Result<Win16HostWindowLiveness, RuntimeError> {
    let (hwnd, identity, cookie, retired) = {
        let state = state.try_borrow().map_err(|_| {
            identity_error(
                Kind::InternalInvariant,
                "query Win16 window liveness without a conflicting worker-state borrow",
            )
        })?;
        let retired = state.retired_window_tokens.contains(&token);
        let mapped = state.windows.get(&token).copied();
        if retired {
            if mapped.is_some() {
                return Err(identity_error(
                    Kind::HostFailure,
                    "Win16 window token is simultaneously active and retired",
                ));
            }
            (None, None, None, true)
        } else {
            let Some(hwnd) = mapped else {
                return Err(identity_error(
                    Kind::HostFailure,
                    "Win16 window liveness query names an unknown host token",
                ));
            };
            let native = hwnd as usize;
            let identity = state
                .windows_by_native
                .get(&native)
                .copied()
                .filter(|identity| identity.window == token)
                .ok_or_else(|| {
                    identity_error(
                        Kind::HostFailure,
                        "Win16 window token no longer owns its exact native map entry",
                    )
                })?;
            let cookie = state.window_identity_cookies.get(&token).copied();
            (Some(hwnd), Some(identity), cookie, false)
        }
    };
    if retired {
        return Ok(Win16HostWindowLiveness::Retired);
    }
    let hwnd = hwnd.ok_or_else(|| {
        identity_error(
            Kind::InternalInvariant,
            "active Win16 window liveness query lost its exact HWND",
        )
    })?;
    let identity = identity.ok_or_else(|| {
        identity_error(
            Kind::InternalInvariant,
            "active Win16 window liveness query lost its native identity",
        )
    })?;
    if hwnd.is_null() {
        return Err(identity_error(
            Kind::HostFailure,
            "Win16 window token maps to a null native HWND",
        ));
    }
    // SAFETY: `hwnd` is an opaque value copied from the worker's exact active
    // token and reverse-identity maps. These APIs do not dereference it.
    if (crate::windows::win32_safe::is_window(hwnd)) == 0 {
        // A failed IsWindow check alone does not publish a lifecycle
        // tombstone. Only remove_window_maps records that exact token as
        // retired; until that owner path runs, keep the state unknown so a
        // caller cannot discard or rebind a queued notification.
        return Err(identity_error(
            Kind::HostFailure,
            "native HWND is no longer live but its exact host token has not reached retirement",
        ));
    }
    let mut process_id = 0;
    // SAFETY: The exact mapped HWND is checked by IsWindow immediately above;
    // the process-id output is a live local integer.
    let thread_id = unsafe { GetWindowThreadProcessId(hwnd, &mut process_id) };
    if process_id == 0 || thread_id == 0 {
        return Err(identity_error(
            Kind::HostFailure,
            "Win16 native window liveness has no exact process/thread identity",
        ));
    }
    if identity.process_id != process_id || identity.thread_id != thread_id {
        return Err(identity_error(
            Kind::HostFailure,
            "Win16 native HWND was rebound to a different process/thread incarnation",
        ));
    }
    if let Some(binding) = cookie {
        if binding.hwnd != hwnd as usize
            || binding.value == 0
            || belongs_to_worker(hwnd) != Some(true)
            || property_value(hwnd) != binding.value
        {
            return Err(identity_error(
                Kind::HostFailure,
                "Win16 native window cookie does not match the exact host token incarnation",
            ));
        }
    } else if identity.owned || belongs_to_worker(hwnd) == Some(true) {
        // Same-worker windows require the already-installed identity cookie.
        // External/System aliases are queried through their existing exact
        // token/native-map association; this path never installs a property.
        return Err(identity_error(
            Kind::HostFailure,
            "same-worker Win16 window is missing its recorded identity cookie",
        ));
    }
    Ok(Win16HostWindowLiveness::Live)
}

/// Adopt an HWND returned by USER. Current-worker windows get a fresh cookie
/// before their token is published. Foreign/other-thread aliases preserve
/// ordinary USER-call behavior but intentionally never resolve a proc.
pub(super) fn adopt(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
) -> Result<Win16HostWindow, RuntimeError> {
    if hwnd.is_null() {
        return Err(identity_error(
            Kind::InvalidInput,
            "Win16 USER returned a null window where a handle was required",
        ));
    }
    let native = hwnd as usize;
    let existing = { state.borrow().windows_by_native.get(&native).copied() };
    if let Some(identity) = existing {
        let has_cookie = {
            state
                .borrow()
                .window_identity_cookies
                .contains_key(&identity.window)
        };
        let owner = belongs_to_worker(hwnd);
        if has_cookie && resolve(state, identity.window) == Some(hwnd) {
            return Ok(identity.window);
        }
        if !has_cookie && !identity.owned && owner == Some(false) {
            // A mapped foreign or other-thread HWND retains prior API
            // semantics; it cannot be used for a native procedure call.
            return Ok(identity.window);
        }

        // The property is absent/mismatched, so this token cannot own this
        // HWND incarnation. A stale owned identity fails closed once instead
        // of being silently rebranded as a callback-capable borrowed alias.
        remove_window_maps(state, identity.window, hwnd);
        if identity.owned {
            return Err(identity_error(
                Kind::HostFailure,
                "Win16 native window identity cookie no longer matches its owned HWND",
            ));
        }
        if owner.is_none() {
            return Err(identity_error(
                Kind::InvalidInput,
                "Win16 USER returned an invalid native window handle",
            ));
        }
    }

    let owner = belongs_to_worker(hwnd).ok_or_else(|| {
        identity_error(
            Kind::InvalidInput,
            "Win16 USER returned an invalid native window handle",
        )
    })?;
    let (process_id, thread_id) = native_owner_identity(hwnd).ok_or_else(|| {
        identity_error(
            Kind::InvalidInput,
            "Win16 USER returned a window without a stable process/thread owner",
        )
    })?;
    let window = allocate_window_token(state)?;
    if owner {
        bind(state, window, hwnd)?;
    }
    let identity = NativeWindowIdentity {
        window,
        class: None,
        creation: None,
        process_id,
        thread_id,
        owned: false,
    };
    let inserted = {
        let mut state = state.borrow_mut();
        if state.windows_by_native.contains_key(&native) || state.windows.contains_key(&window) {
            false
        } else {
            state.windows.insert(window, hwnd);
            state.windows_by_native.insert(native, identity);
            true
        }
    };
    if !inserted {
        if owner {
            retire(state, window, hwnd);
        }
        return Err(identity_error(
            Kind::HostFailure,
            "record a borrowed Win16 HWND without replacing another mapping",
        ));
    }
    Ok(window)
}

/// Record both the native child and its token so parent retirement cannot
/// consume a later window which happens to reuse the same native HWND bits.
/// Adopt a window returned by a successful native creation call. Existing
/// callback adoption is reused only while its exact private cookie matches.
pub(super) fn adopt_created_owned(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
) -> Result<Win16HostWindow, RuntimeError> {
    let token = adopt(state, hwnd)?;
    if resolve(state, token) != Some(hwnd) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "created native window lost its identity before ownership transfer",
        ));
    }
    let mut borrowed = state.borrow_mut();
    let identity = borrowed
        .windows_by_native
        .get_mut(&(hwnd as usize))
        .filter(|identity| identity.window == token)
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "created native window has no matching ownership record",
            )
        })?;
    identity.owned = true;
    Ok(token)
}

pub(super) fn associate_dialog_child(state: &Rc<RefCell<WorkerState>>, child: HWND) {
    let parents = {
        let state = state.borrow();
        state
            .dialog_routes_by_native
            .keys()
            .copied()
            .collect::<Vec<_>>()
    };
    for parent in parents {
        let parent_hwnd = parent as HWND;
        if parent != child as usize
            && (crate::windows::win32_safe::is_child(parent_hwnd, child)) != 0
        {
            let token = state
                .borrow()
                .windows_by_native
                .get(&(child as usize))
                .map(|identity| identity.window);
            if let Some(token) = token {
                state
                    .borrow_mut()
                    .dialog_children_by_native
                    .entry(parent)
                    .or_default()
                    .insert(child as usize, token);
            }
        }
    }
}

/// Retire one token's cookie. Remove the USER property only if it still carries
/// this exact cookie, so a recycled HWND or another owner is left untouched.
pub(super) fn retire(state: &Rc<RefCell<WorkerState>>, token: Win16HostWindow, hwnd: HWND) {
    let binding = {
        let mut state = state.borrow_mut();
        match state.window_identity_cookies.get(&token).copied() {
            Some(binding) if hwnd.is_null() || binding.hwnd == hwnd as usize => {
                state.window_identity_cookies.remove(&token)
            }
            _ => None,
        }
    };
    if let Some(binding) = binding {
        remove_property_if_matches(binding.hwnd as HWND, binding.value);
    }
}

/// Remove every worker cookie during shutdown, without holding a state borrow
/// across any USER calls.
pub(super) fn retire_all(state: &Rc<RefCell<WorkerState>>) {
    let bindings = {
        let mut state = state.borrow_mut();
        std::mem::take(&mut state.window_identity_cookies)
    };
    for binding in bindings.into_values() {
        remove_property_if_matches(binding.hwnd as HWND, binding.value);
    }
}

/// `None` means the HWND is no longer live. Otherwise report whether it is
/// owned by this process and the thread currently executing the worker code.
pub(super) fn belongs_to_worker(hwnd: HWND) -> Option<bool> {
    if hwnd.is_null() || { crate::windows::win32_safe::is_window(hwnd) } == 0 {
        return None;
    }
    let mut process_id = 0_u32;
    // SAFETY: `process_id` is a valid writable output for a live HWND.
    let thread_id = unsafe { GetWindowThreadProcessId(hwnd, &mut process_id) };
    if thread_id == 0 {
        return None;
    }
    // SAFETY: These process/thread queries have no pointer preconditions.
    let current_process = crate::windows::win32_safe::current_process_id();
    let current_thread = crate::windows::win32_safe::current_thread_id();
    Some(process_id == current_process && thread_id == current_thread)
}

fn property_value(hwnd: HWND) -> usize {
    // SAFETY: Callers use a live HWND on the worker thread, and the property
    // name is static and NUL-terminated.
    unsafe { GetPropW(hwnd, IDENTITY_PROPERTY) as usize }
}

fn remove_property_if_matches(hwnd: HWND, value: usize) {
    if value == 0 || belongs_to_worker(hwnd) != Some(true) || property_value(hwnd) != value {
        return;
    }
    // SAFETY: The live window is on this worker thread and still carries the
    // exact property value being retired; no other property's value is removed.
    unsafe { RemovePropW(hwnd, IDENTITY_PROPERTY) };
}

fn identity_error(kind: Kind, context: &'static str) -> RuntimeError {
    RuntimeError::new(kind, context)
}

/// Enumeration has no pending message ownership to ACK. A destroyed or
/// replaced candidate is skipped; unrelated ledger failures remain errors.
pub(super) fn enumeration_current(
    state: &Rc<RefCell<WorkerState>>,
    token: Win16HostWindow,
) -> Result<bool, RuntimeError> {
    let state_ref = state.try_borrow().map_err(|_| {
        identity_error(
            Kind::InternalInvariant,
            "inspect an enumerated HWND without a conflicting borrow",
        )
    })?;
    if state_ref.retired_window_tokens.contains(&token) {
        return Ok(false);
    }
    let hwnd = state_ref.windows.get(&token).copied().ok_or_else(|| {
        identity_error(
            Kind::InternalInvariant,
            "enumeration candidate has no issued HWND token",
        )
    })?;
    let identity = state_ref
        .windows_by_native
        .get(&(hwnd as usize))
        .filter(|identity| identity.window == token)
        .copied()
        .ok_or_else(|| {
            identity_error(
                Kind::InternalInvariant,
                "enumeration candidate lost its token mapping",
            )
        })?;
    let cookie = state_ref.window_identity_cookies.get(&token).copied();
    drop(state_ref);
    if native_owner_identity(hwnd) != Some((identity.process_id, identity.thread_id)) {
        return Ok(false);
    }
    if let Some(cookie) = cookie {
        return Ok(cookie.hwnd == hwnd as usize
            && cookie.value != 0
            && property_value(hwnd) == cookie.value);
    }
    // Foreign USER windows cannot receive this worker's private cookie. Reuse
    // their existing borrowed USER alias policy and verify native ownership.
    Ok(true)
}
