//! A scoped, same-thread observer for exact template payload addresses.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::cell::Cell;
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::Shell::SetWindowSubclass;
use windows_sys::Win32::UI::WindowsAndMessaging::{CallNextHookEx, CBT_CREATEWNDW,
    GetClassNameW, HCBT_CREATEWND, HHOOK, SetWindowsHookExW, UnhookWindowsHookEx, WH_CBT};

struct Frame {
    state: Rc<RefCell<WorkerState>>, operation: u64, creation: Win16CreationId,
    expected: usize, modal: bool, failure: RefCell<Option<RuntimeError>>,
}
thread_local! {
    static FRAMES: RefCell<Vec<Rc<Frame>>> = const { RefCell::new(Vec::new()) };
    static PANICKED: Cell<bool> = const { Cell::new(false) };
    static ORPHANS: RefCell<Vec<HHOOK>> = const { RefCell::new(Vec::new()) };
}
pub(in crate::windows::win16_windows) struct CreationScope { frame: Rc<Frame>, hook: HHOOK, closed: bool }
impl CreationScope {
    pub(super) fn enter(state: &Rc<RefCell<WorkerState>>, operation: u64,
        creation: Win16CreationId, expected: usize, modal: bool) -> Result<Self, RuntimeError>
    {
        ORPHANS.with(|orphans| {
            orphans.borrow_mut().retain(|hook| !unhook(*hook));
            // Every active scope may need an orphan slot while unwinding.
            let active = FRAMES.with(|frames| frames.borrow().len());
            orphans.borrow_mut().try_reserve(active + 1).map_err(|source|
                RuntimeError::with_source(Kind::ResourceExhausted, "reserve dialog CBT cleanup", source))
        })?;
        FRAMES.with(|frames| frames.borrow_mut().try_reserve(1).map_err(|source|
            RuntimeError::with_source(Kind::ResourceExhausted, "reserve dialog CBT frame", source)))?;
        if FRAMES.with(|frames| frames.borrow().is_empty()) { PANICKED.with(|flag| flag.set(false)); }
        let frame = Rc::new(Frame { state: Rc::clone(state), operation, creation, expected,
            modal, failure: RefCell::new(None) });
        let hook = unsafe { SetWindowsHookExW(WH_CBT, Some(hook_proc), std::ptr::null_mut(), GetCurrentThreadId()) };
        if hook.is_null() { return Err(error("install dialog STATIC creation observer")); }
        FRAMES.with(|frames| frames.borrow_mut().push(Rc::clone(&frame)));
        Ok(Self { frame, hook, closed: false })
    }
    pub(in crate::windows::win16_windows) fn finish(mut self) -> Result<(), RuntimeError> { self.close() }
    fn close(&mut self) -> Result<(), RuntimeError> {
        if self.closed { return Ok(()); }
        self.closed = true;
        FRAMES.with(|frames| {
            let mut frames = frames.borrow_mut();
            if let Some(index) = frames.iter().position(|frame| Rc::ptr_eq(frame, &self.frame)) {
                frames.remove(index);
            }
        });
        if !unhook(self.hook) {
            ORPHANS.with(|orphans| orphans.borrow_mut().push(self.hook));
            record(&self.frame, error("remove dialog STATIC creation observer"));
        }
        if PANICKED.with(Cell::get) { record(&self.frame, error("panic in dialog icon native callback")); }
        self.frame.failure.borrow_mut().take().map_or(Ok(()), Err)
    }
}
impl Drop for CreationScope {
    fn drop(&mut self) {
        if let Err(error) = self.close() { super::super::win16_window_callbacks::fail_worker(&self.frame.state, error); }
    }
}
pub(super) fn has_frame(operation: u64, creation: Win16CreationId) -> bool {
    FRAMES.with(|frames| frames.borrow().iter().any(|frame| frame.operation == operation && frame.creation == creation))
}
pub(super) fn active_contract(operation: u64, creation: Win16CreationId) -> Option<(usize, bool, bool)> {
    FRAMES.with(|frames| frames.borrow().iter().rev().find(|frame|
        frame.operation == operation && frame.creation == creation)
        .map(|frame| (frame.expected, frame.modal, frame.failure.borrow().is_some() || PANICKED.with(Cell::get))))
}
pub(super) fn latch_panic() { PANICKED.with(|flag| flag.set(true)); }
pub(super) fn report(operation: u64, creation: Win16CreationId, failure: RuntimeError) {
    let frame = FRAMES.with(|frames| frames.borrow().iter().rev().find(|frame|
        frame.operation == operation && frame.creation == creation).cloned());
    if let Some(frame) = frame { record(&frame, failure); }
}
fn record(frame: &Frame, failure: RuntimeError) {
    let mut slot = frame.failure.borrow_mut();
    if slot.is_none() { *slot = Some(failure); }
}
unsafe extern "system" fn hook_proc(code: i32, w: usize, l: isize) -> isize {
    if code != HCBT_CREATEWND as i32 {
        return unsafe { CallNextHookEx(std::ptr::null_mut(), code, w, l) };
    }
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let frame = FRAMES.with(|frames| frames.borrow().last().cloned());
        let Some(frame) = frame else { return false; };
        match observe(&frame, w as HWND, l) {
            Ok(veto) => veto,
            Err(failure) => { record(&frame, failure); true }
        }
    }));
    let veto = match outcome {
        Ok(veto) => veto,
        Err(_) => { latch_panic(); false }
    };
    let next = unsafe { CallNextHookEx(std::ptr::null_mut(), code, w, l) };
    if veto && next == 0 { 1 } else { next }
}
fn observe(frame: &Frame, hwnd: HWND, parameter: isize) -> Result<bool, RuntimeError> {
    if hwnd.is_null() || parameter == 0 { return Ok(false); }
    let state = &frame.state;
    if state.borrow().active_operations.last().is_none_or(|active| active.id != frame.operation) {
        return Ok(false);
    }
    // CBT supplies this structure synchronously. The nested payload is compared
    // only with our still-owned buffer address, never dereferenced.
    let create = unsafe { &*(parameter as *const CBT_CREATEWNDW) };
    if create.lpcs.is_null() { return Ok(false); }
    let native = unsafe { &*create.lpcs };
    let candidate = {
        let borrowed = state.borrow();
        borrowed.dialog_icon_sidecars.by_payload(frame.operation, frame.creation, native.lpCreateParams as usize)
            .map(|sidecar| (sidecar.window, sidecar.control_id, sidecar.phase, sidecar.hwnd, sidecar.subclass_installed, Arc::clone(&sidecar.owner)))
    };
    let Some((window, control_id, phase, bound, installed, owner)) = candidate else { return Ok(false); };
    let native_id = native.hMenu as usize;
    if frame.failure.borrow().is_some() || !class_is(hwnd, b"STATIC") || native.style & 0x1f != 3
        || (native_id != usize::from(control_id) && !(control_id == 0xffff && native_id == usize::MAX))
        || !class_is(native.hwndParent, b"#32770")
    { return Err(error("dialog STATIC payload matched contradictory native creation")); }
    let (root_token, pinned) = {
        let borrowed = state.borrow();
        let pending = borrowed.pending_dialog_routes.iter().find(|pending|
            pending.operation == frame.operation && pending.creation == frame.creation)
            .ok_or_else(|| error("dialog STATIC creation lost its pending root"))?;
        if pending.root.is_some() { return Err(error("template icon cannot adopt a custom dialog root")); }
        (pending.root_token, pending.root_window)
    };
    if let Some(pinned) = pinned {
        if pinned != native.hwndParent as usize
            || super::super::win16_window_identity::resolve(state, root_token) != Some(native.hwndParent)
        { return Err(error("dialog STATIC parent differs from the pinned root generation")); }
    } else {
        if phase != Phase::Prepared { return Err(error("repeated STATIC observation lost its root")); }
        super::super::win16_window_identity::bind_dialog_root(state, root_token,
            native.hwndParent, None, Some(frame.creation))?;
        let mut borrowed = state.borrow_mut();
        let pending = borrowed.pending_dialog_routes.iter_mut().find(|pending|
            pending.operation == frame.operation && pending.creation == frame.creation)
            .ok_or_else(|| error("dialog root disappeared during identity binding"))?;
        if pending.root_window.is_some() { return Err(error("dialog root was pinned reentrantly")); }
        pending.root_window = Some(native.hwndParent as usize);
    }
    // Several scoped registrations can observe this same CBT event. Accept
    // only the completed pre-NCCREATE binding, after all native predicates and
    // the pinned parent were rechecked. Later phases are never hook replays.
    if phase != Phase::Prepared {
        if phase == Phase::Bound && installed && bound == Some(hwnd as usize)
            && super::super::win16_window_identity::resolve(state, window) == Some(hwnd)
            && state.borrow().windows_by_native.get(&(hwnd as usize)).is_some_and(|identity|
                identity.window == window && identity.creation == Some(frame.creation))
        {
            #[cfg(test)]
            TEST_DUPLICATES.with(|count| count.set(count.get() + 1));
            return Ok(false);
        }
        return Err(error("dialog STATIC creation payload was replayed"));
    }
    super::super::win16_window_identity::bind_dialog_root(state, window, hwnd, None, Some(frame.creation))?;
    owner.bind(hwnd)?;
    {
        let mut borrowed = state.borrow_mut();
        let sidecar = borrowed.dialog_icon_sidecars.by_window_mut(window)
            .ok_or_else(|| error("dialog STATIC sidecar disappeared during binding"))?;
        sidecar.hwnd = Some(hwnd as usize);
        sidecar.phase = Phase::Bound;
    }
    let id = usize::try_from(window.0).map_err(|_| error("dialog STATIC subclass ID overflow"))?;
    if unsafe { SetWindowSubclass(hwnd, Some(subclass::icon_proc), id, 0) } == 0 {
        return Err(error("install exact dialog STATIC subclass"));
    }
    if let Some(sidecar) = state.borrow_mut().dialog_icon_sidecars.by_window_mut(window) {
        sidecar.subclass_installed = true;
    }
    Ok(false)
}
fn class_is(hwnd: HWND, expected: &[u8]) -> bool {
    let mut name = [0u16; 32];
    let length = unsafe { GetClassNameW(hwnd, name.as_mut_ptr(), name.len() as i32) };
    length > 0 && length as usize == expected.len()
        && name[..length as usize].iter().zip(expected).all(|(left, right)|
            u8::try_from(*left).is_ok_and(|left| left.eq_ignore_ascii_case(right)))
}

// Tests suppress selected removal attempts while the real hook remains live.
// Every reported successful removal still comes from UnhookWindowsHookEx.
fn unhook(hook: HHOOK) -> bool {
    #[cfg(test)]
    if TEST_UNHOOK_FAILURES.with(|remaining| {
        let count = remaining.get();
        if count == 0 { false } else { remaining.set(count - 1); true }
    }) {
        TEST_FAILED_UNHOOKS.with(|count| count.set(count.get() + 1));
        return false;
    }
    let removed = unsafe { UnhookWindowsHookEx(hook) } != 0;
    #[cfg(test)]
    if removed { TEST_REMOVED_HOOKS.with(|count| count.set(count.get() + 1)); }
    removed
}
#[cfg(test)]
thread_local! {
    static TEST_UNHOOK_FAILURES: Cell<usize> = const { Cell::new(0) };
    static TEST_FAILED_UNHOOKS: Cell<usize> = const { Cell::new(0) };
    static TEST_REMOVED_HOOKS: Cell<usize> = const { Cell::new(0) };
    static TEST_DUPLICATES: Cell<usize> = const { Cell::new(0) };
}
#[cfg(test)]
pub(super) fn test_fail_unhooks(count: usize) {
    assert!(FRAMES.with(|frames| frames.borrow().is_empty()));
    assert!(ORPHANS.with(|orphans| orphans.borrow().is_empty()));
    TEST_UNHOOK_FAILURES.with(|remaining| remaining.set(count));
    TEST_FAILED_UNHOOKS.with(|value| value.set(0));
    TEST_REMOVED_HOOKS.with(|value| value.set(0));
    TEST_DUPLICATES.with(|value| value.set(0));
}
#[cfg(test)]
pub(super) fn test_hook_state() -> (usize, usize, usize, usize, usize) {
    (TEST_UNHOOK_FAILURES.with(Cell::get), TEST_FAILED_UNHOOKS.with(Cell::get),
        TEST_REMOVED_HOOKS.with(Cell::get), ORPHANS.with(|orphans| orphans.borrow().len()),
        TEST_DUPLICATES.with(Cell::get))
}
#[cfg(test)]
pub(super) fn test_panicked() -> bool { PANICKED.with(Cell::get) }
#[cfg(test)]
pub(super) fn test_cleanup_hooks() -> bool {
    TEST_UNHOOK_FAILURES.with(|remaining| remaining.set(0));
    ORPHANS.with(|orphans| {
        orphans.borrow_mut().retain(|hook| !unhook(*hook));
        orphans.borrow().is_empty()
    })
}
