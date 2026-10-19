//! Exact creation-time HWND identity for synchronous CreateWindowEx calls.
//!
//! A GetDlgItem call can be reentered before CreateWindowEx returns. The CBT
//! create notification exposes that call's concrete HWND before WM_NCCREATE or
//! WM_CREATE, so bind the reserved token there instead of adopting a second
//! alias and trying to reconcile it after USER returns.
//!
//! This hook is installed immediately before the exact native call. Windows
//! inserts a new hook at the head of its chain, so this observer processes the
//! direct creation notification before downstream CBT hooks or the window
//! procedure can reenter creation. It still passes every nonmatching HWND
//! through unchanged.

use std::cell::{Cell, RefCell};
use std::ffi::c_void;
use std::mem::size_of;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;
use std::sync::Arc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16CreationId, Win16HostClass, Win16HostCreationData,
    Win16HostWindow,
};
use windows_sys::Win32::Foundation::{HINSTANCE, HWND};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CBT_CREATEWNDW, CREATESTRUCTW, CallNextHookEx, GetClassNameW, HCBT_CREATEWND, HHOOK, HMENU,
    SetWindowsHookExW, WH_CBT,
};

use super::win16_window_worker::{NativeWindowIdentity, WorkerState};

struct NativeCreateFrame {
    state: Rc<RefCell<WorkerState>>,
    hook: HHOOK,
    operation: u64,
    creation: Win16CreationId,
    window: Win16HostWindow,
    class: Win16HostClass,
    class_name: Rc<[u16]>,
    // Retain the complete call snapshot for diagnostics. USER and hooks may
    // normalize these mutable fields before the CBT notification, so they are
    // deliberately not identity predicates.
    _window_name: Rc<[u16]>,
    _style: u32,
    _ex_style: u32,
    _coordinates: [i32; 4],
    class_instance: HINSTANCE,
    parent: HWND,
    menu: HMENU,
    native_parameter: usize,
    process_id: u32,
    thread_id: u32,
    claimed_hwnd: Option<HWND>,
    error: Option<RuntimeError>,
}

#[derive(Clone)]
struct NativeCreateFrameSnapshot {
    state: Rc<RefCell<WorkerState>>,
    operation: u64,
    creation: Win16CreationId,
    window: Win16HostWindow,
    class: Win16HostClass,
    class_name: Rc<[u16]>,
    class_instance: HINSTANCE,
    parent: HWND,
    menu: HMENU,
    native_parameter: usize,
    process_id: u32,
    thread_id: u32,
}

thread_local! {
    static FRAMES: RefCell<Vec<NativeCreateFrame>> = const { RefCell::new(Vec::new()) };
    // A failed UnhookWindowsHookEx must not orphan the only handle capable of
    // removing that observer. These handles remain owned here and are retried
    // before a later native creation scope is installed.
    static ORPHAN_HOOKS: RefCell<Vec<HHOOK>> = const { RefCell::new(Vec::new()) };
    static EMERGENCY_FAILURE: Cell<Option<u64>> = const { Cell::new(None) };
}

pub(super) struct NativeCreateCallScope {
    operation: u64,
    finished: bool,
}

impl NativeCreateCallScope {
    pub(super) fn enter(
        state: &Rc<RefCell<WorkerState>>,
        creation: Win16CreationId,
        window: Win16HostWindow,
        class: Win16HostClass,
        owner: (u32, u32),
        window_name: &[u16],
        coordinates: [i32; 4],
        parent: HWND,
        menu: HMENU,
        native_parameter: *const std::ffi::c_void,
        data: &Win16HostCreationData,
    ) -> Result<Self, RuntimeError> {
        if data.class != class {
            return Err(create_identity_error(
                Kind::InternalInvariant,
                "reserve an HWND creation frame for a different class identity",
            ));
        }
        let (operation, class_instance, class_name) = {
            let state = state.try_borrow().map_err(|_| {
                create_identity_error(
                    Kind::InternalInvariant,
                    "read the exact active operation before CreateWindowEx",
                )
            })?;
            let operation = state
                .active_operations
                .last()
                .map(|active| active.id)
                .ok_or_else(|| {
                    create_identity_error(
                        Kind::InternalInvariant,
                        "associate CreateWindowEx with an exact active USER operation",
                    )
                })?;
            let class_data = state.classes.get(&class).ok_or_else(|| {
                create_identity_error(
                    Kind::InternalInvariant,
                    "resolve the native class for its CreateWindowEx identity frame",
                )
            })?;
            let mut class_name = Vec::new();
            class_name
                .try_reserve_exact(class_data.name.len())
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "copy the exact native CreateWindowEx class name",
                        error,
                    )
                })?;
            class_name.extend(class_data.name.iter().copied().map(u16::from));
            if class_name.last() != Some(&0)
                || class_name[..class_name.len().saturating_sub(1)].contains(&0)
            {
                return Err(create_identity_error(
                    Kind::InternalInvariant,
                    "capture a terminated native class name for its CBT creation frame",
                ));
            }
            (operation, class_data.instance, class_name)
        };
        let mut frame = NativeCreateFrame {
            state: Rc::clone(state),
            hook: std::ptr::null_mut(),
            operation,
            creation,
            window,
            class,
            class_name: Rc::from(class_name),
            _window_name: Rc::from(window_name),
            _style: data.style,
            _ex_style: data.ex_style,
            _coordinates: coordinates,
            class_instance,
            parent,
            menu,
            native_parameter: native_parameter as usize,
            process_id: owner.0,
            thread_id: owner.1,
            claimed_hwnd: None,
            error: None,
        };

        let active_frames = FRAMES.with(|frames| {
            let mut frames = frames.try_borrow_mut().map_err(|_| create_identity_error(
                Kind::InternalInvariant,
                "reserve an exact native CreateWindowEx frame without a conflicting hook borrow",
            ))?;
            if frames
                .iter()
                .any(|frame| Rc::ptr_eq(&frame.state, state) && frame.operation == operation)
            {
                return Err(create_identity_error(
                    Kind::InternalInvariant,
                    "one USER operation cannot own two active CreateWindowEx invocation frames",
                ));
            }
            if frames
                .last()
                .is_some_and(|frame| !Rc::ptr_eq(&frame.state, state))
            {
                return Err(create_identity_error(
                    Kind::InternalInvariant,
                    "reuse the native creation hook only for its exact worker state",
                ));
            }
            frames.try_reserve(1).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve exact native CreateWindowEx invocation identity",
                    error,
                )
            })?;
            frames.len().checked_add(1).ok_or_else(|| {
                create_identity_error(
                    Kind::ResourceExhausted,
                    "count nested native CreateWindowEx hook owners",
                )
            })
        });
        let active_frames = active_frames?;
        ORPHAN_HOOKS.with(|hooks| {
            hooks
                .try_borrow_mut()
                .map_err(|_| {
                    create_identity_error(
                        Kind::InternalInvariant,
                        "reserve retained CBT hook owners without a conflicting borrow",
                    )
                })?
                .try_reserve(active_frames)
                .map_err(|error| {
                    RuntimeError::with_source(
                        Kind::ResourceExhausted,
                        "reserve ownership slots for every active native creation hook",
                        error,
                    )
                })
        })?;

        retry_orphan_hooks(state)?;
        let emergency_operation = EMERGENCY_FAILURE.with(|failure| failure.take());
        if let Some(operation) = emergency_operation {
            let error = create_identity_error(
                Kind::InternalInvariant,
                "surface a deferred native creation-hook cleanup failure before another USER operation",
            );
            latch_hook_failure(
                state,
                operation,
                "a previous scoped CBT hook cleanup failed during unwinding",
            );
            return Err(error);
        }

        let thread_id = crate::windows::win32_safe::current_thread_id();
        if thread_id == 0 || thread_id != owner.1 {
            return Err(create_identity_error(
                Kind::HostFailure,
                "identify the exact USER worker thread for its scoped CBT creation hook",
            ));
        }
        // SAFETY: `SetWindowsHookExW`, `Some` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        let installed = unsafe {
            SetWindowsHookExW(
                WH_CBT,
                Some(native_cbt_proc),
                std::ptr::null_mut(),
                thread_id,
            )
        };
        if installed.is_null() {
            return Err(RuntimeError::with_source(
                Kind::HostFailure,
                "install the thread-local CBT hook for exact CreateWindowEx identity",
                std::io::Error::from_raw_os_error(
                    (crate::windows::win32_safe::last_error()) as i32,
                ),
            ));
        }
        frame.hook = installed;

        let publish = FRAMES.with(|frames| {
            frames
                .try_borrow_mut()
                .map_err(|_| {
                    create_identity_error(
                        Kind::InternalInvariant,
                        "publish the exact native CreateWindowEx invocation frame",
                    )
                })?
                .push(frame);
            Ok::<(), RuntimeError>(())
        });
        if let Err(error) = publish {
            return match unhook(installed) {
                Ok(()) => Err(error),
                Err(cleanup) => {
                    let retained = retain_failed_hook(installed);
                    latch_hook_failure(
                        state,
                        operation,
                        "a CBT hook could not be removed after its frame publication failed",
                    );
                    let cleanup = if retained {
                        cleanup
                    } else {
                        cleanup.with_cleanup(
                            "retain the failed CBT hook handle after frame publication failed",
                            create_identity_error(
                                Kind::InternalInvariant,
                                "retain the failed CBT hook handle for retry",
                            ),
                        )
                    };
                    Err(error.with_cleanup(
                        "remove the unused CBT hook after publishing its exact creation frame failed",
                        cleanup,
                    ))
                }
            };
        }
        Ok(Self {
            operation,
            finished: false,
        })
    }

    pub(super) fn finish(mut self, returned: HWND) -> Result<Option<HWND>, RuntimeError> {
        let frame = FRAMES.with(|frames| {
            let mut frames = frames.try_borrow_mut().map_err(|_| {
                create_identity_error(
                    Kind::InternalInvariant,
                    "finish the exact native CreateWindowEx invocation frame",
                )
            })?;
            match frames.last() {
                Some(frame) if frame.operation == self.operation => Ok(frames.pop()),
                _ => Err(create_identity_error(
                    Kind::InternalInvariant,
                    "finish CreateWindowEx in exact last-in-first-out invocation order",
                )),
            }
        })?;
        self.finished = true;
        let frame = frame.ok_or_else(|| {
            create_identity_error(
                Kind::InternalInvariant,
                "recover the exact native CreateWindowEx frame after its USER call",
            )
        })?;
        let unhook = match unhook(frame.hook) {
            Ok(()) => Ok(()),
            Err(error) => {
                let retained = retain_failed_hook(frame.hook);
                latch_hook_failure(
                    &frame.state,
                    self.operation,
                    "a scoped CBT hook could not be removed after its native creation call",
                );
                if retained {
                    Err(error)
                } else {
                    Err(error.with_cleanup(
                        "retain ownership of the CBT hook after removal failed",
                        create_identity_error(
                            Kind::InternalInvariant,
                            "retain the failed CBT hook handle for retry",
                        ),
                    ))
                }
            }
        };
        let emergency = EMERGENCY_FAILURE.with(|failure| {
            if failure.get() == Some(self.operation) {
                failure.set(None);
                true
            } else {
                false
            }
        });
        let result = if emergency {
            Err(create_identity_error(
                Kind::InternalInvariant,
                "preserve the native CreateWindowEx hook failure for its exact caller",
            ))
        } else if let Some(error) = frame.error {
            Err(error)
        } else if frame
            .claimed_hwnd
            .is_some_and(|claimed| !returned.is_null() && returned != claimed)
        {
            Err(create_identity_error(
                Kind::HostFailure,
                "CreateWindowEx returned an HWND different from its exact CBT creation notification",
            ))
        } else if !returned.is_null() && frame.claimed_hwnd != Some(returned) {
            Err(create_identity_error(
                Kind::HostFailure,
                "CreateWindowEx returned an HWND without its exact creation-time identity route",
            ))
        } else {
            Ok(frame.claimed_hwnd)
        };
        match (result, unhook) {
            (Err(error), Err(cleanup)) => Err(error.with_cleanup(
                "unhook the native creation observer after its primary failure",
                cleanup,
            )),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(window), Ok(())) => Ok(window),
        }
    }

    /// The exact HWND claim survives a failed native creation when a later
    /// CBT hook vetoes it. Capture it before `finish` removes this frame so the
    /// caller can retire only that reserved token's HWND/cookie.
    pub(super) fn claimed_hwnd(&self) -> Option<HWND> {
        FRAMES.with(|frames| {
            frames.try_borrow().ok().and_then(|frames| {
                frames
                    .last()
                    .filter(|frame| frame.operation == self.operation)
                    .and_then(|frame| frame.claimed_hwnd)
            })
        })
    }
}

impl Drop for NativeCreateCallScope {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let popped = FRAMES.with(|frames| {
            let Ok(mut frames) = frames.try_borrow_mut() else {
                return None;
            };
            let index = frames
                .iter()
                .rposition(|frame| frame.operation == self.operation)?;
            let out_of_order = index + 1 != frames.len();
            let frame = frames.remove(index);
            Some((frame.hook, frame.state, out_of_order))
        });
        if let Some((hook, state, out_of_order)) = popped {
            if out_of_order {
                latch_hook_failure(
                    &state,
                    self.operation,
                    "native creation scopes unwound outside exact last-in-first-out order",
                );
            }
            if unhook(hook).is_err() {
                let retained = retain_failed_hook(hook);
                latch_hook_failure(
                    &state,
                    self.operation,
                    "a scoped CBT hook could not be removed while unwinding its native creation call",
                );
                if !retained {
                    EMERGENCY_FAILURE.with(|failure| {
                        if failure.get().is_none() {
                            failure.set(Some(self.operation));
                        }
                    });
                }
            }
        } else {
            EMERGENCY_FAILURE.with(|failure| {
                if failure.get().is_none() {
                    failure.set(Some(self.operation));
                }
            });
        }
    }
}

// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn native_cbt_proc(
    code: i32,
    w_param: windows_sys::Win32::Foundation::WPARAM,
    l_param: windows_sys::Win32::Foundation::LPARAM,
) -> windows_sys::Win32::Foundation::LRESULT {
    if code != HCBT_CREATEWND as i32 {
        // SAFETY: CallNextHookEx forwards the hook arguments Windows passed into this callback.
        return unsafe { CallNextHookEx(std::ptr::null_mut(), code, w_param, l_param) };
    }
    let decision = catch_unwind(AssertUnwindSafe(|| {
        process_create_notification(w_param as HWND, l_param)
    }));
    let veto = match decision {
        Ok(veto) => veto,
        Err(_) => {
            let operation = FRAMES.with(|frames| {
                frames
                    .try_borrow()
                    .ok()
                    .and_then(|frames| frames.last().map(|frame| frame.operation))
            });
            if let Some(operation) = operation {
                if !record_frame_error(
                    operation,
                    create_identity_error(
                        Kind::InternalInvariant,
                        "contain a panic in the scoped CBT creation observer",
                    ),
                ) {
                    EMERGENCY_FAILURE.with(|failure| {
                        if failure.get().is_none() {
                            failure.set(Some(operation));
                        }
                    });
                }
            }
            // A panic does not prove that this HWND belongs to our exact
            // CreateWindowEx call. Preserve the native hook chain unchanged.
            false
        }
    };
    // SAFETY: CallNextHookEx forwards the hook arguments Windows passed into this callback.
    let next = unsafe { CallNextHookEx(std::ptr::null_mut(), code, w_param, l_param) };
    if veto && next == 0 { 1 } else { next }
}

fn process_create_notification(hwnd: HWND, l_param: isize) -> bool {
    if hwnd.is_null() || l_param == 0 {
        return false;
    }
    let frame = FRAMES.with(|frames| {
        frames.try_borrow().ok().and_then(|frames| {
            let frame = frames.last()?;
            if frame.claimed_hwnd.is_some() || frame.error.is_some() {
                return None;
            }
            Some(NativeCreateFrameSnapshot {
                state: Rc::clone(&frame.state),
                operation: frame.operation,
                creation: frame.creation,
                window: frame.window,
                class: frame.class,
                class_name: Rc::clone(&frame.class_name),
                class_instance: frame.class_instance,
                parent: frame.parent,
                menu: frame.menu,
                native_parameter: frame.native_parameter,
                process_id: frame.process_id,
                thread_id: frame.thread_id,
            })
        })
    });
    let Some(frame) = frame else {
        return false;
    };
    let Some(active) = frame
        .state
        .try_borrow()
        .ok()
        .and_then(|state| state.active_operations.last().map(|active| active.id))
    else {
        return false;
    };
    if active != frame.operation {
        return false;
    }

    // HCBT_CREATEWND supplies the CREATESTRUCT for this specific HWND before
    // USER sends WM_NCCREATE or WM_CREATE. It is valid only for this hook call.
    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
    let cbt = unsafe { &*(l_param as *const CBT_CREATEWNDW) };
    if cbt.lpcs.is_null() {
        return false;
    }
    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
    let create = unsafe { &*cbt.lpcs };
    if !request_matches(&frame, hwnd, create) {
        return false;
    }

    let identity = NativeWindowIdentity {
        window: frame.window,
        class: Some(frame.class),
        creation: Some(frame.creation),
        process_id: frame.process_id,
        thread_id: frame.thread_id,
        owned: true,
    };
    if let Err(error) = bind_native_creation(&frame, hwnd, identity) {
        record_frame_error(frame.operation, error);
        return true;
    }
    let recorded = FRAMES.with(|frames| {
        let Ok(mut frames) = frames.try_borrow_mut() else {
            return false;
        };
        let Some(current) = frames.last_mut().filter(|current| {
            current.operation == frame.operation && current.window == frame.window
        }) else {
            return false;
        };
        current.claimed_hwnd = Some(hwnd);
        true
    });
    if !recorded {
        super::win16_window_identity::retire(&frame.state, frame.window, hwnd);
        super::win16_window_worker::remove_window_maps(&frame.state, frame.window, hwnd);
        record_frame_error(
            frame.operation,
            create_identity_error(
                Kind::InternalInvariant,
                "publish the exact native HWND claim to its active CreateWindowEx frame",
            ),
        );
        return true;
    }
    false
}

fn request_matches(frame: &NativeCreateFrameSnapshot, hwnd: HWND, create: &CREATESTRUCTW) -> bool {
    if create.hwndParent != frame.parent || create.hInstance != frame.class_instance {
        return false;
    }
    // hMenu is an opaque native argument for top-level calls and the original
    // child ID for WS_CHILD calls; compare its value without inferring which
    // meaning applies from mutable STYLE bits.
    if create.hMenu as usize != frame.menu as usize {
        return false;
    }
    // lpCreateParams is an immutable CreateWindowEx argument. System classes
    // normally receive null; MDIClient receives its exact owned structure.
    if create.lpCreateParams as usize != frame.native_parameter {
        return false;
    }
    if !create_struct_class_name_matches(&frame.class_name, create.lpszClass as usize)
        && !native_class_name_matches(&frame.class_name, hwnd)
    {
        return false;
    }
    let process_id = crate::windows::win32_safe::current_process_id();
    let thread_id = crate::windows::win32_safe::current_thread_id();
    process_id == frame.process_id && thread_id == frame.thread_id
}

fn native_class_name_matches(expected: &[u16], hwnd: HWND) -> bool {
    let Some(expected) = expected.strip_suffix(&[0]) else {
        return false;
    };
    if expected.is_empty() || expected.len() >= i32::MAX as usize || expected.contains(&0) {
        return false;
    }
    let mut actual = [0_u16; 512];
    if expected.len() >= actual.len() - 1 {
        return false;
    }
    // SAFETY: GetClassNameW writes into a caller-owned UTF-16 buffer of the capacity passed with it.
    let copied = unsafe { GetClassNameW(hwnd, actual.as_mut_ptr(), actual.len() as i32) };
    copied > 0
        && copied as usize == expected.len()
        && actual[..expected.len()]
            .iter()
            .zip(expected)
            .all(|(left, right)| fold_ascii_wide(*left) == fold_ascii_wide(*right))
}

fn create_struct_class_name_matches(expected: &[u16], pointer: usize) -> bool {
    let Some(expected) = expected.strip_suffix(&[0]) else {
        return false;
    };
    const MAX_CLASS_UNITS: usize = 512;
    if pointer <= 0xFFFF || expected.is_empty() || expected.len() >= MAX_CLASS_UNITS - 1 {
        // CREATESTRUCT permits an atom in this field; the HWND query below
        // resolves that form. A host CreateWindowEx call itself passes a name.
        return false;
    }
    let mut actual = [0_u16; MAX_CLASS_UNITS];
    let read_size = (expected.len() + 1).checked_mul(size_of::<u16>());
    let Some(read_size) = read_size else {
        return false;
    };
    let mut transferred = 0_usize;
    // SAFETY: HCBT_CREATEWND supplies this CREATESTRUCT for the current native
    // creation callback. ReadProcessMemory bounds the nested class-string read
    // and avoids forming a reference from the native pointer.
    let succeeded = unsafe {
        ReadProcessMemory(
            crate::windows::win32_safe::current_process(),
            pointer as *const c_void,
            actual.as_mut_ptr().cast::<c_void>(),
            read_size,
            &mut transferred,
        )
    };
    succeeded != 0
        && transferred == read_size
        && actual[expected.len()] == 0
        && actual[..expected.len()]
            .iter()
            .zip(expected)
            .all(|(left, right)| fold_ascii_wide(*left) == fold_ascii_wide(*right))
}

fn fold_ascii_wide(value: u16) -> u16 {
    if (b'a' as u16..=b'z' as u16).contains(&value) {
        value - b'a' as u16 + b'A' as u16
    } else {
        value
    }
}

fn bind_native_creation(
    frame: &NativeCreateFrameSnapshot,
    hwnd: HWND,
    identity: NativeWindowIdentity,
) -> Result<(), RuntimeError> {
    {
        let mut state = frame.state.try_borrow_mut().map_err(|_| {
            create_identity_error(
                Kind::InternalInvariant,
                "reserve identity-map capacity during the exact CBT creation notification",
            )
        })?;
        if state.windows.contains_key(&identity.window)
            || state.windows_by_native.contains_key(&(hwnd as usize))
        {
            return Err(create_identity_error(
                Kind::HostFailure,
                "bind a creation-time HWND without replacing a preexisting owner",
            ));
        }
        state.windows.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve the exact native HWND mapping before its first callback",
                error,
            )
        })?;
        state.windows_by_native.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve the exact native HWND reverse mapping before its first callback",
                error,
            )
        })?;
    }
    super::win16_window_identity::bind(&frame.state, identity.window, hwnd)?;
    let recorded = {
        let mut state = frame.state.try_borrow_mut().map_err(|_| {
            create_identity_error(
                Kind::InternalInvariant,
                "publish the exact HWND identity after installing its cookie",
            )
        })?;
        if state.windows.contains_key(&identity.window)
            || state.windows_by_native.contains_key(&(hwnd as usize))
        {
            false
        } else {
            state.windows.insert(identity.window, hwnd);
            state.windows_by_native.insert(hwnd as usize, identity);
            true
        }
    };
    if recorded {
        Ok(())
    } else {
        super::win16_window_identity::retire(&frame.state, identity.window, hwnd);
        Err(create_identity_error(
            Kind::HostFailure,
            "publish a creation-time HWND without replacing a concurrent native owner",
        ))
    }
}

fn record_frame_error(operation: u64, error: RuntimeError) -> bool {
    let recorded = FRAMES.with(|frames| {
        let Ok(mut frames) = frames.try_borrow_mut() else {
            return false;
        };
        let Some(frame) = frames
            .last_mut()
            .filter(|frame| frame.operation == operation)
        else {
            return false;
        };
        frame.error = Some(error);
        true
    });
    if !recorded {
        EMERGENCY_FAILURE.with(|failure| {
            if failure.get().is_none() {
                failure.set(Some(operation));
            }
        });
    }
    recorded
}

fn unhook(hook: HHOOK) -> Result<(), RuntimeError> {
    if hook.is_null() {
        return Ok(());
    }
    let removed = (crate::windows::win32_safe::unhook_windows_hook(hook)) != 0;
    if removed {
        Ok(())
    } else {
        Err(RuntimeError::with_source(
            Kind::HostFailure,
            "unhook the exact thread-local native creation observer",
            std::io::Error::from_raw_os_error((crate::windows::win32_safe::last_error()) as i32),
        ))
    }
}

fn retain_failed_hook(hook: HHOOK) -> bool {
    if hook.is_null() {
        return true;
    }
    ORPHAN_HOOKS.with(|hooks| {
        if let Ok(mut hooks) = hooks.try_borrow_mut() {
            // `enter` reserves one retention slot for every live frame. A
            // finish/drop replaces one live slot with one orphan slot.
            if hooks.len() < hooks.capacity() {
                hooks.push(hook);
                return true;
            }
        }
        false
    })
}

fn retry_orphan_hooks(state: &Rc<RefCell<WorkerState>>) -> Result<(), RuntimeError> {
    let mut first_error = None;
    ORPHAN_HOOKS.with(|hooks| {
        let Ok(mut hooks) = hooks.try_borrow_mut() else {
            first_error = Some(create_identity_error(
                Kind::InternalInvariant,
                "retry retained CBT hook removal without a conflicting borrow",
            ));
            return;
        };
        let mut index = hooks.len();
        while index != 0 {
            index -= 1;
            match unhook(hooks[index]) {
                Ok(()) => {
                    hooks.swap_remove(index);
                }
                Err(error) if first_error.is_none() => {
                    first_error = Some(error);
                }
                Err(_) => {}
            }
        }
    });
    if let Some(error) = first_error {
        latch_hook_failure(
            state,
            0,
            "remove a retained CBT hook before starting another native creation",
        );
        Err(error)
    } else {
        Ok(())
    }
}

fn latch_hook_failure(state: &Rc<RefCell<WorkerState>>, operation: u64, message: &'static str) {
    let error = RuntimeError::new(Kind::HostFailure, message);
    let latched = if let Ok(mut state) = state.try_borrow_mut() {
        state.callbacks_enabled = false;
        state.aborted = true;
        if state.terminal_failures.try_reserve(1).is_ok() {
            state.terminal_failures.push(Arc::new(error));
            true
        } else {
            false
        }
    } else {
        false
    };
    if !latched {
        EMERGENCY_FAILURE.with(|failure| {
            if failure.get().is_none() {
                failure.set(Some(operation));
            }
        });
    }
}

fn create_identity_error(kind: Kind, message: &'static str) -> RuntimeError {
    RuntimeError::new(kind, message)
}
