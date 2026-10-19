//! Opt-in hidden USER diagnostic, explicitly invoked by its own CI step.
//! This establishes creation provenance/subclass facts, not icon compatibility.

use std::cell::{Cell, RefCell};
use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CBT_CREATEWNDW, CallNextHookEx, CreateDialogIndirectParamW, GetClassNameW, HCBT_CREATEWND,
    HHOOK, SetWindowsHookExW, WH_CBT, WM_CREATE, WM_INITDIALOG, WM_NCCREATE, WM_NCDESTROY,
    WS_CHILD, WS_POPUP,
};

const CONTROL_ID: u16 = 0xffff;
const ICON_STYLE: u32 = 3;
const SUBCLASS_BASE: usize = 0xC160;
const CALLBACK_PANIC: u32 = 1;
const CALLBACK_STATE: u32 = 2;
const PAYLOAD_MISMATCH: u32 = 4;
const SUBCLASS_FAILURE: u32 = 8;
const CLEANUP_FAILURE: u32 = 16;
const EVENT_OVERFLOW: u32 = 32;

#[derive(Clone, Copy, Debug)]
struct Expected {
    size_pointer: usize,
    data_pointer: usize,
    cookie: [u8; 16],
}

#[derive(Clone, Copy, Debug)]
struct Observed {
    hwnd: HWND,
    parent: HWND,
    payload_form: u8,
    native_id: usize,
    subclass_error: u32,
    installed: bool,
    nccreate: u32,
    create: u32,
    create_result: Option<LRESULT>,
    ncdestroy: u32,
    removed: bool,
}

impl Observed {
    const EMPTY: Self = Self {
        hwnd: ptr::null_mut(),
        parent: ptr::null_mut(),
        payload_form: 0,
        native_id: 0,
        subclass_error: 0,
        installed: false,
        nccreate: 0,
        create: 0,
        create_result: None,
        ncdestroy: 0,
        removed: false,
    };
}

#[derive(Clone, Copy, Debug)]
struct PayloadObservation {
    hwnd: HWND,
    pointer: usize,
    size_and_cookie: Option<[u8; 18]>,
    cookie_only: Option<[u8; 16]>,
}

#[derive(Debug)]
struct Probe {
    expected: [Expected; 2],
    observed: [Observed; 2],
    thread: u32,
    root: HWND,
    initialized: bool,
    payloads: [Option<PayloadObservation>; 4],
    payload_count: usize,
    events: Vec<(usize, u32, bool)>,
}

thread_local! {
    static PROBE: RefCell<Option<Probe>> = const { RefCell::new(None) };
    static FAILURES: Cell<u32> = const { Cell::new(0) };
}

fn fail(flag: u32) {
    FAILURES.with(|flags| flags.set(flags.get() | flag));
}

fn record(index: usize, message: u32, returned: bool, native: LRESULT) {
    PROBE.with(|cell| {
        let Ok(mut state) = cell.try_borrow_mut() else {
            fail(CALLBACK_STATE);
            return;
        };
        let Some(state) = state.as_mut() else {
            fail(CALLBACK_STATE);
            return;
        };
        if index >= state.observed.len() {
            fail(CALLBACK_STATE);
            return;
        }
        if state.events.len() == state.events.capacity() {
            fail(EVENT_OVERFLOW);
            return;
        }
        state.events.push((index, message, returned));
        let observed = &mut state.observed[index];
        match (message, returned) {
            (WM_NCCREATE, false) => observed.nccreate += 1,
            (WM_CREATE, false) => observed.create += 1,
            (WM_CREATE, true) => observed.create_result = Some(native),
            (WM_NCDESTROY, false) => observed.ncdestroy += 1,
            _ => {}
        }
    });
}

fn read_bytes<const N: usize>(pointer: usize) -> Option<[u8; N]> {
    if pointer <= 0xffff {
        return None;
    }
    let mut bytes = [0; N];
    let mut copied = 0;
    // The native callback supplies the pointer. A bounded process read avoids
    // dereferencing a nested pointer or assuming USER's alignment/layout.
    // SAFETY: ReadProcessMemory copies from a checked address inside the owned reservation into an independent buffer.
    let ok = unsafe {
        ReadProcessMemory(
            crate::windows::win32_safe::current_process(),
            pointer as *const c_void,
            bytes.as_mut_ptr().cast(),
            N,
            &mut copied,
        )
    };
    (ok != 0 && copied == N).then_some(bytes)
}

fn observe_creation(hwnd: HWND, parameter: LPARAM) {
    if hwnd.is_null() || parameter == 0 {
        return;
    }
    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
    let cbt = unsafe { &*(parameter as *const CBT_CREATEWNDW) };
    if cbt.lpcs.is_null() {
        fail(CALLBACK_STATE);
        return;
    }
    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
    let create = unsafe { &*cbt.lpcs };
    let mut class = [0u16; 32];
    // SAFETY: GetClassNameW writes into a caller-owned UTF-16 buffer of the capacity passed with it.
    let length = unsafe { GetClassNameW(hwnd, class.as_mut_ptr(), class.len() as i32) };
    let expected_class = [83u16, 116, 97, 116, 105, 99]; // Static, case-insensitive
    if length != 6
        || !class[..6].iter().zip(expected_class).all(|(a, b)| {
            let fold = |unit: u16| {
                if (65..=90).contains(&unit) {
                    unit + 32
                } else {
                    unit
                }
            };
            fold(*a) == fold(b)
        })
    {
        return;
    }
    let native_id = create.hMenu as usize;
    // IDC_STATIC may reach native CREATESTRUCT as a WORD or sign-extended -1.
    if (native_id != usize::from(CONTROL_ID) && native_id != usize::MAX)
        || (create.style as u32 & 0x1f) != ICON_STYLE
    {
        fail(PAYLOAD_MISMATCH);
        return;
    }
    let pointer = create.lpCreateParams as usize;
    let snapshot = PROBE.with(|cell| {
        let Ok(state) = cell.try_borrow() else {
            fail(CALLBACK_STATE);
            return None;
        };
        let state = state.as_ref()?;
        Some((state.thread, state.expected))
    });
    let Some((thread, expected_items)) = snapshot else {
        fail(CALLBACK_STATE);
        return;
    };
    if thread != (crate::windows::win32_safe::current_thread_id()) {
        fail(CALLBACK_STATE);
        return;
    }
    // USER may copy the creation-data block. Keep bounded evidence even when
    // neither address nor contents match, without reading during a state borrow.
    let payload = PayloadObservation {
        hwnd,
        pointer,
        size_and_cookie: read_bytes::<18>(pointer),
        cookie_only: read_bytes::<16>(pointer),
    };
    PROBE.with(|cell| {
        let Ok(mut state) = cell.try_borrow_mut() else {
            fail(CALLBACK_STATE);
            return;
        };
        let Some(state) = state.as_mut() else {
            fail(CALLBACK_STATE);
            return;
        };
        if state.payload_count == state.payloads.len() {
            fail(EVENT_OVERFLOW);
            return;
        }
        let index = state.payload_count;
        state.payloads[index] = Some(payload);
        state.payload_count += 1;
    });
    let original_address = expected_items
        .iter()
        .any(|expected| pointer == expected.size_pointer || pointer == expected.data_pointer);
    let mut matched = None;
    for (index, expected) in expected_items.iter().enumerate() {
        let size_matches = payload.size_and_cookie.is_some_and(|bytes| {
            u16::from_le_bytes([bytes[0], bytes[1]]) == 18 && bytes[2..] == expected.cookie
        });
        let data_matches = payload.cookie_only == Some(expected.cookie);
        let form = if size_matches && pointer == expected.size_pointer {
            Some(1)
        } else if data_matches && pointer == expected.data_pointer {
            Some(2)
        } else if size_matches && !original_address {
            Some(3)
        } else if data_matches && !original_address {
            Some(4)
        } else {
            None
        };
        if let Some(form) = form {
            if matched.is_some() {
                fail(PAYLOAD_MISMATCH);
                return;
            }
            matched = Some((index, form));
        }
    }
    let Some((index, form)) = matched else {
        fail(PAYLOAD_MISMATCH);
        return;
    };
    let claimed = PROBE.with(|cell| {
        let Ok(mut state) = cell.try_borrow_mut() else {
            return false;
        };
        let Some(state) = state.as_mut() else {
            return false;
        };
        let observed = &mut state.observed[index];
        if !observed.hwnd.is_null() {
            return false;
        }
        observed.hwnd = hwnd;
        observed.parent = create.hwndParent;
        observed.payload_form = form;
        observed.native_id = native_id;
        true
    });
    if !claimed {
        fail(CALLBACK_STATE);
        return;
    }
    // No state borrow crosses USER. This is the precise pre-NCCREATE operation
    // being measured, on the same thread as CreateDialogIndirectParamW.
    (crate::windows::win32_safe::set_last_error(0));
    // SAFETY: `SetWindowSubclass`, `Some` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    let installed =
        unsafe { SetWindowSubclass(hwnd, Some(subclass), SUBCLASS_BASE + index, 0) } != 0;
    let subclass_error = crate::windows::win32_safe::last_error();
    PROBE.with(|cell| {
        if let Ok(mut state) = cell.try_borrow_mut() {
            if let Some(state) = state.as_mut() {
                state.observed[index].installed = installed;
                state.observed[index].subclass_error = subclass_error;
            }
        } else {
            fail(CALLBACK_STATE);
        }
    });
    if !installed {
        fail(SUBCLASS_FAILURE);
    }
}

// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn hook(code: i32, window: WPARAM, parameter: LPARAM) -> LRESULT {
    if code == HCBT_CREATEWND as i32 {
        if catch_unwind(AssertUnwindSafe(|| {
            observe_creation(window as HWND, parameter)
        }))
        .is_err()
        {
            fail(CALLBACK_PANIC);
        }
    }
    // Preserve the hook chain even on an unsupported fact or contained panic.
    // SAFETY: CallNextHookEx forwards the hook arguments Windows passed into this callback.
    unsafe { CallNextHookEx(ptr::null_mut(), code, window, parameter) }
}

// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn subclass(
    hwnd: HWND,
    message: u32,
    w_param: WPARAM,
    l_param: LPARAM,
    subclass_id: usize,
    _reference: usize,
) -> LRESULT {
    let forwarded = Cell::new(None);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let index = subclass_id
            .checked_sub(SUBCLASS_BASE)
            .filter(|index| *index < 2);
        if let Some(index) = index {
            if matches!(message, WM_NCCREATE | WM_CREATE | WM_NCDESTROY) {
                record(index, message, false, 0);
            }
            if message == WM_NCDESTROY {
                // SAFETY: `RemoveWindowSubclass`, `Some` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
                let removed =
                    unsafe { RemoveWindowSubclass(hwnd, Some(subclass), subclass_id) } != 0;
                PROBE.with(|cell| {
                    if let Ok(mut state) = cell.try_borrow_mut() {
                        if let Some(state) = state.as_mut() {
                            state.observed[index].removed = removed;
                        }
                    } else {
                        fail(CALLBACK_STATE);
                    }
                });
                if !removed {
                    fail(CLEANUP_FAILURE);
                }
            }
        } else {
            fail(CALLBACK_STATE);
        }
        // SAFETY: DefSubclassProc forwards this subclass message. Pointer parameters stay live for the call.
        let native = unsafe { DefSubclassProc(hwnd, message, w_param, l_param) };
        forwarded.set(Some(native));
        if let Some(index) = index {
            if matches!(message, WM_NCCREATE | WM_CREATE | WM_NCDESTROY) {
                record(index, message, true, native);
            }
        }
        native
    }));
    match result {
        Ok(native) => native,
        Err(_) => {
            fail(CALLBACK_PANIC);
            // SAFETY: DefSubclassProc forwards this subclass message. Pointer parameters stay live for the call.
            forwarded
                .get()
                .unwrap_or_else(|| unsafe { DefSubclassProc(hwnd, message, w_param, l_param) })
        }
    }
}

// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn dialog(hwnd: HWND, message: u32, _w: WPARAM, _l: LPARAM) -> isize {
    if catch_unwind(AssertUnwindSafe(|| {
        if message == WM_INITDIALOG {
            PROBE.with(|cell| {
                if let Ok(mut state) = cell.try_borrow_mut() {
                    if let Some(state) = state.as_mut() {
                        state.root = hwnd;
                        state.initialized = true;
                    }
                } else {
                    fail(CALLBACK_STATE);
                }
            });
        }
    }))
    .is_err()
    {
        fail(CALLBACK_PANIC);
    }
    0 // Do not request focus assignment.
}

struct NativeCleanup {
    hook: HHOOK,
    dialog: HWND,
}

impl NativeCleanup {
    fn cleanup(&mut self) {
        if !self.dialog.is_null() {
            let destroyed = (crate::windows::win32_safe::destroy_window(self.dialog)) != 0;
            if !destroyed || { crate::windows::win32_safe::is_window(self.dialog) } != 0 {
                fail(CLEANUP_FAILURE);
            } else {
                self.dialog = ptr::null_mut();
            }
        }
        if !self.hook.is_null() {
            if (crate::windows::win32_safe::unhook_windows_hook(self.hook)) != 0 {
                self.hook = ptr::null_mut();
            } else {
                fail(CLEANUP_FAILURE);
            }
        }
    }
}

impl Drop for NativeCleanup {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn template() -> (Vec<u32>, [(usize, usize, [u8; 16]); 2]) {
    fn word(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn dword(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    let mut bytes = Vec::new();
    dword(&mut bytes, WS_POPUP); // Deliberately no WS_VISIBLE, caption, or modal style.
    dword(&mut bytes, 0);
    word(&mut bytes, 2);
    for value in [0, 0, 40, 20, 0, 0, 0] {
        word(&mut bytes, value);
    }
    let mut offsets = [(0, 0, [0; 16]); 2];
    for (index, offset) in offsets.iter_mut().enumerate() {
        while bytes.len() % 4 != 0 {
            bytes.push(0);
        }
        dword(&mut bytes, WS_CHILD | ICON_STYLE); // Child also remains hidden.
        dword(&mut bytes, 0);
        for value in [0, 0, 8, 8, CONTROL_ID, 0xffff, 0x0082, 0] {
            word(&mut bytes, value);
        }
        let size = bytes.len();
        word(&mut bytes, 18);
        let data = bytes.len();
        let mut cookie = *b"Compat16Probe000";
        cookie[15] = b'0' + index as u8;
        bytes.extend_from_slice(&cookie);
        *offset = (size, data, cookie);
    }
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
    let words = bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect();
    (words, offsets)
}

#[test]
#[ignore = "hidden USER diagnostic; dedicated CI step supplies timeout and explicit invocation"]
fn hidden_static_payload_and_precreate_subclass() {
    let (words, offsets) = template();
    let base = words.as_ptr() as usize;
    FAILURES.with(|flags| flags.set(0));
    let expected = offsets.map(|(size, data, cookie)| Expected {
        size_pointer: base + size,
        data_pointer: base + data,
        cookie,
    });
    PROBE.with(|cell| {
        assert!(cell.borrow().is_none(), "probe state already active");
        *cell.borrow_mut() = Some(Probe {
            expected,
            observed: [Observed::EMPTY; 2],
            thread: (crate::windows::win32_safe::current_thread_id()),
            root: ptr::null_mut(),
            initialized: false,
            payloads: [None; 4],
            payload_count: 0,
            events: Vec::with_capacity(32),
        });
    });
    let mut cleanup = NativeCleanup {
        hook: ptr::null_mut(),
        dialog: ptr::null_mut(),
    };
    (crate::windows::win32_safe::set_last_error(0));
    // SAFETY: `SetWindowsHookExW`, `Some` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    cleanup.hook = unsafe {
        SetWindowsHookExW(
            WH_CBT,
            Some(hook),
            ptr::null_mut(),
            crate::windows::win32_safe::current_thread_id(),
        )
    };
    let hook_error = crate::windows::win32_safe::last_error();
    if !cleanup.hook.is_null() {
        (crate::windows::win32_safe::set_last_error(0));
        // SAFETY: `CreateDialogIndirectParamW`, `Some` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        cleanup.dialog = unsafe {
            CreateDialogIndirectParamW(
                crate::windows::win32_safe::current_module(),
                words.as_ptr().cast(),
                ptr::null_mut(),
                Some(dialog),
                0,
            )
        };
    }
    let create_error = crate::windows::win32_safe::last_error();
    let created = !cleanup.dialog.is_null();
    let hidden = created && (crate::windows::win32_safe::is_window_visible(cleanup.dialog)) == 0;
    let children = PROBE.with(|cell| {
        cell.borrow()
            .as_ref()
            .unwrap()
            .observed
            .map(|item| item.hwnd)
    });
    let children_observed = children.iter().all(|hwnd| !hwnd.is_null());
    let children_hidden = children
        .iter()
        .filter(|hwnd| !hwnd.is_null())
        // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
        .all(|hwnd| { crate::windows::win32_safe::is_window_visible(*hwnd) } == 0);
    cleanup.cleanup();
    let cleaned = cleanup.dialog.is_null() && cleanup.hook.is_null();
    // Drop retries any failed cleanup while callback state is still available.
    drop(cleanup);
    let state = PROBE.with(|cell| cell.borrow_mut().take().unwrap());
    let failures = FAILURES.with(Cell::get);
    eprintln!(
        "STATIC creation probe: created={created}, hidden={hidden}, children_observed={children_observed}, children_hidden={children_hidden}, cleaned={cleaned}, hook_error={hook_error}, create_error={create_error}, failures={failures:#x}\n{state:#?}"
    );
    for payload in state.payloads.iter().flatten() {
        eprintln!(
            "STATIC payload: hwnd={:?}, pointer={:#x}, size+cookie={:?}, cookie-only={:?}",
            payload.hwnd, payload.pointer, payload.size_and_cookie, payload.cookie_only
        );
    }
    eprintln!(
        "payload forms: 1=original size-word, 2=original data, 3=copied size-word, 4=copied data"
    );
    assert!(
        created,
        "UNSUPPORTED/FAILED: hidden dialog creation; see native errors above"
    );
    assert!(
        hidden && children_hidden,
        "FAILED: probe unexpectedly created a visible window"
    );
    assert!(
        cleaned && failures == 0,
        "UNSUPPORTED/FAILED: callback or native cleanup contract"
    );
    assert!(
        children_observed,
        "UNSUPPORTED/FAILED: not all intended STATIC children were identified"
    );
    assert!(state.initialized);
    assert_ne!(state.observed[0].hwnd, state.observed[1].hwnd);
    for index in 0..2 {
        let phases = [
            (WM_NCCREATE, false),
            (WM_NCCREATE, true),
            (WM_CREATE, false),
            (WM_CREATE, true),
        ];
        let positions = phases.map(|(message, returned)| {
            state
                .events
                .iter()
                .position(|event| *event == (index, message, returned))
        });
        assert!(
            positions.windows(2).all(|pair| {
                matches!((pair[0], pair[1]), (Some(before), Some(after)) if before < after)
            }),
            "FAILED: native NCCREATE/CREATE entry and return order differs"
        );
    }
    for observed in state.observed {
        assert_eq!(observed.parent, state.root);
        assert!((1..=4).contains(&observed.payload_form));
        assert!(observed.installed && observed.removed);
        assert_eq!(observed.nccreate, 1);
        assert_eq!(observed.create, 1);
        assert_eq!(observed.create_result, Some(0));
        assert_eq!(observed.ncdestroy, 1);
        assert_eq!((crate::windows::win32_safe::is_window(observed.hwnd)), 0);
    }
}
