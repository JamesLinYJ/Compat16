//! Hidden USER windows; no ShowWindow, keyboard, mouse, or posted commands.
use super::super::win16_window_worker::{
    self as worker, ActiveOperation, NativeDropRetirementQueue, PendingDialogRoute, WindowWorker,
    WorkerCommand,
};
use super::*;
use crate::windows::{guest_text::GuestTextCodec, win16_gdi::Win16Dcs, win16_images::Win16Images};
use runtime::{Win16HostDialogAtom as Atom, Win16HostDialogResult, Win16HostDialogTemplate};
use std::any::Any;
use std::cell::Cell;
use std::ptr;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
    mpsc,
};
use std::time::Duration;
use windows_sys::Win32::UI::Shell::{DefSubclassProc, SetWindowSubclass};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, WM_CREATE, WM_INITDIALOG, WM_PARENTNOTIFY, WS_CHILD, WS_POPUP,
};

thread_local! {
    static PANIC: RefCell<Option<Box<dyn Any + Send>>> = const { RefCell::new(None) };
    static EARLY: Cell<Option<Win16HostWindow>> = const { Cell::new(None) };
    static INIT: Cell<usize> = const { Cell::new(0) };
}
fn run_on_worker(run: fn(&Rc<RefCell<WorkerState>>)) {
    let codec = GuestTextCodec::new(1252).unwrap();
    let mut worker = WindowWorker::spawn(
        Win16Dcs::with_text_codec(codec),
        Win16Images::new(codec),
        Arc::new(AtomicU64::new(1)),
        codec,
        NativeDropRetirementQueue::shared(),
    )
    .unwrap();
    let (response, receive) = mpsc::channel();
    worker
        .send(WorkerCommand::TestWindowData { run, response })
        .unwrap_or_else(|_| panic!("enqueue root test"));
    let result = receive.recv_timeout(Duration::from_secs(20));
    let shutdown = worker.shutdown();
    if let Err(error) = result.expect("bounded hidden root test") {
        std::panic::resume_unwind(error);
    }
    shutdown.expect("join hidden root worker");
}
fn capture(run: impl FnOnce()) {
    if let Err(error) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
        PANIC.with(|slot| {
            *slot.borrow_mut() = Some(error);
        });
    }
}
fn check_panic() {
    if let Some(error) = PANIC.with(|slot| slot.borrow_mut().take()) {
        std::panic::resume_unwind(error);
    }
}
// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn parent_proc(
    hwnd: HWND,
    message: u32,
    w: usize,
    l: isize,
    _id: usize,
    _data: usize,
) -> isize {
    if message == WM_PARENTNOTIFY && w as u16 == WM_CREATE as u16 {
        capture(|| {
            let state = worker::worker_context().unwrap();
            let input = super::super::win16_window_input::decode_parent_notification(&state, w, l)
                .unwrap()
                .unwrap();
            let runtime::Win16HostParentNotificationData::Child { child, .. } = input.data else {
                panic!("child notification")
            };
            let child = child.expect("created child HWND");
            assert_eq!(identity::resolve(&state, child), Some(l as HWND));
            EARLY.with(|slot| {
                if slot.get().is_none() {
                    slot.set(Some(child));
                }
            });
        });
    }
    // SAFETY: DefSubclassProc forwards this subclass message. Pointer parameters stay live for the call.
    unsafe { DefSubclassProc(hwnd, message, w, l) }
}
// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn dialog_proc(hwnd: HWND, message: u32, _w: usize, l: isize) -> isize {
    capture(|| {
        let state = worker::worker_context().unwrap();
        let route =
            super::super::win16_dialog_callbacks::test_dialog_route(&state, hwnd, message, l)
                .unwrap();
        if message == WM_INITDIALOG {
            let route = route.expect("INIT publishes exact dialog route");
            assert_eq!(Some(route.window), EARLY.with(Cell::get));
            assert_eq!(identity::resolve(&state, route.window), Some(hwnd));
            assert_eq!((crate::windows::win32_safe::is_window_visible(hwnd)), 0);
            INIT.with(|count| count.set(count.get() + 1));
        }
    });
    0
}
fn hidden_window() -> HWND {
    let class: Vec<u16> = "STATIC".encode_utf16().chain([0]).collect();
    // SAFETY: CreateWindowExW receives caller-owned class and title strings that stay live for the call. The creation parameter is null or a live record.
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            class.as_ptr(),
            ptr::null(),
            WS_POPUP,
            0,
            0,
            80,
            80,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
        )
    };
    assert!(!hwnd.is_null());
    assert_eq!((crate::windows::win32_safe::is_window_visible(hwnd)), 0);
    hwnd
}
fn push_operation(state: &Rc<RefCell<WorkerState>>) -> (u64, Win16CreationId) {
    static NEXT: AtomicU64 = AtomicU64::new(90000);
    let operation = NEXT.fetch_add(1, Ordering::Relaxed);
    let (response, _) = mpsc::channel();
    state.borrow_mut().active_operations.push(ActiveOperation {
        id: operation,
        native_font: None,
        kind: runtime::Win16NativeWindowOperationKind::UserService,
        response,
        native_queue_dispatch: false,
        native_dialog_pump: false,
    });
    (operation, Win16CreationId(operation))
}
fn child_dialog(state: &Rc<RefCell<WorkerState>>, with_icon: bool) {
    EARLY.with(|slot| slot.set(None));
    INIT.with(|slot| slot.set(0));
    let parent = hidden_window();
    let parent_token = identity::adopt_created_owned(state, parent).unwrap();
    assert_ne!(
        // SAFETY: `SetWindowSubclass`, `Some` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        unsafe { SetWindowSubclass(parent, Some(parent_proc), 0xc160, 0) },
        0
    );
    let images = state.borrow().images.clone();
    let icon = if with_icon {
        images.system_icon(32512).unwrap()
    } else {
        None
    };
    let mut template = Win16HostDialogTemplate {
        style: WS_CHILD,
        x: 0,
        y: 0,
        width: 40,
        height: 40,
        menu: Atom::None,
        menu_template: None,
        class: Atom::None,
        guest_class_name: None,
        title: Atom::None,
        font: None,
        items: Vec::new(),
    };
    if let Some(icon) = icon {
        template.items.push(runtime::Win16HostDialogItem {
            style: WS_CHILD | 3,
            x: 0,
            y: 0,
            width: 16,
            height: 16,
            id: 1,
            class: Atom::Ordinal(0x82),
            guest_class_name: None,
            title: Atom::None,
            initial_icon: Some(icon),
            creation_data: Vec::new(),
        });
    }
    let (operation, creation) = push_operation(state);
    let result = super::super::win16_user_services_dialog::create(
        state,
        operation,
        creation,
        1,
        Some(parent_token),
        template,
        false,
        0,
        Some(dialog_proc),
    );
    state.borrow_mut().active_operations.pop();
    check_panic();
    let Win16HostDialogResult::Created {
        creation: result, ..
    } = result.unwrap()
    else {
        panic!("modeless result")
    };
    let token = result.live_window.expect("live child dialog");
    assert_eq!(Some(token), EARLY.with(Cell::get));
    assert_eq!(INIT.with(Cell::get), 1);
    let hwnd = identity::resolve(state, token).unwrap();
    assert_eq!(
        state
            .borrow()
            .windows_by_native
            .values()
            .filter(|value| value.window == token)
            .count(),
        1
    );
    assert_eq!(
        state.borrow().windows_by_native[&(hwnd as usize)].creation,
        Some(creation)
    );
    assert!(state.borrow().windows_by_native[&(hwnd as usize)].owned);
    assert_ne!((crate::windows::win32_safe::destroy_window(hwnd)), 0);
    worker::remove_window_maps(state, token, hwnd);
    super::super::win16_dialog_icon_controls::retire_after_call(state);
    assert_ne!((crate::windows::win32_safe::destroy_window(parent)), 0);
    worker::remove_window_maps(state, parent_token, parent);
    if let Some(icon) = icon {
        images.release_icon(icon).unwrap();
    }
    check_panic();
    assert!(state.borrow().pending_dialog_routes.is_empty());
    assert!(state.borrow().windows_by_native.is_empty());
}
fn provisional(state: &Rc<RefCell<WorkerState>>, mode: u8) {
    let hwnd = hidden_window();
    let alias = identity::adopt(state, hwnd).unwrap();
    let reserved = worker::allocate_window_token(state).unwrap();
    let (operation, creation) = push_operation(state);
    state
        .borrow_mut()
        .pending_dialog_routes
        .push(PendingDialogRoute {
            operation,
            creation,
            cookie: operation as usize,
            guest_instance: 1,
            init_parameter: 0,
            root_token: reserved,
            owner: ptr::null_mut(),
            root: None,
            root_window: None,
            init_published: false,
            controls: Vec::new(),
            menu: None,
        });
    match mode {
        0 => {
            state
                .borrow_mut()
                .windows_by_native
                .get_mut(&(hwnd as usize))
                .unwrap()
                .owned = true
        }
        1 => {
            state
                .borrow_mut()
                .windows_by_native
                .get_mut(&(hwnd as usize))
                .unwrap()
                .creation = Some(Win16CreationId(operation + 1))
        }
        2 => identity::retire(state, alias, hwnd),
        3 => {
            state
                .borrow_mut()
                .windows_by_native
                .get_mut(&(hwnd as usize))
                .unwrap()
                .class = Some(runtime::Win16HostClass(999))
        }
        4 => {}
        5 => {
            assert_eq!(
                bind_standard_root(state, operation, creation, hwnd).unwrap(),
                alias
            );
            identity::retire(state, alias, hwnd);
        }
        _ => unreachable!(),
    }
    assert!(bind_standard_root(state, operation + u64::from(mode == 4), creation, hwnd).is_err());
    assert_eq!(
        state
            .borrow()
            .pending_dialog_routes
            .last()
            .unwrap()
            .root_token,
        if mode == 5 { alias } else { reserved }
    );
    assert_eq!(
        state.borrow().windows_by_native[&(hwnd as usize)].window,
        alias
    );
    state.borrow_mut().pending_dialog_routes.pop();
    state.borrow_mut().active_operations.pop();
    assert_ne!((crate::windows::win32_safe::destroy_window(hwnd)), 0);
    worker::remove_window_maps(state, alias, hwnd);
}

#[test]
#[ignore = "requires a hidden Windows USER worker"]
fn dialog_root_native_child_parent_notify_preserves_alias() {
    run_on_worker(|state| child_dialog(state, false));
}
#[test]
#[ignore = "requires a hidden Windows USER worker"]
fn dialog_root_native_icon_child_parent_notify_preserves_alias() {
    run_on_worker(|state| child_dialog(state, true));
}
#[test]
#[ignore = "requires a hidden Windows USER worker"]
fn dialog_root_native_rejects_other_ownership_creation_class_and_operation() {
    run_on_worker(|state| {
        for mode in [0, 1, 3, 4] {
            provisional(state, mode);
        }
    });
}
#[test]
#[ignore = "requires a hidden Windows USER worker"]
fn dialog_root_native_rejects_stale_borrowed_and_pinned_cookies() {
    run_on_worker(|state| {
        for mode in [2, 5] {
            provisional(state, mode);
        }
    });
}
