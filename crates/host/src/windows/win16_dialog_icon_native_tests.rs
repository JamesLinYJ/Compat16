//! Explicit hidden native integration gates; never invoke ShowWindow or input.
use super::*;
use std::any::Any;
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;
use windows_sys::Win32::UI::WindowsAndMessaging::{IsWindowVisible, SendMessageW, WM_INITDIALOG, WM_NCDESTROY};
use crate::windows::{guest_text::GuestTextCodec, win16_gdi::Win16Dcs, win16_images::Win16Images};
use super::super::win16_window_worker::{ActiveOperation, NativeDropRetirementQueue, WindowWorker, WorkerCommand};

thread_local! {
    static PANIC: RefCell<Option<Box<dyn Any + Send>>> = const { RefCell::new(None) };
    static INITIALIZED: Cell<usize> = const { Cell::new(0) };
    static NEST: Cell<bool> = const { Cell::new(false) };
    static MODE: Cell<u8> = const { Cell::new(0) };
    static OBSERVED: Cell<usize> = const { Cell::new(0) };
    static FIRST_CHILD: Cell<usize> = const { Cell::new(0) };
    static REPLACEMENT: Cell<usize> = const { Cell::new(0) };
    static REPLACED: Cell<bool> = const { Cell::new(false) };
    static INJECTED_PANIC: Cell<bool> = const { Cell::new(false) };
    static FAILURE_OWNERS: RefCell<Vec<std::sync::Weak<DialogIconOwner>>> = const { RefCell::new(Vec::new()) };
    static HOOK_FAILED: Cell<bool> = const { Cell::new(false) };
}
fn run_on_worker(run: fn(&Rc<RefCell<WorkerState>>)) {
    let codec = GuestTextCodec::new(1252).unwrap();
    let mut worker = WindowWorker::spawn(Win16Dcs::with_text_codec(codec), Win16Images::new(codec),
        Arc::new(AtomicU64::new(1)), codec, NativeDropRetirementQueue::shared()).unwrap();
    let (response, receive) = mpsc::channel();
    worker.send(WorkerCommand::TestWindowData { run, response }).unwrap_or_else(|_| panic!("enqueue hidden icon test"));
    let result = receive.recv_timeout(Duration::from_secs(20));
    let shutdown = worker.shutdown();
    let result = result.expect("hidden icon test bounded response");
    if let Err(error) = result { std::panic::resume_unwind(error); }
    shutdown.expect("join hidden icon worker");
}
unsafe extern "system" fn dialog_proc(hwnd: HWND, message: u32, _w: usize, l: isize) -> isize {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let state = worker::worker_context().unwrap();
        if message == WM_INITDIALOG {
            assert_eq!(unsafe { IsWindowVisible(hwnd) }, 0);
            if NEST.with(|nest| nest.replace(false)) { exercise(&state, true, 0); }
            if MODE.with(Cell::get) == 3 { return; }
            if matches!(MODE.with(Cell::get), 7 | 8) {
                let state = state.borrow();
                let operation = state.active_operations.last().unwrap().id;
                let owners = state.dialog_icon_sidecars.iter().filter(|sidecar| sidecar.operation == operation)
                    .map(|sidecar| Arc::downgrade(&sidecar.owner)).collect::<Vec<_>>();
                assert_eq!(owners.len(), 2);
                FAILURE_OWNERS.with(|slot| *slot.borrow_mut() = owners);
                if MODE.with(Cell::get) == 7 {
                    assert!(INJECTED_PANIC.with(Cell::get));
                    assert!(observer::test_panicked());
                    assert!(state.dialog_icon_sidecars.iter().filter(|sidecar| sidecar.operation == operation)
                        .all(|sidecar| sidecar.phase == Phase::Ready));
                    assert!(!state.pending_dialog_routes.iter().find(|pending| pending.operation == operation)
                        .unwrap().init_published);
                }
            }
        }
        let route = super::super::win16_dialog_callbacks::test_dialog_route(&state, hwnd, message, l);
        if message == WM_INITDIALOG && matches!(MODE.with(Cell::get), 4 | 7) {
            assert!(route.is_err(), "destroyed child or caught callback panic must block INIT");
            if MODE.with(Cell::get) == 7 {
                assert!(state.borrow().pending_dialog_routes.iter().all(|pending| !pending.init_published));
            }
            return;
        }
        let route = route.unwrap();
        if message == WM_INITDIALOG {
            let route = route.expect("INIT publishes reserved root route");
            let snapshots = {
                let state = state.borrow();
                state.dialog_icon_sidecars.iter().filter(|sidecar| sidecar.creation == route.creation)
                    .map(|sidecar| (sidecar.window, sidecar.hwnd.unwrap(), Arc::clone(&sidecar.owner))).collect::<Vec<_>>()
            };
            assert_eq!(snapshots.len(), 2);
            assert_ne!(snapshots[0].0, snapshots[1].0);
            assert_ne!(snapshots[0].1, snapshots[1].1);
            for (_, child, owner) in snapshots {
                assert_eq!(unsafe { IsWindowVisible(child as HWND) }, 0);
                assert_eq!(unsafe { SendMessageW(child as HWND, 0x0171, 0, 0) }, expected_icon(child, owner.native() as isize));
            }
            INITIALIZED.with(|count| count.set(count.get() + 1));
            if observer::active_contract(route.operation, route.creation).unwrap().1 {
                assert_ne!(unsafe { EndDialog(hwnd, 17) }, 0);
            }
        } else if state.borrow().pending_dialog_routes.iter().any(|pending|
            pending.root_window == Some(hwnd as usize) && !pending.init_published)
        {
            assert!(route.is_none(), "pre-INIT identity must not expose a guest DLGPROC route");
        }
    }));
    if let Err(panic) = result {
        PANIC.with(|slot| { if slot.borrow().is_none() { *slot.borrow_mut() = Some(panic); } });
        if message == WM_INITDIALOG { unsafe { EndDialog(hwnd, -1); DestroyWindow(hwnd); } }
    }
    0
}
fn exercise(state: &Rc<RefCell<WorkerState>>, modal: bool, mode: u8) {
    MODE.with(|slot| slot.set(mode));
    OBSERVED.with(|slot| slot.set(0));
    FIRST_CHILD.with(|slot| slot.set(0));
    REPLACED.with(|slot| slot.set(false));
    HOOK_FAILED.with(|slot| slot.set(false));
    INJECTED_PANIC.with(|slot| slot.set(false));
    FAILURE_OWNERS.with(|slot| slot.borrow_mut().clear());
    let initializations_before = INITIALIZED.with(Cell::get);
    static NEXT: AtomicU64 = AtomicU64::new(10000);
    let operation = NEXT.fetch_add(1, Ordering::Relaxed);
    let creation = Win16CreationId(operation);
    let images = state.borrow().images.clone();
    let shared = images.system_icon(32512).unwrap().unwrap();
    let shared_lease = images.lease_icon(shared).unwrap().unwrap();
    let first = images.retain_acm_icon(shared_lease.native()).unwrap().unwrap();
    let second = images.retain_acm_icon(shared_lease.native()).unwrap().unwrap();
    images.release_icon(shared).unwrap();
    drop(shared_lease);
    let mut template = tests::template();
    template.items[0].initial_icon = Some(first);
    template.items.push(template.items[0].clone());
    template.items[1].initial_icon = Some(second);
    template.items[1].x = 20;
    let replacement = images.system_icon(32515).unwrap().unwrap();
    let replacement_lease = images.lease_icon(replacement).unwrap().unwrap();
    REPLACEMENT.with(|slot| slot.set(if matches!(mode, 5 | 6) { 0 } else { replacement_lease.native() as usize }));
    let hook = TestHook::enter(mode);
    let (response, _receive) = mpsc::channel();
    state.borrow_mut().active_operations.push(ActiveOperation { id: operation,
        native_font: None, kind: runtime::Win16NativeWindowOperationKind::UserService,
        response, native_queue_dispatch: false, native_dialog_pump: modal });
    let result = super::super::win16_user_services_dialog::create(state, operation, creation,
        1, None, template, modal, 0, Some(dialog_proc));
    state.borrow_mut().active_operations.pop();
    drop(hook);
    images.release_icon(replacement).unwrap();
    drop(replacement_lease);
    assert!(!HOOK_FAILED.with(Cell::get));
    if matches!(mode, 2 | 3 | 4 | 7 | 8) {
        if mode == 2 {
            assert!(result.is_err() || matches!(result, Ok(runtime::Win16HostDialogResult::Created { creation, .. }) if creation.live_window.is_none()));
        } else { assert!(result.is_err(), "incomplete INIT or failed observer cleanup must fail closed"); }
        if mode == 7 {
            assert!(INJECTED_PANIC.with(Cell::get));
            assert_eq!(INITIALIZED.with(Cell::get), initializations_before,
                "caught callback panic must publish zero INIT routes");
        }
        if mode == 8 {
            assert_eq!(INITIALIZED.with(Cell::get), initializations_before + 1,
                "failed unhook is injected after successful native initialization");
        }
        images.release_icon(first).unwrap(); images.release_icon(second).unwrap();
        retire_after_call(state);
        assert!(!state.borrow().dialog_icon_sidecars.iter().any(|sidecar| sidecar.operation == operation));
        assert!(!state.borrow().windows_by_native.values().any(|identity| identity.creation == Some(creation)));
        if matches!(mode, 7 | 8) {
            FAILURE_OWNERS.with(|slot| {
                assert_eq!(slot.borrow().len(), 2);
                assert!(slot.borrow().iter().all(|owner| owner.upgrade().is_none()),
                    "failed creation must release both process-retained owner records");
            });
        }
        if let Some(panic) = PANIC.with(|slot| slot.borrow_mut().take()) { std::panic::resume_unwind(panic); }
        return;
    }
    let result = result.expect("create exact template icon dialog");
    if let runtime::Win16HostDialogResult::Created { creation, .. } = result {
        let root = creation.live_window.expect("modeless live root");
        let hwnd = super::super::win16_window_identity::resolve(state, root).unwrap();
        let snapshots = {
            let state = state.borrow();
            state.dialog_icon_sidecars.iter().filter(|sidecar| sidecar.operation == operation)
                .map(|sidecar| (sidecar.window, sidecar.hwnd.unwrap(), Arc::downgrade(&sidecar.owner))).collect::<Vec<_>>()
        };
        // Release guest/table references while STATIC still uses the images.
        images.release_icon(first).unwrap();
        images.release_icon(second).unwrap();
        for (_, child, owner) in &snapshots {
            let owner = owner.upgrade().expect("live control retains image owner");
            let returned = unsafe { SendMessageW(*child as HWND, 0x0171, 0, 0) };
            assert_eq!(returned, expected_icon(*child, owner.native() as isize));
            let recovered = images.adopt_borrowed_icon(returned as _).unwrap();
            if let Some(recovered) = recovered {
                assert_ne!(recovered, first);
                assert_ne!(recovered, second);
                images.release_icon(recovered).unwrap();
            } else { assert!(matches!(mode, 5 | 6)); }
            // Synthetic NCDESTROY cannot free a still-live STATIC's image.
            unsafe { SendMessageW(*child as HWND, WM_NCDESTROY, 0, 0); }
        }
        retire_after_call(state);
        for (_, _, owner) in &snapshots { assert!(owner.upgrade().is_some()); }
        assert_ne!(unsafe { DestroyWindow(hwnd) }, 0);
        worker::remove_window_maps(state, root, hwnd);
        retire_after_call(state);
        for (token, child, owner) in snapshots {
            assert!(owner.upgrade().is_none());
            assert!(!state.borrow().windows.contains_key(&token));
            assert!(!state.borrow().windows_by_native.contains_key(&child));
        }
    } else {
        assert!(matches!(result, runtime::Win16HostDialogResult::ModalResult(Some(17))));
        images.release_icon(first).unwrap(); images.release_icon(second).unwrap();
        retire_after_call(state);
    }
    assert!(!state.borrow().dialog_icon_sidecars.iter().any(|sidecar| sidecar.operation == operation));
    if let Some(panic) = PANIC.with(|slot| slot.borrow_mut().take()) { std::panic::resume_unwind(panic); }
}
#[test]
#[ignore = "hidden USER integration; dedicated CI invocation provides timeout"]
fn hidden_dialog_icons_cover_duplicates_retention_and_nested_scopes() {
    run_on_worker(|state| {
        INITIALIZED.with(|count| count.set(0));
        exercise(state, false, 0);
        exercise(state, false, 1);
        assert!(REPLACED.with(Cell::get));
        exercise(state, false, 5);
        exercise(state, false, 6);
        exercise(state, false, 2);
        exercise(state, false, 3);
        exercise(state, false, 4);
        NEST.with(|nest| nest.set(true));
        exercise(state, true, 0);
        assert_eq!(INITIALIZED.with(Cell::get), 6);
        exercise(state, false, 7);
        assert_eq!(INITIALIZED.with(Cell::get), 6);
        let cleanup = OrphanHookCleanup;
        observer::test_fail_unhooks(2);
        exercise(state, false, 8);
        assert_eq!(observer::test_hook_state(), (1, 1, 0, 1, 0));
        exercise(state, false, 0);
        let duplicate_state = observer::test_hook_state();
        assert_eq!((duplicate_state.0, duplicate_state.1, duplicate_state.2, duplicate_state.3), (0, 2, 1, 1));
        assert!(duplicate_state.4 >= 2, "retained live hook must observe both exact STATIC creations again");
        exercise(state, false, 0);
        let recovered = observer::test_hook_state();
        assert_eq!((recovered.0, recovered.1, recovered.2, recovered.3), (0, 2, 3, 0));
        assert_eq!(recovered.4, duplicate_state.4);
        assert!(observer::test_cleanup_hooks(), "all orphan hooks must be removed by the native API");
        drop(cleanup);
        assert_eq!(INITIALIZED.with(Cell::get), 9);
        eprintln!("hidden icon failure injection: real callback borrow panic blocked INIT; two injected removals retained a live hook; duplicate observations={}; actual successful removals={}; orphan hooks={}", recovered.4, recovered.2, recovered.3);
        assert!(state.borrow().dialog_icon_sidecars.is_empty());
        assert!(state.borrow().pending_dialog_routes.is_empty());
        eprintln!("hidden dialog icons: nine INIT routes; duplicate identities, released-token recovery, synthetic NCDESTROY retention, replacement during SET, veto rollback, missing INIT receipt, destroyed-child rejection, nested modal scopes and cleanup verified");
    });
}

fn expected_icon(child: usize, initial: isize) -> isize {
    if matches!(MODE.with(Cell::get), 1 | 5 | 6) && FIRST_CHILD.with(Cell::get) == child && REPLACED.with(Cell::get) {
        REPLACEMENT.with(Cell::get) as isize
    } else { initial }
}
struct TestHook(windows_sys::Win32::UI::WindowsAndMessaging::HHOOK);
impl TestHook {
    fn enter(mode: u8) -> Self {
        use windows_sys::Win32::UI::WindowsAndMessaging::{SetWindowsHookExW, WH_CBT};
        if !matches!(mode, 1 | 2 | 4 | 5 | 6 | 7) { return Self(std::ptr::null_mut()); }
        let hook = unsafe { SetWindowsHookExW(WH_CBT, Some(test_hook), std::ptr::null_mut(),
            windows_sys::Win32::System::Threading::GetCurrentThreadId()) };
        assert!(!hook.is_null()); Self(hook)
    }
}
impl Drop for TestHook {
    fn drop(&mut self) {
        if !self.0.is_null() && unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::UnhookWindowsHookEx(self.0)
        } == 0 { HOOK_FAILED.with(|failed| failed.set(true)); }
    }
}
unsafe extern "system" fn test_hook(code: i32, w: usize, l: isize) -> isize {
    use windows_sys::Win32::UI::WindowsAndMessaging::{CallNextHookEx, HCBT_CREATEWND};
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if code != HCBT_CREATEWND as i32 { return false; }
        let Some(state) = worker::worker_context() else { return false; };
        let ours = state.borrow().dialog_icon_sidecars.iter().any(|sidecar|
            sidecar.hwnd == Some(w) && sidecar.phase == Phase::Bound);
        if !ours { return false; }
        let count = OBSERVED.with(|count| { let next = count.get() + 1; count.set(next); next });
        if count == 1 { FIRST_CHILD.with(|child| child.set(w)); }
        match MODE.with(Cell::get) {
            1 | 5 | 6 | 7 if count == 1 => {
                if unsafe { windows_sys::Win32::UI::Shell::SetWindowSubclass(
                    w as HWND, Some(replace_proc), 0xD1A6, 0) } == 0
                { HOOK_FAILED.with(|failed| failed.set(true)); }
            }
            2 if count == 2 => return true,
            4 if count == 2 => {
                if unsafe { DestroyWindow(FIRST_CHILD.with(Cell::get) as HWND) } == 0 {
                    HOOK_FAILED.with(|failed| failed.set(true));
                }
            }
            _ => {}
        }
        false
    }));
    let veto = match result { Ok(veto) => veto, Err(panic) => {
        PANIC.with(|slot| *slot.borrow_mut() = Some(panic)); true
    } };
    let next = unsafe { CallNextHookEx(std::ptr::null_mut(), code, w, l) };
    if veto && next == 0 { 1 } else { next }
}
unsafe extern "system" fn replace_proc(hwnd: HWND, message: u32, w: usize, l: isize,
    id: usize, _data: usize) -> isize
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| replace_message(hwnd, message, w, l, id))) {
        Ok(result) => result,
        Err(panic) => { PANIC.with(|slot| *slot.borrow_mut() = Some(panic)); 0 }
    }
}
fn replace_message(hwnd: HWND, message: u32, w: usize, l: isize, id: usize) -> isize {
    use windows_sys::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass};
    if message == WM_NCDESTROY { unsafe { RemoveWindowSubclass(hwnd, Some(replace_proc), id); } }
    if MODE.with(Cell::get) == 5 && message == 0x0171 && !REPLACED.with(|replaced| replaced.replace(true)) {
        unsafe { SendMessageW(hwnd, 0x0170, 0, 0); }
    }
    if MODE.with(Cell::get) == 7 && message == 0x0171 && !INJECTED_PANIC.with(|flag| flag.replace(true)) {
        // Both the production dispatch and its panic recovery will encounter
        // this real conflicting borrow. Only the independent latch can reject
        // INIT after subsequent normal installation reaches Ready.
        let state = worker::worker_context().expect("test subclass owns its worker");
        let _conflict = state.borrow_mut();
        return unsafe { DefSubclassProc(hwnd, message, w, l) };
    }
    let result = unsafe { DefSubclassProc(hwnd, message, w, l) };
    if matches!(MODE.with(Cell::get), 1 | 6) && message == 0x0170 && !REPLACED.with(|replaced| replaced.replace(true)) {
        unsafe { SendMessageW(hwnd, 0x0170, REPLACEMENT.with(Cell::get), 0); }
    }
    result
}

// If an assertion fails between the injected removal and the final retry,
// still remove actual orphan registrations before the worker test returns.
struct OrphanHookCleanup;
impl Drop for OrphanHookCleanup {
    fn drop(&mut self) {
        if !observer::test_cleanup_hooks() { HOOK_FAILED.with(|failed| failed.set(true)); }
    }
}
