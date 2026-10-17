//! Nested `Ctl3dDlgFramePaint` on the USER worker that owns the callback.
//!
//! Run on a Windows desktop:
//! cargo test -p host-services nested_wndproc_reads_dialog_frame -- --ignored --test-threads=1

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::ptr;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use runtime::{RuntimeError, Win16HostCtl3dFrameFacts, Win16HostWindow};
use windows_sys::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, GWL_STYLE, IsWindowVisible, RegisterClassW,
    SendMessageW, SetWindowLongPtrW, UnregisterClassW, WM_NCPAINT, WNDCLASSW, WS_CHILD, WS_POPUP,
    WS_VISIBLE,
};

use super::Win16Windows;
use super::win16_window_identity::adopt_created_owned;
use super::win16_window_worker::{WorkerCommand, WorkerState, remove_window_maps};
use crate::windows::{guest_text::GuestTextCodec, win16_gdi::Win16Dcs, win16_images::Win16Images};

// Windows 3.1 SDK `WINDOWS.H` dialog-frame bits. `WS_VISIBLE` comes from
// windows-sys; these two are the same values the runtime contract uses.
const WS_DLGFRAME: u32 = 0x0040_0000;
const DS_MODALFRAME: u32 = 0x0000_0080;
const DIALOG_FRAME_STYLE: u32 = WS_VISIBLE | WS_DLGFRAME | DS_MODALFRAME;

static CLIENT: AtomicUsize = AtomicUsize::new(0);
static TOKEN: AtomicU64 = AtomicU64::new(0);
static STYLE: AtomicU32 = AtomicU32::new(0);
static ICONIC: AtomicBool = AtomicBool::new(false);
static BLOCKED: AtomicBool = AtomicBool::new(false);
static NEXT_CLASS: AtomicU64 = AtomicU64::new(1);

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static PARENT: Cell<usize> = const { Cell::new(0) };
    static CHILD: Cell<usize> = const { Cell::new(0) };
    static INSTANCE: Cell<usize> = const { Cell::new(0) };
    static CLASS_NAME: RefCell<Vec<u16>> = const { RefCell::new(Vec::new()) };
    static NESTED: RefCell<Option<Result<Option<Win16HostCtl3dFrameFacts>, RuntimeError>>> =
        const { RefCell::new(None) };
    static PANIC: RefCell<Option<Box<dyn Any + Send>>> = const { RefCell::new(None) };
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native windows"]
fn nested_wndproc_reads_dialog_frame_without_waiting_on_the_worker() {
    BLOCKED.store(false, Ordering::Release);
    TOKEN.store(0, Ordering::Release);
    CLIENT.store(0, Ordering::Release);
    let codec = GuestTextCodec::new(1252).expect("create guest text codec");
    let windows = Win16Windows::new(
        Win16Dcs::with_text_codec(codec),
        Win16Images::new(codec),
        Arc::new(AtomicU64::new(1)),
        codec,
    );
    let blocked = exercise(&windows);
    if let Some(message) = blocked {
        // `Drop` would send Abort and wait on the worker that is already
        // blocked inside this call. Leak the client so the failure stays the
        // bounded callback wait.
        std::mem::forget(windows);
        panic!("{message} did not return within 20 seconds");
    }
}

fn exercise(windows: &Win16Windows) -> Option<&'static str> {
    let _retire = Retire(windows);
    if let Some(message) = on_worker(
        windows,
        "create the hidden dialog frame",
        create_hidden_frame,
    ) {
        return Some(message);
    }
    let token = Win16HostWindow(TOKEN.load(Ordering::Acquire));
    assert_ne!(token.0, 0, "hidden dialog frame must be adopted");
    // The runtime thread has no worker context, so this still uses the
    // command queue. The worker is back in its receive loop here.
    let mailbox = windows
        .ctl3d_frame(token)
        .expect("read dialog-frame facts from the runtime thread")
        .expect("adopted hidden dialog frame");
    assert_eq!(mailbox.style & DIALOG_FRAME_STYLE, DIALOG_FRAME_STYLE);
    assert!(!mailbox.iconic);
    STYLE.store(mailbox.style, Ordering::Release);
    ICONIC.store(mailbox.iconic, Ordering::Release);

    // Publish the client only for the callback. The client thread then blocks
    // in `recv_timeout` and does not mutate `Win16Windows`.
    CLIENT.store(&*windows as *const Win16Windows as usize, Ordering::Release);
    let blocked = on_worker(
        windows,
        "nested WM_NCPAINT dialog-frame query",
        reenter_from_wndproc,
    );
    CLIENT.store(0, Ordering::Release);
    blocked
}

struct Retire<'a>(&'a Win16Windows);

impl Drop for Retire<'_> {
    fn drop(&mut self) {
        if BLOCKED.load(Ordering::Acquire) || TOKEN.load(Ordering::Acquire) == 0 {
            return;
        }
        ARMED.with(|armed| armed.set(false));
        let _ = on_worker(
            self.0,
            "retire the hidden dialog frame",
            retire_hidden_frame,
        );
    }
}

fn on_worker(
    windows: &Win16Windows,
    operation: &'static str,
    run: fn(&Rc<RefCell<WorkerState>>),
) -> Option<&'static str> {
    let worker = windows.worker.as_ref().unwrap_or_else(|| {
        panic!(
            "USER worker failed to start: {}",
            windows.worker_start_failure()
        );
    });
    let (response, receive) = mpsc::channel();
    worker
        .send(WorkerCommand::TestWindowData { run, response })
        .unwrap_or_else(|_| panic!("{operation}: USER worker stopped before the callback"));
    match receive.recv_timeout(Duration::from_secs(20)) {
        Ok(Ok(())) => None,
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            BLOCKED.store(true, Ordering::Release);
            Some(operation)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("{operation}: USER worker stopped during the callback")
        }
    }
}

fn create_hidden_frame(state: &Rc<RefCell<WorkerState>>) {
    ARMED.with(|armed| armed.set(false));
    let class_name = format!(
        "Compat16.Ctl3dFrame.{}",
        NEXT_CLASS.fetch_add(1, Ordering::Relaxed)
    )
    .encode_utf16()
    .chain(Some(0))
    .collect::<Vec<_>>();
    let instance = unsafe { GetModuleHandleW(ptr::null()) };
    let class = WNDCLASSW {
        lpfnWndProc: Some(frame_proc),
        hInstance: instance,
        lpszClassName: class_name.as_ptr(),
        ..unsafe { std::mem::zeroed() }
    };
    assert_ne!(
        unsafe { RegisterClassW(&class) },
        0,
        "register hidden frame class"
    );
    INSTANCE.with(|slot| slot.set(instance as usize));
    CLASS_NAME.with(|slot| *slot.borrow_mut() = class_name);
    let class_name = CLASS_NAME.with(|slot| slot.borrow().as_ptr());
    // The parent stays hidden. The child carries the dialog-frame bits,
    // including WS_VISIBLE, and remains hidden because its parent is hidden.
    let parent = unsafe {
        CreateWindowExW(
            0,
            class_name,
            ptr::null(),
            WS_POPUP,
            0,
            0,
            80,
            60,
            ptr::null_mut(),
            ptr::null_mut(),
            instance,
            ptr::null(),
        )
    };
    assert!(!parent.is_null(), "create hidden parent");
    PARENT.with(|slot| slot.set(parent as usize));
    let child = unsafe {
        CreateWindowExW(
            0,
            class_name,
            ptr::null(),
            WS_CHILD,
            0,
            0,
            40,
            30,
            parent,
            ptr::null_mut(),
            instance,
            ptr::null(),
        )
    };
    assert!(!child.is_null(), "create hidden dialog frame");
    CHILD.with(|slot| slot.set(child as usize));
    let style = WS_CHILD | DIALOG_FRAME_STYLE;
    unsafe { SetWindowLongPtrW(child, GWL_STYLE, style as _) };
    assert_eq!(unsafe { IsWindowVisible(parent) }, 0);
    assert_eq!(unsafe { IsWindowVisible(child) }, 0);
    let token = adopt_created_owned(state, child).expect("adopt hidden dialog frame");
    TOKEN.store(token.0, Ordering::Release);
}

fn reenter_from_wndproc(state: &Rc<RefCell<WorkerState>>) {
    assert!(
        super::worker_context().is_some(),
        "dialog-frame callback must run on the USER worker"
    );
    assert!(
        Rc::ptr_eq(&super::worker_context().unwrap(), state),
        "callback worker must be the worker that owns the window"
    );
    ARMED.with(|armed| armed.set(true));
    let child = CHILD.with(Cell::get) as HWND;
    // This SendMessage is synchronous. The worker is still inside
    // TestWindowData, so it cannot process a queued Ctl3dFrame command.
    // `ctl3d_frame` returns only when it reads the facts on this thread.
    unsafe { SendMessageW(child, WM_NCPAINT, 0, 0) };
    ARMED.with(|armed| armed.set(false));
    if let Some(panic) = PANIC.with(|slot| slot.borrow_mut().take()) {
        std::panic::resume_unwind(panic);
    }
    let nested = NESTED
        .with(|slot| slot.borrow_mut().take())
        .expect("WM_NCPAINT must call ctl3d_frame from the window procedure");
    let nested = nested
        .expect("nested dialog-frame query")
        .expect("adopted hidden dialog frame");
    assert_eq!(nested.style, STYLE.load(Ordering::Acquire));
    assert_eq!(nested.iconic, ICONIC.load(Ordering::Acquire));
    assert_eq!(nested.style & DIALOG_FRAME_STYLE, DIALOG_FRAME_STYLE);
    assert!(!nested.iconic);
}

fn retire_hidden_frame(state: &Rc<RefCell<WorkerState>>) {
    ARMED.with(|armed| armed.set(false));
    let child = CHILD.with(|slot| slot.replace(0)) as HWND;
    let parent = PARENT.with(|slot| slot.replace(0)) as HWND;
    let token = Win16HostWindow(TOKEN.swap(0, Ordering::AcqRel));
    if !child.is_null() {
        unsafe { DestroyWindow(child) };
        remove_window_maps(state, token, child);
    }
    if !parent.is_null() {
        unsafe { DestroyWindow(parent) };
    }
    let name = CLASS_NAME.with(|slot| std::mem::take(&mut *slot.borrow_mut()));
    if !name.is_empty() {
        let instance = INSTANCE.with(Cell::get) as HINSTANCE;
        unsafe { UnregisterClassW(name.as_ptr(), instance) };
    }
}

unsafe extern "system" fn frame_proc(
    hwnd: HWND,
    message: u32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    if message == WM_NCPAINT && ARMED.with(|armed| armed.replace(false)) {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert!(
                super::worker_context().is_some(),
                "WM_NCPAINT must run on the USER worker that owns the callback"
            );
            let client = CLIENT.load(Ordering::Acquire) as *const Win16Windows;
            assert!(!client.is_null(), "dialog-frame client must be published");
            // The client thread is blocked waiting for this callback and does
            // not borrow `Win16Windows` mutably. The nested path does not
            // write the client; it uses the worker thread-local.
            let windows = unsafe { &*client };
            let token = Win16HostWindow(TOKEN.load(Ordering::Acquire));
            let facts = windows.ctl3d_frame(token);
            NESTED.with(|slot| *slot.borrow_mut() = Some(facts));
            let missing = windows.ctl3d_frame(Win16HostWindow(u64::MAX));
            assert!(
                matches!(missing, Ok(None)),
                "an unmapped window must return without waiting on the worker"
            );
        }));
        if let Err(panic) = outcome {
            PANIC.with(|slot| {
                if slot.borrow().is_none() {
                    *slot.borrow_mut() = Some(panic);
                }
            });
        }
    }
    unsafe { DefWindowProcW(hwnd, message, w_param, l_param) }
}
