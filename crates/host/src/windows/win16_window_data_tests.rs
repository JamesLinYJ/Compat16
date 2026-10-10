//! Opt-in tests on the real HWND-owning worker. Run on a Windows desktop:
//! cargo test -p host-services win16_window_data::tests -- --ignored --test-threads=1

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::ptr;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use windows_sys::Win32::Foundation::{HINSTANCE, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, GetDesktopWindow, GetParent, IsWindow,
    RegisterClassW, UnregisterClassW, WM_WINDOWPOSCHANGED, WM_WINDOWPOSCHANGING,
    WNDCLASSW, WS_POPUP,
};

use super::*;
use super::super::win16_window_worker::{NativeDropRetirementQueue, WindowWorker, WorkerCommand};
use crate::windows::{guest_text::GuestTextCodec, win16_gdi::Win16Dcs, win16_images::Win16Images};

struct CallbackAction {
    child: usize,
    new_parent: usize,
    run: Box<dyn FnOnce()>,
}

thread_local! {
    static CALLBACK: RefCell<Option<CallbackAction>> = const { RefCell::new(None) };
    static CALLBACK_PANIC: RefCell<Option<Box<dyn Any + Send>>> = const { RefCell::new(None) };
}

unsafe extern "system" fn test_window_proc(
    hwnd: HWND, message: u32, w_param: WPARAM, l_param: LPARAM,
) -> LRESULT {
    if matches!(message, WM_WINDOWPOSCHANGING | WM_WINDOWPOSCHANGED) {
        let action = CALLBACK.with(|slot| {
            let ready = {
                let slot = slot.borrow();
                slot.as_ref().is_some_and(|action| action.child == hwnd as usize
                    && action.new_parent == unsafe { GetParent(hwnd) } as usize)
            };
            if ready { slot.borrow_mut().take() } else { None }
        });
        if let Some(action) = action {
            // Rust panics must never unwind through a native WndProc frame.
            if let Err(error) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action.run)) {
                CALLBACK_PANIC.with(|slot| *slot.borrow_mut() = Some(error));
            }
            if unsafe { IsWindow(hwnd) } == 0 {
                return 0;
            }
        }
    }
    unsafe { DefWindowProcW(hwnd, message, w_param, l_param) }
}

fn run_on_worker(run: fn(&SharedWorker)) {
    let codec = GuestTextCodec::new(1252).expect("create guest text codec");
    let mut worker = WindowWorker::spawn(
        Win16Dcs::with_text_codec(codec), Win16Images::new(codec),
        Arc::new(AtomicU64::new(1)), codec, NativeDropRetirementQueue::shared(),
    ).expect("start native window-data worker");
    let (response, receive) = mpsc::channel();
    worker.send(WorkerCommand::TestWindowData { run, response })
        .unwrap_or_else(|_| panic!("enqueue native window-data test"));
    let result = receive.recv_timeout(Duration::from_secs(20))
        .expect("receive native window-data test");
    let shutdown = worker.shutdown();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
    shutdown.expect("shut down native window-data worker");
}

struct NativeWindows {
    state: SharedWorker,
    class_name: Vec<u16>,
    instance: HINSTANCE,
    windows: RefCell<Vec<(Win16HostWindow, HWND)>>,
}

impl NativeWindows {
    fn new(state: &SharedWorker) -> Rc<Self> {
        static NEXT_CLASS: AtomicU64 = AtomicU64::new(1);
        let class_name = format!("Compat16.WindowDataTest.{}",
            NEXT_CLASS.fetch_add(1, Ordering::Relaxed))
            .encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let instance = unsafe { GetModuleHandleW(ptr::null()) };
        let class = WNDCLASSW {
            lpfnWndProc: Some(test_window_proc),
            hInstance: instance,
            lpszClassName: class_name.as_ptr(),
            ..unsafe { std::mem::zeroed() }
        };
        assert_ne!(unsafe { RegisterClassW(&class) }, 0);
        Rc::new(Self {
            state: Rc::clone(state), class_name, instance,
            windows: RefCell::new(Vec::new()),
        })
    }

    fn window(&self, parent: HWND, style: u32) -> (Win16HostWindow, HWND) {
        let hwnd = unsafe { CreateWindowExW(
            0, self.class_name.as_ptr(), ptr::null(), style,
            0, 0, 80, 60, parent, ptr::null_mut(), self.instance, ptr::null(),
        ) };
        assert!(!hwnd.is_null(), "create hidden native test window");
        let token = identity::adopt_created_owned(&self.state, hwnd)
            .expect("adopt exact test window identity");
        self.windows.borrow_mut().push((token, hwnd));
        (token, hwnd)
    }

    fn retire(&self, window: (Win16HostWindow, HWND)) {
        assert_ne!(unsafe { DestroyWindow(window.1) }, 0);
        worker::remove_window_maps(&self.state, window.0, window.1);
    }
}

impl Drop for NativeWindows {
    fn drop(&mut self) {
        CALLBACK.with(|slot| { slot.borrow_mut().take(); });
        for (token, hwnd) in self.windows.get_mut().drain(..).rev() {
            if identity::resolve(&self.state, token) == Some(hwnd) {
                unsafe { DestroyWindow(hwnd) };
            }
            worker::remove_window_maps(&self.state, token, hwnd);
        }
        unsafe { UnregisterClassW(self.class_name.as_ptr(), self.instance) };
    }
}

fn finish_callback() {
    let pending = CALLBACK.with(|slot| slot.borrow_mut().take().is_some());
    if let Some(error) = CALLBACK_PANIC.with(|slot| slot.borrow_mut().take()) {
        std::panic::resume_unwind(error);
    }
    assert!(!pending, "native call must exercise the armed synchronous callback");
}

fn reparent(state: &SharedWorker, child: Win16HostWindow, parent: Win16WindowTarget)
    -> Win16WindowDataResult
{
    execute(state, Win16WindowDataCall::SetParent {
        window: Win16WindowTarget::Mapped(child), parent,
    }).expect("complete native parent mutation")
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native windows"]
fn parent_query_distinguishes_child_edges_owners_desktop_and_retirement() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let parent = windows.window(ptr::null_mut(), WS_POPUP);
        let child = windows.window(parent.1, WS_CHILD);
        let popup = windows.window(parent.1, WS_POPUP);
        assert_eq!(query_parent(state, child.0).unwrap(),
            Win16HostWindowParentObservation::Live { child_parent: Some(parent.0) });
        let desktop = worker::token_for_native(state, unsafe { GetDesktopWindow() }).unwrap();
        assert_eq!(query_parent(state, popup.0).unwrap(),
            Win16HostWindowParentObservation::Live { child_parent: Some(desktop) });
        assert!(matches!(execute(state, Win16WindowDataCall::GetParent {
            window: Win16WindowTarget::Mapped(popup.0),
        }).unwrap(), Win16WindowDataResult::Parent {
            succeeded: true, previous: Some(owner), child_parent: Some(actual_parent),
        } if owner == parent.0 && actual_parent == desktop));
        let other_owner = windows.window(ptr::null_mut(), WS_POPUP);
        assert!(matches!(reparent(state, popup.0, Win16WindowTarget::Mapped(other_owner.0)),
            Win16WindowDataResult::ParentMutation {
                attempted: true, succeeded: true, previous: Some(owner),
            } if owner == parent.0));
        assert_eq!(unsafe { GetParent(popup.1) }, other_owner.1);
        assert_eq!(read_scalar(popup.1, Win16WindowDataField::Style).unwrap() & WS_CHILD, 0);
        let result = reparent(state, child.0, Win16WindowTarget::Null);
        let Win16WindowDataResult::ParentMutation {
            attempted: true, succeeded: true, previous: Some(previous),
        } = result else { panic!("unexpected desktop reparent result: {result:?}") };
        assert_eq!(previous, parent.0);
        assert_eq!(identity::resolve_user_window(state, desktop), Some(unsafe { GetDesktopWindow() }));
        assert_eq!(query_parent(state, child.0).unwrap(),
            Win16HostWindowParentObservation::Live { child_parent: Some(desktop) });
        assert!(query_parent(state, Win16HostWindow(u64::MAX)).is_err());
        windows.retire(child);
        assert_eq!(query_parent(state, child.0).unwrap(), Win16HostWindowParentObservation::Retired);
    });
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native windows"]
fn stale_cookie_rejects_scalar_parent_target_and_parent_query() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let parent = windows.window(ptr::null_mut(), WS_POPUP);
        let other = windows.window(ptr::null_mut(), WS_POPUP);
        let child = windows.window(parent.1, WS_CHILD);
        let cookie = state.borrow().window_identity_cookies[&other.0];
        state.borrow_mut().window_identity_cookies.get_mut(&other.0).unwrap().value =
            cookie.value.wrapping_add(1);
        let observed = query_parent(state, other.0);
        let got = execute(state, Win16WindowDataCall::Get {
            window: Win16WindowTarget::Mapped(other.0), field: Win16WindowDataField::Style,
        });
        let set = execute(state, Win16WindowDataCall::Set {
            window: Win16WindowTarget::Mapped(other.0), field: Win16WindowDataField::ControlId,
            value: 17, mask: u32::MAX,
        });
        let result = reparent(state, child.0, Win16WindowTarget::Mapped(other.0));
        state.borrow_mut().window_identity_cookies.insert(other.0, cookie);
        assert!(observed.is_err(), "cookie mismatch must not masquerade as retirement");
        assert!(matches!(got.unwrap(), Win16WindowDataResult::Value(None)));
        assert!(matches!(set.unwrap(), Win16WindowDataResult::Value(None)));
        assert!(matches!(result, Win16WindowDataResult::ParentMutation { attempted: false, succeeded: false, .. }));
        assert_eq!(unsafe { GetParent(child.1) }, parent.1);
    });
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native windows"]
fn synchronous_reparent_callback_retires_previous_parent_without_readopting_it() {
    run_on_worker(|state| {
        // Destruction during SetParent can affect the native API return even
        // after the child has moved. Compare independent direct/bridged cases
        // instead of assuming USER returns the now-destroyed previous HWND.
        let run_case = |bridged: bool| {
            let windows = NativeWindows::new(state);
            let old_parent = windows.window(ptr::null_mut(), WS_POPUP);
            let new_parent = windows.window(ptr::null_mut(), WS_POPUP);
            let child = windows.window(old_parent.1, WS_CHILD);
            let replacement = Rc::new(Cell::new(None));
            let callback_windows = Rc::downgrade(&windows);
            let callback_replacement = Rc::clone(&replacement);
            CALLBACK.with(|slot| *slot.borrow_mut() = Some(CallbackAction {
                child: child.1 as usize,
                new_parent: new_parent.1 as usize,
                run: Box::new(move || {
                    let windows = callback_windows.upgrade().expect("live test fixture");
                    assert!(windows.state.try_borrow_mut().is_ok());
                    windows.retire(old_parent);
                    callback_replacement.set(Some(windows.window(ptr::null_mut(), WS_POPUP)));
                }),
            }));
            let (succeeded, previous_is_old) = if bridged {
                let result = reparent(state, child.0, Win16WindowTarget::Mapped(new_parent.0));
                let Win16WindowDataResult::ParentMutation { attempted: true, succeeded, previous } = result
                    else { panic!("missing attempted native mutation: {result:?}"); };
                // An immutable candidate may still name the original token;
                // it must never adopt the callback's replacement incarnation.
                assert!(previous.is_none() || previous == Some(old_parent.0), "{result:?}");
                eprintln!("bridged destruction callback outcome: {result:?}");
                (succeeded, previous == Some(old_parent.0))
            } else {
                unsafe { SetLastError(0) };
                let previous = unsafe { SetParent(child.1, new_parent.1) };
                let error = unsafe { GetLastError() };
                eprintln!("direct destruction callback outcome: previous={previous:?}, error={error}");
                let succeeded = !previous.is_null() || error == 0;
                (succeeded, succeeded && previous == old_parent.1)
            };
            finish_callback();
            assert_eq!(query_parent(state, old_parent.0).unwrap(), Win16HostWindowParentObservation::Retired);
            assert_eq!(query_parent(state, child.0).unwrap(),
                Win16HostWindowParentObservation::Live { child_parent: Some(new_parent.0) });
            let replacement = replacement.get().expect("callback created a replacement native window");
            assert_ne!(replacement.0, old_parent.0);
            assert_eq!(identity::resolve(state, replacement.0), Some(replacement.1));
            (succeeded, previous_is_old)
        };
        let native = run_case(false);
        let bridged = run_case(true);
        assert_eq!(bridged, native, "preserve native return while retaining exact previous-token identity");
    });
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native windows"]
fn synchronous_reparent_callback_retires_child_before_result_ancestry_query() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let old_parent = windows.window(ptr::null_mut(), WS_POPUP);
        let new_parent = windows.window(ptr::null_mut(), WS_POPUP);
        let child = windows.window(old_parent.1, WS_CHILD);
        let replacement = Rc::new(Cell::new(None));
        let callback_windows = Rc::downgrade(&windows);
        let callback_replacement = Rc::clone(&replacement);
        CALLBACK.with(|slot| *slot.borrow_mut() = Some(CallbackAction {
            child: child.1 as usize,
            new_parent: new_parent.1 as usize,
            run: Box::new(move || {
                let callback_windows = callback_windows.upgrade().expect("live test fixture");
                assert!(callback_windows.state.try_borrow_mut().is_ok());
                callback_windows.retire(child);
                callback_replacement.set(Some(callback_windows.window(old_parent.1, WS_CHILD)));
            }),
        }));
        let result = reparent(state, child.0, Win16WindowTarget::Mapped(new_parent.0));
        finish_callback();
        assert!(matches!(result, Win16WindowDataResult::ParentMutation { attempted: true, .. }));
        assert_eq!(query_parent(state, child.0).unwrap(), Win16HostWindowParentObservation::Retired);
        let replacement = replacement.get().expect("callback created a replacement child");
        assert_ne!(replacement.0, child.0);
        assert_eq!(query_parent(state, replacement.0).unwrap(),
            Win16HostWindowParentObservation::Live { child_parent: Some(old_parent.0) });
    });
}


#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native windows"]
fn reparent_never_projects_a_replacement_parent_identity_at_the_same_native_bits() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let old_parent = windows.window(ptr::null_mut(), WS_POPUP);
        let new_parent = windows.window(ptr::null_mut(), WS_POPUP);
        let child = windows.window(old_parent.1, WS_CHILD);
        let replacement = Rc::new(Cell::new(None));
        let callback_windows = Rc::downgrade(&windows);
        let callback_replacement = Rc::clone(&replacement);
        CALLBACK.with(|slot| *slot.borrow_mut() = Some(CallbackAction {
            child: child.1 as usize,
            new_parent: new_parent.1 as usize,
            run: Box::new(move || {
                let windows = callback_windows.upgrade().expect("live test fixture");
                // Deterministically replace the cookie/token at identical HWND
                // bits. This models reuse without depending on USER's handle
                // allocator choosing the same bits after DestroyWindow.
                worker::remove_window_maps(&windows.state, old_parent.0, old_parent.1);
                let token = identity::adopt_created_owned(&windows.state, old_parent.1).unwrap();
                windows.windows.borrow_mut().push((token, old_parent.1));
                callback_replacement.set(Some(token));
            }),
        }));
        let result = reparent(state, child.0, Win16WindowTarget::Mapped(new_parent.0));
        finish_callback();
        assert!(matches!(result, Win16WindowDataResult::ParentMutation {
            attempted: true, succeeded: true, previous: Some(previous),
        } if previous == old_parent.0));
        let replacement = replacement.get().unwrap();
        assert_ne!(replacement, old_parent.0);
        assert_eq!(identity::resolve(state, replacement), Some(old_parent.1));
        assert_eq!(query_parent(state, old_parent.0).unwrap(), Win16HostWindowParentObservation::Retired);
    });
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native windows"]
fn reparent_never_queries_a_replacement_child_identity_at_the_same_native_bits() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let old_parent = windows.window(ptr::null_mut(), WS_POPUP);
        let new_parent = windows.window(ptr::null_mut(), WS_POPUP);
        let child = windows.window(old_parent.1, WS_CHILD);
        let replacement = Rc::new(Cell::new(None));
        let callback_windows = Rc::downgrade(&windows);
        let callback_replacement = Rc::clone(&replacement);
        CALLBACK.with(|slot| *slot.borrow_mut() = Some(CallbackAction {
            child: child.1 as usize,
            new_parent: new_parent.1 as usize,
            run: Box::new(move || {
                let windows = callback_windows.upgrade().expect("live test fixture");
                // Recycle the exact token/cookie incarnation at the same raw
                // HWND, then give its replacement a different parent. An
                // ancestry read using only the original raw HWND is now wrong.
                worker::remove_window_maps(&windows.state, child.0, child.1);
                let token = identity::adopt_created_owned(&windows.state, child.1).unwrap();
                windows.windows.borrow_mut().push((token, child.1));
                assert!(set_parent(child.1, old_parent.1).is_some());
                callback_replacement.set(Some(token));
            }),
        }));
        let result = reparent(state, child.0, Win16WindowTarget::Mapped(new_parent.0));
        finish_callback();
        assert!(matches!(result, Win16WindowDataResult::ParentMutation {
            attempted: true, succeeded: true, ..
        }));
        let replacement = replacement.get().unwrap();
        assert_ne!(replacement, child.0);
        assert_eq!(query_parent(state, child.0).unwrap(), Win16HostWindowParentObservation::Retired);
        assert_eq!(query_parent(state, replacement).unwrap(),
            Win16HostWindowParentObservation::Live { child_parent: Some(old_parent.0) });
    });
}

// Reuse the exact-identity fixture and synchronous native callback harness.
#[path = "win16_set_window_pos_tests.rs"]
mod set_window_pos_tests;

#[path = "win16_open_icon_tests.rs"]
mod open_icon_tests;

#[path = "win16_set_parent_tests.rs"]
mod set_parent_tests;

#[path = "win16_close_window_tests.rs"]
mod close_window_tests;

#[path = "win16_arrange_iconic_windows_tests.rs"]
mod arrange_iconic_windows_tests;

#[path = "win16_get_clip_cursor_tests.rs"]
mod get_clip_cursor_tests;
