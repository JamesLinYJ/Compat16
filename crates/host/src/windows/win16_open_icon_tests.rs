//! Opt-in native OpenIcon contract tests on the owning USER worker.
//! cargo test -p host-services open_icon_tests -- --ignored --test-threads=1

use super::*;
use runtime::{Win16WindowCall, Win16WindowCallResult};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    IsIconic, OpenIcon, SetWindowLongPtrW, ShowWindow, GWLP_WNDPROC, SW_MINIMIZE,
    WM_QUERYOPEN,
};

thread_local! {
    static QUERY_ALLOW: Cell<bool> = const { Cell::new(true) };
    static QUERY_COUNT: Cell<usize> = const { Cell::new(0) };
    static QUERY_ACTION: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
}

unsafe extern "system" fn query_proc(hwnd: HWND, message: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    if message == WM_QUERYOPEN {
        QUERY_COUNT.with(|value| value.set(value.get() + 1));
        let action = QUERY_ACTION.with(|slot| slot.borrow_mut().take());
        if let Some(action) = action {
            if let Err(error) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
                CALLBACK_PANIC.with(|slot| *slot.borrow_mut() = Some(error));
            }
        }
        return QUERY_ALLOW.with(|value| isize::from(value.get()));
    }
    unsafe { DefWindowProcW(hwnd, message, wp, lp) }
}

fn open(state: &SharedWorker, window: Win16WindowTarget) -> bool {
    match super::super::super::win16_window_ops::execute(state,
        Win16WindowCall::OpenIcon { window }).expect("complete native OpenIcon") {
        Win16WindowCallResult::Boolean(value) => value,
        result => panic!("unexpected OpenIcon result: {result:?}"),
    }
}

#[test]
#[ignore = "requires a Windows USER desktop; minimizes, restores and activates a test window"]
fn open_icon_uses_native_success_and_query_open_veto() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let target = windows.window(ptr::null_mut(), WS_POPUP);
        assert_ne!(unsafe { SetWindowLongPtrW(target.1, GWLP_WNDPROC, query_proc as *const () as isize) }, 0);
        QUERY_COUNT.with(|count| count.set(0));
        QUERY_ALLOW.with(|allow| allow.set(false));
        unsafe { ShowWindow(target.1, SW_MINIMIZE) };
        assert_ne!(unsafe { IsIconic(target.1) }, 0);
        // Compare the return to the real API, including implementations that
        // report successful delivery despite a guest vetoing restoration.
        let native_veto_result = unsafe { OpenIcon(target.1) != 0 };
        assert_eq!(open(state, Win16WindowTarget::Mapped(target.0)), native_veto_result);
        assert_ne!(unsafe { IsIconic(target.1) }, 0);
        assert_eq!(QUERY_COUNT.with(Cell::get), 2);
        QUERY_ALLOW.with(|allow| allow.set(true));
        assert!(open(state, Win16WindowTarget::Mapped(target.0)));
        assert_eq!(unsafe { IsIconic(target.1) }, 0);
        assert_eq!(QUERY_COUNT.with(Cell::get), 3);
    });
}

#[test]
#[ignore = "requires a Windows USER desktop; creates a minimized test window"]
fn open_icon_reentry_rejects_replaced_identity_and_invalid_targets() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let target = windows.window(ptr::null_mut(), WS_POPUP);
        assert_ne!(unsafe { SetWindowLongPtrW(target.1, GWLP_WNDPROC, query_proc as *const () as isize) }, 0);
        QUERY_ALLOW.with(|allow| allow.set(false));
        unsafe { ShowWindow(target.1, SW_MINIMIZE) };
        for target in [Win16WindowTarget::Null, Win16WindowTarget::Invalid,
            Win16WindowTarget::Mapped(Win16HostWindow(u64::MAX))] {
            assert!(!open(state, target));
        }
        let cookie = state.borrow().window_identity_cookies[&target.0];
        state.borrow_mut().window_identity_cookies.get_mut(&target.0).unwrap().value =
            cookie.value.wrapping_add(1);
        let stale_cookie_result = open(state, Win16WindowTarget::Mapped(target.0));
        state.borrow_mut().window_identity_cookies.insert(target.0, cookie);
        assert!(!stale_cookie_result);
        let replacement = Rc::new(Cell::new(None));
        let callback_replacement = Rc::clone(&replacement);
        let callback_windows = Rc::clone(&windows);
        QUERY_ACTION.with(|slot| *slot.borrow_mut() = Some(Box::new(move || {
            let state = &callback_windows.state;
            // This synchronous callback must be allowed to borrow worker state.
            assert_eq!(identity::resolve(state, target.0), Some(target.1));
            worker::remove_window_maps(state, target.0, target.1);
            let new = identity::adopt_created_owned(state, target.1).unwrap();
            callback_windows.windows.borrow_mut().push((new, target.1));
            // A stale forward alias to the same HWND cannot pass cookie/reverse
            // identity validation during nested native calls.
            state.borrow_mut().windows.insert(target.0, target.1);
            assert!(!open(state, Win16WindowTarget::Mapped(target.0)));
            state.borrow_mut().windows.remove(&target.0);
            callback_replacement.set(Some(new));
        })));
        open(state, Win16WindowTarget::Mapped(target.0));
        let pending = QUERY_ACTION.with(|slot| slot.borrow_mut().take().is_some());
        if let Some(error) = CALLBACK_PANIC.with(|slot| slot.borrow_mut().take()) {
            std::panic::resume_unwind(error);
        }
        assert!(!pending, "OpenIcon must deliver the synchronous query");
        let replacement = replacement.get().unwrap();
        assert_ne!(replacement, target.0);
        assert_eq!(identity::resolve(state, target.0), None);
        assert_eq!(identity::resolve(state, replacement), Some(target.1));
        assert!(!open(state, Win16WindowTarget::Mapped(target.0)));
        assert_ne!(unsafe { IsIconic(target.1) }, 0);
    });
}
