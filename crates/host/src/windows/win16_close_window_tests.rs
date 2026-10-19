//! Opt-in native CloseWindow tests on the owning USER worker.
//! cargo test -p host-services close_window_tests -- --ignored --test-threads=1

use super::*;
use runtime::{Win16WindowCall, Win16WindowCallResult};
use windows_sys::Win32::UI::WindowsAndMessaging::{WS_CHILD, WS_OVERLAPPEDWINDOW};

fn close(state: &SharedWorker, window: Win16WindowTarget) -> bool {
    match super::super::super::win16_window_ops::execute(
        state,
        Win16WindowCall::CloseWindow { window },
    )
    .expect("complete native CloseWindow")
    {
        Win16WindowCallResult::Boolean(value) => value,
        result => panic!("unexpected CloseWindow result: {result:?}"),
    }
}

#[test]
#[ignore = "requires a Windows USER desktop; minimizes a test window"]
fn close_window_minimizes_without_destroying_or_retiring_identity() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let target = windows.window(ptr::null_mut(), WS_OVERLAPPEDWINDOW);
        let cookie = state.borrow().window_identity_cookies[&target.0];
        assert_eq!((crate::windows::win32_safe::is_iconic(target.1)), 0);
        assert!(close(state, Win16WindowTarget::Mapped(target.0)));
        assert_ne!((crate::windows::win32_safe::is_iconic(target.1)), 0);
        close(state, Win16WindowTarget::Mapped(target.0));
        assert_ne!((crate::windows::win32_safe::is_iconic(target.1)), 0);
        assert_ne!((crate::windows::win32_safe::is_window(target.1)), 0);
        assert_eq!(identity::resolve(state, target.0), Some(target.1));
        assert_eq!(
            state.borrow().window_identity_cookies[&target.0].value,
            cookie.value
        );
    });
}

#[test]
#[ignore = "requires a Windows USER desktop; creates popup and child test windows"]
fn close_window_ignores_popup_child_null_unknown_and_stale_targets() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let parent = windows.window(ptr::null_mut(), WS_OVERLAPPEDWINDOW);
        let popup = windows.window(ptr::null_mut(), WS_POPUP);
        let child = windows.window(parent.1, WS_CHILD);
        for target in [popup, child] {
            assert!(!close(state, Win16WindowTarget::Mapped(target.0)));
            assert_eq!((crate::windows::win32_safe::is_iconic(target.1)), 0);
            assert_eq!(identity::resolve(state, target.0), Some(target.1));
        }
        for target in [
            Win16WindowTarget::Null,
            Win16WindowTarget::Invalid,
            Win16WindowTarget::Mapped(Win16HostWindow(u64::MAX)),
        ] {
            assert!(!close(state, target));
        }
        let cookie = state.borrow().window_identity_cookies[&parent.0];
        state
            .borrow_mut()
            .window_identity_cookies
            .get_mut(&parent.0)
            .unwrap()
            .value = cookie.value.wrapping_add(1);
        let stale_result = close(state, Win16WindowTarget::Mapped(parent.0));
        state
            .borrow_mut()
            .window_identity_cookies
            .insert(parent.0, cookie);
        assert!(!stale_result);
        assert_eq!((crate::windows::win32_safe::is_iconic(parent.1)), 0);
        windows.retire(parent);
        assert!(!close(state, Win16WindowTarget::Mapped(parent.0)));
    });
}

#[test]
#[ignore = "requires a Windows USER desktop; minimizes a test window with synchronous reentry"]
fn close_window_reentry_rejects_replaced_identity_without_retiring_replacement() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let target = windows.window(ptr::null_mut(), WS_OVERLAPPEDWINDOW);
        let replacement = Rc::new(Cell::new(None));
        let callback_replacement = Rc::clone(&replacement);
        let callback_windows = Rc::clone(&windows);
        CALLBACK.with(|slot| {
            *slot.borrow_mut() = Some(CallbackAction {
                child: target.1 as usize,
                new_parent: 0,
                run: Box::new(move || {
                    let state = &callback_windows.state;
                    // The synchronous native callback must be free to borrow state.
                    assert_eq!(identity::resolve(state, target.0), Some(target.1));
                    worker::remove_window_maps(state, target.0, target.1);
                    let new = identity::adopt_created_owned(state, target.1).unwrap();
                    callback_windows.windows.borrow_mut().push((new, target.1));
                    state.borrow_mut().windows.insert(target.0, target.1);
                    assert!(!close(state, Win16WindowTarget::Mapped(target.0)));
                    state.borrow_mut().windows.remove(&target.0);
                    callback_replacement.set(Some(new));
                }),
            })
        });
        close(state, Win16WindowTarget::Mapped(target.0));
        finish_callback();
        let replacement = replacement.get().unwrap();
        assert_ne!(replacement, target.0);
        assert_eq!(identity::resolve(state, target.0), None);
        assert_eq!(identity::resolve(state, replacement), Some(target.1));
        assert_ne!((crate::windows::win32_safe::is_window(target.1)), 0);
        assert_ne!((crate::windows::win32_safe::is_iconic(target.1)), 0);
        assert!(!close(state, Win16WindowTarget::Mapped(target.0)));
    });
}
