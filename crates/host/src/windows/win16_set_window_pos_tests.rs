//! Opt-in native positioning tests using the window-data identity fixture.
//! cargo test -p host-services set_window_pos_tests -- --ignored --test-threads=1

use super::*;
use runtime::{Win16WindowCall, Win16WindowCallResult, Win16WindowInsertAfter};
use windows_sys::Win32::Foundation::RECT;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetWindow, GetWindowRect, GW_HWNDPREV, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE,
    SWP_NOZORDER, WS_EX_TOPMOST,
};

fn position(
    state: &SharedWorker, window: Win16HostWindow,
    insert_after: Win16WindowInsertAfter, rect: [i16; 4], flags: u32,
) -> bool {
    let [x, y, width, height] = rect;
    match super::super::super::win16_window_ops::execute(state, Win16WindowCall::SetWindowPos {
        window: Win16WindowTarget::Mapped(window), insert_after, x, y, width, height,
        flags: flags as u16,
    }).expect("complete native SetWindowPos") {
        Win16WindowCallResult::Boolean(result) => result,
        result => panic!("unexpected position result: {result:?}"),
    }
}

fn rect(hwnd: HWND) -> [i32; 4] {
    let mut rect = RECT::default();
    assert_ne!(unsafe { GetWindowRect(hwnd, &mut rect) }, 0);
    [rect.left, rect.top, rect.right, rect.bottom]
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native windows"]
fn set_window_pos_validates_insertion_cookie_only_when_z_order_is_used() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let parent = windows.window(ptr::null_mut(), WS_POPUP);
        let target = windows.window(parent.1, WS_CHILD);
        let sibling = windows.window(parent.1, WS_CHILD);
        let before = rect(target.1);
        let cookie = state.borrow().window_identity_cookies[&sibling.0];
        state.borrow_mut().window_identity_cookies.get_mut(&sibling.0).unwrap().value =
            cookie.value.wrapping_add(1);
        let rejected = position(state, target.0, Win16WindowInsertAfter::Window(sibling.0),
            [20, 30, 100, 90], SWP_NOACTIVATE);
        let after_rejected = rect(target.1);
        let ignored = position(state, target.0, Win16WindowInsertAfter::Window(sibling.0),
            [20, 30, 100, 90], SWP_NOACTIVATE | SWP_NOZORDER);
        state.borrow_mut().window_identity_cookies.insert(sibling.0, cookie);
        assert!(!rejected, "a stale insertion must fail before any native mutation");
        assert_eq!(after_rejected, before);
        assert!(ignored, "NOZORDER must not validate an ignored insertion cookie");
        assert_ne!(rect(target.1), before);
        assert!(position(state, target.0,
            Win16WindowInsertAfter::Window(Win16HostWindow(u64::MAX)),
            [40, 50, 120, 110], SWP_NOACTIVATE | SWP_NOZORDER));
        let target_cookie = state.borrow().window_identity_cookies[&target.0];
        state.borrow_mut().window_identity_cookies.get_mut(&target.0).unwrap().value =
            target_cookie.value.wrapping_add(1);
        let stale_target = position(state, target.0, Win16WindowInsertAfter::Top,
            [60, 70, 140, 130], SWP_NOACTIVATE | SWP_NOZORDER);
        state.borrow_mut().window_identity_cookies.insert(target.0, target_cookie);
        assert!(!stale_target, "NOZORDER does not waive target identity validation");
    });
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native windows"]
fn set_window_pos_rejects_stale_forward_alias_after_exact_hwnd_identity_replacement() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let parent = windows.window(ptr::null_mut(), WS_POPUP);
        let target = windows.window(parent.1, WS_CHILD);
        let sibling = windows.window(parent.1, WS_CHILD);
        // Model raw HWND reuse deterministically, then retain a stale forward
        // alias. A direct state.windows lookup would accept the wrong identity.
        worker::remove_window_maps(state, sibling.0, sibling.1);
        let replacement = identity::adopt_created_owned(state, sibling.1).unwrap();
        windows.windows.borrow_mut().push((replacement, sibling.1));
        state.borrow_mut().windows.insert(sibling.0, sibling.1);
        let before = rect(target.1);
        let rejected = position(state, target.0, Win16WindowInsertAfter::Window(sibling.0),
            [20, 30, 100, 90], SWP_NOACTIVATE);
        state.borrow_mut().windows.remove(&sibling.0);
        assert!(!rejected);
        assert_eq!(rect(target.1), before);
        assert_ne!(replacement, sibling.0);
        assert_eq!(identity::resolve(state, sibling.0), None);
        assert_eq!(identity::resolve(state, replacement), Some(sibling.1));
        assert!(position(state, target.0, Win16WindowInsertAfter::Window(replacement),
            [20, 30, 100, 90], SWP_NOACTIVATE));
    });
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native windows"]
fn set_window_pos_preserves_native_pseudo_handles_and_nozorder_behavior() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let parent = windows.window(ptr::null_mut(), WS_POPUP);
        let target = windows.window(parent.1, WS_CHILD);
        let sibling = windows.window(parent.1, WS_CHILD);
        let flags = SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE;
        assert!(position(state, target.0, Win16WindowInsertAfter::Bottom, [0; 4], flags));
        assert_eq!(unsafe { GetWindow(target.1, GW_HWNDPREV) }, sibling.1);
        assert!(position(state, target.0, Win16WindowInsertAfter::Top, [0; 4], flags | SWP_NOZORDER));
        assert_eq!(unsafe { GetWindow(target.1, GW_HWNDPREV) }, sibling.1);
        assert!(position(state, target.0, Win16WindowInsertAfter::Top, [0; 4], flags));
        assert!(unsafe { GetWindow(target.1, GW_HWNDPREV) }.is_null());
        assert!(position(state, target.0, Win16WindowInsertAfter::Window(sibling.0), [0; 4], flags));
        assert_eq!(unsafe { GetWindow(target.1, GW_HWNDPREV) }, sibling.1);

        let popup = windows.window(ptr::null_mut(), WS_POPUP);
        assert!(position(state, popup.0, Win16WindowInsertAfter::Topmost, [0; 4], flags));
        assert_ne!(read_scalar(popup.1, Win16WindowDataField::ExStyle).unwrap() & WS_EX_TOPMOST, 0);
        assert!(position(state, popup.0, Win16WindowInsertAfter::NotTopmost, [0; 4], flags));
        assert_eq!(read_scalar(popup.1, Win16WindowDataField::ExStyle).unwrap() & WS_EX_TOPMOST, 0);
    });
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native windows"]
fn set_window_pos_releases_state_for_callbacks_without_readopting_retired_insertion() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let parent = windows.window(ptr::null_mut(), WS_POPUP);
        let target = windows.window(parent.1, WS_CHILD);
        let sibling = windows.window(parent.1, WS_CHILD);
        let replacement = Rc::new(Cell::new(None));
        let callback_windows = Rc::downgrade(&windows);
        let callback_replacement = Rc::clone(&replacement);
        CALLBACK.with(|slot| *slot.borrow_mut() = Some(CallbackAction {
            child: target.1 as usize,
            new_parent: parent.1 as usize,
            run: Box::new(move || {
                let windows = callback_windows.upgrade().expect("live test fixture");
                assert!(windows.state.try_borrow_mut().is_ok());
                worker::remove_window_maps(&windows.state, sibling.0, sibling.1);
                let token = identity::adopt_created_owned(&windows.state, sibling.1).unwrap();
                windows.windows.borrow_mut().push((token, sibling.1));
                callback_replacement.set(Some(token));
            }),
        }));
        assert!(position(state, target.0, Win16WindowInsertAfter::Window(sibling.0),
            [20, 30, 100, 90], SWP_NOACTIVATE));
        finish_callback();
        let replacement = replacement.get().unwrap();
        assert_ne!(replacement, sibling.0);
        assert_eq!(identity::resolve(state, replacement), Some(sibling.1));
        assert_eq!(identity::resolve(state, sibling.0), None);
        assert!(!state.borrow().windows.contains_key(&sibling.0));
    });
}
