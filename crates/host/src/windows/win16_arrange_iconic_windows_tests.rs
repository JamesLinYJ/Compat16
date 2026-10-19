//! Opt-in USER.170 tests confined to owned hidden parents and their children.
//! cargo test -p host-services arrange_iconic_windows_tests -- --ignored --test-threads=1

use super::super::super::win16_window_ops::arrange_iconic_windows_with;
use super::*;
use runtime::{Win16WindowCall, Win16WindowCallResult};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    ArrangeIconicWindows, GetWindowRect, SWP_NOACTIVATE, SWP_NOSIZE, SWP_NOZORDER, SetWindowPos,
    WS_MINIMIZE, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
};

fn rectangle(window: HWND) -> (i32, i32, i32, i32) {
    let mut rect = windows_sys::Win32::Foundation::RECT::default();
    // SAFETY: GetWindowRect writes into a caller-owned RECT that outlives the call.
    assert_ne!(unsafe { GetWindowRect(window, &mut rect) }, 0);
    (rect.left, rect.top, rect.right, rect.bottom)
}

fn displace_child(window: HWND) {
    // SAFETY: SetWindowPos takes no caller pointer. The HWND is a window on this thread.
    assert_ne!(
        unsafe {
            SetWindowPos(
                window,
                ptr::null_mut(),
                400,
                400,
                0,
                0,
                SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOSIZE,
            )
        },
        0
    );
}

fn arrange(state: &SharedWorker, window: Win16WindowTarget) -> u16 {
    match super::super::super::win16_window_ops::execute(
        state,
        Win16WindowCall::ArrangeIconicWindows { window },
    )
    .expect("complete native arrangement")
    {
        Win16WindowCallResult::Integer(value) => value as u16,
        result => panic!("unexpected ArrangeIconicWindows result: {result:?}"),
    }
}

#[test]
#[ignore = "requires Windows USER; only arranges children of an owned hidden parent"]
fn arrange_iconic_windows_forwards_native_row_height_and_keeps_identities() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let parent = windows.window(ptr::null_mut(), WS_OVERLAPPEDWINDOW);
        let child = windows.window(parent.1, WS_CHILD | WS_MINIMIZE | WS_VISIBLE);
        let sibling = windows.window(parent.1, WS_CHILD | WS_VISIBLE);
        let sibling_before = rectangle(sibling.1);
        assert_eq!((crate::windows::win32_safe::is_iconic(sibling.1)), 0);
        assert_eq!((crate::windows::win32_safe::is_window_visible(parent.1)), 0);
        assert_eq!((crate::windows::win32_safe::is_window_visible(child.1)), 0);
        assert_ne!((crate::windows::win32_safe::is_iconic(child.1)), 0);
        // Establish the native layout on this desktop, then deliberately move
        // the minimized child away. The bridge must reproduce the native
        // coordinates while leaving its non-minimized sibling untouched.
        // SAFETY: `ArrangeIconicWindows` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        let expected = unsafe { ArrangeIconicWindows(parent.1) } as u16;
        let native_arranged = rectangle(child.1);
        assert_eq!(rectangle(sibling.1), sibling_before);
        displace_child(child.1);
        let displaced = rectangle(child.1);
        assert_ne!(
            (displaced.0, displaced.1),
            (native_arranged.0, native_arranged.1),
            "fixture must actually displace the minimized child"
        );
        assert_eq!(
            arrange(state, Win16WindowTarget::Mapped(parent.0)),
            expected
        );
        let arranged = rectangle(child.1);
        assert_ne!((arranged.0, arranged.1), (displaced.0, displaced.1));
        assert_eq!(arranged, native_arranged);
        assert_eq!(rectangle(sibling.1), sibling_before);
        assert_eq!(identity::resolve(state, parent.0), Some(parent.1));
        assert_eq!(identity::resolve(state, child.0), Some(child.1));
        // No-icons behavior is deliberately whatever this native USER returns.
        let empty = windows.window(ptr::null_mut(), WS_OVERLAPPEDWINDOW);
        assert_eq!(
            arrange(state, Win16WindowTarget::Mapped(empty.0)),
            // SAFETY: `ArrangeIconicWindows` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
            unsafe { ArrangeIconicWindows(empty.1) } as u16
        );
    });
}

#[test]
#[ignore = "requires Windows USER; validates hidden owned HWND identities"]
fn arrange_iconic_windows_invalid_and_stale_targets_never_call_native() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let parent = windows.window(ptr::null_mut(), WS_OVERLAPPEDWINDOW);
        let unexpected = |_| -> u32 { panic!("invalid target must not enter native API") };
        for target in [
            Win16WindowTarget::Null,
            Win16WindowTarget::Invalid,
            Win16WindowTarget::Mapped(Win16HostWindow(u64::MAX)),
        ] {
            assert_eq!(arrange_iconic_windows_with(state, target, unexpected), 0);
            assert_eq!(arrange(state, target), 0);
        }
        let cookie = state.borrow().window_identity_cookies[&parent.0];
        state
            .borrow_mut()
            .window_identity_cookies
            .get_mut(&parent.0)
            .unwrap()
            .value = cookie.value.wrapping_add(1);
        assert_eq!(
            arrange_iconic_windows_with(state, Win16WindowTarget::Mapped(parent.0), unexpected),
            0
        );
        state
            .borrow_mut()
            .window_identity_cookies
            .insert(parent.0, cookie);
        assert_eq!(
            arrange_iconic_windows_with(state, Win16WindowTarget::Mapped(parent.0), |native| {
                assert_eq!(native, parent.1);
                // Resolution must have released all RefCell borrows.
                let _state = state.borrow_mut();
                37
            }),
            37
        );
        windows.retire(parent);
        assert_eq!(
            arrange_iconic_windows_with(state, Win16WindowTarget::Mapped(parent.0), unexpected),
            0
        );
    });
}

#[test]
#[ignore = "requires Windows USER; arranges only an owned hidden parent's child with reentry"]
fn arrange_iconic_windows_native_callback_rejects_replaced_parent_and_child_identities() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let parent = windows.window(ptr::null_mut(), WS_OVERLAPPEDWINDOW);
        let child = windows.window(parent.1, WS_CHILD | WS_MINIMIZE | WS_VISIBLE);
        displace_child(child.1);
        let replacement = Rc::new(Cell::new(None));
        let callback_replacement = Rc::clone(&replacement);
        let callback_windows = Rc::clone(&windows);
        CALLBACK.with(|slot| {
            *slot.borrow_mut() = Some(CallbackAction {
                child: child.1 as usize,
                new_parent: parent.1 as usize,
                run: Box::new(move || {
                    let state = &callback_windows.state;
                    assert_eq!(identity::resolve(state, parent.0), Some(parent.1));
                    worker::remove_window_maps(state, parent.0, parent.1);
                    let new = identity::adopt_created_owned(state, parent.1).unwrap();
                    callback_windows.windows.borrow_mut().push((new, parent.1));
                    state.borrow_mut().windows.insert(parent.0, parent.1);
                    assert_eq!(
                        arrange_iconic_windows_with(
                            state,
                            Win16WindowTarget::Mapped(parent.0),
                            |_| panic!("stale alias reached native")
                        ),
                        0
                    );
                    state.borrow_mut().windows.remove(&parent.0);
                    // Retire/rebind the callback source independently of its parent.
                    worker::remove_window_maps(state, child.0, child.1);
                    let new_child = identity::adopt_created_owned(state, child.1).unwrap();
                    callback_windows
                        .windows
                        .borrow_mut()
                        .push((new_child, child.1));
                    state.borrow_mut().windows.insert(child.0, child.1);
                    assert_eq!(
                        arrange_iconic_windows_with(
                            state,
                            Win16WindowTarget::Mapped(child.0),
                            |_| panic!("stale child reached native")
                        ),
                        0
                    );
                    state.borrow_mut().windows.remove(&child.0);
                    callback_replacement.set(Some((new, new_child)));
                }),
            })
        });
        arrange(state, Win16WindowTarget::Mapped(parent.0));
        finish_callback();
        let (replacement, replacement_child) = replacement.get().unwrap();
        assert_ne!(replacement, parent.0);
        assert_ne!(replacement_child, child.0);
        assert_eq!(identity::resolve(state, parent.0), None);
        assert_eq!(identity::resolve(state, replacement), Some(parent.1));
        assert_eq!(identity::resolve(state, child.0), None);
        assert_eq!(identity::resolve(state, replacement_child), Some(child.1));
        assert_eq!(arrange(state, Win16WindowTarget::Mapped(child.0)), 0);
        assert_eq!(arrange(state, Win16WindowTarget::Mapped(parent.0)), 0);
    });
}
