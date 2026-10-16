//! Exact HWND-cookie and immutable native queue evidence for USER.224.
//! cargo test -p host-services get_window_task_ -- --ignored --test-threads=1

use super::*;
use runtime::{Win16HostTaskQueue, Win16WindowEnumerationQuery as Query,
    Win16WindowEnumerationReply as Reply};
use crate::windows::win16_windows::{win16_guest_notifications as notifications,
    win16_window_enumeration::query};

fn task_queue(state: &SharedWorker, window: Win16HostWindow) -> Option<Win16HostTaskQueue> {
    let Reply::TaskQueue(queue) = query(state, Query::TaskQueue(window)).unwrap()
        else { panic!("expected exact window queue reply"); };
    queue
}

#[test]
#[ignore = "requires Windows USER; creates hidden native windows"]
fn get_window_task_native_queue_is_immutable_and_includes_borrowed_control_aliases() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let parent = windows.window(ptr::null_mut(), WS_POPUP);
        assert_eq!(task_queue(state, parent.0), None, "an unbound queue has no guest task");
        let owner = guest_core::OwnerId(0x1234);
        let queue = notifications::bind_task_queue(owner, 0x4567, 7).unwrap().unwrap();
        assert_eq!(task_queue(state, parent.0), Some(queue));

        // A child can first reach the guest through GetDlgItem/EnumChildWindows
        // as a borrowed alias. Lifetime ownership does not change its queue.
        let child_hwnd = unsafe { CreateWindowExW(0, windows.class_name.as_ptr(), ptr::null(),
            WS_CHILD, 0, 0, 20, 20, parent.1, ptr::null_mut(), windows.instance, ptr::null()) };
        assert!(!child_hwnd.is_null());
        let child = identity::adopt(state, child_hwnd).unwrap();
        windows.windows.borrow_mut().push((child, child_hwnd));
        assert!(!state.borrow().windows_by_native[&(child_hwnd as usize)].owned);
        assert_eq!(task_queue(state, child), Some(queue));
        let desktop = identity::adopt(state, unsafe { GetDesktopWindow() }).unwrap();
        assert_eq!(task_queue(state, desktop), None, "foreign aliases have no guest HTASK");

        assert_eq!(notifications::bind_task_queue(guest_core::OwnerId(0x2345), 0x5678, 8).unwrap(), None);
        assert_eq!(notifications::bind_task_queue(owner, 0x4567, 8).unwrap(), None);
        assert_eq!(task_queue(state, parent.0), Some(queue));
        assert_eq!(task_queue(state, child), Some(queue));
        assert!(notifications::retire_task_queue(owner, 0x4567, 7, queue));
        assert_eq!(task_queue(state, parent.0), None);
        assert_eq!(task_queue(state, child), None);
        assert_eq!(notifications::bind_task_queue(owner, 0x4567, 7).unwrap(), None);
    });
}

#[test]
#[ignore = "requires Windows USER; creates hidden native windows"]
fn get_window_task_native_rejects_cookie_mismatch_retired_and_replaced_hwnd_tokens() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let target = windows.window(ptr::null_mut(), WS_POPUP);
        let queue = notifications::bind_task_queue(guest_core::OwnerId(0x1234), 0x4567, 7)
            .unwrap().unwrap();
        assert_eq!(task_queue(state, target.0), Some(queue));
        assert_eq!(task_queue(state, Win16HostWindow(u64::MAX)), None);
        let cookie = state.borrow().window_identity_cookies[&target.0];
        state.borrow_mut().window_identity_cookies.get_mut(&target.0).unwrap().value = cookie.value + 1;
        assert_eq!(task_queue(state, target.0), None);
        state.borrow_mut().window_identity_cookies.insert(target.0, cookie);
        assert_eq!(task_queue(state, target.0), Some(queue));

        // Retiring a token and adopting the same HWND bits creates a different
        // cookie/token incarnation. The old guest alias must stay unresolved.
        worker::remove_window_maps(state, target.0, target.1);
        let replacement = identity::adopt_created_owned(state, target.1).unwrap();
        windows.windows.borrow_mut().push((replacement, target.1));
        assert_ne!(replacement, target.0);
        assert_eq!(task_queue(state, target.0), None);
        assert_eq!(task_queue(state, replacement), Some(queue));
        windows.retire((replacement, target.1));
        assert_eq!(task_queue(state, replacement), None);
        assert_eq!(task_queue(state, target.0), None);
    });
}
