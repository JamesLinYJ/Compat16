//! Opt-in: disposable Windows desktop only; changes test captions/icons.
//! cargo test -p host-services flash_window_tests -- --ignored --test-threads=1

use super::super::super::win16_window_ops::{execute as window_call, flash_window_with};
use super::*;
use runtime::{Win16WindowCall, Win16WindowCallResult};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    FlashWindow, IsIconic, SW_SHOWMINNOACTIVE, ShowWindow, WS_OVERLAPPEDWINDOW,
};

fn flash(state: &SharedWorker, window: Win16WindowTarget, invert: bool) -> bool {
    match window_call(state, Win16WindowCall::FlashWindow { window, invert }).unwrap() {
        Win16WindowCallResult::Boolean(value) => value,
        result => panic!("unexpected FlashWindow result: {result:?}"),
    }
}

#[test]
#[ignore = "disposable Windows desktop only; changes test caption and minimized icon"]
fn flash_window_uses_native_prior_state_and_win16_iconic_contract() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let target = windows.window(ptr::null_mut(), WS_OVERLAPPEDWINDOW);
        let mapped = Win16WindowTarget::Mapped(target.0);
        // FALSE restores the original caption; repeated calls have stable state.
        unsafe {
            FlashWindow(target.1, 0);
        }
        let previous = unsafe { FlashWindow(target.1, 0) != 0 };
        assert_eq!(flash(state, mapped, false), previous);
        unsafe {
            ShowWindow(target.1, SW_SHOWMINNOACTIVE);
        }
        assert_ne!(unsafe { IsIconic(target.1) }, 0);
        for invert in [false, true, false] {
            assert!(flash(state, mapped, invert));
            assert_ne!(unsafe { IsIconic(target.1) }, 0);
            assert_eq!(identity::resolve(state, target.0), Some(target.1));
        }
    });
}

#[test]
#[ignore = "disposable Windows desktop only; creates hidden native test windows"]
fn flash_window_rejects_null_unknown_retired_and_stale_without_native_calls() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let target = windows.window(ptr::null_mut(), WS_OVERLAPPEDWINDOW);
        let rejected = |window| {
            assert!(!flash_window_with(
                state,
                window,
                false,
                |_| panic!("invalid identity must not query native state"),
                |_, _| panic!("invalid identity must not flash")
            ));
        };
        for invalid in [
            Win16WindowTarget::Null,
            Win16WindowTarget::Invalid,
            Win16WindowTarget::Mapped(Win16HostWindow(u64::MAX)),
        ] {
            rejected(invalid);
        }
        let cookie = state.borrow().window_identity_cookies[&target.0];
        state
            .borrow_mut()
            .window_identity_cookies
            .get_mut(&target.0)
            .unwrap()
            .value = cookie.value.wrapping_add(1);
        rejected(Win16WindowTarget::Mapped(target.0));
        state
            .borrow_mut()
            .window_identity_cookies
            .insert(target.0, cookie);
        windows.retire(target);
        rejected(Win16WindowTarget::Mapped(target.0));
    });
}

#[test]
#[ignore = "disposable Windows desktop only; creates hidden native test windows"]
fn flash_window_normalizes_only_live_iconic_targets_after_reentry() {
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        for iconic in [false, true] {
            for invert in [false, true] {
                for previous in [false, true] {
                    let target = windows.window(ptr::null_mut(), WS_OVERLAPPEDWINDOW);
                    let mapped = Win16WindowTarget::Mapped(target.0);
                    assert_eq!(
                        flash_window_with(
                            state,
                            mapped,
                            invert,
                            |_| iconic,
                            |native, effective_invert| {
                                assert_eq!(native, target.1);
                                assert_eq!(effective_invert, iconic || invert);
                                assert!(state.try_borrow_mut().is_ok());
                                previous
                            }
                        ),
                        iconic || previous
                    );
                    let mut replacement = None;
                    // Inject native-call reentry to deterministically exercise
                    // reuse without depending on desktop caption paint policy.
                    assert_eq!(
                        flash_window_with(
                            state,
                            mapped,
                            invert,
                            |_| iconic,
                            |native, _| {
                                worker::remove_window_maps(state, target.0, native);
                                let new = identity::adopt_created_owned(state, native).unwrap();
                                windows.windows.borrow_mut().push((new, native));
                                replacement = Some(new);
                                state.borrow_mut().windows.insert(target.0, native);
                                assert!(!flash(state, mapped, true));
                                state.borrow_mut().windows.remove(&target.0);
                                previous
                            }
                        ),
                        previous
                    );
                    assert_eq!(identity::resolve(state, target.0), None);
                    assert_eq!(
                        identity::resolve(state, replacement.unwrap()),
                        Some(target.1)
                    );
                }
            }
        }
    });
}
