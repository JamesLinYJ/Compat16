//! Read-only native USER.309 oracle. Never changes clipping or cursor position.
//! cargo test -p host-services get_clip_cursor_tests -- --ignored --test-threads=1

use super::*;
use runtime::{Win16HostRect, Win16WindowCall, Win16WindowCallResult};
use windows_sys::Win32::Foundation::RECT;
use windows_sys::Win32::UI::WindowsAndMessaging::GetClipCursor;

fn native_clip() -> Option<Win16HostRect> {
    let mut rect = RECT::default();
    (unsafe { GetClipCursor(&mut rect) } != 0).then_some(Win16HostRect {
        left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom,
    })
}

#[test]
#[ignore = "requires Windows USER; reads only the desktop cursor clipping rectangle"]
fn get_clip_cursor_matches_read_only_native_oracle() {
    run_on_worker(|state| {
        // External applications may change desktop clipping concurrently.
        // Matching samples establish an observed native value, not a promise
        // that clipping remains constant. No screen-size fallback is valid:
        // native failure (e.g. WINSTA_READATTRIBUTES) is an optional output.
        for _ in 0..8 {
            let before = native_clip();
            let result = super::super::super::win16_window_ops::execute(
                state, Win16WindowCall::GetClipCursor,
            ).expect("complete native clipping read");
            let Win16WindowCallResult::Rect(actual) = result else {
                panic!("GetClipCursor must produce an optional RECT, never a guest BOOL");
            };
            let after = native_clip();
            if actual == before || actual == after {
                if actual.is_some() {
                    eprintln!("GetClipCursor: successful RECT matched a direct native read");
                } else {
                    eprintln!("GetClipCursor: native failure transport matched; successful geometry retrieval not established");
                }
                return;
            }
            // Even equal bracketing samples cannot exclude an ABA change.
            // Retry rather than failing on a potentially transient clip read.
        }
        panic!("GetClipCursor oracle did not establish a matching native sample; \
            possible bridge mismatch or concurrent desktop clipping/access changes; \
            rerun on a quiescent desktop");
    });
}

#[test]
fn get_clip_cursor_native_adapter_reads_once_and_never_fabricates_failure_bounds() {
    for success in [false, true] {
        let mut calls = 0;
        let result = super::super::super::win16_window_ops::get_clip_cursor_with(|rect| {
            calls += 1;
            // Even a failed native call may have touched its local output.
            *rect = RECT { left: -123, top: -456, right: 70000, bottom: 80000 };
            success
        });
        assert_eq!(calls, 1);
        let Win16WindowCallResult::Rect(actual) = result else {
            panic!("native read must produce an optional RECT");
        };
        assert_eq!(actual, success.then_some(Win16HostRect {
            left: -123, top: -456, right: 70000, bottom: 80000,
        }));
    }
}
