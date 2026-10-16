//! Read-only native USER.247 oracle and deterministic result adaptation.
//! cargo test -p host-services get_cursor_tests -- --ignored --test-threads=1

use super::*;
use runtime::{
    Win16HostUserCursorAcceleratorOperation as Operation,
    Win16HostUserCursorAcceleratorResult as ResultValue,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{GetCursor, HCURSOR};
use crate::windows::win16_windows::win16_user_cursor_accelerator::{execute as execute_cursor, get_cursor_with};

#[test]
fn get_cursor_native_adapter_reads_once_and_preserves_null_or_borrowed_identity() {
    let images = Win16Images::new(GuestTextCodec::new(1252).expect("Windows ANSI code page"));
    let mut calls = 0;
    assert_eq!(get_cursor_with(&images, || {
        calls += 1;
        ptr::null_mut()
    }).unwrap(), ResultValue::GetCursor(None));
    assert_eq!(calls, 1);

    // Fake native bits are only compared and registered as borrowed. They
    // never enter USER32, and releasing their token must not destroy them.
    let native = 0x123456usize as HCURSOR;
    let ResultValue::GetCursor(Some(cursor)) = get_cursor_with(&images, || {
        calls += 1;
        native
    }).unwrap() else { panic!("non-null cursor must produce an opaque cursor token"); };
    assert_eq!(calls, 2);
    assert_ne!(cursor.0, native as usize as u64);
    assert_eq!(images.native_cursor(cursor).unwrap(), Some(native));
    assert_eq!(get_cursor_with(&images, || {
        calls += 1;
        native
    }).unwrap(), ResultValue::GetCursor(Some(cursor)));
    assert_eq!(calls, 3);
    images.release_cursor(cursor).unwrap();
    assert_eq!(images.native_cursor(cursor).unwrap(), None);
}

#[test]
#[ignore = "requires Windows USER; reads only the calling USER worker's current cursor"]
fn get_cursor_matches_read_only_native_worker_oracle() {
    run_on_worker(|state| {
        let images = state.borrow().images.clone();
        for _ in 0..8 {
            let before = unsafe { GetCursor() };
            let result = execute_cursor(state, Operation::GetCursor)
                .expect("complete native current cursor read");
            let ResultValue::GetCursor(cursor) = result else {
                panic!("GetCursor must produce an optional opaque cursor token");
            };
            let actual = cursor.map(|cursor| images.native_cursor(cursor)
                .expect("resolve current cursor token")
                .expect("non-null current cursor token retains its native image"))
                .unwrap_or(ptr::null_mut());
            let after = unsafe { GetCursor() };
            if actual == before || actual == after {
                if actual.is_null() {
                    eprintln!("GetCursor: null native cursor matched; non-null cursor retrieval not established");
                } else {
                    eprintln!("GetCursor: resolved cursor matched a direct native read on the USER worker");
                }
                return;
            }
            // Bracketing reads cannot exclude a transient change or ABA.
        }
        panic!("GetCursor oracle did not establish a matching native sample; \
            possible bridge mismatch or concurrent cursor change; rerun on a quiescent desktop");
    });
}
