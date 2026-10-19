//! Allocate and consume a native HDWP in one owner-thread operation.

use runtime::{Win16DeferredWindowPos, Win16WindowInsertAfter};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BeginDeferWindowPos, DeferWindowPos, EndDeferWindowPos, HWND_BOTTOM, HWND_NOTOPMOST, HWND_TOP,
    HWND_TOPMOST, SWP_NOZORDER,
};

use super::super::win16_window_identity::resolve_user_window;
use super::SharedWorker;

pub(super) fn execute(state: &SharedWorker, positions: Vec<Win16DeferredWindowPos>) -> bool {
    let Ok(count) = i32::try_from(positions.len()) else {
        return false;
    };
    let mut native_positions: Vec<(HWND, HWND, Win16DeferredWindowPos)> = Vec::new();
    if native_positions.try_reserve_exact(positions.len()).is_err() {
        return false;
    }
    // Validate every token and allocate all Rust storage before native Begin:
    // USER exposes no abort function for a still-live HDWP. Exact worker HWND
    // cookies cannot change before End's callbacks, because collection sends
    // no window messages and all three native APIs run on this same worker.
    // Foreign aliases retain the shared ordinary-USER resolution semantics.
    for position in positions {
        let Some(window) = resolve_user_window(state, position.window) else {
            return false;
        };
        let insert_after = if u32::from(position.flags) & SWP_NOZORDER != 0 {
            HWND_TOP
        } else {
            match position.insert_after {
                Win16WindowInsertAfter::Top => HWND_TOP,
                Win16WindowInsertAfter::Bottom => HWND_BOTTOM,
                Win16WindowInsertAfter::Topmost => HWND_TOPMOST,
                Win16WindowInsertAfter::NotTopmost => HWND_NOTOPMOST,
                Win16WindowInsertAfter::Window(token) => {
                    let Some(native) = resolve_user_window(state, token) else {
                        return false;
                    };
                    native
                }
            }
        };
        native_positions.push((window, insert_after, position));
    }

    // No Rust allocation, token resolution, early cancellation check, or
    // fallible bookkeeping may strand native ownership below this point.
    // Defer failure destroys the HDWP; success always uses the newly returned
    // handle. End owns the remaining native lifetime, including guest reentry
    // and terminal cancellation through the existing USER continuation.
    // SAFETY: `BeginDeferWindowPos` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    let mut batch = unsafe { BeginDeferWindowPos(count) };
    if batch.is_null() {
        return false;
    }
    for (window, insert_after, position) in native_positions {
        // SAFETY: `DeferWindowPos` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        batch = unsafe {
            DeferWindowPos(
                batch,
                window,
                insert_after,
                i32::from(position.x),
                i32::from(position.y),
                i32::from(position.width),
                i32::from(position.height),
                u32::from(position.flags),
            )
        };
        if batch.is_null() {
            return false;
        }
    }
    // Drop all worker borrows before native USER can send window procedures.
    // SAFETY: `EndDeferWindowPos` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    unsafe { EndDeferWindowPos(batch) != 0 }
}
