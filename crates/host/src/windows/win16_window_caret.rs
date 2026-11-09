//! Native queue caret operations, executed only on the HWND-owning USER worker.
//!
//! Native controls can create the queue's caret too. Do not shadow its owner,
//! position, shape or hide/show count, or destroy it on guest focus messages.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16CaretShape, Win16HostGdiObject, Win16HostPoint,
    Win16WindowCall, Win16WindowCallResult, Win16WindowTarget,
};
use windows_sys::Win32::Foundation::{HWND, POINT};
use windows_sys::Win32::Graphics::Gdi::HBITMAP;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateCaret, DestroyCaret, GUITHREADINFO, GetCaretPos, GetGUIThreadInfo,
    GetWindowThreadProcessId, HideCaret, SetCaretPos, ShowCaret,
};

use super::win16_window_worker::WorkerState;

thread_local! {
    static CARET_BITMAPS: RefCell<BTreeMap<Win16HostGdiObject, Option<usize>>> =
        RefCell::new(BTreeMap::new());
}

/// Publish the operation's resolved bitmap tokens for the caret call.
/// The map is restored when `body` returns, including on panic. The
/// `RefCell` is not held across `body`.
pub(super) fn with_bitmaps<T>(
    bitmaps: &BTreeMap<Win16HostGdiObject, Option<usize>>,
    body: impl FnOnce() -> T,
) -> T {
    let previous =
        CARET_BITMAPS.with(|slot| std::mem::replace(&mut *slot.borrow_mut(), bitmaps.clone()));
    let _guard = CaretBitmapGuard { previous };
    body()
}

struct CaretBitmapGuard {
    previous: BTreeMap<Win16HostGdiObject, Option<usize>>,
}

impl Drop for CaretBitmapGuard {
    fn drop(&mut self) {
        CARET_BITMAPS.with(|slot| {
            *slot.borrow_mut() = std::mem::take(&mut self.previous);
        });
    }
}

fn caret_bitmap(shape: Win16CaretShape) -> Result<Option<HBITMAP>, RuntimeError> {
    Ok(match shape {
        Win16CaretShape::Solid => Some(std::ptr::null_mut()),
        Win16CaretShape::Gray => Some(1_usize as HBITMAP),
        Win16CaretShape::Bitmap(token) => {
            let mapped = CARET_BITMAPS.with(|slot| slot.borrow().get(&token).copied());
            match mapped {
                Some(Some(native)) => Some(native as HBITMAP),
                // The token is retained, but it is not a bitmap. Leave the
                // queue caret unchanged.
                Some(None) => None,
                None => {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "bitmap caret lost its resolved native bitmap",
                    ));
                }
            }
        }
    })
}

pub(super) fn execute(
    state: &Rc<RefCell<WorkerState>>,
    call: Win16WindowCall,
) -> Result<Win16WindowCallResult, RuntimeError> {
    use Win16WindowCall as Call;
    use Win16WindowCallResult as ResultValue;

    Ok(match call {
        Call::CreateCaret {
            window,
            shape,
            width,
            height,
        } => {
            // Bitmap 0 is solid and 1 is gray. Any other shape is a retained
            // HBITMAP. CreateCaret ignores width and height for a real bitmap.
            // A token that is not a bitmap does not replace the current caret.
            let Some(bitmap) = caret_bitmap(shape)? else {
                return Ok(ResultValue::Boolean(false));
            };
            // SAFETY: `CreateCaret` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
            ResultValue::Boolean(hwnd(state, window).is_some_and(|native| unsafe {
                CreateCaret(native, bitmap, i32::from(width), i32::from(height)) != 0
            }))
        }
        // SAFETY: `DestroyCaret` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        Call::DestroyCaret => ResultValue::Boolean(unsafe { DestroyCaret() != 0 }),
        // SAFETY: `SetCaretPos` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        Call::SetCaretPos { x, y } => {
            ResultValue::Boolean(unsafe { SetCaretPos(i32::from(x), i32::from(y)) != 0 })
        }
        Call::HideCaret { window } => ResultValue::Boolean(
            hwnd(state, window)
                // SAFETY: `HideCaret` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
                .is_some_and(|native| unsafe { HideCaret(native) != 0 }),
        ),
        Call::ShowCaret { window } => ResultValue::Boolean(
            hwnd(state, window)
                // SAFETY: `ShowCaret` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
                .is_some_and(|native| unsafe { ShowCaret(native) != 0 }),
        ),
        Call::GetCaretPos => {
            let mut point = POINT::default();
            // SAFETY: `GetCaretPos` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
            let success = unsafe { GetCaretPos(&mut point) != 0 };
            ResultValue::Point(success.then_some(Win16HostPoint {
                x: point.x,
                y: point.y,
            }))
        }
        _ => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "non-caret operation reached the native Win16 caret bridge",
            ));
        }
    })
}

fn hwnd(state: &Rc<RefCell<WorkerState>>, window: Win16WindowTarget) -> Option<HWND> {
    match window {
        // HideCaret/ShowCaret(NULL) mean the calling queue's current caret.
        Win16WindowTarget::Null => Some(std::ptr::null_mut()),
        Win16WindowTarget::Invalid => None,
        // Caret ownership is queue-local. Only exact live HWND identities on
        // this worker may be used; an unrelated thread's HWND is not a target.
        Win16WindowTarget::Mapped(window) => super::win16_window_identity::resolve(state, window),
    }
}

/// Run after window destruction callbacks and before queue retirement. Query
/// native state rather than a runtime-created flag, so control-created carets
/// are included and an already absent caret needs no destroy operation.
pub(super) fn shutdown() -> Result<(), RuntimeError> {
    let mut info = GUITHREADINFO {
        cbSize: std::mem::size_of::<GUITHREADINFO>() as u32,
        ..Default::default()
    };
    // GetGUIThreadInfo(0) addresses the foreground thread, not this worker.
    // Use its actual ID even when the application is inactive or unfocused.
    let thread = crate::windows::win32_safe::current_thread_id();
    // SAFETY: GetGUIThreadInfo writes into a caller-owned GUITHREADINFO.
    if unsafe { GetGUIThreadInfo(thread, &mut info) } == 0 {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "query the USER worker's queue caret before shutdown",
        ));
    }
    // The queue snapshot can expose a caret belonging to another GUI thread.
    // DestroyCaret cannot destroy that owner's resource. A stale HWND after
    // window destruction likewise proves no live caret window on this worker.
    // https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-destroycaret
    let owned = !info.hwndCaret.is_null()
        // SAFETY: GetWindowThreadProcessId optionally writes a caller-owned process id.
        && unsafe { GetWindowThreadProcessId(info.hwndCaret, std::ptr::null_mut()) } == thread;
    // SAFETY: `DestroyCaret` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
    if owned && unsafe { DestroyCaret() } == 0 {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "worker shutdown could not destroy its queue caret; cleanup remains incomplete",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{caret_bitmap, with_bitmaps};
    use runtime::{Win16CaretShape, Win16HostGdiObject};
    use std::collections::BTreeMap;
    use windows_sys::Win32::Graphics::Gdi::HBITMAP;

    #[test]
    fn bitmap_caret_uses_the_snapshotted_native_handle() {
        let token = Win16HostGdiObject(0x51);
        let other = Win16HostGdiObject(0x52);
        let map = BTreeMap::from([(token, Some(0xABCusize)), (other, None)]);
        with_bitmaps(&map, || {
            assert_eq!(
                caret_bitmap(Win16CaretShape::Solid).unwrap(),
                Some(std::ptr::null_mut())
            );
            assert_eq!(
                caret_bitmap(Win16CaretShape::Gray).unwrap(),
                Some(1_usize as HBITMAP),
            );
            assert_eq!(
                caret_bitmap(Win16CaretShape::Bitmap(token)).unwrap(),
                Some(0xABC_usize as HBITMAP),
            );
            assert_eq!(caret_bitmap(Win16CaretShape::Bitmap(other)).unwrap(), None);
            assert!(caret_bitmap(Win16CaretShape::Bitmap(Win16HostGdiObject(0x53))).is_err());
        });
        assert!(caret_bitmap(Win16CaretShape::Bitmap(token)).is_err());
    }
}
