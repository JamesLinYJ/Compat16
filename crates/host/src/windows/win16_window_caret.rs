//! Native queue caret operations, executed only on the HWND-owning USER worker.
//!
//! Native controls can create the queue's caret too. Do not shadow its owner,
//! position, shape or hide/show count, or destroy it on guest focus messages.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16CaretShape, Win16HostPoint,
    Win16WindowCall, Win16WindowCallResult, Win16WindowTarget,
};
use windows_sys::Win32::Foundation::{HWND, POINT};
use windows_sys::Win32::Graphics::Gdi::HBITMAP;
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateCaret, DestroyCaret, GetCaretPos, GetGUIThreadInfo, GUITHREADINFO,
    HideCaret, SetCaretPos, ShowCaret,
};

use super::win16_window_worker::WorkerState;

pub(super) fn execute(
    state: &Rc<RefCell<WorkerState>>,
    call: Win16WindowCall,
) -> Result<Win16WindowCallResult, RuntimeError> {
    use Win16WindowCall as Call;
    use Win16WindowCallResult as ResultValue;

    Ok(match call {
        Call::CreateCaret { window, shape, width, height } => {
            // These are native API shape selectors, never guest HBITMAP bits.
            // USER chooses default dimensions for zero and starts hidden.
            let bitmap: HBITMAP = match shape {
                Win16CaretShape::Solid => std::ptr::null_mut(),
                Win16CaretShape::Gray => 1_usize as HBITMAP,
            };
            ResultValue::Boolean(hwnd(state, window).is_some_and(|native| unsafe {
                CreateCaret(native, bitmap, i32::from(width), i32::from(height)) != 0
            }))
        }
        Call::DestroyCaret => ResultValue::Boolean(unsafe { DestroyCaret() != 0 }),
        Call::SetCaretPos { x, y } => ResultValue::Boolean(unsafe {
            SetCaretPos(i32::from(x), i32::from(y)) != 0
        }),
        Call::HideCaret { window } => ResultValue::Boolean(hwnd(state, window)
            .is_some_and(|native| unsafe { HideCaret(native) != 0 })),
        Call::ShowCaret { window } => ResultValue::Boolean(hwnd(state, window)
            .is_some_and(|native| unsafe { ShowCaret(native) != 0 })),
        Call::GetCaretPos => {
            let mut point = POINT::default();
            let success = unsafe { GetCaretPos(&mut point) != 0 };
            ResultValue::Point(success.then_some(Win16HostPoint { x: point.x, y: point.y }))
        }
        _ => return Err(RuntimeError::new(Kind::InternalInvariant,
            "non-caret operation reached the native Win16 caret bridge")),
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
    if unsafe { GetGUIThreadInfo(GetCurrentThreadId(), &mut info) } == 0 {
        return Err(RuntimeError::new(Kind::HostFailure,
            "query the USER worker's queue caret before shutdown"));
    }
    if !info.hwndCaret.is_null() && unsafe { DestroyCaret() } == 0 {
        return Err(RuntimeError::new(Kind::HostFailure,
            "worker shutdown could not destroy its queue caret; cleanup remains incomplete"));
    }
    Ok(())
}
