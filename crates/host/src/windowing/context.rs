use super::events::{decode_character, decode_key, decode_mouse};
use super::paint::paint_window;
use std::cell::Cell;
use std::sync::mpsc::Sender;
use std::sync::Mutex;
use windows_sys::Win32::Foundation::{GetLastError, HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DefWindowProcW, GetWindowLongPtrW, SetWindowLongPtrW, GWLP_USERDATA, WM_CLOSE, WM_KEYDOWN,
    WM_CHAR, WM_KEYUP, WM_NCDESTROY, WM_PAINT, WM_SYSKEYDOWN, WM_SYSKEYUP,
};
use graphics::{HostEvent, WindowHandle};

use super::WindowingError;

#[derive(Debug)]
pub(super) enum CallbackRecord {
    Event(HostEvent),
    Failure(WindowingError),
}

pub(super) struct WindowContext {
    pub(super) handle: WindowHandle,
    pub(super) events: Sender<CallbackRecord>,
    pub(super) surface: Mutex<Option<super::paint::OwnedDib>>,
    destroyed: Cell<bool>,
}

impl WindowContext {
    pub(super) fn new(handle: WindowHandle, events: Sender<CallbackRecord>) -> Self {
        Self {
            handle,
            events,
            surface: Mutex::new(None),
            destroyed: Cell::new(false),
        }
    }

    pub(super) fn is_destroyed(&self) -> bool {
        self.destroyed.get()
    }

    pub(super) fn emit(&self, event: HostEvent) {
        let _ = self.events.send(CallbackRecord::Event(event));
    }

    pub(super) fn report_native_failure(&self, operation: &'static str) {
        let error = unsafe { GetLastError() };
        let _ = self
            .events
            .send(CallbackRecord::Failure(WindowingError::Native {
                operation,
                code: (error != 0).then_some(error),
            }));
    }

    pub(super) fn report_failure(&self, error: WindowingError) {
        let _ = self.events.send(CallbackRecord::Failure(error));
    }
}

/// Window procedure installed only on the adapter's private registered class.
/// The panic boundary prevents Rust unwinding from crossing the system ABI.
pub(super) unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        window_proc_inner(hwnd, message, w_param, l_param)
    })) {
        Ok(result) => result,
        Err(_) => {
            // SAFETY: The context remains owned by its Windowing record or the
            // synchronous destroy/create caller through this callback return.
            unsafe {
                report_callback_panic(hwnd);
            }
            // SAFETY: hwnd/message parameters are those supplied to this system
            // callback; DefWindowProcW does not retain any borrowed pointers.
            unsafe { DefWindowProcW(hwnd, message, w_param, l_param) }
        }
    }
}

unsafe fn report_callback_panic(hwnd: HWND) {
    // SAFETY: This callback is installed only for our private class. A nonzero
    // GWLP_USERDATA value was written from a stable WindowContext Box owned
    // until WM_NCDESTROY has completed.
    let raw_context = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const WindowContext;
    if !raw_context.is_null() {
        // SAFETY: See the ownership contract above.
        unsafe { &*raw_context }.report_failure(WindowingError::CallbackPanic);
    }
}

unsafe fn window_proc_inner(hwnd: HWND, message: u32, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
    // SAFETY: Only the private class registered by this module stores a pointer
    // in GWLP_USERDATA. The owning Windowing keeps the Box alive until
    // WM_NCDESTROY has returned (including parent-triggered child destruction).
    let raw_context = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const WindowContext;
    let context = if raw_context.is_null() {
        None
    } else {
        // SAFETY: See the callback-context lifetime contract above.
        Some(unsafe { &*raw_context })
    };

    if message == WM_NCDESTROY {
        if let Some(context) = context {
            context.destroyed.set(true);
            // WM_NCDESTROY is the final lifetime notification. Clear the stored
            // pointer before control returns to Windows; Rust frees it afterward.
            unsafe {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            }
        }
        // SAFETY: Forwarding this final notification is required by USER.
        return unsafe { DefWindowProcW(hwnd, message, w_param, l_param) };
    }

    let Some(context) = context else {
        // Creation failure or an unrelated HWND reached this procedure.
        return unsafe { DefWindowProcW(hwnd, message, w_param, l_param) };
    };

    match message {
        WM_CLOSE => {
            context.emit(HostEvent::Close {
                window: context.handle,
            });
            // Keep native destruction under portable USER/model control.
            0
        }
        WM_PAINT => {
            paint_window(hwnd, context);
            0
        }
        WM_CHAR => {
            if let Some(event) = decode_character(context.handle, message, w_param, l_param) {
                context.emit(event);
            }
            0
        }
        WM_KEYDOWN | WM_SYSKEYDOWN | WM_KEYUP | WM_SYSKEYUP => {
            if let Some(event) = decode_key(context.handle, message, w_param, l_param) {
                context.emit(event);
            }
            // Keep default system-key behavior, including Alt+F4 -> WM_CLOSE.
            unsafe { DefWindowProcW(hwnd, message, w_param, l_param) }
        }
        _ => {
            if let Some(event) = decode_mouse(context.handle, message, w_param, l_param) {
                context.emit(event);
            }
            // Preserve native activation, focus, and non-modeled input behavior.
            unsafe { DefWindowProcW(hwnd, message, w_param, l_param) }
        }
    }
}
