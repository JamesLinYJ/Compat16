//! Private window used to wake and cancel the DDEML owner during modal pumps.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CREATESTRUCTW, CreateWindowExW, DefWindowProcW, DestroyWindow, GWLP_USERDATA,
    GetWindowLongPtrW, HWND_MESSAGE, RegisterClassW, SetWindowLongPtrW, UnregisterClassW,
    WM_NCCREATE, WM_NCDESTROY, WNDCLASSW,
};

use super::{WAKE_MESSAGE, WorkerContext};

pub(super) struct ControlWindow {
    pub(super) hwnd: windows_sys::Win32::Foundation::HWND,
    class_name: Vec<u16>,
    instance: windows_sys::Win32::Foundation::HINSTANCE,
}

pub(super) fn create(
    context: &WorkerContext,
    thread_id: u32,
) -> Result<ControlWindow, RuntimeError> {
    let instance = unsafe { GetModuleHandleW(ptr::null()) };
    if instance.is_null() {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "GetModuleHandleW could not identify the DDE owner module",
        ));
    }
    let class_name: Vec<u16> = format!("DdeOwnerControl_{thread_id}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let class = WNDCLASSW {
        lpfnWndProc: Some(control_window_proc),
        hInstance: instance,
        lpszClassName: class_name.as_ptr(),
        ..WNDCLASSW::default()
    };
    if unsafe { RegisterClassW(&class) } == 0 {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "RegisterClassW could not register the DDE owner control class",
        ));
    }
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            class_name.as_ptr(),
            ptr::null(),
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            ptr::null_mut(),
            instance,
            (context as *const WorkerContext).cast(),
        )
    };
    if hwnd.is_null() {
        unsafe {
            UnregisterClassW(class_name.as_ptr(), instance);
        }
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "CreateWindowExW could not create the DDE owner control window",
        ));
    }
    Ok(ControlWindow {
        hwnd,
        class_name,
        instance,
    })
}

pub(super) fn destroy(window: ControlWindow) -> Result<(), RuntimeError> {
    let window_destroyed = unsafe { DestroyWindow(window.hwnd) } != 0;
    let class_removed =
        unsafe { UnregisterClassW(window.class_name.as_ptr(), window.instance) } != 0;
    if !window_destroyed || !class_removed {
        return Err(RuntimeError::new(
            Kind::HostFailure,
            "DDE owner control window or class could not be released",
        ));
    }
    Ok(())
}

unsafe extern "system" fn control_window_proc(
    hwnd: windows_sys::Win32::Foundation::HWND,
    message: u32,
    wparam: windows_sys::Win32::Foundation::WPARAM,
    lparam: windows_sys::Win32::Foundation::LPARAM,
) -> windows_sys::Win32::Foundation::LRESULT {
    match catch_unwind(AssertUnwindSafe(|| {
        control_window_proc_inner(hwnd, message, wparam, lparam)
    })) {
        Ok(result) => result,
        Err(_) => {
            // Recovery is itself inside a second unwind barrier: a panic in
            // fatal-latch or cancellation code must also stay inside WndProc.
            let _ = catch_unwind(AssertUnwindSafe(|| {
                let candidate =
                    unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const WorkerContext;
                let _ = super::with_current_worker(|context| {
                    if ptr::eq(context, candidate) {
                        super::latch_control_panic(context);
                    }
                });
            }));
            0
        }
    }
}

fn control_window_proc_inner(
    hwnd: windows_sys::Win32::Foundation::HWND,
    message: u32,
    wparam: windows_sys::Win32::Foundation::WPARAM,
    lparam: windows_sys::Win32::Foundation::LPARAM,
) -> windows_sys::Win32::Foundation::LRESULT {
    if message == WM_NCCREATE {
        let create = unsafe { &*(lparam as *const CREATESTRUCTW) };
        let context = create.lpCreateParams.cast::<WorkerContext>();
        if context.is_null() {
            return 0;
        }
        unsafe {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, context as isize);
        }
        return 1;
    }
    let candidate = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const WorkerContext;
    if message == WAKE_MESSAGE && !candidate.is_null() {
        // GWLP_USERDATA can outlive WorkerContext if DestroyWindow fails.
        // Dereference only the exact context still published in this thread's
        // live TLS slot; the slot is cleared before `run` returns.
        let live = super::with_current_worker(|context| {
            if !ptr::eq(context, candidate) {
                return false;
            }
            super::on_control_message(context, wparam, lparam);
            true
        });
        if live == Some(true) {
            return 0;
        }
        return 0;
    }
    if message == WM_NCDESTROY {
        unsafe {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
    }
    unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
}
