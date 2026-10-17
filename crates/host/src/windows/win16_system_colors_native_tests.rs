//! Global USER effects run only on disposable GitHub-hosted native runners.
use super::*;
use runtime::{Win16WindowCall, Win16WindowCallResult};
use windows_sys::Win32::Graphics::Gdi::{COLOR_WINDOW, GetSysColor, SetSysColors};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::SwapMouseButton;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GWLP_WNDPROC, GetSystemMetrics, SM_SWAPBUTTON, SetWindowLongPtrW, WM_SYSCOLORCHANGE,
};

fn require_disposable_runner() {
    assert_eq!(
        std::env::var("GITHUB_ACTIONS").as_deref(),
        Ok("true"),
        "BLOCKED: disposable CI required"
    );
    assert_eq!(
        std::env::var("RUNNER_ENVIRONMENT").as_deref(),
        Ok("github-hosted"),
        "BLOCKED: shared desktops excluded"
    );
    assert_eq!(std::env::var("RUNNER_OS").as_deref(), Ok("Windows"));
    let (runner, architecture) = match std::env::consts::ARCH {
        "x86_64" => ("windows-2022", "x64"),
        "aarch64" => ("windows-11-arm", "arm64"),
        _ => panic!("unsupported native host"),
    };
    assert_eq!(std::env::var("NATIVE_RUNNER_LABEL").as_deref(), Ok(runner));
    assert_eq!(
        std::env::var("BUILD_ARCHITECTURE").as_deref(),
        Ok(architecture)
    );
}
thread_local! {
    static COLOR_NOTIFICATIONS: Cell<usize> = const {Cell::new(0)};
    static COLOR_ACTION: RefCell<Option<Box<dyn FnOnce()>>> = const {RefCell::new(None)};
}
unsafe extern "system" fn color_proc(hwnd: HWND, message: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    if message == WM_SYSCOLORCHANGE {
        COLOR_NOTIFICATIONS.with(|count| count.set(count.get() + 1));
        let action = COLOR_ACTION.with(|slot| slot.borrow_mut().take());
        if let Some(action) = action {
            if let Err(error) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
                CALLBACK_PANIC.with(|slot| *slot.borrow_mut() = Some(error));
            }
        }
    }
    unsafe { DefWindowProcW(hwnd, message, wp, lp) }
}
struct RestoreColor {
    value: u32,
    armed: bool,
}
impl RestoreColor {
    fn restore(&mut self) -> bool {
        // SAFETY: both single-element values remain live during the call.
        let result = unsafe { SetSysColors(1, &COLOR_WINDOW, &self.value) != 0 };
        if result {
            self.armed = false;
        }
        result
    }
}
impl Drop for RestoreColor {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.restore();
        }
    }
}

#[test]
#[ignore = "disposable CI only; temporarily changes and restores one system color"]
fn system_colors_native_worker_allows_synchronous_notification_reentry() {
    require_disposable_runner();
    run_on_worker(|state| {
        let windows = NativeWindows::new(state);
        let window = windows.window(ptr::null_mut(), 0);
        assert_ne!(
            unsafe { SetWindowLongPtrW(window.1, GWLP_WNDPROC, color_proc as *const () as isize) },
            0
        );
        let original = unsafe { GetSysColor(COLOR_WINDOW) };
        let mut restore = RestoreColor {
            value: original,
            armed: true,
        };
        let changed = original ^ 1;
        COLOR_NOTIFICATIONS.with(|count| count.set(0));
        let retained = Rc::clone(state);
        COLOR_ACTION.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                // Synchronous notification must be able to reenter worker state.
                assert_eq!(identity::resolve(&retained, window.0), Some(window.1));
                assert_eq!(unsafe { GetSysColor(COLOR_WINDOW) }, changed);
                drop(retained.borrow_mut());
            }))
        });
        let result = super::super::super::win16_window_ops::execute(
            state,
            Win16WindowCall::SetSysColors {
                indices: vec![COLOR_WINDOW],
                colors: vec![changed],
            },
        )
        .unwrap();
        let pending = COLOR_ACTION.with(|slot| slot.borrow_mut().take().is_some());
        if let Some(error) = CALLBACK_PANIC.with(|slot| slot.borrow_mut().take()) {
            std::panic::resume_unwind(error);
        }
        assert!(matches!(result, Win16WindowCallResult::Boolean(true)));
        assert!(
            !pending,
            "SetSysColors must notify the owning thread synchronously"
        );
        assert!(COLOR_NOTIFICATIONS.with(Cell::get) > 0);
        assert_eq!(unsafe { GetSysColor(COLOR_WINDOW) }, changed);
        assert!(restore.restore());
        assert_eq!(unsafe { GetSysColor(COLOR_WINDOW) }, original);
    });
}

struct RestoreButtons(bool);
impl Drop for RestoreButtons {
    fn drop(&mut self) {
        unsafe {
            SwapMouseButton(i32::from(self.0));
        }
    }
}
#[test]
#[ignore = "disposable CI only; temporarily reverses and restores mouse-button mapping"]
fn system_colors_native_mouse_adapter_returns_previous_mapping() {
    require_disposable_runner();
    let original = unsafe { GetSystemMetrics(SM_SWAPBUTTON) != 0 };
    let _restore = RestoreButtons(original);
    assert_eq!(
        crate::windows::win16_user_services_system::swap_mouse_button(!original),
        original
    );
    assert_eq!(unsafe { GetSystemMetrics(SM_SWAPBUTTON) != 0 }, !original);
    assert_eq!(
        crate::windows::win16_user_services_system::swap_mouse_button(original),
        !original
    );
    assert_eq!(unsafe { GetSystemMetrics(SM_SWAPBUTTON) != 0 }, original);
}
