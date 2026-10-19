//! Real USER minimized sizing, using the shared hidden-window fixture.

use super::super::super::{
    win16_user_services_controls, win16_window_callbacks, win16_window_default,
    win16_window_position, win16_window_sizing, win16_window_worker,
};
use super::{HiddenWindows, RegisteredClass, on_worker};
use runtime::{
    Win16HostCallback, Win16HostMessage, Win16HostMessageOutput as Output, Win16HostMessageResult,
    Win16HostPoint, Win16HostWindow,
};
use std::{
    any::Any,
    cell::{Cell, RefCell},
};
use win16_window_worker::{ActiveOperation, LiveCallback};
use windows_sys::Win32::Foundation::{HWND, POINT, RECT};
use windows_sys::Win32::Graphics::Gdi::ClientToScreen;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreateMenu, DefWindowProcW, DestroyMenu, GetClientRect, GetMenuItemRect,
    GetSystemMetrics, GetWindowRect, HMENU, IsIconic, IsWindowVisible, MF_STRING, MoveWindow,
    SM_CXBORDER, SM_CXMINTRACK, SM_CYBORDER, SM_CYCAPTION, SM_CYMINTRACK, SW_RESTORE,
    SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, SetMenu, SetWindowPos, ShowWindow,
    WM_GETMINMAXINFO, WM_NCCALCSIZE, WM_WINDOWPOSCHANGING, WS_CAPTION, WS_MINIMIZE, WS_MINIMIZEBOX,
    WS_SYSMENU,
};

thread_local! {
    static TARGET: Cell<Option<Win16HostWindow>> = const { Cell::new(None) };
    static MAXIMUM: Cell<Option<Win16HostPoint>> = const { Cell::new(None) };
    static POSITION: Cell<Option<(i32, i32)>> = const { Cell::new(None) };
    static FAILURE: RefCell<Option<Box<dyn Any + Send>>> = const { RefCell::new(None) };
}

unsafe extern "system" fn probe(hwnd: HWND, message: u32, w: usize, l: isize) -> isize {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let window = TARGET.with(Cell::get)?;
        let state = win16_window_worker::worker_context()?;
        if message == WM_GETMINMAXINFO {
            let native =
                unsafe { &*(l as *const windows_sys::Win32::UI::WindowsAndMessaging::MINMAXINFO) };
            let mut info = win16_window_sizing::minmax_for_guest(native);
            if let Some(maximum) = MAXIMUM.with(Cell::get) {
                info.max_size = maximum;
            }
            // The fixture stands in for one already-validated guest reply.
            // Keep the real worker, native callback, and nested USER call.
            let mut worker = state.borrow_mut();
            let operation = worker.active_operations.last()?.id;
            let identity = worker.windows_by_native.get(&(hwnd as usize)).copied()?;
            worker.live_callbacks.push(LiveCallback {
                callback: Win16HostCallback(0x100),
                operation,
                source: runtime::Win16NativeCallbackSource::WindowMessage {
                    window,
                    class: None,
                    message,
                },
                creation: None,
                identity: Some(identity),
                message: Some(message),
                hwnd,
                w_param: Some(w),
                l_param: Some(l),
                native_message_context: None,
                creation_cookie: None,
                mdi_create_struct: None,
            });
            drop(worker);
            struct CallbackGuard(std::rc::Rc<RefCell<win16_window_worker::WorkerState>>);
            impl Drop for CallbackGuard {
                fn drop(&mut self) {
                    self.0.borrow_mut().live_callbacks.pop();
                }
            }
            let _callback = CallbackGuard(std::rc::Rc::clone(&state));
            let reply = Win16HostMessageResult {
                value: 0,
                dialog_result: None,
                output: Output::MinMaxInfo(info),
            };
            let written = win16_window_callbacks::write_native_output(
                &state,
                message,
                l,
                w,
                Some((window, hwnd)),
                None,
                None,
                &reply,
            );
            assert!(written);
            return Some(0);
        }
        if message == WM_NCCALCSIZE {
            let input = win16_window_callbacks::copy_nonclient_input(&state, w, l).unwrap();
            let result = win16_window_default::default_message(
                &state,
                window,
                None,
                Win16HostMessage::NonClientCalcSize {
                    w_param: input.w_param,
                    data: input.data,
                },
                None,
            )
            .unwrap()
            .unwrap();
            assert!(win16_window_callbacks::write_native_output(
                &state,
                message,
                l,
                w,
                Some((window, hwnd)),
                input.original_position,
                input.original_position_high_flags,
                &result
            ));
            return Some(result.value as isize);
        }
        if message == WM_WINDOWPOSCHANGING {
            let input = win16_window_position::copy_native_input(&state, w, l)
                .unwrap()
                .unwrap();
            let result = win16_window_default::default_message(
                &state,
                window,
                None,
                Win16HostMessage::WindowPosition {
                    changing: true,
                    w_param: input.w_param,
                    data: input.data,
                },
                None,
            )
            .unwrap()
            .unwrap();
            if let Output::WindowPosition(position) = &result.output {
                POSITION.with(|slot| slot.set(Some((position.width, position.height))));
            }
            assert!(win16_window_callbacks::write_native_output(
                &state,
                message,
                l,
                w,
                Some((window, hwnd)),
                None,
                Some(input.native_high_flags),
                &result
            ));
            return Some(result.value as isize);
        }
        None
    }));
    match result {
        Ok(Some(value)) => value,
        Ok(None) => unsafe { DefWindowProcW(hwnd, message, w, l) },
        Err(error) => {
            FAILURE.with(|slot| *slot.borrow_mut() = Some(error));
            unsafe { DefWindowProcW(hwnd, message, w, l) }
        }
    }
}

fn exercise(
    state: &std::rc::Rc<RefCell<win16_window_worker::WorkerState>>,
    maximum: Option<Win16HostPoint>,
    expected: (i32, i32),
    restore: bool,
) {
    let (response, _receive) = std::sync::mpsc::channel();
    state.borrow_mut().active_operations.push(ActiveOperation {
        id: 31337,
        kind: runtime::Win16NativeWindowOperationKind::Default,
        native_font: None,
        response,
        native_queue_dispatch: false,
        native_dialog_pump: false,
    });
    struct Reset<'a>(&'a std::rc::Rc<RefCell<win16_window_worker::WorkerState>>);
    impl Drop for Reset<'_> {
        fn drop(&mut self) {
            TARGET.with(|slot| slot.set(None));
            MAXIMUM.with(|slot| slot.set(None));
            self.0.borrow_mut().active_operations.pop();
        }
    }
    let _reset = Reset(state);
    let class = RegisteredClass::new(Some(probe));
    let mut windows = HiddenWindows::new(state);
    let (window, hwnd) = windows.create_geometry(
        class.0.as_ptr(),
        WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_MINIMIZE,
        154,
        240,
    );
    assert_ne!(unsafe { IsIconic(hwnd) }, 0);
    TARGET.with(|slot| slot.set(Some(window)));
    POSITION.with(|slot| slot.set(None));
    FAILURE.with(|slot| *slot.borrow_mut() = None);
    MAXIMUM.with(|slot| slot.set(maximum));
    if restore {
        let visible = unsafe { IsWindowVisible(hwnd) };
        let mut info: runtime::Win16HostMinMaxInfo =
            unsafe { win16_window_sizing::minmax_for_guest(&std::mem::zeroed()) };
        info.max_size = Win16HostPoint {
            x: i32::MAX,
            y: i32::MAX,
        };
        win16_window_sizing::repair_restore_size(
            state,
            window,
            hwnd,
            Win16HostPoint {
                x: expected.0,
                y: expected.1,
            },
            info,
        )
        .unwrap();
        assert_eq!(unsafe { IsWindowVisible(hwnd) }, visible);
        assert_ne!(unsafe { IsIconic(hwnd) }, 0);
    }
    assert_ne!(unsafe { MoveWindow(hwnd, 78, 35, 154, 240, 1) }, 0);
    if let Some(failure) = FAILURE.with(|slot| slot.borrow_mut().take()) {
        std::panic::resume_unwind(failure);
    }
    assert_eq!(POSITION.with(Cell::get), Some(expected));
    assert!(state.borrow().window_sizing_contexts.is_empty());
    if restore {
        unsafe { ShowWindow(hwnd, SW_RESTORE) };
        assert_eq!(unsafe { IsIconic(hwnd) }, 0);
        if let Some(failure) = FAILURE.with(|slot| slot.borrow_mut().take()) {
            std::panic::resume_unwind(failure);
        }
        let mut rect: RECT = unsafe { std::mem::zeroed() };
        assert_ne!(unsafe { GetWindowRect(hwnd, &mut rect) }, 0);
        assert_eq!((rect.right - rect.left, rect.bottom - rect.top), expected);
        let border_x = unsafe { GetSystemMetrics(SM_CXBORDER) };
        let border_y = unsafe { GetSystemMetrics(SM_CYBORDER) };
        let caption = crate::windows::win16_common::get_system_metrics(SM_CYCAPTION);
        let mut client: RECT = unsafe { std::mem::zeroed() };
        assert_ne!(unsafe { GetClientRect(hwnd, &mut client) }, 0);
        assert_eq!(
            (client.right, client.bottom),
            (
                expected.0 - border_x * 2,
                expected.1 - border_y * 2 - caption
            )
        );
        // Both conditional NCCALCSIZE layouts and AdjustWindowRect use the
        // same fixed-caption rule; their client/outer rectangles invert.
        let input = runtime::Win16HostRect {
            left: 0,
            top: 0,
            right: expected.0,
            bottom: expected.1,
        };
        let result = win16_window_default::default_message(
            state,
            window,
            None,
            Win16HostMessage::NonClientCalcSize {
                w_param: 0,
                data: runtime::Win16HostNonClientCalcSize::Rect(input),
            },
            None,
        )
        .unwrap()
        .unwrap();
        let Output::NonClientCalcSize(runtime::Win16HostNonClientCalcSize::Rect(client)) =
            result.output
        else {
            panic!("expected RECT output")
        };
        assert_eq!(
            (client.left, client.top, client.right, client.bottom),
            (
                border_x,
                border_y + caption,
                expected.0 - border_x,
                expected.1 - border_y
            )
        );
        let adjusted = win16_user_services_controls::execute(
            state,
            runtime::Win16HostDialogControlOperation::AdjustWindowRect {
                rect: client,
                style: WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                ex_style: 0,
                menu: false,
            },
        )
        .unwrap();
        let runtime::Win16HostDialogControlResult::Rect(Some(outer)) = adjusted else {
            panic!("expected adjusted RECT")
        };
        assert_eq!(outer, input);
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            GWL_EXSTYLE, GWL_STYLE, GetWindowLongPtrW, HTCLIENT, SM_CXDLGFRAME, SM_CXEDGE,
            SM_CXFRAME, SM_CYDLGFRAME, SM_CYEDGE, SM_CYFRAME, SWP_FRAMECHANGED, SendMessageW,
            SetWindowLongPtrW, WM_NCHITTEST, WS_EX_CLIENTEDGE, WS_EX_DLGMODALFRAME, WS_THICKFRAME,
        };
        let original_style = unsafe { GetWindowLongPtrW(hwnd, GWL_STYLE) } as u32;
        let original_ex = unsafe { GetWindowLongPtrW(hwnd, GWL_EXSTYLE) } as u32;
        for (extra, ex, bx, by) in [
            (
                WS_THICKFRAME,
                0,
                unsafe { GetSystemMetrics(SM_CXFRAME) },
                unsafe { GetSystemMetrics(SM_CYFRAME) },
            ),
            (
                0,
                WS_EX_DLGMODALFRAME,
                unsafe { GetSystemMetrics(SM_CXDLGFRAME) },
                unsafe { GetSystemMetrics(SM_CYDLGFRAME) },
            ),
            (
                0,
                WS_EX_CLIENTEDGE,
                border_x + unsafe { GetSystemMetrics(SM_CXEDGE) },
                border_y + unsafe { GetSystemMetrics(SM_CYEDGE) },
            ),
            (0, 0, border_x, border_y),
        ] {
            unsafe {
                SetWindowLongPtrW(hwnd, GWL_STYLE, (original_style | extra) as isize);
                SetWindowLongPtrW(hwnd, GWL_EXSTYLE, (original_ex | ex) as isize);
            }
            assert_ne!(
                unsafe {
                    SetWindowPos(
                        hwnd,
                        std::ptr::null_mut(),
                        0,
                        0,
                        0,
                        0,
                        SWP_FRAMECHANGED | SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
                    )
                },
                0
            );
            assert_ne!(unsafe { GetClientRect(hwnd, &mut rect) }, 0);
            assert_eq!(
                (rect.right, rect.bottom),
                (expected.0 - bx * 2, expected.1 - by * 2 - caption),
                "caption metrics must match each frame style"
            );
            let mut origin = POINT { x: 1, y: 1 };
            assert_ne!(unsafe { ClientToScreen(hwnd, &mut origin) }, 0);
            let point = i32::from(origin.x as u16) | (i32::from(origin.y as u16) << 16);
            assert_eq!(
                unsafe { SendMessageW(hwnd, WM_NCHITTEST, 0, point as isize) },
                HTCLIENT as isize,
                "native hit testing must recognize the projected client edge"
            );
        }
        // Size-only checks miss client rectangles that cover native menu text.
        struct UnattachedMenu(HMENU);
        impl Drop for UnattachedMenu {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe { DestroyMenu(self.0) };
                }
            }
        }
        let mut owned = UnattachedMenu(unsafe { CreateMenu() });
        assert!(!owned.0.is_null());
        assert_ne!(
            unsafe { AppendMenuW(owned.0, MF_STRING, 1, windows_sys::core::w!("File")) },
            0
        );
        let menu = owned.0;
        assert_ne!(unsafe { SetMenu(hwnd, menu) }, 0);
        owned.0 = std::ptr::null_mut(); // DestroyWindow now owns the menu.
        let mut item: RECT = unsafe { std::mem::zeroed() };
        assert_ne!(unsafe { GetMenuItemRect(hwnd, menu, 0, &mut item) }, 0);
        let mut origin = POINT { x: 0, y: 0 };
        assert_ne!(unsafe { ClientToScreen(hwnd, &mut origin) }, 0);
        assert!(
            item.bottom <= origin.y,
            "native menu is overlapped by the legacy client"
        );
        // Normal tracking and SWP_NOSIZE must retain modern native rules.
        assert_ne!(unsafe { MoveWindow(hwnd, 0, 0, 1, 1, 1) }, 0);
        let normal = (unsafe { GetSystemMetrics(SM_CXMINTRACK) }, unsafe {
            GetSystemMetrics(SM_CYMINTRACK)
        });
        assert_eq!(POSITION.with(Cell::get), Some(normal));
        assert_ne!(
            unsafe {
                SetWindowPos(
                    hwnd,
                    std::ptr::null_mut(),
                    0,
                    0,
                    1,
                    1,
                    SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
                )
            },
            0
        );
        assert_ne!(unsafe { GetWindowRect(hwnd, &mut rect) }, 0);
        assert_eq!((rect.right - rect.left, rect.bottom - rect.top), normal);
    }
}

#[test]
#[ignore = "requires a Windows USER desktop; creates owned native windows"]
fn legacy_minimized_move_restores_the_requested_window_size() {
    on_worker(|state| exercise(state, None, (154, 240), true));
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native windows"]
fn legacy_minimized_move_respects_guest_maximum_dimensions() {
    on_worker(|state| {
        exercise(
            state,
            Some(Win16HostPoint { x: 100, y: 70 }),
            (100, 70),
            false,
        )
    });
}
