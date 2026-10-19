//! Saved procedure reuse on actual same-thread native windows, without input.

use super::*;
use std::cell::Cell;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, RegisterClassW, UnregisterClassW,
    WM_NCDESTROY, WM_PAINT, WNDCLASSW, WNDPROC, WS_POPUP,
};
use super::super::Win16Windows;
use super::super::win16_window_worker::{WorkerCommand, remove_window_maps};
use crate::windows::{guest_text::GuestTextCodec, win16_gdi::Win16Dcs, win16_images::Win16Images};

fn on_worker(run: fn(&Rc<RefCell<WorkerState>>)) {
    let codec = GuestTextCodec::new(1252).unwrap();
    let windows = Win16Windows::new(
        Win16Dcs::with_text_codec(codec), Win16Images::new(codec),
        Arc::new(AtomicU64::new(1)), codec,
    );
    let worker = windows.worker.as_ref().expect("start native USER worker");
    let (response, receive) = mpsc::channel();
    worker.send(WorkerCommand::TestWindowData { run, response }).unwrap();
    match receive.recv_timeout(Duration::from_secs(20)) {
        Ok(Ok(())) => {}
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(error) => {
            // A timed-out callback must not turn Drop's join into an unbounded wait.
            std::mem::forget(windows);
            panic!("native procedure worker did not finish: {error}");
        }
    }
}

struct HiddenWindows<'a> {
    state: &'a Rc<RefCell<WorkerState>>,
    windows: Vec<(Win16HostWindow, HWND)>,
}

impl<'a> HiddenWindows<'a> {
    fn new(state: &'a Rc<RefCell<WorkerState>>) -> Self {
        Self { state, windows: Vec::new() }
    }

    fn create(&mut self, class: *const u16) -> (Win16HostWindow, HWND) {
        self.create_styled(class, WS_POPUP)
    }

    fn create_styled(&mut self, class: *const u16, style: u32) -> (Win16HostWindow, HWND) {
        self.create_geometry(class, style, 80, 30)
    }

    fn create_geometry(&mut self, class: *const u16, style: u32, width: i32, height: i32) -> (Win16HostWindow, HWND) {
        let hwnd = unsafe { CreateWindowExW(0, class, windows_sys::core::w!("native text"),
            style, 0, 0, width, height, ptr::null_mut(), ptr::null_mut(),
            GetModuleHandleW(ptr::null()), ptr::null()) };
        assert!(!hwnd.is_null(), "create hidden native window");
        let token = match win16_window_identity::adopt_created_owned(self.state, hwnd) {
            Ok(token) => token,
            Err(error) => {
                unsafe { DestroyWindow(hwnd) };
                panic!("adopt hidden window: {error}");
            }
        };
        self.windows.push((token, hwnd));
        (token, hwnd)
    }

    fn destroy(&mut self, window: Win16HostWindow) {
        let index = self.windows.iter().position(|(token, _)| *token == window).unwrap();
        let (token, hwnd) = self.windows.remove(index);
        assert_ne!(unsafe { DestroyWindow(hwnd) }, 0);
        remove_window_maps(self.state, token, hwnd);
    }
}

#[path = "win16_window_sizing_native_tests.rs"]
mod sizing;

impl Drop for HiddenWindows<'_> {
    fn drop(&mut self) {
        for (token, hwnd) in self.windows.drain(..).rev() {
            unsafe { DestroyWindow(hwnd) };
            remove_window_maps(self.state, token, hwnd);
        }
    }
}

struct RegisteredClass(Vec<u16>, windows_sys::Win32::Foundation::HINSTANCE);

impl RegisteredClass {
    fn new(procedure: WNDPROC) -> Self {
        static NEXT_CLASS: AtomicU64 = AtomicU64::new(1);
        let name: Vec<u16> = format!("Compat16.NativeProcedure.{}", NEXT_CLASS.fetch_add(1, Ordering::Relaxed))
            .encode_utf16().chain(Some(0)).collect();
        let instance = unsafe { GetModuleHandleW(ptr::null()) };
        let class = WNDCLASSW { lpfnWndProc: procedure, hInstance: instance,
            lpszClassName: name.as_ptr(), ..unsafe { std::mem::zeroed() } };
        assert_ne!(unsafe { RegisterClassW(&class) }, 0);
        Self(name, instance)
    }
}

impl Drop for RegisteredClass {
    fn drop(&mut self) { unsafe { UnregisterClassW(self.0.as_ptr(), self.1) }; }
}

thread_local! {
    static PAINT_WINDOW: Cell<usize> = const { Cell::new(0) };
}

unsafe extern "system" fn paint_probe(hwnd: HWND, message: u32, w: usize, l: isize) -> isize {
    if message == WM_PAINT {
        PAINT_WINDOW.with(|slot| slot.set(hwnd as usize));
        return 0x55aa;
    }
    unsafe { DefWindowProcW(hwnd, message, w, l) }
}

fn null_result(state: &Rc<RefCell<WorkerState>>, procedure: Win16HostProcedure,
    window: Win16HostWindow) -> Option<u32> {
    call(state, procedure, window, None, Win16HostMessage::Scalar {
        kind: runtime::Win16ScalarMessage::Null, w_param: 0, l_param: 0,
    }, None)
        .unwrap().map(|result| result.value)
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native windows"]
fn saved_native_procedure_reuses_the_same_implementation_for_paint() {
    on_worker(|state| {
        let class = RegisteredClass::new(Some(paint_probe));
        let mut windows = HiddenWindows::new(state);
        let (source, source_hwnd) = windows.create(class.0.as_ptr());
        let (target, target_hwnd) = windows.create(class.0.as_ptr());
        assert_eq!(get_window_procedure(source_hwnd), get_window_procedure(target_hwnd));
        let saved = query(state, source).unwrap().unwrap();
        assert_eq!(null_result(state, saved, target), Some(0));
        PAINT_WINDOW.with(|slot| slot.set(0));
        let painted = call(state, saved, target, None,
            Win16HostMessage::Paint { dc: None }, None).unwrap().unwrap();
        assert_eq!(painted.value, 0x55aa, "preserve the native WM_PAINT result");
        assert_eq!(PAINT_WINDOW.with(Cell::get), target_hwnd as usize,
            "the saved implementation must receive the target HWND");
    });
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native windows"]
fn saved_native_procedure_uses_target_subclass_proof_after_source_retirement() {
    on_worker(|state| {
        let mut windows = HiddenWindows::new(state);
        let (source, _) = windows.create(windows_sys::core::w!("STATIC"));
        let (target, _) = windows.create(windows_sys::core::w!("STATIC"));
        let saved = query(state, source).unwrap().unwrap();
        let target_saved = query(state, target).unwrap().unwrap();
        assert_ne!(saved, target_saved, "capture identities remain window-specific");
        assert_eq!(set_procedure(state, source, saved, false).unwrap(), Some(saved));
        assert_eq!(set_procedure(state, target, target_saved, false).unwrap(), Some(target_saved));
        assert_eq!(null_result(state, saved, target), Some(0));
        let binding = state.borrow().window_identity_cookies[&target];
        state.borrow_mut().window_identity_cookies.get_mut(&target).unwrap().value ^= usize::MAX;
        let stale = null_result(state, saved, target);
        state.borrow_mut().window_identity_cookies.insert(target, binding);
        assert_eq!(stale, None, "shared code does not bypass the target cookie");
        windows.destroy(source);
        assert_eq!(null_result(state, saved, source), None, "retired HWND stays retired");
        assert_eq!(null_result(state, saved, target), Some(0), "provider code remains pinned");
        assert_eq!(set_procedure(state, target, target_saved, true).unwrap(), Some(target_saved));
    });
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native windows"]
fn saved_native_procedure_rejects_unproven_targets_and_cross_window_installation() {
    on_worker(|state| {
        let mut windows = HiddenWindows::new(state);
        let (source, _) = windows.create(windows_sys::core::w!("STATIC"));
        let (target, _) = windows.create(windows_sys::core::w!("EDIT"));
        let (same_implementation, _) = windows.create(windows_sys::core::w!("STATIC"));
        let saved = query(state, source).unwrap().unwrap();
        assert_eq!(set_procedure(state, same_implementation, saved, false).unwrap(), None,
            "installation still requires that exact window's capture");
        assert_eq!(null_result(state, saved, target), None);
        assert_eq!(null_result(state, saved, Win16HostWindow(u64::MAX)), None);
        assert_eq!(set_procedure(state, target, saved, false).unwrap(), None);
        let target_saved = query(state, target).unwrap().unwrap();
        assert_eq!(set_procedure(state, target, target_saved, false).unwrap(), Some(target_saved));
        assert_eq!(null_result(state, saved, target), None, "a different saved base is insufficient");
        let binding = state.borrow().window_identity_cookies[&source];
        state.borrow_mut().window_identity_cookies.get_mut(&source).unwrap().value ^= usize::MAX;
        let stale = null_result(state, saved, source);
        state.borrow_mut().window_identity_cookies.insert(source, binding);
        assert_eq!(stale, None, "same-window calls still require the original live cookie");
    });
}

thread_local! {
    static DESTROY_TARGET: Cell<Option<(Win16HostProcedure, Win16HostWindow, usize)>> = const { Cell::new(None) };
    static DESTROY_CALLS: Cell<usize> = const { Cell::new(0) };
    static NESTED_DESTROY: RefCell<Option<Result<Option<Win16HostMessageResult>, RuntimeError>>> = const { RefCell::new(None) };
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native windows"]
fn saved_native_procedure_keeps_typed_control_dispatch_identity() {
    on_worker(|state| {
        let mut windows = HiddenWindows::new(state);
        let (source, _) = windows.create(windows_sys::core::w!("EDIT"));
        let (target, _) = windows.create(windows_sys::core::w!("EDIT"));
        let saved = query(state, source).unwrap().unwrap();
        let target_saved = query(state, target).unwrap().unwrap();
        assert_eq!(set_procedure(state, target, target_saved, false).unwrap(), Some(target_saved));
        let dispatch = runtime::Win16HostControlDispatch::CallWindowProc { procedure: saved };
        let expected = super::super::win16_standard_controls::query(state,
            runtime::Win16HostControlQuery { window: target, dispatch }).unwrap().identity.unwrap();
        let result = call(state, saved, target, None,
            Win16HostMessage::Control(runtime::Win16HostControlCall {
                window: target, expected, dispatch,
                message: runtime::Win16HostControlMessage::Edit(runtime::Win16HostEditMessage::GetLineCount),
            }), None).unwrap().expect("typed EDIT call through shared saved procedure");
        assert_eq!(result.value, 1);
    });
}

unsafe extern "system" fn destroy_probe(hwnd: HWND, message: u32, w: usize, l: isize) -> isize {
    if message == WM_NCDESTROY
        && let Some((saved, window, target)) = DESTROY_TARGET.with(Cell::get)
        && target == hwnd as usize
    {
        let calls = DESTROY_CALLS.with(|count| { let next = count.get() + 1; count.set(next); next });
        if calls > 1 {
            // Observe forbidden reentry without freeing native state twice.
            return 0x55;
        }
        if let Some(state) = super::super::win16_window_worker::worker_context() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
                call(&state, saved, window, None, Win16HostMessage::Scalar {
                    kind: runtime::Win16ScalarMessage::NcDestroy, w_param: 0, l_param: 0,
                }, None))).unwrap_or_else(|_| Err(RuntimeError::new(Kind::InternalInvariant,
                    "nested saved procedure call panicked")));
            NESTED_DESTROY.with(|slot| *slot.borrow_mut() = Some(result));
        }
    }
    unsafe { DefWindowProcW(hwnd, message, w, l) }
}

#[test]
#[ignore = "requires a Windows USER desktop; creates hidden native windows"]
fn saved_native_procedure_alias_cannot_repeat_base_nc_destroy() {
    on_worker(|state| {
        let class = RegisteredClass::new(Some(destroy_probe));
        let mut windows = HiddenWindows::new(state);
        let (source, _) = windows.create(class.0.as_ptr());
        let (target, hwnd) = windows.create(class.0.as_ptr());
        let saved = query(state, source).unwrap().unwrap();
        let target_saved = query(state, target).unwrap().unwrap();
        assert_eq!(set_procedure(state, target, target_saved, false).unwrap(), Some(target_saved));
        DESTROY_TARGET.with(|slot| slot.set(Some((saved, target, hwnd as usize))));
        DESTROY_CALLS.with(|slot| slot.set(0));
        NESTED_DESTROY.with(|slot| *slot.borrow_mut() = None);
        windows.destroy(target);
        DESTROY_TARGET.with(|slot| slot.set(None));
        assert_eq!(DESTROY_CALLS.with(Cell::get), 1);
        let nested = NESTED_DESTROY.with(|slot| slot.borrow_mut().take()).expect("nested saved procedure call");
        assert_eq!(nested.unwrap().map(|result| result.value), Some(0));
    });
}
