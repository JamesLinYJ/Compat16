//! Native USER queue provenance, using hidden windows on their owning worker.

use super::*;
use crate::windows::{guest_text::GuestTextCodec, win16_gdi::Win16Dcs, win16_images::Win16Images};
use runtime::{Win16MessageCall, Win16MessageCallResult};
use std::sync::{Arc, atomic::AtomicU64, mpsc};
use std::time::Duration;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, PostMessageW, WS_POPUP,
};

fn on_worker(run: fn(&Rc<RefCell<WorkerState>>)) {
    let codec = GuestTextCodec::new(1252).unwrap();
    let mut worker = worker::WindowWorker::spawn(
        Win16Dcs::with_text_codec(codec),
        Win16Images::new(codec),
        Arc::new(AtomicU64::new(1)),
        codec,
        worker::NativeDropRetirementQueue::shared(),
    )
    .unwrap();
    let (response, receive) = mpsc::channel();
    worker
        .send(WorkerCommand::TestWindowData { run, response })
        .unwrap_or_else(|_| panic!("send native timer test to USER worker"));
    let result = receive.recv_timeout(Duration::from_secs(20)).unwrap();
    let shutdown = worker.shutdown();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
    shutdown.unwrap();
}

struct Window {
    state: Rc<RefCell<WorkerState>>,
    token: Win16HostWindow,
    hwnd: HWND,
}

impl Window {
    fn new(state: &Rc<RefCell<WorkerState>>) -> Self {
        let class: Vec<u16> = "STATIC\0".encode_utf16().collect();
        let hwnd = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                std::ptr::null(),
                WS_POPUP,
                0,
                0,
                40,
                40,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        assert!(!hwnd.is_null());
        let token = super::super::win16_window_identity::adopt_created_owned(state, hwnd).unwrap();
        Self {
            state: Rc::clone(state),
            token,
            hwnd,
        }
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        unsafe {
            DestroyWindow(self.hwnd);
        }
        worker::remove_window_maps(&self.state, self.token, self.hwnd);
    }
}

fn bind_queue() -> runtime::Win16HostTaskQueue {
    super::super::win16_guest_notifications::bind_task_queue(guest_core::OwnerId(1), 0x80, 1)
        .unwrap()
        .unwrap()
}

struct Operation {
    state: Rc<RefCell<WorkerState>>,
    _receive: mpsc::Receiver<Result<runtime::Win16WindowStep, RuntimeError>>,
}

impl Operation {
    fn begin(state: &Rc<RefCell<WorkerState>>) -> Self {
        let (response, receive) = mpsc::channel();
        assert!(state.borrow().active_operations.is_empty());
        state
            .borrow_mut()
            .active_operations
            .push(worker::ActiveOperation {
                id: 1,
                native_font: None,
                kind: runtime::Win16NativeWindowOperationKind::PeekMessage,
                response,
                native_queue_dispatch: false,
                native_dialog_pump: false,
            });
        Self {
            state: Rc::clone(state),
            _receive: receive,
        }
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        let active = self.state.borrow_mut().active_operations.pop().unwrap();
        assert_eq!(active.id, 1);
    }
}

unsafe extern "system" fn native_timer_proc(_hwnd: HWND, _message: u32, _id: usize, _time: u32) {}

#[test]
#[ignore = "requires Windows USER; creates a hidden worker-owned window"]
fn system_timer_native_callback_never_becomes_guest_scalar_or_farproc() {
    on_worker(|state| {
        let _operation = Operation::begin(state);
        let window = Window::new(state);
        let filter = NativeFilter {
            queue: bind_queue(),
            hwnd: window.hwnd,
            window: Some(window.token),
            min: 0,
            max: 0,
        };
        let mut native = MSG {
            hwnd: window.hwnd,
            message: Win16ScalarMessage::SystemTimer as u32,
            wParam: 0xfff9,
            // A real process function address, never an invalid native pointer.
            // This synthetic message has no registered server timer: Windows
            // decides whether to dispatch it, and the guest must never see it.
            lParam: native_timer_proc as *const () as isize,
            ..MSG::default()
        };
        assert!(
            dispatch::expose_or_dispatch(state, native, filter, PM_REMOVE, false)
                .unwrap()
                .is_none()
        );
        native.lParam = 0;
        let delivery = dispatch::expose_or_dispatch(state, native, filter, PM_REMOVE, false)
            .unwrap()
            .unwrap();
        let message = delivery.message.unwrap();
        assert_eq!(message.message, Win16ScalarMessage::SystemTimer as u16);
        assert_eq!(message.w_param, 0xfff9);
        assert_eq!(message.l_param, Win16MessageParam::Scalar(0));

        // A private native callback encountered by PM_NOREMOVE follows the
        // existing remove/compare/dispatch route rather than leaking bits.
        native.lParam = native_timer_proc as *const () as isize;
        assert_ne!(
            unsafe { PostMessageW(window.hwnd, native.message, native.wParam, native.lParam) },
            0
        );
        let filter = NativeFilter {
            min: native.message,
            max: native.message,
            ..filter
        };
        let (peeked, deferred) = peek_matching(state, filter, 0).unwrap().unwrap();
        assert!(
            dispatch::expose_or_dispatch(state, peeked, filter, 0, deferred)
                .unwrap()
                .is_none()
        );
        assert!(peek_matching(state, filter, PM_REMOVE).unwrap().is_none());
    });
}

#[test]
#[ignore = "requires Windows USER; creates a hidden worker-owned window"]
fn system_timer_native_guest_posts_preserve_namespace_bits_and_peek_ownership() {
    on_worker(|state| {
        let _operation = Operation::begin(state);
        let window = Window::new(state);
        let queue = bind_queue();
        let (response, _receive) = mpsc::channel();
        for thread_only in [false, true] {
            for kind in [Win16ScalarMessage::Timer, Win16ScalarMessage::SystemTimer] {
                let (guest_w, guest_l) = (0xfff9, 0x1234_5678);
                let call = if thread_only {
                    Win16MessageCall::PostThreadMessage {
                        message: kind as u16,
                        w_param: guest_w,
                        l_param: Win16MessageParam::GuestBits(guest_l),
                        guest_class: None,
                    }
                } else {
                    Win16MessageCall::PostMessage {
                        window: window.token,
                        message: kind as u16,
                        w_param: guest_w,
                        l_param: Win16MessageParam::GuestBits(guest_l),
                        guest_class: None,
                    }
                };
                assert_eq!(
                    super::super::win16_message_calls::execute(state, 0, call, &response).unwrap(),
                    Win16MessageCallResult::Boolean(true)
                );
                let filter = Win16MessageFilter {
                    window: if thread_only {
                        Win16MessageWindow::ThreadOnly
                    } else {
                        Win16MessageWindow::Window(window.token)
                    },
                    min_message: 0,
                    max_message: 0,
                    task_queue: Some(queue),
                };
                for flags in [0, 0, PM_REMOVE as u16] {
                    let MessagePoll::Message(delivery) =
                        peek_message(state, filter, flags).unwrap()
                    else {
                        panic!("expected posted guest timer message");
                    };
                    let message = delivery.message.unwrap();
                    assert_eq!(message.message, kind as u16);
                    assert_eq!(message.window, (!thread_only).then_some(window.token));
                    assert_eq!(message.w_param, guest_w);
                    assert_eq!(message.l_param, Win16MessageParam::GuestBits(guest_l));
                    assert_eq!(
                        state.borrow().guest_timer_posts.len(),
                        usize::from(flags == 0)
                    );
                }
            }
        }
    });
}
