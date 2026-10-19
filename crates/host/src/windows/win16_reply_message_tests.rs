//! Opt-in, hidden-window tests of real cross-thread sends on the USER worker.
//! No interactive input is generated.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use runtime::{
    RuntimeError, Win16CreationId, Win16HostCallback, Win16HostClass, Win16HostClassName,
    Win16HostClassSpec, Win16HostCreationData, Win16HostMessage, Win16HostMessageOutput,
    Win16HostMessageResult, Win16HostTaskQueue, Win16HostWindow, Win16MessageCall,
    Win16MessageCallResult, Win16MessageFilter, Win16MessageParam, Win16MessageWindow,
    Win16WindowOperation, Win16WindowReply, Win16WindowResult, Win16WindowStep,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    PostMessageW, SendMessageW, WM_GETTEXT, WS_POPUP,
};

use super::super::win16_window_worker::{
    NativeClassResource, NativeDropRetirementQueue, WindowWorker, WorkerCommand, WorkerState,
};
use crate::windows::{guest_text::GuestTextCodec, win16_gdi::Win16Dcs, win16_images::Win16Images};

const CLASS: Win16HostClass = Win16HostClass(1);
const OUTER: u16 = 0x0401;
const INNER: u16 = 0x0402;
const MARKER: u16 = 0x0450;
const TIMEOUT: Duration = Duration::from_secs(10);
static NATIVE_WINDOW: AtomicUsize = AtomicUsize::new(0);
// The fixture uses one process-wide class name and native HWND observation.
// Serialize explicitly even when the opt-in test runner uses multiple threads.
static SERIAL: Mutex<()> = Mutex::new(());
type Steps = Receiver<Result<Win16WindowStep, RuntimeError>>;

struct Fixture {
    worker: WindowWorker,
    identities: Arc<AtomicU64>,
    window: Win16HostWindow,
    hwnd: usize,
    queue: Win16HostTaskQueue,
    _serial: MutexGuard<'static, ()>,
}

fn capture_window(state: &Rc<RefCell<WorkerState>>) {
    let state = state.borrow();
    assert_eq!(state.windows.len(), 1);
    NATIVE_WINDOW.store(
        *state.windows.values().next().unwrap() as usize,
        Ordering::Release,
    );
}

fn receive(steps: &Steps) -> Win16WindowStep {
    steps
        .recv_timeout(TIMEOUT)
        .expect("USER worker response timed out")
        .expect("native USER operation")
}

fn result(value: u32) -> Win16HostMessageResult {
    Win16HostMessageResult {
        value,
        dialog_result: None,
        output: Win16HostMessageOutput::None,
    }
}

impl Fixture {
    fn new() -> Self {
        let serial = SERIAL.lock().unwrap();
        let codec = GuestTextCodec::new(1252).unwrap();
        let identities = Arc::new(AtomicU64::new(1));
        let worker = WindowWorker::spawn(
            Win16Dcs::with_text_codec(codec),
            Win16Images::new(codec),
            Arc::clone(&identities),
            codec,
            NativeDropRetirementQueue::shared(),
        )
        .unwrap();
        let (response, steps) = mpsc::channel();
        worker
            .send(WorkerCommand::RegisterClass {
                class: CLASS,
                spec: Win16HostClassSpec {
                    style: 0,
                    class_extra: 0,
                    window_extra: 0,
                    icon: None,
                    cursor: None,
                    background: None,
                    system_class: None,
                },
                icon: 0,
                cursor: 0,
                background: Default::default(),
                response,
            })
            .unwrap_or_else(|_| panic!("register guest class command"));
        assert!(steps.recv_timeout(TIMEOUT).unwrap().unwrap().is_some());
        let (response, steps) = mpsc::channel();
        worker
            .send(WorkerCommand::BindTaskQueue {
                owner: guest_core::OwnerId(1),
                guest_htask: 0x100,
                task_selector_generation: 1,
                response,
            })
            .unwrap_or_else(|_| panic!("bind guest task queue command"));
        let queue = steps.recv_timeout(TIMEOUT).unwrap().unwrap().unwrap();
        let mut fixture = Self {
            worker,
            identities,
            window: Win16HostWindow(0),
            hwnd: 0,
            queue,
            _serial: serial,
        };
        let created = fixture.complete(Win16WindowOperation::Create {
            creation: Win16CreationId(fixture.next()),
            data: Win16HostCreationData {
                class: CLASS,
                guest_instance: 0,
                guest_class_name: Win16HostClassName::Name(b"ReplyMessageTest".to_vec()),
                guest_menu: 0,
                class_menu_template: None,
                create_parameter: 0,
                creation_data: None,
                mdi_client: None,
                dialog_root: false,
                menu: None,
                title: Some(b"ReplyMessage test".to_vec()),
                style: WS_POPUP,
                ex_style: 0,
                x: 0,
                y: 0,
                width: 32,
                height: 32,
                parent: None,
                child_id: None,
            },
        });
        let Win16WindowResult::Created(created) = created else {
            panic!("expected created window")
        };
        fixture.window = created.live_window.expect("hidden guest-class window");
        let (response, steps) = mpsc::channel();
        fixture
            .worker
            .send(WorkerCommand::TestWindowData {
                run: capture_window,
                response,
            })
            .unwrap_or_else(|_| panic!("capture native window command"));
        steps.recv_timeout(TIMEOUT).unwrap().unwrap();
        fixture.hwnd = NATIVE_WINDOW.load(Ordering::Acquire);
        assert_ne!(fixture.hwnd, 0);
        fixture
    }

    fn next(&self) -> u64 {
        self.identities.fetch_add(1, Ordering::Relaxed)
    }

    fn begin(&self, operation: Win16WindowOperation) -> (u64, Steps) {
        let id = self.next();
        let (response, steps) = mpsc::channel();
        self.worker
            .send(WorkerCommand::Begin {
                id,
                operation,
                win_exec: None,
                control_color_return: None,
                native_bitmaps: BTreeMap::new(),
                native_font: None,
                toolbar_bitmap_leases: BTreeMap::new(),
                native_regions: BTreeMap::new(),
                gray_string_brush: None,
                metafile: None,
                response,
            })
            .unwrap_or_else(|_| panic!("begin native USER operation"));
        (id, steps)
    }

    fn resume(&self, id: u64, callback: Win16HostCallback, result: Win16HostMessageResult) {
        self.worker
            .send(WorkerCommand::Resume {
                id,
                reply: Win16WindowReply { callback, result },
                native_control_color_result: None,
            })
            .unwrap_or_else(|_| panic!("resume native callback"));
    }

    fn finish(&self, id: u64, steps: &Steps) -> Win16WindowResult {
        loop {
            match receive(steps) {
                Win16WindowStep::Complete(value) => return value,
                Win16WindowStep::Callback {
                    callback,
                    window,
                    message,
                    operation_id,
                    ..
                } => {
                    assert_eq!(operation_id.0, id);
                    let value = self.complete(Win16WindowOperation::Default {
                        window,
                        callback: Some(callback),
                        message,
                    });
                    let Win16WindowResult::Message(Some(value)) = value else {
                        panic!("default processing result")
                    };
                    self.resume(id, callback, value);
                }
                Win16WindowStep::Untranslated { .. } => {}
                step => panic!("unexpected native step: {step:?}"),
            }
        }
    }

    fn complete(&self, operation: Win16WindowOperation) -> Win16WindowResult {
        let (id, steps) = self.begin(operation);
        self.finish(id, &steps)
    }

    fn call(&self, call: Win16MessageCall) -> Win16MessageCallResult {
        let Win16WindowResult::MessageCall(value) =
            self.complete(Win16WindowOperation::MessageCall(call))
        else {
            panic!("expected message-call result")
        };
        value
    }

    fn pump(&self) -> (u64, Steps) {
        self.begin(Win16WindowOperation::GetMessage {
            filter: Win16MessageFilter {
                window: Win16MessageWindow::Window(self.window),
                min_message: MARKER,
                max_message: MARKER,
                task_queue: Some(self.queue),
            },
        })
    }

    fn callback(&self, id: u64, steps: &Steps) -> (Win16HostCallback, Win16HostMessage) {
        match receive(steps) {
            Win16WindowStep::Callback {
                callback,
                message,
                operation_id,
                ..
            } => {
                assert_eq!(operation_id.0, id);
                (callback, message)
            }
            step => panic!("expected suspended guest WndProc: {step:?}"),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.worker
            .shutdown()
            .expect("retire hidden USER test window");
    }
}

// Reuse the opt-in, serialized USER worker fixture for class-menu payloads.
#[path = "win16_class_menu_native_tests.rs"]
mod class_menu_native_tests;

// Reuse the same fixture for native class resource replacement.
#[path = "win16_class_resource_native_tests.rs"]
mod class_resource_native_tests;

#[test]
#[ignore = "requires native Windows USER; creates a hidden window without interactive input"]
fn reply_message_cross_thread_result_precedes_receiver_return_and_keeps_all_32_bits() {
    let host = Fixture::new();
    assert_eq!(
        host.call(Win16MessageCall::InSendMessage),
        Win16MessageCallResult::Boolean(false)
    );
    assert_eq!(
        host.call(Win16MessageCall::ReplyMessage { result: -1 }),
        Win16MessageCallResult::Boolean(false)
    );
    for early in [0, 0x1234_5678, i32::MIN, -1] {
        let (done, returned) = mpsc::channel();
        let hwnd = host.hwnd;
        let sender = std::thread::spawn(move || {
            // SAFETY: SendMessageW runs synchronously on the window thread. Pointer arguments are caller-owned records that stay live for the call and are not guest addresses.
            let value = unsafe { SendMessageW(hwnd as _, u32::from(OUTER), 0, 0) };
            done.send(value).unwrap();
            assert_ne!(
                // SAFETY: PostMessageW queues scalar message parameters. Any pointer in lParam stays valid until the receiving window procedure returns.
                unsafe { PostMessageW(hwnd as _, u32::from(MARKER), 0, 0) },
                0
            );
        });
        let (id, steps) = host.pump();
        let (callback, _) = host.callback(id, &steps);
        assert_eq!(
            host.call(Win16MessageCall::InSendMessage),
            Win16MessageCallResult::Boolean(true)
        );
        assert!(returned.try_recv().is_err(), "sender must still be blocked");
        assert_eq!(
            host.call(Win16MessageCall::ReplyMessage { result: early }),
            Win16MessageCallResult::Boolean(true)
        );
        assert_eq!(returned.recv_timeout(TIMEOUT).unwrap(), early as isize);
        // The native WndProc is still suspended here; its eventual result
        // must not replace the result already delivered to the sender.
        host.resume(id, callback, result(0x7654_3210));
        host.finish(id, &steps);
        sender.join().unwrap();
    }
}

#[test]
#[ignore = "requires native Windows USER; creates a hidden window without interactive input"]
fn reply_message_nested_same_thread_send_keeps_the_outer_cross_thread_context() {
    let host = Fixture::new();
    // A standalone same-thread SendMessage has no synchronous remote sender.
    let send = || {
        Win16WindowOperation::MessageCall(Win16MessageCall::SendMessage {
            window: host.window,
            message: INNER,
            w_param: 0,
            l_param: Win16MessageParam::GuestBits(0),
            guest_class: Some(CLASS),
        })
    };
    let (same_id, same_steps) = host.begin(send());
    let (same_callback, _) = host.callback(same_id, &same_steps);
    assert_eq!(
        host.call(Win16MessageCall::InSendMessage),
        Win16MessageCallResult::Boolean(false)
    );
    assert_eq!(
        host.call(Win16MessageCall::ReplyMessage { result: 3 }),
        Win16MessageCallResult::Boolean(false)
    );
    host.resume(same_id, same_callback, result(17));
    host.finish(same_id, &same_steps);

    let (done, returned) = mpsc::channel();
    let hwnd = host.hwnd;
    let sender = std::thread::spawn(move || {
        // SAFETY: SendMessageW runs synchronously on the window thread. Pointer arguments are caller-owned records that stay live for the call and are not guest addresses.
        done.send(unsafe { SendMessageW(hwnd as _, u32::from(OUTER), 0, 0) })
            .unwrap();
        assert_ne!(
            // SAFETY: PostMessageW queues scalar message parameters. Any pointer in lParam stays valid until the receiving window procedure returns.
            unsafe { PostMessageW(hwnd as _, u32::from(MARKER), 0, 0) },
            0
        );
    });
    let (outer_id, outer_steps) = host.pump();
    let (outer_callback, _) = host.callback(outer_id, &outer_steps);
    let (inner_id, inner_steps) = host.begin(send());
    let (inner_callback, _) = host.callback(inner_id, &inner_steps);
    assert_eq!(
        host.call(Win16MessageCall::InSendMessage),
        Win16MessageCallResult::Boolean(true)
    );
    let early = 0x8000_1234_u32 as i32;
    assert_eq!(
        host.call(Win16MessageCall::ReplyMessage { result: early }),
        Win16MessageCallResult::Boolean(true)
    );
    assert_eq!(returned.recv_timeout(TIMEOUT).unwrap(), early as isize);
    host.resume(inner_id, inner_callback, result(17));
    host.finish(inner_id, &inner_steps);
    host.resume(outer_id, outer_callback, result(0x3456));
    host.finish(outer_id, &outer_steps);
    sender.join().unwrap();
}

#[test]
#[ignore = "requires native Windows USER; creates a hidden window without interactive input"]
fn reply_message_text_uses_native_early_reply_copyback_semantics() {
    let host = Fixture::new();
    for early_reply in [false, true] {
        let (done, returned) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let (finished, finish) = mpsc::channel();
        let hwnd = host.hwnd;
        let sender = std::thread::spawn(move || {
            let mut text = [0_u16; 64];
            // SAFETY: SendMessageW runs synchronously on the window thread. Pointer arguments are caller-owned records that stay live for the call and are not guest addresses.
            let count = unsafe {
                SendMessageW(
                    hwnd as _,
                    WM_GETTEXT,
                    text.len(),
                    text.as_mut_ptr() as isize,
                )
            };
            let early = text;
            text[..8].copy_from_slice(&[114, 101, 116, 105, 114, 101, 100, 0]); // retired
            // Publish only after reuse, so the receiver's later callback
            // return is deterministically checked against a retired buffer.
            done.send((count, early)).unwrap();
            released.recv_timeout(TIMEOUT).unwrap();
            assert_ne!(
                // SAFETY: PostMessageW queues scalar message parameters. Any pointer in lParam stays valid until the receiving window procedure returns.
                unsafe { PostMessageW(hwnd as _, u32::from(MARKER), 0, 0) },
                0
            );
            finish.recv_timeout(TIMEOUT).unwrap();
            text
        });
        let (id, steps) = host.pump();
        let (callback, message) = host.callback(id, &steps);
        assert!(matches!(message, Win16HostMessage::GetText { .. }));
        if early_reply {
            assert_eq!(
                host.call(Win16MessageCall::ReplyMessage { result: 6 }),
                Win16MessageCallResult::Boolean(true)
            );
            let (count, text) = returned.recv_timeout(TIMEOUT).unwrap();
            assert_eq!(count, 6);
            assert_eq!(
                text[0], 0,
                "USER does not marshal text on early ReplyMessage"
            );
        }
        host.resume(
            id,
            callback,
            Win16HostMessageResult {
                value: 5,
                dialog_result: None,
                output: Win16HostMessageOutput::Text(b"after\0".to_vec()),
            },
        );
        if !early_reply {
            let (count, text) = returned.recv_timeout(TIMEOUT).unwrap();
            assert_eq!(count, 5);
            assert_eq!(&text[..6], &[97, 102, 116, 101, 114, 0]);
        }
        release.send(()).unwrap();
        host.finish(id, &steps);
        finished.send(()).unwrap();
        let text = sender.join().unwrap();
        assert_eq!(&text[..8], &[114, 101, 116, 105, 114, 101, 100, 0]);
    }
}
