//! Native-only timer work and Win16 queue records retain distinct ownership.

use super::*;
use std::cell::Cell;
use std::time::Instant;
use windows_sys::Win32::UI::WindowsAndMessaging::{SetTimer, WM_TIMER};

#[derive(Clone, Copy, Default)]
struct Observation {
    calls: usize,
    thread: u32,
    hwnd: usize,
    message: u32,
    id: usize,
    borrow_free: bool,
    destroy: bool,
}

thread_local! {
    static OBSERVED: Cell<Observation> = Cell::new(Observation::default());
}

// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn record_timer(hwnd: HWND, message: u32, id: usize, _time: u32) {
    OBSERVED.with(|slot| {
        let mut observation = slot.get();
        observation.calls += 1;
        observation.thread = crate::windows::win32_safe::current_thread_id();
        observation.hwnd = hwnd as usize;
        observation.message = message;
        observation.id = id;
        observation.borrow_free =
            worker::worker_context().is_some_and(|state| state.try_borrow_mut().is_ok());
        slot.set(observation);
        (crate::windows::win32_safe::kill_timer(hwnd, id));
        if observation.destroy {
            (crate::windows::win32_safe::destroy_window(hwnd));
        }
    });
}

struct NativeTimer {
    hwnd: HWND,
    id: usize,
}

impl NativeTimer {
    fn new(hwnd: HWND) -> Self {
        // SAFETY: `SetTimer`, `Some` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        let returned = unsafe { SetTimer(hwnd, 0x4477, 10, Some(record_timer)) };
        assert_ne!(returned, 0);
        Self {
            hwnd,
            id: if hwnd.is_null() { returned } else { 0x4477 },
        }
    }
}

impl Drop for NativeTimer {
    fn drop(&mut self) {
        (crate::windows::win32_safe::kill_timer(self.hwnd, self.id));
    }
}

fn filter(window: Option<&Window>) -> NativeFilter {
    NativeFilter {
        queue: bind_queue(),
        hwnd: window.map_or((-1_isize) as HWND, |window| window.hwnd),
        window: window.map(|window| window.token),
        min: WM_TIMER,
        max: WM_TIMER,
    }
}

fn guest_filter(native: NativeFilter) -> Win16MessageFilter {
    Win16MessageFilter {
        task_queue: Some(native.queue),
        window: native
            .window
            .map_or(Win16MessageWindow::ThreadOnly, Win16MessageWindow::Window),
        min_message: native.min as u16,
        max_message: native.max as u16,
    }
}

fn await_timer(state: &Rc<RefCell<WorkerState>>, filter: NativeFilter) -> (MSG, bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(message) = peek_matching(state, filter, 0).unwrap() {
            assert_eq!(message.0.message, WM_TIMER);
            return message;
        }
        assert!(
            Instant::now() < deadline,
            "native SetTimer did not produce a queue record"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn call(state: &Rc<RefCell<WorkerState>>, call: Win16MessageCall) -> Win16MessageCallResult {
    let (response, _receive) = mpsc::channel();
    super::super::super::win16_message_calls::execute(state, 0, call, &response).unwrap()
}

fn set_guest_timer(
    state: &Rc<RefCell<WorkerState>>,
    window: &Window,
    callback: bool,
    system: bool,
) -> u64 {
    let Win16MessageCallResult::Timer(Some(id)) = call(
        state,
        Win16MessageCall::SetTimer {
            window: Some(window.token),
            timer_id: 0x42,
            interval_ms: 10,
            native_timer_id: None,
            guest_callback: callback,
            system,
        },
    ) else {
        panic!("could not install guest timer");
    };
    id
}

fn kill_guest_timer(state: &Rc<RefCell<WorkerState>>, window: &Window, id: u64) {
    assert_eq!(
        call(
            state,
            Win16MessageCall::KillTimer {
                window: Some(window.token),
                host_timer_id: id,
            }
        ),
        Win16MessageCallResult::Boolean(true)
    );
}

#[test]
#[ignore = "requires Windows USER; runs native timers on their owning worker"]
fn host_timer_native_peeks_dispatch_once_on_installing_thread() {
    on_worker(|state| {
        let _operation = Operation::begin(state);
        let window = Window::new(state);
        for target in [Some(&window), None] {
            for flags in [0, 2, PM_REMOVE as u16] {
                OBSERVED.set(Observation::default());
                let timer =
                    NativeTimer::new(target.map_or(std::ptr::null_mut(), |window| window.hwnd));
                let filter = filter(target);
                // Materialize a thread timer through an all-window native
                // peek before testing ThreadOnly retrieval. On Windows, the
                // -1 filter alone need not generate the low-priority MSG.
                let generation_filter = if target.is_none() {
                    NativeFilter {
                        hwnd: std::ptr::null_mut(),
                        ..filter
                    }
                } else {
                    filter
                };
                let (native, _) = await_timer(state, generation_filter);
                assert_eq!(native.wParam, timer.id);
                assert_eq!(native.lParam, record_timer as *const () as isize);
                assert!(matches!(
                    peek_message(state, guest_filter(filter), flags).unwrap(),
                    MessagePoll::Empty
                ));
                let observed = OBSERVED.get();
                assert_eq!(observed.calls, 1);
                assert_eq!(
                    observed.thread,
                    (crate::windows::win32_safe::current_thread_id())
                );
                assert_eq!(
                    (observed.hwnd, observed.message, observed.id),
                    (timer.hwnd as usize, WM_TIMER, timer.id)
                );
                assert!(observed.borrow_free);
                assert!(peek_matching(state, filter, PM_REMOVE).unwrap().is_none());
            }
        }
    });
}

#[test]
#[ignore = "requires Windows USER; runs native timers on their owning worker"]
fn host_timer_native_deferred_dispatch_preserves_following_guest_peeks() {
    on_worker(|state| {
        let _operation = Operation::begin(state);
        let window = Window::new(state);
        OBSERVED.set(Observation::default());
        let _timer = NativeTimer::new(window.hwnd);
        let timer_filter = filter(Some(&window));
        await_timer(state, timer_filter);
        let reservation =
            super::super::super::win16_deferred_native_messages::reserve_slot(state).unwrap();
        let (native, deferred) = peek_matching(state, timer_filter, PM_REMOVE)
            .unwrap()
            .unwrap();
        assert!(!deferred);
        reservation.defer(native, Some(window.token)).unwrap();
        // SAFETY: PostMessageW queues scalar message parameters. Any pointer in lParam stays valid until the receiving window procedure returns.
        assert_ne!(unsafe { PostMessageW(window.hwnd, 0, 0x55, 0) }, 0);
        let any = Win16MessageFilter {
            min_message: 0,
            max_message: 0,
            ..guest_filter(timer_filter)
        };
        for flags in [0, 0, PM_REMOVE as u16] {
            let MessagePoll::Message(delivery) = peek_message(state, any, flags).unwrap() else {
                panic!("expected the ordinary message after native timer work");
            };
            let message = delivery.message.unwrap();
            assert_eq!(
                (message.message, message.w_param, message.l_param),
                (0, 0x55, Win16MessageParam::Scalar(0))
            );
            assert_eq!(OBSERVED.get().calls, 1);
        }
        assert!(
            peek_matching(state, timer_filter, PM_REMOVE)
                .unwrap()
                .is_none()
        );
    });
}

#[test]
#[ignore = "requires Windows USER; runs native timers on their owning worker"]
fn host_timer_native_changed_queue_routes_actual_removed_guest_record() {
    on_worker(|state| {
        let _operation = Operation::begin(state);
        let window = Window::new(state);
        OBSERVED.set(Observation::default());
        let timer = NativeTimer::new(window.hwnd);
        let filter = filter(Some(&window));
        let (expected, deferred) = await_timer(state, filter);
        assert!(!deferred);
        peek_matching(state, filter, PM_REMOVE).unwrap().unwrap();
        (crate::windows::win32_safe::kill_timer(timer.hwnd, timer.id));
        assert_eq!(
            call(
                state,
                Win16MessageCall::PostMessage {
                    window: window.token,
                    message: WM_TIMER as u16,
                    w_param: 0x62,
                    l_param: Win16MessageParam::GuestBits(0x1234_5678),
                    guest_class: None,
                }
            ),
            Win16MessageCallResult::Boolean(true)
        );
        let message = dispatch::expose_or_dispatch(state, expected, filter, 0, false)
            .unwrap()
            .unwrap()
            .message
            .unwrap();
        assert_eq!(
            (message.message, message.w_param, message.l_param),
            (
                WM_TIMER as u16,
                0x62,
                Win16MessageParam::GuestBits(0x1234_5678)
            )
        );
        assert_eq!(OBSERVED.get().calls, 0);
        assert!(state.borrow().guest_timer_posts.is_empty());
    });
}

#[test]
#[ignore = "requires Windows USER; runs native timers on their owning worker"]
fn host_timer_native_live_guest_timers_keep_no_remove_and_generation() {
    on_worker(|state| {
        let _operation = Operation::begin(state);
        let window = Window::new(state);
        for callback in [false, true] {
            for system in [false, true] {
                let id = set_guest_timer(state, &window, callback, system);
                let filter = filter(Some(&window));
                await_timer(state, filter);
                for flags in [0, 0, PM_REMOVE as u16] {
                    let MessagePoll::Message(delivery) =
                        peek_message(state, guest_filter(filter), flags).unwrap()
                    else {
                        panic!("expected live guest timer");
                    };
                    let message = delivery.message.unwrap();
                    assert_eq!(
                        message.message,
                        if system {
                            Win16ScalarMessage::SystemTimer as u16
                        } else {
                            WM_TIMER as u16
                        }
                    );
                    assert_eq!(message.w_param, 0x42);
                    assert_eq!(
                        message.l_param,
                        if callback {
                            Win16MessageParam::TimerHostId(id)
                        } else {
                            Win16MessageParam::Scalar(0)
                        }
                    );
                }
                kill_guest_timer(state, &window, id);
            }
        }
    });
}

#[test]
#[ignore = "requires Windows USER; runs native timers on their owning worker"]
fn host_timer_native_killed_guest_timer_keeps_pending_generation() {
    on_worker(|state| {
        let _operation = Operation::begin(state);
        let window = Window::new(state);
        let id = set_guest_timer(state, &window, true, false);
        let filter = filter(Some(&window));
        await_timer(state, filter);
        kill_guest_timer(state, &window, id);
        // KillTimer does not retract an already queued native message. The
        // retained guest generation still owns its pending callback address.
        for flags in [0, 0, PM_REMOVE as u16] {
            let MessagePoll::Message(delivery) =
                peek_message(state, guest_filter(filter), flags).unwrap()
            else {
                panic!("expected the already queued guest timer generation");
            };
            assert_eq!(
                delivery.message.unwrap().l_param,
                Win16MessageParam::TimerHostId(id)
            );
        }
        assert!(state.borrow().live_callbacks.is_empty());
        assert!(peek_matching(state, filter, PM_REMOVE).unwrap().is_none());
    });
}

#[test]
#[ignore = "requires Windows USER; runs native timers on their owning worker"]
fn host_timer_native_unregistered_thunk_drains_without_callback_delivery() {
    on_worker(|state| {
        let _operation = Operation::begin(state);
        let window = Window::new(state);
        let filter = filter(Some(&window));
        assert!(worker::native_timer_record(state, window.hwnd, 0xfff9).is_none());
        // This is native queue data with the actual host thunk. Guest timer
        // posts use their registered sidecar instead of this unregistered ID.
        assert_ne!(
            // SAFETY: PostMessageW queues scalar message parameters. Any pointer in lParam stays valid until the receiving window procedure returns.
            unsafe {
                PostMessageW(
                    window.hwnd,
                    WM_TIMER,
                    0xfff9,
                    worker::host_timer_proc_pointer(),
                )
            },
            0
        );
        assert!(matches!(
            peek_message(state, guest_filter(filter), 0).unwrap(),
            MessagePoll::Empty
        ));
        assert!(state.borrow().live_callbacks.is_empty());
        assert!(peek_matching(state, filter, PM_REMOVE).unwrap().is_none());
    });
}

#[test]
#[ignore = "requires Windows USER; runs native timers on their owning worker"]
fn host_timer_native_unselected_filter_preserves_native_work() {
    on_worker(|state| {
        let _operation = Operation::begin(state);
        let window = Window::new(state);
        OBSERVED.set(Observation::default());
        let _timer = NativeTimer::new(window.hwnd);
        let filter = filter(Some(&window));
        await_timer(state, filter);
        let excluded = Win16MessageFilter {
            min_message: 0x400,
            max_message: 0x400,
            ..guest_filter(filter)
        };
        assert!(matches!(
            peek_message(state, excluded, 0).unwrap(),
            MessagePoll::Empty
        ));
        assert_eq!(OBSERVED.get().calls, 0);
        assert!(matches!(
            peek_message(state, guest_filter(filter), 0).unwrap(),
            MessagePoll::Empty
        ));
        assert_eq!(OBSERVED.get().calls, 1);
    });
}

#[test]
#[ignore = "requires Windows USER; runs native timers on their owning worker"]
fn host_timer_native_callback_retiring_filter_stops_message_retrieval() {
    on_worker(|state| {
        let _operation = Operation::begin(state);
        let window = Window::new(state);
        OBSERVED.set(Observation {
            destroy: true,
            ..Default::default()
        });
        let _timer = NativeTimer::new(window.hwnd);
        let filter = filter(Some(&window));
        await_timer(state, filter);
        assert!(matches!(
            peek_message(state, guest_filter(filter), 0).unwrap(),
            MessagePoll::Error
        ));
        assert_eq!(OBSERVED.get().calls, 1);
        assert!(OBSERVED.get().borrow_free);
    });
}
