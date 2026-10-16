//! USER message, timer, focus, capture and keyboard operations on the native
//! window worker thread.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostClass, Win16HostWindow, Win16MessageCall,
    Win16MessageCallResult, Win16MessageParam, Win16ScalarMessage, Win16WindowInputMessage,
    Win16WindowStep,
};
use windows_sys::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetCapture, GetFocus, GetKeyboardState, ReleaseCapture, SetCapture, SetFocus, SetKeyboardState,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetInputState, GetMessageExtraInfo, GetMessagePos, GetMessageTime, GetQueueStatus, HWND_BROADCAST, InSendMessage,
    KillTimer, PostMessageW, PostThreadMessageW, SendMessageW, SetTimer, TIMERPROC,
};

use super::win16_message_loop::{self, WaitResult};
use super::win16_window_callbacks::host_timer_proc;
use super::win16_window_worker as worker_window;
use super::win16_window_worker::WorkerState;

#[path = "win16_kernel_yield.rs"]
mod kernel_yield;

const WM_COMMAND: u16 = 0x0111;
const WM_TIMER: u16 = 0x0113;
const WM_ACTIVATEAPP: u16 = 0x001c;
const WM_PARENTNOTIFY: u16 = 0x0210;
const WM_USER: u16 = 0x0400;
const WM_CHANGECBCHAIN: u16 = 0x030d;

#[derive(Debug)]
struct MessageWaitRetirementFailure { primary: RuntimeError, cleanup: RuntimeError }

impl std::fmt::Display for MessageWaitRetirementFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}; wait cleanup failed: {}", self.primary, self.cleanup)
    }
}

impl std::error::Error for MessageWaitRetirementFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.primary) }
}

pub(super) fn execute(
    state: &Rc<RefCell<WorkerState>>,
    operation_id: u64,
    call: Win16MessageCall,
    response: &std::sync::mpsc::Sender<Result<Win16WindowStep, RuntimeError>>,
) -> Result<Win16MessageCallResult, RuntimeError> {
    // Validate our typed protocol before an invalid receiver or a timer
    // shortcut can turn a routing defect into an ordinary guest failure.
    match &call {
        Win16MessageCall::SendMessage {
            message,
            l_param: Win16MessageParam::WindowInput(input),
            ..
        }
        | Win16MessageCall::PostMessage {
            message,
            l_param: Win16MessageParam::WindowInput(input),
            ..
        } if input.message_id() != *message => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "typed window-input payload was used for a different message",
            ));
        }
        Win16MessageCall::SendMessage {
            l_param: Win16MessageParam::Mdi(_),
            ..
        } => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "typed MDI SendMessage bypassed the synchronous MDI message/output route",
            ));
        }
        _ => {}
    }
    match call {
        Win16MessageCall::Yield { task_queue } => kernel_yield::execute(state, task_queue),
        Win16MessageCall::SendBroadcast { kind, w_param, l_param } => {
            let Some((message, native_w, native_l)) = broadcast_arguments(state, kind, w_param, l_param)?
                else { return Ok(Win16MessageCallResult::Long(0)); };
            let result = unsafe { SendMessageW(HWND_BROADCAST, message, native_w, native_l) };
            Ok(Win16MessageCallResult::Long(result as i32))
        }
        Win16MessageCall::PostBroadcast { kind, w_param, l_param } => {
            let Some((message, native_w, native_l)) = broadcast_arguments(state, kind, w_param, l_param)?
                else { return Ok(Win16MessageCallResult::Boolean(false)); };
            let succeeded = unsafe { PostMessageW(HWND_BROADCAST, message, native_w, native_l) } != 0;
            Ok(Win16MessageCallResult::Boolean(succeeded))
        }
        Win16MessageCall::SendMessage {
            window,
            message,
            w_param,
            l_param,
            guest_class,
        } => {
            let Some(hwnd) = resolve_window(state, window) else {
                return Ok(Win16MessageCallResult::Long(0));
            };
            let Some((native_message, native_w, native_l)) =
                message_arguments(state, window, message, w_param, l_param, guest_class)?
            else {
                return Ok(Win16MessageCallResult::Long(0));
            };
            let result = unsafe { SendMessageW(hwnd, native_message, native_w, native_l) };
            Ok(Win16MessageCallResult::Long(result as i32))
        }
        Win16MessageCall::PostMessage {
            window,
            message,
            w_param,
            l_param,
            guest_class,
        } => {
            let Some(hwnd) = resolve_window(state, window) else {
                return Ok(Win16MessageCallResult::Boolean(false));
            };
            if message == WM_TIMER {
                let Win16MessageParam::GuestBits(guest_l_param) = l_param else {
                    return Ok(Win16MessageCallResult::Boolean(false));
                };
                if guest_l_param == 0 {
                    // A zero LPARAM is an ordinary WM_TIMER message. Keep it
                    // in the native queue so modeless and modal windows route
                    // it through their normal WndProc/DLGPROC default rules.
                    let succeeded =
                        unsafe { PostMessageW(hwnd, u32::from(message), usize::from(w_param), 0) }
                            != 0;
                    return Ok(Win16MessageCallResult::Boolean(succeeded));
                }
                let succeeded =
                    worker_window::post_guest_timer_message(state, hwnd, w_param, guest_l_param)?;
                return Ok(Win16MessageCallResult::Boolean(succeeded));
            }
            let Some((native_message, native_w, native_l)) =
                message_arguments(state, window, message, w_param, l_param, guest_class)?
            else {
                return Ok(Win16MessageCallResult::Boolean(false));
            };
            let succeeded = unsafe { PostMessageW(hwnd, native_message, native_w, native_l) } != 0;
            Ok(Win16MessageCallResult::Boolean(succeeded))
        }
        Win16MessageCall::PostThreadMessage {
            message,
            w_param,
            l_param,
            ..
        } => {
            if message == WM_TIMER {
                let Win16MessageParam::GuestBits(guest_l_param) = l_param else {
                    return Ok(Win16MessageCallResult::Boolean(false));
                };
                if guest_l_param == 0 {
                    let thread = unsafe { GetCurrentThreadId() };
                    let succeeded = unsafe {
                        PostThreadMessageW(thread, u32::from(message), usize::from(w_param), 0)
                    } != 0;
                    return Ok(Win16MessageCallResult::Boolean(succeeded));
                }
                let succeeded = worker_window::post_guest_timer_message(
                    state,
                    std::ptr::null_mut(),
                    w_param,
                    guest_l_param,
                )?;
                return Ok(Win16MessageCallResult::Boolean(succeeded));
            }
            let Some(mut native_w) = super::win16_character_messages::to_native(state,
                u32::from(message), w_param)? else {
                    return Ok(Win16MessageCallResult::Boolean(false));
                };
            let native_l = match l_param {
                Win16MessageParam::Scalar(value) | Win16MessageParam::GuestBits(value) => {
                    (value as i32) as isize
                }
                Win16MessageParam::ActivationApp(input) if message == WM_ACTIVATEAPP => {
                    let Some((native_w_param, native_l)) =
                        super::win16_window_input::encode_activation_app(input)
                    else {
                        return Ok(Win16MessageCallResult::Boolean(false));
                    };
                    native_w = native_w_param;
                    native_l
                }
                // A thread message has no recipient HWND. HWND-bearing
                // command, clipboard, and window-input payloads need a window
                // target and cannot be represented by a thread message.
                Win16MessageParam::Command { .. }
                | Win16MessageParam::ClipboardChainChange { .. }
                | Win16MessageParam::ParentNotification(_)
                | Win16MessageParam::ControlColor(_)
                | Win16MessageParam::ActivationApp(_)
                | Win16MessageParam::TimerHostId(_)
                | Win16MessageParam::Mdi(_)
                | Win16MessageParam::WindowInput(_)
                | Win16MessageParam::GuestNotification { .. } => {
                    return Ok(Win16MessageCallResult::Boolean(false));
                }
            };
            let thread = unsafe { GetCurrentThreadId() };
            let succeeded = unsafe {
                PostThreadMessageW(thread, u32::from(message), native_w, native_l)
            } != 0;
            Ok(Win16MessageCallResult::Boolean(succeeded))
        }
        Win16MessageCall::WaitMessage => {
            worker_window::begin_user_wait(
                state, operation_id, worker_window::UserWaitKind::WaitMessage,
            )?;
            let outcome = (|| loop {
                if state.borrow().aborted { return Err(canceled()); }
                worker_window::pump_classic_dde_messages(state)?;
                match win16_message_loop::wait_for_input_or_command(state)? {
                    WaitResult::NativeInput => return Ok(Win16MessageCallResult::Boolean(true)),
                    WaitResult::PendingGuestWork { generation } => {
                        worker_window::yield_pending_guest_work(
                            state,
                            operation_id,
                            generation,
                            worker_window::UserWaitKind::WaitMessage,
                            response,
                        )?;
                    }
                    WaitResult::Command(command) => {
                        worker_window::process_command(state, command);
                    }
                }
            })();
            let retired = worker_window::end_user_wait(
                state, operation_id, worker_window::UserWaitKind::WaitMessage,
            );
            match (outcome, retired) {
                (Ok(value), Ok(())) => Ok(value),
                (Err(error), Ok(())) => Err(error),
                (Ok(_), Err(error)) => Err(error),
                (Err(primary), Err(cleanup)) => Err(RuntimeError::with_source(
                    primary.kind().with_cleanup(cleanup.kind()),
                    "Win16 WaitMessage failed while retiring classic-DDE wait ownership",
                    MessageWaitRetirementFailure { primary, cleanup },
                )),
            }
        },
        Win16MessageCall::SetTimer {
            window,
            timer_id,
            interval_ms,
            native_timer_id,
            guest_callback,
        } => {
            let hwnd = match window {
                Some(window) => match resolve_window(state, window) {
                    Some(hwnd) => hwnd,
                    None => return Ok(Win16MessageCallResult::Timer(None)),
                },
                None => std::ptr::null_mut(),
            };
            let previous = match native_timer_id {
                Some(host_id) => match worker_window::timer_record_by_host_id(state, host_id) {
                    Some(record)
                        if record.active
                            && record.window == window
                            && record.guest_timer_id == timer_id
                            && record.hwnd == hwnd as usize =>
                    {
                        Some(record)
                    }
                    _ => return Ok(Win16MessageCallResult::Timer(None)),
                },
                None => None,
            };
            let requested_id = if hwnd.is_null() {
                // USER assigns thread-timer IDs itself. Creating a new native
                // ID first lets an already queued generation remain distinct
                // until the replacement is safely installed.
                0
            } else if guest_callback {
                let Some(id) = worker_window::allocate_native_callback_timer_id(state, hwnd) else {
                    return Ok(Win16MessageCallResult::Timer(None));
                };
                id
            } else {
                usize::from(timer_id)
            };
            let Some(host_id) = worker_window::allocate_host_timer_id(state) else {
                return Ok(Win16MessageCallResult::Timer(None));
            };
            let timer_proc: TIMERPROC = guest_callback.then_some(host_timer_proc);
            let result =
                unsafe { SetTimer(hwnd, requested_id, u32::from(interval_ms), timer_proc) };
            if result == 0 {
                return Ok(Win16MessageCallResult::Timer(None));
            }
            // HWND-owned timers retain the requested key; SetTimer only
            // promises a nonzero success result for that form. Thread timers
            // use the newly assigned identifier returned by USER.
            let native_id = if hwnd.is_null() { result } else { requested_id };
            let record = worker_window::NativeTimerRecord {
                host_id,
                window,
                guest_timer_id: timer_id,
                hwnd: hwnd as usize,
                native_id,
                guest_callback,
                active: true,
            };
            let same_id_replacement = !hwnd.is_null() && !guest_callback;
            if !worker_window::register_native_timer(state, record, same_id_replacement) {
                // The OS may reuse a NULL-HWND UINT_PTR after KillTimer. Such
                // reuse would make an old queued WM_TIMER indistinguishable
                // from this generation, so retire the just-created timer and
                // report the native failure instead of changing its meaning.
                unsafe { KillTimer(hwnd, native_id) };
                return Ok(Win16MessageCallResult::Timer(None));
            }
            if let Some(previous) = previous {
                if (previous.hwnd, previous.native_id) != (hwnd as usize, native_id) {
                    unsafe { KillTimer(previous.hwnd as HWND, previous.native_id) };
                    worker_window::retire_native_timer(state, previous.host_id);
                }
            }
            Ok(Win16MessageCallResult::Timer(Some(host_id)))
        }
        Win16MessageCall::KillTimer {
            window,
            host_timer_id,
        } => {
            let Some(record) = worker_window::timer_record_by_host_id(state, host_timer_id)
                .filter(|record| record.active && record.window == window)
            else {
                return Ok(Win16MessageCallResult::Boolean(false));
            };
            let hwnd = match window {
                Some(window) => match resolve_window(state, window) {
                    Some(hwnd) if hwnd as usize == record.hwnd => hwnd,
                    _ => return Ok(Win16MessageCallResult::Boolean(false)),
                },
                None if record.hwnd == 0 => std::ptr::null_mut(),
                None => {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 thread timer has a native window owner",
                    ));
                }
            };
            let succeeded = unsafe { KillTimer(hwnd, record.native_id) } != 0;
            if succeeded {
                worker_window::retire_native_timer(state, host_timer_id);
            }
            Ok(Win16MessageCallResult::Boolean(succeeded))
        }
        Win16MessageCall::SetFocus { window } => {
            let hwnd = match window {
                None => std::ptr::null_mut(),
                Some(window) => match resolve_window(state, window) {
                    Some(hwnd) => hwnd,
                    None => return Ok(Win16MessageCallResult::Window(None)),
                },
            };
            let old = unsafe { SetFocus(hwnd) };
            Ok(Win16MessageCallResult::Window(window_token(state, old)?))
        }
        Win16MessageCall::GetFocus => {
            let current = unsafe { GetFocus() };
            Ok(Win16MessageCallResult::Window(window_token(
                state, current,
            )?))
        }
        Win16MessageCall::SetCapture { window } => {
            let Some(hwnd) = resolve_window(state, window) else {
                return Ok(Win16MessageCallResult::Window(None));
            };
            let old = unsafe { SetCapture(hwnd) };
            Ok(Win16MessageCallResult::Window(window_token(state, old)?))
        }
        Win16MessageCall::GetCapture => {
            let current = unsafe { GetCapture() };
            Ok(Win16MessageCallResult::Window(window_token(
                state, current,
            )?))
        }
        Win16MessageCall::ReleaseCapture => Ok(Win16MessageCallResult::Boolean(
            unsafe { ReleaseCapture() } != 0,
        )),
        Win16MessageCall::GetMessagePos => {
            Ok(Win16MessageCallResult::Dword(unsafe { GetMessagePos() }))
        }
        Win16MessageCall::GetMessageTime => {
            Ok(Win16MessageCallResult::Long(unsafe { GetMessageTime() }))
        }
        Win16MessageCall::GetMessageExtraInfo => {
            // SDK LPARAM is a 32-bit LONG here. Keep its low 32 bits as queue
            // metadata, without treating native LONG_PTR bits as a pointer.
            Ok(Win16MessageCallResult::Long(unsafe {
                GetMessageExtraInfo() as i32
            }))
        }
        Win16MessageCall::InSendMessage => {
            // wait_for_guest_reply executes nested Begin commands inline on
            // the still-live native WndProc stack, preserving its send context.
            // Capture it now; completion retries only project this saved BOOL.
            Ok(Win16MessageCallResult::Boolean(unsafe {
                InSendMessage() != 0
            }))
        }
        Win16MessageCall::GetInputState => Ok(Win16MessageCallResult::Boolean(
            unsafe { GetInputState() } != 0,
        )),
        Win16MessageCall::GetQueueStatus { flags } => Ok(Win16MessageCallResult::Dword(unsafe {
            GetQueueStatus(u32::from(flags))
        })),
        Win16MessageCall::GetKeyboardState => {
            let mut keys = [0_u8; 256];
            let succeeded = unsafe { GetKeyboardState(keys.as_mut_ptr()) } != 0;
            Ok(Win16MessageCallResult::KeyboardState {
                succeeded,
                state: keys,
            })
        }
        Win16MessageCall::SetKeyboardState { state: keys } => {
            let succeeded = unsafe { SetKeyboardState(keys.as_ptr()) } != 0;
            Ok(Win16MessageCallResult::Boolean(succeeded))
        }
    }
}

fn broadcast_arguments(
    state: &Rc<RefCell<WorkerState>>,
    kind: Win16ScalarMessage,
    w_param: u16,
    l_param: u32,
) -> Result<Option<(u32, WPARAM, LPARAM)>, RuntimeError> {
    // Revalidate at the host boundary: no guest window identity authorizes
    // dereferencing a FARPROC, drawing handle, or pointer in a broadcast.
    if !kind.broadcast_parameters_are_scalar(w_param, l_param) {
        return Err(RuntimeError::new(
            Kind::InvalidInput,
            "Win16 broadcast parameters require a non-scalar native adapter",
        ));
    }
    let message = u32::from(kind as u16);
    Ok(super::win16_character_messages::to_native(state, message, w_param)?
        .map(|native_w| (message, native_w, (l_param as i32) as isize)))
}

fn resolve_window(state: &Rc<RefCell<WorkerState>>, window: Win16HostWindow) -> Option<HWND> {
    // A live HWND can belong to a later incarnation. Reuse the USER identity
    // resolver for receivers and handle-valued parameters before dispatch.
    super::win16_window_identity::resolve_user_window(state, window)
}

fn window_token(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
) -> Result<Option<Win16HostWindow>, RuntimeError> {
    if hwnd.is_null() {
        return Ok(None);
    }
    worker_window::token_for_native(state, hwnd).map(Some)
}

fn message_arguments(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    message: u16,
    w_param: u16,
    l_param: Win16MessageParam,
    guest_class: Option<Win16HostClass>,
) -> Result<Option<(u32, WPARAM, LPARAM)>, RuntimeError> {
    validate_window_input_tag(message, l_param)?;
    let Some(hwnd) = resolve_window(state, window) else {
        return Ok(None);
    };
    let args = match l_param {
        Win16MessageParam::Mdi(queued) => {
            let Some((native_message, native_w, native_l)) =
                super::win16_message_loop::encode_mdi_message_call(
                    state, window, hwnd, message, queued,
                )?
            else {
                return Ok(None);
            };
            return Ok(Some((native_message, native_w, native_l)));
        }
        Win16MessageParam::WindowInput(input) => {
            let Some((native_message, native_w, native_l)) =
                super::win16_window_input::encode_window_input(state, input)?
            else {
                return Ok(None);
            };
            if native_message != u32::from(message) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "window-input conversion changed the native message identifier",
                ));
            }
            (native_w, native_l)
        }
        Win16MessageParam::ActivationApp(input) if message == WM_ACTIVATEAPP => {
            let Some((native_w, native_l)) =
                super::win16_window_input::encode_activation_app(input)
            else {
                return Ok(None);
            };
            (native_w, native_l)
        }
        Win16MessageParam::ParentNotification(input) if message == WM_PARENTNOTIFY => {
            let Some((native_w, native_l)) =
                super::win16_window_input::encode_parent_notification(state, input)?
            else {
                return Ok(None);
            };
            (native_w, native_l)
        }
        Win16MessageParam::ControlColor(_) => return Ok(None),
        Win16MessageParam::Scalar(value) => {
            // A nonzero paint WPARAM is an HDC, requiring the synchronous
            // typed route and a lease spanning any reentrant callbacks.
            if u32::from(message) == windows_sys::Win32::UI::WindowsAndMessaging::WM_PAINT
                && w_param != 0
            {
                return Ok(None);
            }
            if Win16ScalarMessage::from_raw(message).is_none() {
                return Ok(None);
            }
            let Some(native_w) = super::win16_character_messages::to_native(state,
                u32::from(message), w_param)? else { return Ok(None); };
            (native_w, (value as i32) as isize)
        }
        Win16MessageParam::GuestBits(value) => {
            if message < WM_USER || !has_guest_proc(state, window, hwnd, guest_class) {
                return Ok(None);
            }
            (usize::from(w_param), (value as i32) as isize)
        }
        // Owned notifications must enter through the exact sidecar operation;
        // a generic SendMessage/PostMessage call has no source receipt or
        // queue-incarnation capability to validate and may not forward FAR bits.
        Win16MessageParam::GuestNotification { .. } => return Ok(None),
        Win16MessageParam::Command {
            control, notify, ..
        } if message == WM_COMMAND => {
            let child = match control {
                Some(control) => match resolve_window(state, control) {
                    Some(child) => child,
                    _ => return Ok(None),
                },
                None => std::ptr::null_mut(),
            };
            let command = usize::from(w_param) | (usize::from(notify) << 16);
            (command, child as isize)
        }
        Win16MessageParam::ClipboardChainChange { removed, next }
            if message == WM_CHANGECBCHAIN =>
        {
            let Some(removed) = resolve_optional_window(state, removed) else {
                return Ok(None);
            };
            let Some(next) = resolve_optional_window(state, next) else {
                return Ok(None);
            };
            (removed as WPARAM, next as LPARAM)
        }
        Win16MessageParam::Command { .. }
        | Win16MessageParam::ClipboardChainChange { .. }
        | Win16MessageParam::ActivationApp(_)
        | Win16MessageParam::ParentNotification(_)
        | Win16MessageParam::TimerHostId(_) => {
            return Ok(None);
        }
    };
    Ok(Some((u32::from(message), args.0, args.1)))
}

fn validate_window_input_tag(
    message: u16,
    parameter: Win16MessageParam,
) -> Result<(), RuntimeError> {
    if let Win16MessageParam::WindowInput(input) = parameter {
        if !Win16WindowInputMessage::accepts(message) || input.message_id() != message {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "typed window-input payload was used for a different message",
            ));
        }
    }
    Ok(())
}

pub(super) fn has_guest_proc(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: HWND,
    guest_class: Option<Win16HostClass>,
) -> bool {
    let state = state.borrow();
    state
        .windows_by_native
        .get(&(hwnd as usize))
        .is_some_and(|identity| {
            identity.window == window
                && match guest_class {
                    Some(expected) => {
                        identity.class == Some(expected) && state.classes.contains_key(&expected)
                    }
                    None => state
                        .dialog_routes_by_native
                        .get(&(hwnd as usize))
                        .is_some_and(|route| route.window == window),
                }
        })
}

fn resolve_optional_window(
    state: &Rc<RefCell<WorkerState>>,
    window: Option<Win16HostWindow>,
) -> Option<HWND> {
    match window {
        Some(window) => resolve_window(state, window),
        None => Some(std::ptr::null_mut()),
    }
}

fn canceled() -> RuntimeError {
    RuntimeError::new(
        Kind::HostFailure,
        "Win16 native message wait was canceled by worker shutdown",
    )
}
