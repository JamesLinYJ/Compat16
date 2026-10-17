//! Native USER message-loop operations on the dedicated window worker.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostMdiMessageResult, Win16HostMdiOutput,
    Win16HostQueuedDelivery, Win16HostQueuedMessage, Win16HostWindow, Win16MessageFilter,
    Win16MessageParam, Win16MessageSource, Win16MessageWindow, Win16ScalarMessage,
    Win16WindowInputMessage, Win16WindowResult,
};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, MSG, PM_REMOVE, PeekMessageW, PostQuitMessage, TranslateMessage,
    WM_CHANGECBCHAIN, WM_CLOSE, WM_COMMAND, WM_DESTROY, WM_SYSCOMMAND, WM_USER,
};

use super::win16_window_worker::{self as worker, WorkerCommand, WorkerState};

#[path = "win16_message_loop_drop.rs"]
mod drop_files;
pub(super) use drop_files::{
    reject_removed_native_drop, retain_deferred_native_drop, retire_drop_files_for_window,
};

#[path = "win16_message_loop_dispatch.rs"]
mod dispatch;

#[path = "win16_message_loop_wait_command.rs"]
mod wait_command;
use wait_command::try_receive_command;
#[path = "win16_message_loop_wait.rs"]
mod wait;
use wait::take_pending_guest_work_generation;
#[path = "win16_mdi_queue.rs"]
mod mdi_queue;
pub(super) use mdi_queue::{
    capture_native_queued_message as capture_mdi_message,
    validate_owned_target as validate_mdi_owned_target,
};
pub(super) use wait::wait_for_input_or_command;
pub(super) use wait_command::wait_for_worker_command;

pub(super) fn encode_mdi_message_call(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    hwnd: HWND,
    message: u16,
    queued: runtime::Win16HostMdiQueuedMessage,
) -> Result<Option<(u32, usize, isize)>, RuntimeError> {
    mdi_queue::encode_dispatch(state, Some(window), hwnd, message, queued)
}

pub(super) enum WaitResult {
    Command(WorkerCommand),
    NativeInput,
    PendingGuestWork { generation: u64 },
}

pub(super) enum MessagePoll {
    Message(Win16HostQueuedDelivery),
    Empty,
    Error,
    PendingGuestWork { generation: u64 },
}

pub(super) fn get_message(
    state: &Rc<RefCell<WorkerState>>,
    filter: Win16MessageFilter,
) -> Result<MessagePoll, RuntimeError> {
    let Some(native_filter) = resolve_filter(state, filter) else {
        return Ok(MessagePoll::Error);
    };
    loop {
        if state.borrow().aborted {
            return Err(canceled_message_operation());
        }
        if let Some(generation) = take_pending_guest_work_generation(state) {
            return Ok(MessagePoll::PendingGuestWork { generation });
        }
        if !filter_is_alive(state, native_filter) {
            return Ok(MessagePoll::Error);
        }
        if let Some((queued, from_deferred)) = peek_matching(state, native_filter, PM_REMOVE)? {
            if !filter_is_alive(state, native_filter) {
                drop_files::retire_if_native_drop(state, &queued, true)?;
                return Ok(MessagePoll::Error);
            }
            if let Some(message) = dispatch::expose_or_dispatch(
                state,
                queued,
                native_filter,
                PM_REMOVE,
                from_deferred,
            )? {
                return Ok(MessagePoll::Message(message));
            }
            continue;
        }
        if !filter_is_alive(state, native_filter) {
            return Ok(MessagePoll::Error);
        }
        match wait::wait_for_input_or_command_with_filter(state, Some(native_filter))? {
            WaitResult::Command(command) => worker::process_command(state, command),
            WaitResult::NativeInput => {}
            WaitResult::PendingGuestWork { generation } => {
                return Ok(MessagePoll::PendingGuestWork { generation });
            }
        }
    }
}

pub(super) fn peek_message(
    state: &Rc<RefCell<WorkerState>>,
    filter: Win16MessageFilter,
    flags: u16,
) -> Result<MessagePoll, RuntimeError> {
    let Some(native_filter) = resolve_filter(state, filter) else {
        return Ok(MessagePoll::Error);
    };
    // Win16 and Win32 PM flags share their bit layout. Preserve unknown bits
    // so the native USER implementation determines their documented behavior.
    let native_flags = u32::from(flags);
    loop {
        if state.borrow().aborted {
            return Err(canceled_message_operation());
        }
        if !filter_is_alive(state, native_filter) {
            return Ok(MessagePoll::Error);
        }
        let Some((queued, from_deferred)) = peek_matching(state, native_filter, native_flags)?
        else {
            return if filter_is_alive(state, native_filter) {
                Ok(MessagePoll::Empty)
            } else {
                Ok(MessagePoll::Error)
            };
        };
        if !filter_is_alive(state, native_filter) {
            drop_files::retire_if_native_drop(state, &queued, native_flags & PM_REMOVE != 0)?;
            return Ok(MessagePoll::Error);
        }
        if let Some(message) =
            dispatch::expose_or_dispatch(state, queued, native_filter, native_flags, from_deferred)?
        {
            return Ok(MessagePoll::Message(message));
        }
    }
}

pub(super) fn translate_message(
    state: &Rc<RefCell<WorkerState>>,
    message: Win16HostQueuedMessage,
) -> Result<bool, RuntimeError> {
    translate_keyboard_message(state, message, |native| {
        // SAFETY: native holds owned, translated MSG values; this API reads
        // keyboard flags and never interprets guest LPARAM as a host pointer.
        unsafe { TranslateMessage(native) != 0 }
    })
}

pub(super) fn translate_mdi_accelerator(
    state: &Rc<RefCell<WorkerState>>,
    mdi_client: runtime::Win16HostWindow,
    message: Win16HostQueuedMessage,
) -> Result<bool, RuntimeError> {
    let Some(client) = resolve_message_window(state, Some(mdi_client))? else {
        return Ok(false);
    };
    translate_keyboard_message(state, message, |native| {
        // SAFETY: the client belongs to this USER thread and the local MSG
        // has the same pointer-free keyboard projection as TranslateMessage.
        unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::TranslateMDISysAccel(client, native) != 0
        }
    })
}

fn translate_keyboard_message(
    state: &Rc<RefCell<WorkerState>>,
    message: Win16HostQueuedMessage,
    translate: impl FnOnce(&MSG) -> bool,
) -> Result<bool, RuntimeError> {
    require_guest_source(message)?;
    validate_window_input_tag(message)?;
    if let Win16MessageParam::Mdi(queued) = message.l_param {
        mdi_queue::validate_guest_message_id(message.message, queued)?;
        // MDI messages are not keyboard input. In particular, their guest
        // HWND/HMENU words must not be rebuilt as native WPARAM/LPARAM here.
        return Ok(false);
    }
    let Some(hwnd) = resolve_message_window(state, message.window)? else {
        return Ok(false);
    };
    let (native_message_id, native_w_param, l_param) = match message.l_param {
        Win16MessageParam::WindowInput(input) => {
            let Some((native_message, native_w, native_l)) =
                super::win16_window_input::encode_window_input(state, input)?
            else {
                return Ok(false);
            };
            if native_message != u32::from(message.message) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "window-input conversion changed the native message identifier",
                ));
            }
            (native_message, native_w, native_l)
        }
        Win16MessageParam::ActivationApp(_)
        | Win16MessageParam::ParentNotification(_)
        | Win16MessageParam::ControlColor(_) => {
            return Ok(false);
        }
        // TranslateMessage reads keyboard flag bits and does not dereference
        // LPARAM. GuestBits is kept numeric in this owned MSG.
        Win16MessageParam::Scalar(value)
        | Win16MessageParam::GuestBits(value)
        | Win16MessageParam::GuestNotification { l_param: value, .. } => (
            u32::from(message.message),
            usize::from(message.w_param),
            (value as i32) as isize,
        ),
        // TranslateMessage only translates key-down messages; WM_COMMAND is
        // not one of them, and its LPARAM is a typed HWND family.
        Win16MessageParam::Command { .. } | Win16MessageParam::ClipboardChainChange { .. } => {
            (u32::from(message.message), usize::from(message.w_param), 0)
        }
        Win16MessageParam::TimerHostId(_) => {
            (u32::from(message.message), usize::from(message.w_param), 0)
        }
        Win16MessageParam::Mdi(_) => {
            unreachable!("typed MDI messages return before native translation")
        }
    };
    let mut native = native_message(hwnd, message, l_param);
    native.message = native_message_id;
    native.wParam = native_w_param;
    Ok(translate(&native))
}

pub(super) fn dispatch_message(
    state: &Rc<RefCell<WorkerState>>,
    message: Win16HostQueuedMessage,
) -> Result<Win16WindowResult, RuntimeError> {
    require_guest_source(message)?;
    validate_window_input_tag(message)?;
    let Some(hwnd) = resolve_message_window(state, message.window)? else {
        return Ok(Win16WindowResult::Dispatched(0));
    };
    if let Win16MessageParam::Mdi(queued) = message.l_param {
        let Some(window) = message.window else {
            return Ok(Win16WindowResult::Dispatched(0));
        };
        let Some((result, retirements)) =
            super::win16_window_default::mdi::dispatch_queued_message(
                state,
                window,
                hwnd,
                message.message,
                queued,
                message.time,
                message.point,
            )?
        else {
            return Ok(Win16WindowResult::Dispatched(0));
        };
        return Ok(Win16WindowResult::DispatchedMdi {
            result,
            retirements,
        });
    }
    let native_message_id = u32::from(message.message);
    let (native_w_param, native_l_param) = match message.l_param {
        Win16MessageParam::WindowInput(input) => {
            let Some((native_message, native_w, native_l)) =
                super::win16_window_input::encode_window_input(state, input)?
            else {
                return Ok(Win16WindowResult::Dispatched(0));
            };
            if native_message != u32::from(message.message) {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "window-input conversion changed the native message identifier",
                ));
            }
            (native_w, native_l)
        }
        Win16MessageParam::ActivationApp(input) if message.message == 0x001c => {
            let Some((native_w, native_l)) =
                super::win16_window_input::encode_activation_app(input)
            else {
                return Ok(Win16WindowResult::Dispatched(0));
            };
            (native_w, native_l)
        }
        Win16MessageParam::ParentNotification(input) if message.message == 0x0210 => {
            let Some((native_w, native_l)) =
                super::win16_window_input::encode_parent_notification(state, input)?
            else {
                return Ok(Win16WindowResult::Dispatched(0));
            };
            (native_w, native_l)
        }
        Win16MessageParam::ControlColor(_) => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "callback-scoped control-color HDC reached queued native dispatch",
            ));
        }
        Win16MessageParam::Scalar(value) => {
            let Some(native_w) = super::win16_character_messages::to_native(state,
                u32::from(message.message), message.w_param)? else {
                    return Ok(Win16WindowResult::Dispatched(0));
                };
            (native_w, (value as i32) as isize)
        },
        Win16MessageParam::Mdi(_) => {
            unreachable!("typed MDI messages returned through the shared MDI result route")
        }
        Win16MessageParam::Command {
            control, notify, ..
        } if message.message == WM_COMMAND as u16 => {
            let native_control = match control {
                Some(token) => match state.borrow().windows.get(&token).copied() {
                    Some(hwnd) => hwnd,
                    None => return Ok(Win16WindowResult::Dispatched(0)),
                },
                None => std::ptr::null_mut(),
            };
            let w_param = usize::from(message.w_param) | (usize::from(notify) << 16);
            (w_param, native_control as isize)
        }
        Win16MessageParam::ClipboardChainChange { removed, next }
            if message.message == WM_CHANGECBCHAIN as u16 =>
        {
            let Some(removed) = resolve_message_window(state, removed)? else {
                return Ok(Win16WindowResult::Dispatched(0));
            };
            let Some(next) = resolve_message_window(state, next)? else {
                return Ok(Win16WindowResult::Dispatched(0));
            };
            (removed as usize, next as isize)
        }
        Win16MessageParam::GuestBits(value) if message.message >= WM_USER as u16 => {
            let Some(window) = message.window else {
                return Ok(Win16WindowResult::Dispatched(0));
            };
            let class = worker::registered_class_for_native(state, hwnd);
            if !super::win16_message_calls::has_guest_proc(state, window, hwnd, class) {
                return Ok(Win16WindowResult::Dispatched(0));
            }
            (usize::from(message.w_param), (value as i32) as isize)
        }
        Win16MessageParam::GuestBits(_) | Win16MessageParam::GuestNotification { .. } => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "guest LPARAM/provenance reached native DispatchMessage without conversion",
            ));
        }
        Win16MessageParam::TimerHostId(_) => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "native timer identity reached guest DispatchMessage without Win16 translation",
            ));
        }
        Win16MessageParam::Command { .. } => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "typed WM_COMMAND LPARAM was used for a different message family",
            ));
        }
        Win16MessageParam::ClipboardChainChange { .. } => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "typed clipboard-chain HWNDs were used for a different message family",
            ));
        }
        Win16MessageParam::ActivationApp(_) | Win16MessageParam::ParentNotification(_) => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "typed USER message payload was used for a different message family",
            ));
        }
    };
    let kind = Win16ScalarMessage::from_raw(message.message);
    // Only the pointer-free MM_* subrange is allowed through a stock native
    // default procedure. WAVEHDR16/MIDIHDR16 FAR LPARAMs were routed to guest
    // callbacks by the runtime and never reach this native ABI call.
    if kind.is_none()
        && message.message != WM_COMMAND as u16
        && message.message != WM_CHANGECBCHAIN as u16
        && message.message < WM_USER as u16
        && !matches!(message.l_param, Win16MessageParam::WindowInput(_))
        && !matches!(message.l_param, Win16MessageParam::Mdi(_))
        && !matches!(
            message.l_param,
            Win16MessageParam::ActivationApp(_) | Win16MessageParam::ParentNotification(_)
        )
        && !(runtime::is_multimedia_notification_message(message.message)
            && !runtime::multimedia_notification_has_guest_far_lparam(message.message)
            && matches!(message.l_param, Win16MessageParam::Scalar(_)))
        && !(Win16ScalarMessage::is_timer_message(message.message) && native_l_param == 0)
    {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "an unconverted guest message reached native DispatchMessage",
        ));
    }
    if Win16ScalarMessage::is_timer_message(message.message) && native_l_param != 0 {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "guest timer callback address reached native DispatchMessage",
        ));
    }
    let mut native = native_message(hwnd, message, native_l_param);
    native.message = native_message_id;
    native.wParam = native_w_param;

    // Pin exact attached menu trees only after all message validation and
    // LPARAM conversion can no longer return early. This scope observes USER
    // teardown without changing clipboard-chain behavior.
    let mdi_children_before_close = if may_destroy_window_tree(message.message, message.w_param) {
        match message.window {
            Some(window) => Some(
                super::win16_window_default::mdi::snapshot_window_retirements(state, window, hwnd)?,
            ),
            None => None,
        }
    } else {
        None
    };
    let value = unsafe { DispatchMessageW(&native) as i32 };
    if let Some(snapshot) = mdi_children_before_close {
        let retirements =
            super::win16_window_default::mdi::finish_window_retirements(state, snapshot);
        if !retirements.receipts.is_empty() || !retirements.invalidated_menus.is_empty() {
            return Ok(Win16WindowResult::DispatchedMdi {
                result: Win16HostMdiMessageResult {
                    value: value as u32,
                    output: Win16HostMdiOutput::None,
                },
                retirements,
            });
        }
    }
    Ok(Win16WindowResult::Dispatched(value))
}

fn may_destroy_window_tree(message: u16, w_param: u16) -> bool {
    message == WM_CLOSE as u16
        || message == WM_DESTROY as u16
        || (message == WM_SYSCOMMAND as u16 && w_param & 0xfff0 == 0xf060)
}

pub(super) fn post_quit_message(exit_code: u16) {
    unsafe { PostQuitMessage(i32::from(exit_code)) };
}

#[derive(Clone, Copy)]
struct NativeFilter {
    queue: runtime::Win16HostTaskQueue,
    hwnd: HWND,
    window: Option<runtime::Win16HostWindow>,
    min: u32,
    max: u32,
}

fn resolve_filter(
    state: &Rc<RefCell<WorkerState>>,
    filter: Win16MessageFilter,
) -> Option<NativeFilter> {
    let queue = super::win16_guest_notifications::require_bound_queue(filter.task_queue)?;
    let (hwnd, window) = match filter.window {
        Win16MessageWindow::Any => (std::ptr::null_mut(), None),
        Win16MessageWindow::ThreadOnly => ((-1_isize) as HWND, None),
        Win16MessageWindow::Window(token) => {
            let hwnd = *state.borrow().windows.get(&token)?;
            (hwnd, Some(token))
        }
    };
    Some(NativeFilter {
        queue,
        hwnd,
        window,
        min: u32::from(filter.min_message),
        max: u32::from(filter.max_message),
    })
}

fn filter_is_alive(state: &Rc<RefCell<WorkerState>>, filter: NativeFilter) -> bool {
    let Some(token) = filter.window else {
        return true;
    };
    let Some(hwnd) = state.borrow().windows.get(&token).copied() else {
        return false;
    };
    unsafe { windows_sys::Win32::UI::WindowsAndMessaging::IsWindow(hwnd) != 0 }
}

fn peek_matching(
    state: &Rc<RefCell<WorkerState>>,
    filter: NativeFilter,
    flags: u32,
) -> Result<Option<(MSG, bool)>, RuntimeError> {
    // Commands take priority over a queued message so Abort always cancels a
    // blocked GetMessage before guest callback work continues.
    if let Some(command) = try_receive_command(state)? {
        worker::process_command(state, command);
        if state.borrow().aborted {
            return Err(canceled_message_operation());
        }
    }
    super::win16_guest_notifications::requeue_deferred()?;
    if let Some(message) = super::win16_deferred_native_messages::peek_matching(
        state,
        filter.hwnd,
        filter.min,
        filter.max,
        flags & PM_REMOVE != 0,
    )? {
        return Ok(Some((message, true)));
    }
    let _retrieval = super::win16_guest_notifications::guest_retrieval_scope(filter.queue, flags)?;
    let mut native = MSG::default();
    let removed = unsafe { PeekMessageW(&mut native, filter.hwnd, filter.min, filter.max, flags) };
    Ok((removed != 0).then_some((native, false)))
}

fn native_message(hwnd: HWND, message: Win16HostQueuedMessage, l_param: isize) -> MSG {
    MSG {
        hwnd,
        message: u32::from(message.message),
        wParam: usize::from(message.w_param),
        lParam: l_param,
        time: message.time,
        pt: windows_sys::Win32::Foundation::POINT {
            x: message.point.x,
            y: message.point.y,
        },
    }
}

fn resolve_message_window(
    state: &Rc<RefCell<WorkerState>>,
    token: Option<runtime::Win16HostWindow>,
) -> Result<Option<HWND>, RuntimeError> {
    let Some(token) = token else {
        return Ok(Some(std::ptr::null_mut()));
    };
    let hwnd = *state.borrow().windows.get(&token).ok_or_else(|| {
        RuntimeError::new(
            Kind::InvalidInput,
            "Win16 message refers to an unknown native window",
        )
    })?;
    if unsafe { windows_sys::Win32::UI::WindowsAndMessaging::IsWindow(hwnd) } == 0 {
        return Ok(None);
    }
    Ok(Some(hwnd))
}

fn require_guest_source(message: Win16HostQueuedMessage) -> Result<(), RuntimeError> {
    if message.source == Win16MessageSource::GuestMessage {
        Ok(())
    } else {
        Err(RuntimeError::new(
            Kind::InternalInvariant,
            "native queue MSG was submitted as a guest message operation",
        ))
    }
}

fn validate_window_input_tag(message: Win16HostQueuedMessage) -> Result<(), RuntimeError> {
    if let Win16MessageParam::WindowInput(input) = message.l_param {
        if !Win16WindowInputMessage::accepts(message.message)
            || input.message_id() != message.message
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "typed window-input payload was used for a different message",
            ));
        }
    }
    Ok(())
}

fn canceled_message_operation() -> RuntimeError {
    RuntimeError::new(
        Kind::HostFailure,
        "Win16 native message operation was canceled by worker shutdown",
    )
}
