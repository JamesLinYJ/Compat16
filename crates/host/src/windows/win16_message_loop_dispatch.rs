//! Native MSG exposure and dispatch after USER queue filtering.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostQueuedDelivery, Win16HostQueuedMessage,
    Win16MessageParam, Win16MessageSource, Win16ScalarMessage, Win16WindowInputMessage,
};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetParent, MSG, PM_REMOVE, PeekMessageW, WM_CHANGECBCHAIN, WM_CHAR,
    WM_COMMAND, WM_DEADCHAR, WM_DROPFILES, WM_NCACTIVATE, WM_QUIT, WM_SYSCHAR,
    WM_SYSDEADCHAR, WM_TIMER, WM_USER,
};

use super::{NativeFilter, WorkerState, filter_is_alive, mdi_queue, worker};

pub(super) fn expose_or_dispatch(
    state: &Rc<RefCell<WorkerState>>,
    mut native: MSG,
    filter: NativeFilter,
    peek_flags: u32,
    from_deferred: bool,
) -> Result<Option<Win16HostQueuedDelivery>, RuntimeError> {
    let removed = peek_flags & PM_REMOVE != 0;
    if !filter_is_alive(state, filter) {
        super::drop_files::retire_if_native_drop(state, &native, removed)?;
        return Ok(None);
    }
    match super::super::win16_guest_notifications::lookup(state, &native, removed)? {
        super::super::win16_guest_notifications::CarrierLookup::Live(notification) => {
            return Ok(Some(Win16HostQueuedDelivery::message(
                super::super::win16_guest_notifications::queued_message(notification, &native),
            )));
        }
        super::super::win16_guest_notifications::CarrierLookup::Retired => {
            if !removed {
                let Some((actual, actual_deferred)) =
                    remove_after_peek(state, &native, filter, peek_flags, from_deferred)?
                else {
                    return Ok(None);
                };
                if !same_message(&native, &actual) {
                    return expose_or_dispatch(
                        state,
                        actual,
                        filter,
                        peek_flags | PM_REMOVE,
                        actual_deferred,
                    );
                }
                let _ = super::super::win16_guest_notifications::lookup(state, &actual, true)?;
            }
            return Ok(None);
        }
        super::super::win16_guest_notifications::CarrierLookup::NotCarrier => {}
    }

    if native.message == WM_DROPFILES {
        return match super::drop_files::expose_native_drop_files(state, native, removed) {
            Ok(delivery) => Ok(delivery),
            Err(error) if error.kind() == Kind::CompatibilityGap => {
                super::super::win16_window_position::report_diagnostic(
                    state,
                    Kind::CompatibilityGap,
                    "native WM_DROPFILES could not be represented for the guest; the drop was rejected",
                );
                Ok((!removed).then(Win16HostQueuedDelivery::empty))
            }
            Err(error) => Err(error),
        };
    }

    if native.message == WM_QUIT {
        return Ok(Some(Win16HostQueuedDelivery::message(
            Win16HostQueuedMessage {
                source: Win16MessageSource::NativeQueue,
                window: None,
                message: WM_QUIT as u16,
                w_param: native.wParam as u16,
                l_param: Win16MessageParam::Scalar(0),
                time: native.time,
                point: runtime::Win16HostPoint {
                    x: native.pt.x,
                    y: native.pt.y,
                },
            },
        )));
    }

    let Some(message_id) = u16::try_from(native.message).ok() else {
        if !removed {
            let Some((actual, actual_deferred)) =
                remove_after_peek(state, &native, filter, peek_flags, from_deferred)?
            else {
                return Ok(None);
            };
            if !same_message(&native, &actual) {
                return expose_or_dispatch(
                    state,
                    actual,
                    filter,
                    peek_flags | PM_REMOVE,
                    actual_deferred,
                );
            }
            native = actual;
        }
        if !filter_is_alive(state, filter) {
            return Ok(None);
        }
        unsafe { DispatchMessageW(&native) };
        return Ok(None);
    };

    if let Some(message) = mdi_queue::capture_native_queued_message(state, &native)? {
        return Ok(Some(Win16HostQueuedDelivery::message(message)));
    }

    if native.message == 0x001c {
        if let Some(input) =
            super::super::win16_window_input::decode_activation_app(native.wParam, native.lParam)
        {
            let window = if native.hwnd.is_null() {
                Some(None)
            } else {
                state
                    .borrow()
                    .windows_by_native
                    .get(&(native.hwnd as usize))
                    .map(|identity| Some(identity.window))
            };
            if let Some(window) = window {
                return Ok(Some(Win16HostQueuedDelivery::message(
                    Win16HostQueuedMessage {
                        source: Win16MessageSource::NativeQueue,
                        window,
                        message: message_id,
                        w_param: 0,
                        l_param: Win16MessageParam::ActivationApp(input),
                        time: native.time,
                        point: runtime::Win16HostPoint {
                            x: native.pt.x,
                            y: native.pt.y,
                        },
                    },
                )));
            }
        }
    }

    if native.message == 0x0210 {
        let parent_window = {
            state
                .borrow()
                .windows_by_native
                .get(&(native.hwnd as usize))
                .map(|identity| identity.window)
        };
        if let Some(window) = parent_window {
            if let Some(input) = super::super::win16_window_input::decode_parent_notification(
                state,
                native.wParam,
                native.lParam,
            )? {
                return Ok(Some(Win16HostQueuedDelivery::message(
                    Win16HostQueuedMessage {
                        source: Win16MessageSource::NativeQueue,
                        window: Some(window),
                        message: message_id,
                        w_param: 0,
                        l_param: Win16MessageParam::ParentNotification(input),
                        time: native.time,
                        point: runtime::Win16HostPoint {
                            x: native.pt.x,
                            y: native.pt.y,
                        },
                    },
                )));
            }
        }
    }

    if native.message == WM_TIMER && native.lParam == worker::host_timer_proc_pointer() {
        // A guest-posted timer has a sidecar keyed by its private WPARAM
        // marker. The LPARAM is always our host-owned TIMERPROC, never the
        // guest FAR value. PM_NOREMOVE leaves the sidecar paired with its MSG.
        if let Some(posted) = worker::guest_timer_post(state, native.hwnd, native.wParam, removed) {
            let window = if native.hwnd.is_null() {
                Some(None)
            } else {
                state
                    .borrow()
                    .windows_by_native
                    .get(&(native.hwnd as usize))
                    .map(|identity| Some(identity.window))
            };
            if let Some(window) = window {
                return Ok(Some(Win16HostQueuedDelivery::message(
                    Win16HostQueuedMessage {
                        source: Win16MessageSource::NativeQueue,
                        window,
                        message: posted.guest_message,
                        w_param: posted.guest_w_param,
                        l_param: Win16MessageParam::GuestBits(posted.guest_l_param),
                        time: native.time,
                        point: runtime::Win16HostPoint {
                            x: native.pt.x,
                            y: native.pt.y,
                        },
                    },
                )));
            }
            if removed {
                return Ok(None);
            }
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "posted Win16 WM_TIMER target lost its HWND mapping before PeekMessage",
            ));
        }

        // SetTimer callbacks also use the host thunk. The exact native HWND
        // and UINT_PTR recover the retained generation, while the runtime
        // writes the corresponding guest FAR into MSG16.
        if let Some(record) = worker::native_timer_record(state, native.hwnd, native.wParam)
            .filter(|record| record.guest_callback)
        {
            let guest_message = if record.system {
                Win16ScalarMessage::SystemTimer as u16
            } else {
                message_id
            };
            return Ok(Some(Win16HostQueuedDelivery::message(
                Win16HostQueuedMessage {
                    source: Win16MessageSource::NativeQueue,
                    window: record.window,
                    message: guest_message,
                    w_param: record.guest_timer_id,
                    // This queue record has our exact native thunk in LPARAM and
                    // a live guest TIMERPROC generation. Runtime restores the
                    // original guest FAR from this host-only timer identity.
                    l_param: Win16MessageParam::TimerHostId(record.host_id),
                    time: native.time,
                    point: runtime::Win16HostPoint {
                        x: native.pt.x,
                        y: native.pt.y,
                    },
                },
            )));
        }

        // Known generations, including pending callbacks after KillTimer,
        // were returned above. An unregistered thunk contains only our host
        // procedure; Windows dispatch runs its checked, empty lookup.
        return dispatch_native(state, native, filter, peek_flags, from_deferred);
    }

    if native.message == WM_TIMER && native.lParam != 0 {
        // Guest timer registrations and posts use our exact thunk above.
        // Other native TIMERPROCs are internal USER work, even during a
        // guest PM_NOREMOVE check. Pump their original MSG on this worker;
        // their pointer-width callback never becomes a guest FAR or scalar.
        return dispatch_native(state, native, filter, peek_flags, from_deferred);
    }

    if native.message == WM_TIMER && native.lParam == 0 {
        // A zero LPARAM is an ordinary queued message, not evidence that it
        // came from SetTimer. Resolve its destination through the current
        // HWND map so a recycled HWND cannot inherit an old timer record.
        // Only a callback-free timer on that exact live window may translate
        // the native ID; all other messages keep their scalar WPARAM.
        let current_window = if native.hwnd.is_null() {
            Some(None)
        } else {
            state
                .borrow()
                .windows_by_native
                .get(&(native.hwnd as usize))
                .map(|identity| Some(identity.window))
        };
        if let Some(window) = current_window {
            let matched = worker::native_timer_record(state, native.hwnd, native.wParam)
                .filter(|record| !record.guest_callback && record.window == window);
            let guest_timer_id = matched.map(|record| record.guest_timer_id);
            let system_timer = matched.is_some_and(|record| record.system);
            if let Some(guest_timer_id) =
                guest_timer_id.or_else(|| u16::try_from(native.wParam).ok())
            {
                let guest_message = if system_timer {
                    Win16ScalarMessage::SystemTimer as u16
                } else {
                    message_id
                };
                return Ok(Some(Win16HostQueuedDelivery::message(
                    Win16HostQueuedMessage {
                        source: Win16MessageSource::NativeQueue,
                        window,
                        message: guest_message,
                        w_param: guest_timer_id,
                        l_param: Win16MessageParam::Scalar(0),
                        time: native.time,
                        point: runtime::Win16HostPoint {
                            x: native.pt.x,
                            y: native.pt.y,
                        },
                    },
                )));
            }
        }
        if native.wParam > usize::from(u16::MAX) {
            if !removed {
                return Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "unregistered native WM_TIMER identifier does not fit the Win16 message ABI",
                ));
            }
            if filter_is_alive(state, filter) {
                unsafe { DispatchMessageW(&native) };
            }
            return Ok(None);
        }
    }

    // Native -1 has no lossless MSG16 representation or persistent callback
    // capability. Let the ordinary native dispatch below deliver the original
    // MSG; its synchronous WndProc callback retains the private context.
    let native_nonclient_suppression =
        native.message == WM_NCACTIVATE && native.lParam == -1 && !native.hwnd.is_null();
    if Win16WindowInputMessage::accepts(message_id) && !native_nonclient_suppression {
        if native.hwnd.is_null() {
            // PostAppMessage preserves window-input IDs as a thread
            // message. Its LPARAM remains guest bits, not native HWND data.
            return Ok(Some(Win16HostQueuedDelivery::message(
                Win16HostQueuedMessage {
                    source: Win16MessageSource::NativeQueue,
                    window: None,
                    message: message_id,
                    w_param: native.wParam as u16,
                    l_param: Win16MessageParam::GuestBits(native.lParam as u32),
                    time: native.time,
                    point: runtime::Win16HostPoint {
                        x: native.pt.x,
                        y: native.pt.y,
                    },
                },
            )));
        }
        let window = state
            .borrow()
            .windows_by_native
            .get(&(native.hwnd as usize))
            .map(|identity| identity.window);
        if let Some(window) = window {
            let input = if native.message == WM_NCACTIVATE {
                // NCACTIVATE's inferred minimized word comes from its receiver,
                // while its native -1 sentinel never becomes a guest HWND.
                super::super::win16_window_input::decode_nonclient_activation(
                    state,
                    native.hwnd,
                    native.wParam,
                    native.lParam,
                )?
            } else {
                super::super::win16_window_input::decode_window_input(
                    state,
                    native.message,
                    native.wParam,
                    native.lParam,
                )?
            };
            if let Some(input) = input {
                if input.message_id() != message_id {
                    return Err(RuntimeError::new(
                        Kind::InternalInvariant,
                        "native window-input conversion returned a different message",
                    ));
                }
                return Ok(Some(Win16HostQueuedDelivery::message(
                    Win16HostQueuedMessage {
                        source: Win16MessageSource::NativeQueue,
                        window: Some(window),
                        message: message_id,
                        // The typed payload carries all Win16 words and native
                        // handle identities; runtime derives the guest WPARAM.
                        w_param: 0,
                        l_param: Win16MessageParam::WindowInput(input),
                        time: native.time,
                        point: runtime::Win16HostPoint {
                            x: native.pt.x,
                            y: native.pt.y,
                        },
                    },
                )));
            }
        }
    }

    if matches!(
        native.message,
        WM_CHAR | WM_DEADCHAR | WM_SYSCHAR | WM_SYSDEADCHAR
    ) {
        let Some(guest_character) =
            super::super::win16_window_text_context::native_guest_character(state, native.wParam)
        else {
            if !removed {
                let Some((actual, actual_deferred)) =
                    remove_after_peek(state, &native, filter, peek_flags, from_deferred)?
                else {
                    return Ok(None);
                };
                if !same_message(&native, &actual) {
                    return expose_or_dispatch(
                        state,
                        actual,
                        filter,
                        peek_flags | PM_REMOVE,
                        actual_deferred,
                    );
                }
            }
            super::super::win16_window_position::report_diagnostic(
                state,
                Kind::CompatibilityGap,
                "native Unicode character has no ANSI/DBCS Win16 word projection; the queued character was consumed",
            );
            return Ok(None);
        };
        let window = if native.hwnd.is_null() {
            Some(None)
        } else {
            state
                .borrow()
                .windows_by_native
                .get(&(native.hwnd as usize))
                .map(|identity| Some(identity.window))
        };
        if let Some(window) = window {
            return Ok(Some(Win16HostQueuedDelivery::message(
                Win16HostQueuedMessage {
                    source: Win16MessageSource::NativeQueue,
                    window,
                    message: message_id,
                    w_param: guest_character,
                    l_param: Win16MessageParam::Scalar(native.lParam as u32),
                    time: native.time,
                    point: runtime::Win16HostPoint {
                        x: native.pt.x,
                        y: native.pt.y,
                    },
                },
            )));
        }
    }

    if native.message == WM_CHANGECBCHAIN {
        let window = state
            .borrow()
            .windows_by_native
            .get(&(native.hwnd as usize))
            .map(|identity| identity.window);
        if let Some(window) = window {
            let removed = if native.wParam == 0 {
                None
            } else {
                Some(worker::token_for_native(state, native.wParam as HWND)?)
            };
            let next = if native.lParam == 0 {
                None
            } else {
                Some(worker::token_for_native(state, native.lParam as HWND)?)
            };
            return Ok(Some(Win16HostQueuedDelivery::message(
                Win16HostQueuedMessage {
                    source: Win16MessageSource::NativeQueue,
                    window: Some(window),
                    message: message_id,
                    w_param: 0,
                    l_param: Win16MessageParam::ClipboardChainChange { removed, next },
                    time: native.time,
                    point: runtime::Win16HostPoint {
                        x: native.pt.x,
                        y: native.pt.y,
                    },
                },
            )));
        }
    }

    if native.message == WM_COMMAND {
        // Win16 stores control HWND16 in LPARAM's low word and notification
        // code in its high word. Native Windows stores the full HWND in
        // LPARAM and splits ID/notification across WPARAM.
        let command = if native.hwnd.is_null() {
            // Thread messages have no WndProc destination. PostAppMessage
            // LPARAM is an opaque guest value, so keep it numeric.
            Some((None, Win16MessageParam::GuestBits(native.lParam as u32)))
        } else if native.lParam == 0 {
            let window = state
                .borrow()
                .windows_by_native
                .get(&(native.hwnd as usize))
                .map(|identity| identity.window);
            window.map(|window| {
                (
                    Some(window),
                    Win16MessageParam::Command {
                        control: None,
                        control_parent: None,
                        notify: (native.wParam >> 16) as u16,
                    },
                )
            })
        } else {
            let window = state
                .borrow()
                .windows_by_native
                .get(&(native.hwnd as usize))
                .map(|identity| identity.window);
            let control = if unsafe {
                windows_sys::Win32::UI::WindowsAndMessaging::IsWindow(native.lParam as HWND)
            } != 0
            {
                Some(worker::token_for_native(state, native.lParam as HWND)?)
            } else {
                None
            };
            let parent = if control.is_some() {
                unsafe { GetParent(native.lParam as HWND) }
            } else {
                std::ptr::null_mut()
            };
            let control_parent = if parent.is_null() {
                None
            } else {
                Some(worker::token_for_native(state, parent)?)
            };
            match (window, control) {
                (Some(window), Some(control)) => Some((
                    Some(window),
                    Win16MessageParam::Command {
                        control: Some(control),
                        control_parent,
                        notify: (native.wParam >> 16) as u16,
                    },
                )),
                _ => None,
            }
        };
        if let Some((window, l_param)) = command {
            return Ok(Some(Win16HostQueuedDelivery::message(
                Win16HostQueuedMessage {
                    source: Win16MessageSource::NativeQueue,
                    window,
                    message: message_id,
                    w_param: native.wParam as u16,
                    l_param,
                    time: native.time,
                    point: runtime::Win16HostPoint {
                        x: native.pt.x,
                        y: native.pt.y,
                    },
                },
            )));
        }
    }

    if native.message >= WM_USER && !native.hwnd.is_null() {
        let guest_window = {
            let state = state.borrow();
            state
                .windows_by_native
                .get(&(native.hwnd as usize))
                .and_then(|identity| {
                    let registered = identity
                        .class
                        .is_some_and(|class| state.classes.contains_key(&class));
                    let dialog = state
                        .dialog_routes_by_native
                        .get(&(native.hwnd as usize))
                        .is_some_and(|route| route.window == identity.window);
                    (registered || dialog).then_some(identity.window)
                })
        };
        if let Some(window) = guest_window {
            return Ok(Some(Win16HostQueuedDelivery::message(
                Win16HostQueuedMessage {
                    source: Win16MessageSource::NativeQueue,
                    window: Some(window),
                    message: message_id,
                    w_param: native.wParam as u16,
                    // WM_USER and above are application-defined. This HWND is
                    // served by a registered private guest WndProc, so its guest
                    // LPARAM is retained as bits and never interpreted as a
                    // native pointer by the worker.
                    l_param: Win16MessageParam::GuestBits(native.lParam as u32),
                    time: native.time,
                    point: runtime::Win16HostPoint {
                        x: native.pt.x,
                        y: native.pt.y,
                    },
                },
            )));
        }
    }

    let timer_without_native_callback = native.message == WM_TIMER && native.lParam == 0;
    // Nonzero WM_PAINT WPARAM is an HDC. Keep the native MSG intact until
    // dispatch, where the typed callback borrows it; never truncate it to WORD.
    let paint_has_dc = native.message == windows_sys::Win32::UI::WindowsAndMessaging::WM_PAINT
        && native.wParam != 0;
    // Native WM_SYSTIMER may carry a Windows-owned, pointer-width callback.
    // Only callback-free timer values fit MSG16's scalar contract. Registered
    // guest timers/posts were resolved through their exact sidecars above;
    // other native callbacks stay in the original MSG for Windows dispatch.
    let timer_parameters_are_scalar = !Win16ScalarMessage::is_timer_message(message_id)
        || (native.lParam == 0 && native.wParam <= usize::from(u16::MAX));
    let pointer_free = (Win16ScalarMessage::from_raw(message_id).is_some()
        && !paint_has_dc && timer_parameters_are_scalar)
        || timer_without_native_callback;
    let token = if native.hwnd.is_null() {
        Some(None)
    } else {
        state
            .borrow()
            .windows_by_native
            .get(&(native.hwnd as usize))
            .map(|identity| Some(identity.window))
    };
    if pointer_free {
        if let Some(window) = token {
            return Ok(Some(Win16HostQueuedDelivery::message(
                Win16HostQueuedMessage {
                    source: Win16MessageSource::NativeQueue,
                    window,
                    message: message_id,
                    w_param: native.wParam as u16,
                    l_param: if timer_without_native_callback {
                        Win16MessageParam::Scalar(0)
                    } else {
                        Win16MessageParam::Scalar(native.lParam as u32)
                    },
                    time: native.time,
                    point: runtime::Win16HostPoint {
                        x: native.pt.x,
                        y: native.pt.y,
                    },
                },
            )));
        }
    }

    // A message whose LPARAM has not been explicitly classified never crosses
    // to the guest. Its private WndProc applies typed marshalling or reports
    // the unsupported message; OS-owned windows remain entirely in Windows.
    dispatch_native(state, native, filter, peek_flags, from_deferred)
}

fn dispatch_native(
    state: &Rc<RefCell<WorkerState>>,
    mut native: MSG,
    filter: NativeFilter,
    peek_flags: u32,
    from_deferred: bool,
) -> Result<Option<Win16HostQueuedDelivery>, RuntimeError> {
    if peek_flags & PM_REMOVE == 0 {
        let Some((actual, actual_deferred)) =
            remove_after_peek(state, &native, filter, peek_flags, from_deferred)?
        else {
            return Ok(None);
        };
        if !same_message(&native, &actual) {
            return expose_or_dispatch(
                state,
                actual,
                filter,
                peek_flags | PM_REMOVE,
                actual_deferred,
            );
        }
        native = actual;
    }
    if !filter_is_alive(state, filter) {
        return Ok(None);
    }
    // SAFETY: Only an owned native queue MSG reaches this function. Removal
    // was rechecked after sent-message reentrancy; all worker borrows ended
    // before Windows invokes its original procedure on the owning thread.
    unsafe { DispatchMessageW(&native) };
    Ok(None)
}

fn remove_after_peek(
    state: &Rc<RefCell<WorkerState>>,
    expected: &MSG,
    filter: NativeFilter,
    flags: u32,
    from_deferred: bool,
) -> Result<Option<(MSG, bool)>, RuntimeError> {
    if from_deferred {
        return super::super::win16_deferred_native_messages::remove_exact(
            state,
            expected,
            filter.hwnd,
            filter.min,
            filter.max,
        )
        .map(|message| message.map(|message| (message, true)));
    }
    // PeekMessage can dispatch sent messages. A callback may change the queue
    // before removal; the caller compares and routes the actual removed MSG.
    let _retrieval = super::super::win16_guest_notifications::guest_retrieval_scope(
        filter.queue,
        flags | PM_REMOVE,
    )?;
    let mut removed = MSG::default();
    let found = unsafe {
        PeekMessageW(
            &mut removed,
            filter.hwnd,
            filter.min,
            filter.max,
            flags | PM_REMOVE,
        )
    };
    Ok((found != 0).then_some((removed, false)))
}

fn same_message(left: &MSG, right: &MSG) -> bool {
    left.hwnd == right.hwnd
        && left.message == right.message
        && left.wParam == right.wParam
        && left.lParam == right.lParam
        && left.time == right.time
        && left.pt.x == right.pt.x
        && left.pt.y == right.pt.y
}
