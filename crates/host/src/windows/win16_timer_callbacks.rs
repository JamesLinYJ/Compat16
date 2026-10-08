//! Native timer callbacks suspended through the checked guest continuation pump.

use super::*;

/// Host-owned TIMERPROC used for Win16 timers and guest-posted WM_TIMER
/// sidecars. Windows may invoke this from a modal loop without entering the
/// private WndProc, so preserve the active operation and synchronously yield
/// to the guest runtime through the same Resume protocol.
pub(in crate::windows::win16_windows) unsafe extern "system" fn host_timer_proc(
    hwnd: HWND,
    _message: u32,
    timer_id: usize,
    time: u32,
) {
    let outcome = catch_unwind(AssertUnwindSafe(||
        dispatch_timer_proc(hwnd, timer_id, time)));
    if outcome.is_err() {
        if let Some(state) = worker_context() {
            fail_worker(&state, RuntimeError::new(Kind::InternalInvariant,
                "native Win16 TIMERPROC panicked; native callbacks were canceled"));
        }
    }
}

fn dispatch_timer_proc(hwnd: HWND, timer_id: usize, time: u32) {
    let Some(state) = worker_context() else { return; };
    let event = if let Some(posted) = worker_window::guest_timer_post(
        &state, hwnd, timer_id, true,
    ) {
        let window = if hwnd.is_null() {
            None
        } else {
            match worker_window::token_for_native(&state, hwnd) {
                Ok(window) => Some(window),
                Err(_) => return,
            }
        };
        Some((window, None, posted.guest_w_param, posted.guest_l_param))
    } else {
        worker_window::native_timer_record(&state, hwnd, timer_id)
            .filter(|record| record.guest_callback)
            .map(|record| (
                record.window,
                Some(record.host_id),
                record.guest_timer_id,
                0,
            ))
    };
    let Some((window, host_timer_id, guest_w_param, guest_l_param)) = event else {
        return;
    };
    let active = {
        let state = state.borrow();
        if state.callbacks_enabled && !state.aborted {
            state.active_operations.last().cloned()
        } else {
            None
        }
    };
    let Some(active) = active else {
        // No native operation is waiting on this USER thread. Never execute a
        // guest FAR outside a checked runtime continuation.
        return;
    };
    let live_callback_reservation = state.borrow_mut().live_callbacks.try_reserve(1);
    if let Err(error) = live_callback_reservation {
        fail_worker(&state, RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve terminal identity for native Win16 TIMERPROC callback",
            error,
        ));
        return;
    }
    let Some(callback) = worker_window::allocate_callback_id(&state) else {
        fail_worker(&state, RuntimeError::new(Kind::ResourceExhausted,
            "Win16 native callback identity exhausted"));
        return;
    };
    let source = runtime::Win16NativeCallbackSource::Timer {
        window,
        host_timer_id,
        guest_w_param,
        guest_l_param,
        time,
    };
    let identity = (!hwnd.is_null()).then(|| {
        state.borrow().windows_by_native.get(&(hwnd as usize)).copied()
    }).flatten();
    state.borrow_mut().live_callbacks.push(LiveCallback {
        callback,
        operation: active.id,
        source,
        creation: None,
        identity,
        message: None,
        hwnd,
        w_param: None,
        l_param: None,
        native_message_context: None,
        creation_cookie: None,
        mdi_create_struct: None,
    });
    let step = Win16WindowStep::GuestTimerCallback {
        operation_id: runtime::Win16HostWindowOperationId(active.id),
        callback,
        window,
        host_timer_id,
        guest_w_param,
        guest_l_param,
        time,
        source,
    };
    if active.response.send(Ok(step)).is_err() {
        remove_live_callback(&state, callback);
        fail_worker(&state, RuntimeError::new(Kind::HostFailure,
            "Win16 runtime dropped a suspended timer callback"));
        return;
    }
    // The result of TIMERPROC is void. The runtime uses the reply only to
    // resume this native callback after guest execution has completed.
    let _ = wait_for_guest_reply(&state, &active, callback);
    remove_live_callback(&state, callback);
}
