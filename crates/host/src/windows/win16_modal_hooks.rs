//! Thread-lifetime USER hooks and exact modal cancellation dispatch.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use runtime::{DiagnosticKind as Kind, RuntimeError};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, GetClassNameW, GetWindowThreadProcessId, HC_ACTION, HCBT_ACTIVATE,
    HCBT_DESTROYWND, HHOOK, MSG, PM_NOREMOVE, PM_REMOVE, PostMessageW, SetWindowsHookExW, WH_CBT,
    WH_GETMESSAGE, WM_NULL,
};

use super::{
    GuestWorkMarkerDisposition, MODAL_WAKE_MESSAGE, ModalKind, ModalToken, ModalWorkerControl,
    clear_worker_control, current_control, mark_system_modal_cancelled, modal_stack_is_empty,
};

/// Same-thread hooks are required because MessageBox/ DialogBox own their
/// nested loops and do not wait on the worker's ordinary event handle.
pub(in crate::windows) struct ModalWorkerHooks {
    get_message: Option<HHOOK>,
    cbt: Option<HHOOK>,
    control: Arc<ModalWorkerControl>,
}

impl ModalWorkerHooks {
    pub(in crate::windows) fn install(
        control: Arc<ModalWorkerControl>,
    ) -> Result<Self, RuntimeError> {
        let thread_id = crate::windows::win32_safe::current_thread_id();
        control.bind_thread(thread_id)?;
        control.register_guest_work_message()?;
        let already_installed = super::WORKER_CONTROL.with(|slot| {
            let Ok(mut slot) = slot.try_borrow_mut() else {
                return true;
            };
            if slot.is_some() {
                true
            } else {
                *slot = Some(Arc::clone(&control));
                false
            }
        });
        if already_installed {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 modal worker hooks are already installed on this thread",
            ));
        }

        // hmod is null because both hooks target this process's current thread.
        // SAFETY: `SetWindowsHookExW`, `Some` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        let get_message = unsafe {
            SetWindowsHookExW(
                WH_GETMESSAGE,
                Some(modal_get_message_proc),
                std::ptr::null_mut(),
                thread_id,
            )
        };
        if get_message.is_null() {
            let error = crate::windows::win32_safe::last_error();
            clear_worker_control(&control);
            return Err(RuntimeError::with_source(
                Kind::HostFailure,
                "install the Win16 USER worker message hook",
                std::io::Error::from_raw_os_error(error as i32),
            ));
        }
        // SAFETY: `SetWindowsHookExW`, `Some` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        let cbt = unsafe {
            SetWindowsHookExW(
                WH_CBT,
                Some(modal_cbt_proc),
                std::ptr::null_mut(),
                thread_id,
            )
        };
        if cbt.is_null() {
            let error = crate::windows::win32_safe::last_error();
            let failure = RuntimeError::with_source(
                Kind::HostFailure,
                "install the Win16 USER worker CBT hook",
                std::io::Error::from_raw_os_error(error as i32),
            );
            let removed = crate::windows::win32_safe::unhook_windows_hook(get_message);
            let rollback = if removed == 0 {
                let error = crate::windows::win32_safe::last_error();
                Some(RuntimeError::with_source(
                    Kind::HostFailure,
                    "remove the partially installed Win16 USER message hook",
                    std::io::Error::from_raw_os_error(error as i32),
                ))
            } else {
                None
            };
            clear_worker_control(&control);
            return Err(match rollback {
                Some(additional) => combine_failures(
                    failure,
                    additional,
                    "Win16 modal hook installation and rollback both failed",
                ),
                None => failure,
            });
        }
        control.mark_guest_work_ready();
        Ok(Self {
            get_message: Some(get_message),
            cbt: Some(cbt),
            control,
        })
    }

    /// Called after every native modal API has returned, before its receipt.
    pub(in crate::windows) fn finish(mut self) -> Result<(), RuntimeError> {
        self.control.close_guest_work_lane();
        let mut failure = None;
        if !modal_stack_is_empty() {
            failure = Some(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 USER worker is exiting with an active modal registration",
            ));
        }
        let get_message_removed = self.get_message.take().is_some_and(|hook| {
            if (crate::windows::win32_safe::unhook_windows_hook(hook)) == 0 {
                let error = crate::windows::win32_safe::last_error();
                merge_failure(
                    &mut failure,
                    RuntimeError::with_source(
                        Kind::HostFailure,
                        "remove a Win16 USER worker message hook",
                        std::io::Error::from_raw_os_error(error as i32),
                    ),
                    "Win16 modal hook cleanup failed",
                );
                false
            } else {
                true
            }
        });
        if get_message_removed {
            if let Err(error) = drain_private_wakes(&self.control) {
                merge_failure(
                    &mut failure,
                    error,
                    "Win16 modal worker queue cleanup failed",
                );
            }
        }
        if let Some(hook) = self.cbt.take() {
            if (crate::windows::win32_safe::unhook_windows_hook(hook)) == 0 {
                let error = crate::windows::win32_safe::last_error();
                merge_failure(
                    &mut failure,
                    RuntimeError::with_source(
                        Kind::HostFailure,
                        "remove a Win16 USER worker CBT hook",
                        std::io::Error::from_raw_os_error(error as i32),
                    ),
                    "Win16 modal hook cleanup failed",
                );
            }
        }
        clear_worker_control(&self.control);
        self.control.flush_ingress_failure_after_native_return();
        if let Some(error) = self.control.take_callback_failure() {
            merge_failure(&mut failure, error, "Win16 modal hook callback failed");
        }
        failure.map_or(Ok(()), Err)
    }
}

impl Drop for ModalWorkerHooks {
    fn drop(&mut self) {
        self.control.close_guest_work_lane();
        for hook in [self.cbt.take(), self.get_message.take()]
            .into_iter()
            .flatten()
        {
            if (crate::windows::win32_safe::unhook_windows_hook(hook)) == 0 {
                let error = crate::windows::win32_safe::last_error();
                self.control
                    .record_callback_failure(RuntimeError::with_source(
                        Kind::HostFailure,
                        "remove a Win16 USER worker modal hook during unwinding",
                        std::io::Error::from_raw_os_error(error as i32),
                    ));
            }
        }
        clear_worker_control(&self.control);
    }
}

// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn modal_get_message_proc(
    code: i32,
    w_param: usize,
    l_param: isize,
) -> isize {
    if code >= 0 && code as u32 == HC_ACTION && w_param as u32 == PM_REMOVE && l_param != 0 {
        let result = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: HC_ACTION supplies the current MSG in lParam; this
            // worker-thread hook runs before that message is dispatched.
            let message = unsafe { &mut *(l_param as *mut MSG) };
            handle_worker_message(message);
        }));
        if result.is_err() {
            if let Some(control) = current_control() {
                control.record_callback_failure(RuntimeError::new(
                    Kind::HostFailure,
                    "Win16 owner-thread message hook panicked",
                ));
                if control.terminal_requested() {
                    (crate::windows::win32_safe::post_quit_message(0));
                }
            }
        }
    }
    // SAFETY: CallNextHookEx forwards the hook arguments Windows passed into this callback.
    unsafe { CallNextHookEx(std::ptr::null_mut(), code, w_param, l_param) }
}

fn handle_worker_message(message: &mut MSG) {
    let Some(control) = current_control() else {
        return;
    };
    let mut failure_delivered = false;
    if let Some((operation_id, scope_id)) = control.active_modal_work_scope()
        && super::super::win16_windows::current_operation_id() == Some(operation_id)
        && let Some((work, cause)) = control.pending_modal_failure(operation_id, scope_id)
    {
        match super::super::win16_windows::worker_context() {
            Some(worker) => {
                if let Err(error) = super::super::win16_windows::yield_pending_modal_guest_work(
                    &worker,
                    work,
                    Some(cause),
                ) {
                    let failure = control.abort_after_ingress_failure(work, error);
                    control.record_callback_failure(failure);
                }
                failure_delivered = true;
            }
            None => {
                let failure = RuntimeError::new(
                    Kind::InternalInvariant,
                    "modal ingress failure has no live USER worker context",
                );
                let failure = control.abort_after_ingress_failure(work, failure);
                control.record_callback_failure(failure);
                failure_delivered = true;
            }
        }
    }

    if message.hwnd.is_null()
        && control.guest_work_message() == Some(message.message)
        && message.wParam == control.worker_nonce
    {
        let Some(marker_id) = usize::try_from(message.lParam).ok() else {
            return;
        };
        match control.classify_guest_work_marker(marker_id) {
            GuestWorkMarkerDisposition::Unknown => {}
            GuestWorkMarkerDisposition::Stale => {
                suppress_worker_marker(message);
                return;
            }
            GuestWorkMarkerDisposition::Current(work) => {
                suppress_worker_marker(message);
                if failure_delivered
                    || control.terminal_requested()
                    || !exact_active_modal_scope(work.operation_id, work.scope_id)
                {
                    control.abandon_modal_guest_work(work);
                    return;
                }
                let Some(worker) = super::super::win16_windows::worker_context() else {
                    let failure = RuntimeError::new(
                        Kind::InternalInvariant,
                        "registered modal marker has no live USER worker context",
                    );
                    let failure = control.abort_after_ingress_failure(work, failure);
                    control.record_callback_failure(failure);
                    return;
                };
                if let Err(error) =
                    super::super::win16_windows::yield_pending_modal_guest_work(&worker, work, None)
                {
                    let failure = control.abort_after_ingress_failure(work, error);
                    control.record_callback_failure(failure);
                }
                return;
            }
        }
    }
    // The hook also sees PeekMessageA calls nested inside a suspended guest
    // callback. Only native modal-pump removals lack the exact worker
    // operation/queue retrieval scope and may be hidden as WM_NULL.
    if !modal_stack_is_empty()
        && !super::super::win16_windows::is_guest_notification_remove_retrieval()
    {
        match super::super::win16_windows::route_modal_guest_notification(message) {
            Ok(true) => return,
            Ok(false) => {}
            Err(error) => {
                // The carrier was suppressed before this error was returned;
                // surface the exhausted/invalid sidecar state after unwind.
                control.record_callback_failure(error);
                return;
            }
        }
    }
    // Dialog-targeted private cancellation has a non-null HWND and belongs
    // to its DLGPROC, even if its token numerically equals the worker nonce.
    if !message.hwnd.is_null()
        || message.message != MODAL_WAKE_MESSAGE
        || message.wParam != control.worker_nonce
    {
        return;
    }
    let request = message.lParam as u64;
    message.message = WM_NULL;
    message.wParam = 0;
    message.lParam = 0;
    message.hwnd = std::ptr::null_mut();
    if !control.wake_is_posted(request) {
        return;
    }
    cancel_registered_modals(&control);
    if !control
        .quit_posted
        .load(std::sync::atomic::Ordering::Acquire)
    {
        // The terminal owner-thread quit unwinds nested system modal loops.
        // The worker ACK still waits for each native call and operation to return.
        (crate::windows::win32_safe::post_quit_message(0));
        control
            .quit_posted
            .store(true, std::sync::atomic::Ordering::Release);
        if let Err(error) = mark_system_modal_cancelled(&control) {
            control.record_callback_failure(error);
        }
    }
}

fn exact_active_modal_scope(operation_id: u64, scope_id: u64) -> bool {
    if super::super::win16_windows::current_operation_id() != Some(operation_id) {
        return false;
    }
    super::scope::MODAL_FRAMES.with(|frames| {
        frames.try_borrow().ok().is_some_and(|frames| {
            frames.last().is_some_and(|frame| {
                frame.entered
                    && frame.operation_id == operation_id
                    && frame.token.0 as u64 == scope_id
            })
        })
    })
}

fn suppress_worker_marker(message: &mut MSG) {
    message.hwnd = std::ptr::null_mut();
    message.message = WM_NULL;
    message.wParam = 0;
    message.lParam = 0;
}

fn cancel_registered_modals(control: &Arc<ModalWorkerControl>) {
    let actions = match snapshot_dialog_cancels() {
        Ok(actions) => actions,
        Err(error) => {
            control.record_callback_failure(error);
            Vec::new()
        }
    };
    for (token, dialog) in actions {
        // No TLS borrow is held across PostMessageW, which can reenter USER.
        // SAFETY: PostMessageW queues scalar message parameters. Any pointer in lParam stays valid until the receiving window procedure returns.
        if unsafe { PostMessageW(dialog, MODAL_WAKE_MESSAGE, token.0, 0) } == 0 {
            let error = crate::windows::win32_safe::last_error();
            record_frame_failure(
                control,
                token,
                RuntimeError::with_source(
                    Kind::HostFailure,
                    "post cancellation to the registered Win16 DLGPROC HWND",
                    std::io::Error::from_raw_os_error(error as i32),
                ),
            );
        } else {
            mark_cancel_posted(token);
        }
    }
}

fn snapshot_dialog_cancels() -> Result<Vec<(ModalToken, HWND)>, RuntimeError> {
    super::MODAL_FRAMES.with(|frames| {
        let frames = frames.try_borrow().map_err(|_| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 modal scope stack is already borrowed during cancellation",
            )
        })?;
        let mut actions = Vec::new();
        actions.try_reserve_exact(frames.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "allocate Win16 nested modal cancellation records",
                error,
            )
        })?;
        for frame in frames.iter().rev() {
            if frame.kind == ModalKind::DialogProcedure
                && !frame.cancel_posted
                && let Some(dialog) = frame.hwnd
            {
                actions.push((frame.token, dialog));
            }
        }
        Ok(actions)
    })
}

fn mark_cancel_posted(token: ModalToken) {
    super::MODAL_FRAMES.with(|frames| {
        let Ok(mut frames) = frames.try_borrow_mut() else {
            if let Some(control) = current_control() {
                control.record_callback_failure(RuntimeError::new(
                    Kind::InternalInvariant,
                    "Win16 modal scope stack is borrowed after posting a cancellation",
                ));
            }
            return;
        };
        if let Some(frame) = frames.iter_mut().find(|frame| frame.token == token) {
            frame.cancel_posted = true;
        } else if let Some(control) = current_control() {
            control.record_callback_failure(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 modal frame disappeared after posting its cancellation",
            ));
        }
    });
}

fn record_frame_failure(control: &Arc<ModalWorkerControl>, token: ModalToken, error: RuntimeError) {
    let mut pending = Some(error);
    let recorded = super::MODAL_FRAMES.with(|frames| {
        let Ok(mut frames) = frames.try_borrow_mut() else {
            return false;
        };
        let Some(frame) = frames.iter_mut().find(|frame| frame.token == token) else {
            return false;
        };
        let additional = pending.take().expect("failure remains available");
        super::merge_failure(
            &mut frame.failure,
            additional,
            "Win16 modal cancellation failures combined",
        );
        true
    });
    if !recorded {
        if let Some(error) = pending {
            control.record_callback_failure(error);
        }
    }
}

// SAFETY: Windows calls this function with the system ABI in its signature. Pointer arguments are valid only for this invocation and are not guest addresses.
unsafe extern "system" fn modal_cbt_proc(code: i32, w_param: usize, l_param: isize) -> isize {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if code >= 0 {
            match code as u32 {
                HCBT_ACTIVATE => capture_message_box(w_param as HWND),
                HCBT_DESTROYWND => mark_window_closing(w_param as HWND),
                _ => {}
            }
        }
    }));
    if result.is_err() {
        if let Some(control) = current_control() {
            control.record_callback_failure(RuntimeError::new(
                Kind::HostFailure,
                "Win16 modal CBT hook panicked",
            ));
        }
    }
    // SAFETY: CallNextHookEx forwards the hook arguments Windows passed into this callback.
    unsafe { CallNextHookEx(std::ptr::null_mut(), code, w_param, l_param) }
}

fn capture_message_box(dialog: HWND) {
    let Some(control) = current_control() else {
        return;
    };
    if dialog.is_null() || !control.owner_thread() || control.terminal_requested() {
        return;
    }
    let Some(operation_id) = super::super::win16_windows::current_operation_id() else {
        return;
    };
    let mut class_name = [0u16; 32];
    let class_length =
        // SAFETY: GetClassNameW writes into a caller-owned UTF-16 buffer of the capacity passed with it.
        unsafe { GetClassNameW(dialog, class_name.as_mut_ptr(), class_name.len() as i32) };
    if class_length != 6 || class_name[..6] != (*b"#32770").map(u16::from) {
        return;
    }
    let mut owner_process = 0u32;
    // SAFETY: GetWindowThreadProcessId optionally writes a caller-owned process id.
    let owner_thread = unsafe { GetWindowThreadProcessId(dialog, &mut owner_process) };
    if owner_thread == 0
        || owner_thread != control.thread_id.load(std::sync::atomic::Ordering::Acquire)
        || owner_process != (crate::windows::win32_safe::current_process_id())
    {
        return;
    }
    super::MODAL_FRAMES.with(|frames| {
        let Ok(mut frames) = frames.try_borrow_mut() else {
            control.record_callback_failure(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 modal stack is borrowed during MessageBox HWND capture",
            ));
            return;
        };
        let Some(frame) = frames.last_mut() else {
            return;
        };
        if matches!(
            frame.kind,
            ModalKind::MessageBoxOk | ModalKind::NativeSystemModal
        ) && frame.operation_id == operation_id
            && frame.hwnd.is_none()
        {
            frame.hwnd = Some(dialog);
        }
    });
}

fn mark_window_closing(dialog: HWND) {
    let failed = super::MODAL_FRAMES.with(|frames| {
        let Ok(mut frames) = frames.try_borrow_mut() else {
            return true;
        };
        if let Some(frame) = frames
            .iter_mut()
            .rev()
            .find(|frame| frame.hwnd == Some(dialog))
        {
            // HCBT_DESTROYWND is an about-to-destroy notice; API return retires identity.
            frame.closing = true;
        }
        false
    });
    if failed && let Some(control) = current_control() {
        control.record_callback_failure(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 modal stack is borrowed during HWND retirement observation",
        ));
    }
}

fn drain_private_wakes(control: &ModalWorkerControl) -> Result<(), RuntimeError> {
    if (crate::windows::win32_safe::current_thread_id())
        != control.thread_id.load(std::sync::atomic::Ordering::Acquire)
    {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 modal wake queue was drained outside its owner thread",
        ));
    }
    loop {
        let mut message = MSG::default();
        // PeekMessage can return WM_QUIT regardless of the message filter, so
        // validate the actual id and thread-message HWND before removing it.
        // SAFETY: PeekMessageW writes into a caller-owned MSG that outlives the call.
        let found = unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::PeekMessageW(
                &mut message,
                std::ptr::null_mut(),
                MODAL_WAKE_MESSAGE,
                MODAL_WAKE_MESSAGE,
                PM_NOREMOVE,
            )
        };
        if found == 0
            || message.message != MODAL_WAKE_MESSAGE
            || !message.hwnd.is_null()
            || message.wParam != control.worker_nonce
        {
            return Ok(());
        }
        let expected_request = message.lParam;
        // SAFETY: PeekMessageW writes into a caller-owned MSG that outlives the call.
        let removed = unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::PeekMessageW(
                &mut message,
                std::ptr::null_mut(),
                MODAL_WAKE_MESSAGE,
                MODAL_WAKE_MESSAGE,
                PM_REMOVE,
            )
        };
        if removed == 0
            || message.message != MODAL_WAKE_MESSAGE
            || !message.hwnd.is_null()
            || message.wParam != control.worker_nonce
            || message.lParam != expected_request
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 modal wake queue changed identity during stale-message removal",
            ));
        }
    }
}

fn merge_failure(
    destination: &mut Option<RuntimeError>,
    additional: RuntimeError,
    context: &'static str,
) {
    *destination = Some(match destination.take() {
        Some(primary) => combine_failures(primary, additional, context),
        None => additional,
    });
}

fn combine_failures(
    primary: RuntimeError,
    additional: RuntimeError,
    context: &'static str,
) -> RuntimeError {
    let kind = primary.kind().with_cleanup(additional.kind());
    RuntimeError::with_source(
        kind,
        context,
        ModalFailurePair {
            primary,
            additional,
        },
    )
}

#[derive(Debug)]
struct ModalFailurePair {
    primary: RuntimeError,
    additional: RuntimeError,
}

impl std::fmt::Display for ModalFailurePair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; additional failure: {}",
            self.primary, self.additional
        )
    }
}

impl std::error::Error for ModalFailurePair {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
