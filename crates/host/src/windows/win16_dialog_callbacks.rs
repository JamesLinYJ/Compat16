//! Native DLGPROC routing through checked runtime callback continuations.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostDialogMessage, Win16HostMessage,
    Win16HostMessageOutput as Output, Win16ScalarMessage, Win16WindowStep,
};
use windows_sys::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows_sys::Win32::UI::Shell::HDROP;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DWLP_MSGRESULT, GetParent, IsChild, IsWindow, MINMAXINFO, MSG, SetWindowLongPtrW, WINDOWPOS,
    WM_CHANGECBCHAIN, WM_COMMAND, WM_DESTROY, WM_DROPFILES, WM_ERASEBKGND, WM_GETDLGCODE,
    WM_GETMINMAXINFO, WM_GETTEXT, WM_GETTEXTLENGTH, WM_INITDIALOG, WM_NCACTIVATE, WM_NCCALCSIZE,
    WM_NCDESTROY, WM_NCPAINT, WM_PAINT, WM_SETTEXT, WM_WINDOWPOSCHANGED, WM_WINDOWPOSCHANGING,
};

use super::win16_window_callbacks;
use super::win16_window_geometry::copy_minmax;
use super::win16_window_worker::{
    self as worker, ActiveOperation, DialogRoute, LiveCallback, NativeDropCallbackClaim,
    NativeDropCallbackResolution, NativeDropOwner as NativeDropQueueOwner, WorkerState,
};
#[path = "win16_dialog_callback_routes.rs"]
mod callback_routes;

pub(super) unsafe extern "system" fn host_dialog_proc(
    hwnd: HWND,
    message: u32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> isize {
    if message == windows_sys::Win32::UI::WindowsAndMessaging::WM_ACTIVATEAPP && w_param == 0 {
        super::win16_cursor_clip::forget_after_deactivation();
    }
    let is_native_drop = message == WM_DROPFILES
        && !super::win16_guest_notifications::is_carrier_message(hwnd, message, w_param, l_param);
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        dispatch_dialog_proc(hwnd, message, w_param, l_param)
    }));
    match outcome {
        // DefDlgProc may run after a DLGPROC returns FALSE. HDROP has already
        // been finished by our typed snapshot owner, so suppress that native
        // fallback and never let USER observe the old wParam bits.
        Ok(_) if is_native_drop => 1,
        Ok(result) => result,
        Err(_) => {
            if let Some(state) = worker::worker_context() {
                win16_window_callbacks::fail_worker(
                    &state,
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "native Win16 DLGPROC panicked; native callbacks were canceled",
                    ),
                );
            }
            if is_native_drop { 1 } else { 0 }
        }
    }
}

fn dispatch_dialog_proc(hwnd: HWND, message: u32, w_param: WPARAM, l_param: LPARAM) -> isize {
    let is_native_drop = message == WM_DROPFILES
        && !super::win16_guest_notifications::is_carrier_message(hwnd, message, w_param, l_param);
    // DLGPROC takes ownership of WM_DROPFILES just like WndProc. Keep the
    // HDROP local through every early return, then release it after copying
    // the guest-facing snapshot; never let DefDlgProc see stale handle bits.
    let Some(state) = worker::worker_context() else {
        if is_native_drop {
            let _owner = NativeDialogDropOwner::raw(w_param as usize);
        }
        return 0;
    };
    let (queued_drop_claim, stale_drop_lease) = if is_native_drop {
        match win16_window_callbacks::claim_queued_drop_callback(&state, hwnd, w_param as usize) {
            Ok(NativeDropCallbackResolution::Unqueued) => (None, false),
            Ok(NativeDropCallbackResolution::ExactLive(claim)) => (Some(claim), false),
            Ok(NativeDropCallbackResolution::StaleLease(claim)) => (Some(claim), true),
            Err(error) => {
                win16_window_callbacks::fail_worker(&state, error);
                return 0;
            }
        }
    } else {
        (None, false)
    };
    let mut native_drop = if is_native_drop {
        Some(match queued_drop_claim {
            Some(claim) => NativeDialogDropOwner::queued(claim),
            None => NativeDialogDropOwner::raw(w_param as usize),
        })
    } else {
        None
    };
    if stale_drop_lease {
        // The unique ledger owner has already been claimed and a retirement
        // receipt published. Release it locally, but do not create a raw owner
        // or route a stale cookie generation to guest DLGPROC code.
        if let Some(owner) = native_drop.as_mut() {
            owner.finish();
        }
        super::win16_window_position::report_diagnostic(
            &state,
            Kind::CompatibilityGap,
            "rejected queued WM_DROPFILES after its exact HWND cookie generation retired",
        );
        return 0;
    }
    let enabled = {
        let state = state.borrow();
        state.callbacks_enabled && !state.aborted
    };
    if !enabled {
        retire_after_native_destroy(&state, hwnd, message);
        return 0;
    }

    let route = match callback_routes::dialog_route(&state, hwnd, message, l_param) {
        Ok(Some(route)) => route,
        Ok(None) => {
            notify_untranslated(&state, message);
            retire_after_native_destroy(&state, hwnd, message);
            return 0;
        }
        Err(error) => {
            if is_native_drop && error.kind() == Kind::CompatibilityGap {
                super::win16_window_position::report_diagnostic(
                    &state,
                    Kind::CompatibilityGap,
                    "native WM_DROPFILES could not be represented for the guest dialog; the drop was rejected",
                );
                retire_after_native_destroy(&state, hwnd, message);
                return 0;
            }
            win16_window_callbacks::fail_worker(&state, error);
            retire_after_native_destroy(&state, hwnd, message);
            return 0;
        }
    };
    let active = {
        let state = state.borrow();
        if state.callbacks_enabled && !state.aborted {
            state.active_operations.last().cloned()
        } else {
            None
        }
    };
    if active.is_none() {
        if super::win16_guest_notifications::is_carrier_message(hwnd, message, w_param, l_param) {
            super::win16_guest_notifications::defer_callback_marker(
                hwnd, message, w_param, l_param,
            );
        } else {
            notify_untranslated(&state, message);
        }
        retire_after_native_destroy(&state, hwnd, message);
        return 0;
    }
    if message == WM_DESTROY {
        worker::retire_clipboard_viewer(&state, route.window);
    }
    let (payload, original_nonclient_position, original_native_high_flags) =
        match copy_dialog_message(
            &state,
            route,
            hwnd,
            message,
            w_param,
            l_param,
            native_drop
                .as_ref()
                .and_then(NativeDialogDropOwner::queued_delivery)
                .cloned(),
        ) {
            Ok(Some(payload)) => payload,
            Ok(None) => {
                notify_untranslated(&state, message);
                retire_after_native_destroy(&state, hwnd, message);
                return 0;
            }
            Err(error) => {
                if is_native_drop && error.kind() == Kind::CompatibilityGap {
                    super::win16_window_position::report_diagnostic(
                        &state,
                        Kind::CompatibilityGap,
                        "native WM_DROPFILES could not be copied for the guest dialog; the drop was rejected",
                    );
                    retire_after_native_destroy(&state, hwnd, message);
                    return 0;
                }
                win16_window_callbacks::fail_worker(&state, error);
                retire_after_native_destroy(&state, hwnd, message);
                return 0;
            }
        };
    if let Some(owner) = native_drop.as_mut() {
        owner.finish();
    }
    let _callback_dc =
        win16_window_callbacks::CallbackDcGuard::new_dialog(&state, route.window, &payload);

    let _terminal_notification = super::win16_common_dialog_callbacks::terminal_guard(
        &state,
        match &payload {
            Win16HostDialogMessage::Message(Win16HostMessage::FindReplaceNotification(
                notification,
            )) => Some(notification),
            _ => None,
        },
    );
    let Some(active) = active else {
        unreachable!("active callback checked above")
    };
    let identity = state
        .borrow()
        .windows_by_native
        .get(&(hwnd as usize))
        .copied();
    let Some(identity) = identity
        .filter(|identity| identity.window == route.window)
        .filter(|_| super::win16_window_identity::resolve(&state, route.window) == Some(hwnd))
    else {
        notify_untranslated(&state, message);
        retire_after_native_destroy(&state, hwnd, message);
        return 0;
    };
    let class_init_owner =
        message == WM_INITDIALOG && identity.class.is_some() && !route.class_init_in_progress;
    let class_init_nested =
        message == WM_INITDIALOG && identity.class.is_some() && route.class_init_in_progress;
    if class_init_owner {
        let _class_init_guard =
            match win16_window_callbacks::begin_dialog_class_init(&state, hwnd, route) {
                Ok(guard) => guard,
                Err(error) => {
                    win16_window_callbacks::fail_worker(&state, error);
                    retire_after_native_destroy(&state, hwnd, message);
                    return 0;
                }
            };
        let Win16HostDialogMessage::Init {
            focus,
            focus_ancestry,
            ..
        } = &payload
        else {
            win16_window_callbacks::fail_worker(
                &state,
                RuntimeError::new(
                    Kind::InternalInvariant,
                    "private dialog class initialization has no copied focus payload",
                ),
            );
            return 0;
        };
        let class_result = win16_window_callbacks::dispatch_dialog_class_init_callback(
            &state,
            route,
            identity,
            hwnd,
            w_param,
            l_param,
            *focus,
            focus_ancestry.clone(),
        );
        let still_active = callback_routes::class_init_is_active(&state, hwnd, route)
            && super::win16_window_identity::resolve(&state, route.window) == Some(hwnd);
        let callbacks_enabled = {
            let state = state.borrow();
            state.callbacks_enabled && !state.aborted
        };
        if !still_active
            || !callbacks_enabled
            || callback_routes::class_init_default_called(&state, hwnd, route)
        {
            return class_result as i32 as isize;
        }
        // The private class WndProc handled WM_INITDIALOG itself. Preserve its
        // full Win16 LONG (AX:DX) as this WndProc's LRESULT; a DLGPROC WORD
        // conversion would lose nonzero upper-word results. An explicit
        // DefDlgProc call already ran the nested DLGPROC path above and is
        // covered by the exact-route/reentrancy guard.
        return class_result as i32 as isize;
    }
    let live_callback_reservation = state.borrow_mut().live_callbacks.try_reserve(1);
    if let Err(error) = live_callback_reservation {
        win16_window_callbacks::fail_worker(
            &state,
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve terminal identity for native Win16 dialog callback",
                error,
            ),
        );
        retire_after_native_destroy(&state, hwnd, message);
        return 0;
    }
    let Some(callback) = worker::allocate_callback_id(&state) else {
        win16_window_callbacks::fail_worker(
            &state,
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 native callback identity exhausted",
            ),
        );
        retire_after_native_destroy(&state, hwnd, message);
        return 0;
    };
    let is_drop_files = is_native_drop;
    let native_message_context = if is_drop_files {
        None
    } else {
        match &payload {
            Win16HostDialogMessage::Message(message_payload) => {
                win16_window_callbacks::native_callback_context(
                    &state,
                    route.window,
                    hwnd,
                    active.id,
                    message,
                    w_param,
                    l_param,
                    message_payload,
                )
            }
            Win16HostDialogMessage::Init { .. } | Win16HostDialogMessage::GetDlgCode { .. } => None,
        }
    };
    let _common_dialog_storage = match &payload {
        Win16HostDialogMessage::Message(Win16HostMessage::FindReplaceNotification(
            notification,
        )) => {
            super::win16_common_dialog_worker::notification_guard(&state, notification.request_id)
        }
        _ => None,
    };
    state.borrow_mut().live_callbacks.push(LiveCallback {
        callback,
        operation: active.id,
        source: runtime::Win16NativeCallbackSource::WindowMessage {
            window: identity.window,
            class: identity.class,
            message,
        },
        creation: None,
        identity: Some(identity),
        message: Some(message),
        hwnd,
        w_param: Some(if is_drop_files { 0 } else { w_param }),
        l_param: Some(if is_drop_files { 0 } else { l_param }),
        native_message_context,
        creation_cookie: None,
        mdi_create_struct: None,
    });
    crate::windows::win16_gdi::flush_thread_batch();
    if active
        .response
        .send(Ok(Win16WindowStep::DialogCallback {
            operation_id: runtime::Win16HostWindowOperationId(active.id),
            callback,
            window: route.window,
            message: payload.clone(),
            source: runtime::Win16NativeCallbackSource::WindowMessage {
                window: identity.window,
                class: identity.class,
                message,
            },
        }))
        .is_err()
    {
        win16_window_callbacks::remove_live_callback(&state, callback);
        win16_window_callbacks::fail_worker(
            &state,
            RuntimeError::new(
                Kind::HostFailure,
                "Win16 runtime dropped a suspended dialog callback",
            ),
        );
        retire_after_native_destroy(&state, hwnd, message);
        return 0;
    }

    let reply = win16_window_callbacks::wait_for_guest_reply(&state, &active, callback);
    let native_result = match reply {
        Some(callback_reply) => {
            let win16_window_callbacks::GuestCallbackReply {
                result: reply,
                native_control_color_result,
            } = callback_reply;
            // WINDOWSX.H SetDlgMsgResult: comparison and keyboard-to-item
            // messages return INT16 directly; zero means equality, not an
            // unhandled BOOL. Do not consume DWLP_MSGRESULT for these.
            if matches!(
                message,
                windows_sys::Win32::UI::WindowsAndMessaging::WM_COMPAREITEM
                    | windows_sys::Win32::UI::WindowsAndMessaging::WM_VKEYTOITEM
                    | windows_sys::Win32::UI::WindowsAndMessaging::WM_CHARTOITEM
            ) {
                win16_window_callbacks::remove_live_callback(&state, callback);
                return (reply.value as u16 as i16) as isize;
            }
            let handled = reply.value as u16 != 0;
            let native_color_message =
                super::win16_window_input::control_color_kind(message).is_some();
            let native_color_result = match (&reply.output, native_color_message) {
                (Output::ControlColor(_), true) => native_control_color_result,
                (_, false) if native_control_color_result.is_none() => None,
                _ => None,
            };
            let color_result_valid = if native_color_message {
                matches!(
                    (&reply.output, native_control_color_result),
                    (Output::ControlColor(_), Some(_))
                )
            } else {
                native_control_color_result.is_none()
            };
            let mut native_text_result = None;
            let output_valid = color_result_valid
                && write_dialog_output(
                    &state,
                    message,
                    &payload,
                    route.window,
                    hwnd,
                    l_param,
                    w_param,
                    original_nonclient_position,
                    original_native_high_flags,
                    handled,
                    &reply,
                    &mut native_text_result,
                );
            if output_valid {
                if message == WM_GETTEXTLENGTH
                    && handled
                    && let Some(value) = reply.dialog_result
                {
                    super::win16_window_text_context::record_guest_text_length_result(
                        &state,
                        route.window,
                        hwnd,
                        value as i32 as isize,
                    );
                }
                let native_result_slot = if native_color_message {
                    // WM_CTLCOLOR is the DLGPROC's direct HBRUSH return; it
                    // does not consume DWL_MSGRESULT.
                    None
                } else {
                    native_text_result.or_else(|| {
                        reply.dialog_result.filter(|_| handled).map(|value| {
                            if message == WM_NCCALCSIZE {
                                (value as u16) as i32 as isize
                            } else {
                                value as i32 as isize
                            }
                        })
                    })
                };
                if let Some(native_value) = native_result_slot {
                    // The native dialog manager consumes this separate slot
                    // for message-specific results. The DLGPROC return below
                    // still carries the guest BOOL16, including INITDIALOG's
                    // focus decision; no text length is inferred as a result.
                    // Reentrant guest execution can destroy this dialog and
                    // create another with the same HWND bits. A result belongs
                    // only to the original property-bound window identity.
                    if super::win16_window_identity::resolve(&state, route.window) == Some(hwnd) {
                        unsafe {
                            SetWindowLongPtrW(hwnd, DWLP_MSGRESULT as i32, native_value as _)
                        };
                    }
                }
                if native_color_message {
                    // The host-only identity resolves to a live native HBRUSH;
                    // SDK pseudo-brushes were converted before native USER sees it.
                    native_color_result.map_or(0, super::HostNativeBrushResult::native_lresult)
                } else {
                    // Win16 DLGPROC returns a 16-bit BOOL. Preserve its ABI value
                    // in the low word of the native INT_PTR result.
                    if handled {
                        (reply.value as u16) as isize
                    } else {
                        0
                    }
                }
            } else {
                win16_window_callbacks::fail_worker(
                    &state,
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 DLGPROC output does not match its native message",
                    ),
                );
                0
            }
        }
        None => 0,
    };
    win16_window_callbacks::remove_live_callback(&state, callback);
    if class_init_nested {
        callback_routes::mark_class_init_default_called(&state, hwnd, route);
    }
    retire_after_native_destroy(&state, hwnd, message);
    native_result
}

fn copy_dialog_message(
    state: &Rc<RefCell<WorkerState>>,
    route: DialogRoute,
    hwnd: HWND,
    message: u32,
    w_param: WPARAM,
    l_param: LPARAM,
    queued_drop_claim: Option<runtime::Win16HostQueuedDropFiles>,
) -> Result<Option<(Win16HostDialogMessage, Option<*mut WINDOWPOS>, Option<u32>)>, RuntimeError> {
    if super::win16_guest_notifications::is_carrier_message(hwnd, message, w_param, l_param) {
        let Some(notification) = super::win16_guest_notifications::callback_notification(
            state, hwnd, message, w_param, l_param,
        )?
        else {
            return Ok(None);
        };
        return Ok(Some((
            Win16HostDialogMessage::Message(Win16HostMessage::GuestNotification(notification)),
            None,
            None,
        )));
    }
    let (copied, original_nonclient_position, original_native_high_flags) = match message {
        WM_DROPFILES => {
            let drop = if let Some(queued) = queued_drop_claim {
                Win16HostMessage::QueuedDropFiles(queued)
            } else {
                let codec = state.borrow().text_codec;
                let drop =
                    win16_window_callbacks::snapshot_native_drop_files(w_param as HDROP, codec)?;
                Win16HostMessage::DropFiles(drop)
            };
            (Win16HostDialogMessage::Message(drop), None, None)
        }
        WM_INITDIALOG => {
            if l_param as usize != route.cookie {
                return Err(RuntimeError::new(
                    Kind::InternalInvariant,
                    "native WM_INITDIALOG cookie differs from its exact pending route",
                ));
            }
            let focus = w_param as HWND;
            let focus_token = if focus.is_null() {
                None
            } else {
                Some(worker::token_for_native(state, focus)?)
            };
            let mut focus_ancestry = Vec::new();
            if !focus.is_null() && unsafe { IsChild(hwnd, focus) } != 0 {
                let mut current = focus;
                let mut visited = BTreeSet::new();
                let mut native_edges = Vec::new();
                let mut reached_dialog = false;
                loop {
                    if current == hwnd {
                        reached_dialog = true;
                        break;
                    }
                    // Bound optional ancestry collection so concurrent USER
                    // changes cannot keep the callback waiting indefinitely.
                    // Reaching this host work budget only omits metadata;
                    // the guest focus value and dialog behavior are retained.
                    const MAX_ANCESTRY_HOPS: usize = 1024;
                    if visited.len() >= MAX_ANCESTRY_HOPS || !visited.insert(current as usize) {
                        break;
                    }
                    let parent = unsafe { GetParent(current) };
                    if parent.is_null() {
                        break;
                    }
                    native_edges.push((current, parent));
                    current = parent;
                    if current == hwnd {
                        reached_dialog = true;
                        break;
                    }
                }

                // Keep only a complete, still-current chain. A native window
                // can be reparented while USER initializes it; such a race
                // omits ancestry metadata without losing the focus HWND.
                let stable_chain = reached_dialog
                    && unsafe { IsChild(hwnd, focus) } != 0
                    && native_edges
                        .iter()
                        .all(|(child, parent)| (unsafe { GetParent(*child) }) == *parent);
                if stable_chain {
                    let tokens = native_edges
                        .iter()
                        .map(|(child, parent)| {
                            Ok((
                                worker::token_for_native(state, *child)?,
                                worker::token_for_native(state, *parent)?,
                            ))
                        })
                        .collect::<Result<Vec<_>, RuntimeError>>()?;
                    let still_stable = unsafe { IsChild(hwnd, focus) } != 0
                        && native_edges
                            .iter()
                            .all(|(child, parent)| (unsafe { GetParent(*child) }) == *parent);
                    if still_stable {
                        focus_ancestry = tokens;
                    }
                }
            }
            (
                Win16HostDialogMessage::Init {
                    focus: focus_token,
                    focus_ancestry,
                    init_parameter: route.init_parameter,
                },
                None,
                None,
            )
        }
        WM_GETDLGCODE => {
            let copied_message = if l_param == 0 {
                None
            } else {
                let native = unsafe { &*(l_param as *const MSG) };
                let Some(message) = callback_routes::copy_native_queued_message(state, native)?
                else {
                    return Ok(None);
                };
                Some(message)
            };
            (
                Win16HostDialogMessage::GetDlgCode {
                    virtual_key: w_param as u16,
                    message: copied_message,
                },
                None,
                None,
            )
        }
        WM_NCCALCSIZE if l_param != 0 => {
            let input = win16_window_callbacks::copy_nonclient_input(state, w_param, l_param)?;
            (
                Win16HostDialogMessage::Message(Win16HostMessage::NonClientCalcSize {
                    w_param: input.w_param,
                    data: input.data,
                }),
                input.original_position,
                input.original_position_high_flags,
            )
        }
        WM_WINDOWPOSCHANGING | WM_WINDOWPOSCHANGED if l_param != 0 => {
            let Some(input) =
                super::win16_window_position::copy_native_input(state, w_param, l_param)?
            else {
                return Ok(None);
            };
            (
                Win16HostDialogMessage::Message(Win16HostMessage::WindowPosition {
                    changing: message == WM_WINDOWPOSCHANGING,
                    w_param: input.w_param,
                    data: input.data,
                }),
                None,
                Some(input.native_high_flags),
            )
        }
        _ => match copy_typed_message(state, route.window, hwnd, message, w_param, l_param)? {
            Some(message) => (Win16HostDialogMessage::Message(message), None, None),
            None => return Ok(None),
        },
    };
    Ok(Some((
        copied,
        original_nonclient_position,
        original_native_high_flags,
    )))
}

/// The exact PM_NOREMOVE queue owner moves into a modal DLGPROC when that
/// native pump dispatches the same HDROP; unqueued direct messages use the
/// same RAII type without a queue lease.
enum NativeDialogDropRelease {
    Raw(NativeDropQueueOwner),
    Queued(NativeDropCallbackClaim),
}

struct NativeDialogDropOwner(Option<NativeDialogDropRelease>);

impl NativeDialogDropOwner {
    fn raw(handle: usize) -> Self {
        Self(Some(NativeDialogDropRelease::Raw(
            NativeDropQueueOwner::new(handle),
        )))
    }

    fn queued(claim: NativeDropCallbackClaim) -> Self {
        Self(Some(NativeDialogDropRelease::Queued(claim)))
    }

    fn queued_delivery(&self) -> Option<&runtime::Win16HostQueuedDropFiles> {
        match self.0.as_ref() {
            Some(NativeDialogDropRelease::Queued(claim)) => Some(&claim.delivery),
            _ => None,
        }
    }

    fn finish(&mut self) {
        match self.0.take() {
            Some(NativeDialogDropRelease::Raw(mut owner)) => owner.finish(),
            Some(NativeDialogDropRelease::Queued(mut claim)) => claim.finish(),
            None => {}
        }
    }
}

impl Drop for NativeDialogDropOwner {
    fn drop(&mut self) {
        self.finish();
    }
}

fn copy_typed_message(
    state: &Rc<RefCell<WorkerState>>,
    window: runtime::Win16HostWindow,
    hwnd: HWND,
    message: u32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> Result<Option<Win16HostMessage>, RuntimeError> {
    if super::win16_owner_draw_callbacks::is_message(message) {
        return super::win16_owner_draw_callbacks::copy_input(
            state, window, message, w_param, l_param,
        );
    }
    match super::win16_common_dialog_callbacks::classify(state, window, message, l_param)? {
        super::win16_common_dialog_worker::RegisteredCommonDialogMessage::NotFamily => {}
        super::win16_common_dialog_worker::RegisteredCommonDialogMessage::NativeOnly => {
            return Ok(None);
        }
        super::win16_common_dialog_worker::RegisteredCommonDialogMessage::FindReplace(
            notification,
        ) => {
            return Ok(Some(Win16HostMessage::FindReplaceNotification(
                notification,
            )));
        }
    }
    match super::win16_common_controls_drag_list::classify(
        state, window, message, w_param, l_param,
    )? {
        super::win16_common_controls_drag_list::DragListDispatch::NotDragList => {}
        super::win16_common_controls_drag_list::DragListDispatch::SuppressUnprovenNativePointer => {
            return Ok(None);
        }
        super::win16_common_controls_drag_list::DragListDispatch::Guest(notification) => {
            return Ok(Some(Win16HostMessage::DragListNotification(notification)));
        }
    }
    if message == 0x001c {
        return Ok(
            super::win16_window_input::decode_activation_app(w_param, l_param)
                .map(Win16HostMessage::ActivationApp),
        );
    }
    if message == 0x0210 {
        return Ok(
            super::win16_window_input::decode_parent_notification(state, w_param, l_param)?
                .map(Win16HostMessage::ParentNotification),
        );
    }
    if super::win16_window_input::control_color_kind(message).is_some() {
        return Ok(super::win16_window_input::decode_control_color(
            state, window, message, w_param, l_param,
        )?
        .map(Win16HostMessage::ControlColor));
    }
    let input = if message == WM_NCACTIVATE {
        let Some(hwnd) = super::win16_window_identity::resolve(state, window) else {
            return Ok(None);
        };
        super::win16_window_input::decode_nonclient_activation(state, hwnd, w_param, l_param)?
    } else {
        super::win16_window_input::decode_window_input(state, message, w_param, l_param)?
    };
    if let Some(input) = input {
        return Ok(Some(Win16HostMessage::WindowInput(input)));
    }
    let copied = match message {
        WM_COMMAND => {
            let (control, control_parent) = if l_param == 0 {
                (None, None)
            } else {
                let native = l_param as HWND;
                if unsafe { IsWindow(native) } == 0 {
                    return Ok(None);
                } else {
                    let control = worker::token_for_native(state, native)?;
                    let native_parent = unsafe { GetParent(native) };
                    let control_parent = if native_parent.is_null() {
                        None
                    } else {
                        Some(worker::token_for_native(state, native_parent)?)
                    };
                    (Some(control), control_parent)
                }
            };
            Win16HostMessage::Command {
                id: w_param as u16,
                notify: (w_param >> 16) as u16,
                control,
                control_parent,
            }
        }
        WM_ERASEBKGND | WM_PAINT => {
            let dc = if w_param == 0 {
                None
            } else {
                Some(
                    worker::adopt_callback_dc(state, window, w_param)?.ok_or_else(|| {
                        RuntimeError::new(
                            Kind::HostFailure,
                            "native dialog drawing HDC could not be tokenized",
                        )
                    })?,
                )
            };
            if message == WM_PAINT {
                Win16HostMessage::Paint { dc }
            } else {
                Win16HostMessage::EraseBackground { dc }
            }
        }
        WM_CHANGECBCHAIN => {
            let removed = if w_param == 0 {
                None
            } else {
                Some(worker::token_for_native(state, w_param as HWND)?)
            };
            let next = if l_param == 0 {
                None
            } else {
                Some(worker::token_for_native(state, l_param as HWND)?)
            };
            worker::update_clipboard_viewer_chain(state, window, w_param as HWND, l_param as HWND);
            Win16HostMessage::ClipboardChainChange { removed, next }
        }
        WM_SETTEXT => Win16HostMessage::SetText(unsafe {
            super::win16_window_text_context::copy_native_wide_z(state, l_param as *const u16)?
        }),
        WM_GETTEXT => {
            let (capacity, buffer_is_null) = super::win16_window_text_context::guest_capacity(
                state,
                window,
                hwnd,
                message,
                w_param,
                l_param == 0,
            )?;
            Win16HostMessage::GetText {
                capacity,
                buffer_is_null,
            }
        }
        WM_GETTEXTLENGTH => Win16HostMessage::GetTextLength,
        WM_GETMINMAXINFO if l_param != 0 => {
            let native = unsafe { &*(l_param as *const MINMAXINFO) };
            Win16HostMessage::MinMaxInfo(copy_minmax(native))
        }
        WM_NCPAINT => Win16HostMessage::NonClientPaint,
        _ if message <= u32::from(u16::MAX) && message >= 0x0400 => Win16HostMessage::GuestOpaque {
            message: message as u16,
            w_param: w_param as u16,
            l_param: l_param as u32,
        },
        _ if message <= u32::from(u16::MAX) => {
            let Some(kind) = Win16ScalarMessage::from_raw(message as u16) else {
                return Ok(None);
            };
            if kind == Win16ScalarMessage::Timer && l_param != 0 {
                return Ok(None);
            }
            Win16HostMessage::Scalar {
                kind,
                w_param: match super::win16_character_messages::to_guest(state, message, w_param) {
                    Some(word) => word, None => return Ok(None),
                },
                l_param: l_param as u32,
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(copied))
}

fn write_dialog_output(
    state: &Rc<RefCell<WorkerState>>,
    message: u32,
    payload: &Win16HostDialogMessage,
    receiver: runtime::Win16HostWindow,
    hwnd: HWND,
    l_param: LPARAM,
    capacity: usize,
    original_nonclient_position: Option<*mut WINDOWPOS>,
    original_native_high_flags: Option<u32>,
    handled: bool,
    result: &runtime::Win16HostMessageResult,
    native_text_result: &mut Option<isize>,
) -> bool {
    match payload {
        Win16HostDialogMessage::Message(Win16HostMessage::ControlColor(_)) => {
            // DLGPROC WM_CTLCOLOR returns HBRUSH directly, including NULL;
            // its truthiness is not the ordinary BOOL handled convention.
            matches!(&result.output, Output::ControlColor(_))
        }
        Win16HostDialogMessage::Message(Win16HostMessage::OwnerDraw(
            runtime::Win16OwnerDrawMessage::Measure { .. },
        )) => match (&result.output, handled) {
            (Output::OwnerDrawMeasure { .. }, true) => win16_window_callbacks::write_native_output(
                state,
                message,
                l_param,
                capacity,
                Some((receiver, hwnd)),
                None,
                None,
                result,
            ),
            (Output::None, false) => true,
            _ => false,
        },
        Win16HostDialogMessage::Message(Win16HostMessage::FindReplaceNotification(_)) => {
            // FINDREPLACE edits are notification I/O, independent of DLGPROC's
            // handled flag; native default handling follows the ordinary BOOL.
            matches!(&result.output, Output::None)
                || win16_window_callbacks::write_native_output(
                    state,
                    message,
                    l_param,
                    capacity,
                    Some((receiver, hwnd)),
                    None,
                    None,
                    result,
                )
        }
        Win16HostDialogMessage::Message(Win16HostMessage::GetText { .. }) => {
            match (&result.output, handled) {
                (Output::Text(_), true) => {
                    let Some(count) = result.dialog_result.filter(|count| *count != u32::MAX)
                    else {
                        return false;
                    };
                    let Some(native_count) = win16_window_callbacks::write_native_text_output(
                        state,
                        receiver,
                        hwnd,
                        l_param,
                        capacity,
                        count,
                        &result.output,
                    ) else {
                        return false;
                    };
                    *native_text_result = Some(native_count);
                    true
                }
                (Output::None, false) => true,
                (Output::None, true) if result.dialog_result == Some(0) => {
                    *native_text_result = Some(0);
                    true
                }
                (Output::None, true) if result.dialog_result == Some(u32::MAX) => {
                    *native_text_result = Some(-1);
                    true
                }
                _ => false,
            }
        }
        Win16HostDialogMessage::Message(Win16HostMessage::MinMaxInfo(_)) => {
            match (&result.output, handled) {
                (Output::MinMaxInfo(_), true) => win16_window_callbacks::write_native_output(
                    state,
                    message,
                    l_param,
                    capacity,
                    Some((receiver, hwnd)),
                    None,
                    None,
                    result,
                ),
                (Output::None, false) => true,
                _ => false,
            }
        }
        Win16HostDialogMessage::Message(Win16HostMessage::NonClientCalcSize { .. }) => {
            match (&result.output, handled) {
                (Output::NonClientCalcSize(_), false) | (Output::None, _) => true,
                (Output::NonClientCalcSize(_), true) => {
                    win16_window_callbacks::write_native_output(
                        state,
                        message,
                        l_param,
                        capacity,
                        Some((receiver, hwnd)),
                        original_nonclient_position,
                        original_native_high_flags,
                        result,
                    )
                }
                _ => false,
            }
        }
        Win16HostDialogMessage::Message(Win16HostMessage::WindowPosition { changing, .. }) => {
            if !handled {
                // FALSE leaves the dialog manager's native default path in
                // control; callback edits are not applied to the USER buffer.
                return true;
            }
            match (*changing, &result.output) {
                (true, Output::WindowPosition(data)) => {
                    let Some(original_native_high_flags) = original_native_high_flags else {
                        return false;
                    };
                    super::win16_window_position::write_output(
                        state,
                        Some((receiver, hwnd)),
                        l_param,
                        *data,
                        original_native_high_flags,
                    )
                }
                (true, Output::None) => {
                    super::win16_window_position::report_missing_changing_output(
                        state,
                        Some((receiver, hwnd)),
                        l_param,
                    )
                }
                (false, Output::WindowPosition(_) | Output::None) => true,
                _ => false,
            }
        }
        Win16HostDialogMessage::Message(_) => matches!(&result.output, Output::None),
        Win16HostDialogMessage::Init { .. } | Win16HostDialogMessage::GetDlgCode { .. } => {
            matches!(&result.output, Output::None)
        }
    }
}

fn notify_untranslated(state: &Rc<RefCell<WorkerState>>, message: u32) {
    let active: Option<ActiveOperation> = {
        let state = state.borrow();
        if state.callbacks_enabled && !state.aborted {
            state.active_operations.last().cloned()
        } else {
            None
        }
    };
    if let Some(active) = active {
        if active
            .response
            .send(Ok(Win16WindowStep::Untranslated { message }))
            .is_err()
        {
            win16_window_callbacks::fail_worker(
                state,
                RuntimeError::new(
                    Kind::HostFailure,
                    "Win16 runtime dropped an untranslated dialog message",
                ),
            );
        }
    }
}

fn retire_after_native_destroy(state: &Rc<RefCell<WorkerState>>, hwnd: HWND, message: u32) {
    if message == WM_NCDESTROY {
        let route = state
            .borrow()
            .dialog_routes_by_native
            .get(&(hwnd as usize))
            .copied();
        if let Some(route) = route {
            worker::remove_window_maps(state, route.window, hwnd);
        }
    }
}

#[cfg(test)]
pub(super) fn test_dialog_route(
    state: &Rc<RefCell<WorkerState>>, hwnd: HWND, message: u32, parameter: isize,
) -> Result<Option<DialogRoute>, RuntimeError> {
    callback_routes::dialog_route(state, hwnd, message, parameter)
}
