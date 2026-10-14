//! Native WndProc marshalling and suspended-callback continuations.

use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;
use std::sync::Arc;

use super::win16_window_geometry::copy_minmax;
use crate::windows::guest_text::GuestTextCodec;
use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16CreationId, Win16HostCallback, Win16HostDropFiles,
    Win16HostMessage, Win16HostMessageOutput as Output, Win16HostMessageResult, Win16HostPoint,
    Win16HostQueuedDropFiles, Win16HostWindow, Win16ScalarMessage, Win16WindowStep,
};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::UI::Shell::{DragQueryFileW, DragQueryPoint, HDROP};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CREATESTRUCTW, DefDlgProcW, DefWindowProcW, GetParent, IsWindow, MINMAXINFO, WINDOWPOS,
    WM_CHANGECBCHAIN, WM_COMMAND, WM_CREATE, WM_DESTROY, WM_DROPFILES, WM_ERASEBKGND,
    WM_GETDLGCODE, WM_GETMINMAXINFO, WM_GETTEXT, WM_GETTEXTLENGTH, WM_NCACTIVATE, WM_NCCALCSIZE,
    WM_NCCREATE, WM_NCDESTROY, WM_NCPAINT, WM_PAINT, WM_SETFONT, WM_SETTEXT, WM_TIMER,
    WM_WINDOWPOSCHANGED, WM_WINDOWPOSCHANGING,
};

use super::win16_window_worker::{
    self as worker_window, ActiveOperation, LiveCallback, NativeCallbackContext,
    NativeCreateCookie, NativeDropCallbackClaim, NativeDropCallbackResolution,
    NativeDropOwner as NativeDropQueueOwner, NativeDropRetirementQueue, NativeWindowIdentity,
    WorkerCommand, WorkerState,
};

// Even one-byte ANSI names need a NUL each, plus the list terminator and
// eight-byte Win16 DROPFILESTRUCT16, inside one 64-KiB far-addressable block.
const MAX_WIN16_DROP_PATHS: usize = (u16::MAX as usize + 1 - 8 - 1) / 2;
#[path = "win16_window_creation_input.rs"]
mod creation_input;
#[path = "win16_window_dialog_init.rs"]
mod dialog_init;
#[path = "win16_window_callback_drag_list.rs"]
mod drag_list_context;
#[path = "win16_window_callback_drag_dispatch.rs"]
mod drag_list_dispatch;
pub(super) use super::win16_window_default::default_message;
pub(super) use dialog_init::{begin_dialog_class_init, dispatch_dialog_class_init_callback};
#[path = "win16_window_fallback.rs"]
mod fallback;
pub(super) use fallback::untranslated;
#[path = "win16_window_nonclient.rs"]
mod win16_window_nonclient;
pub(super) use win16_window_nonclient::{
    NativeNonClientCalcSize, copy_native_input as copy_nonclient_input,
    write_output as write_nonclient_output,
};
#[path = "win16_window_text_output.rs"]
mod text_output;
pub(in crate::windows::win16_windows) use text_output::{
    write_native_output, write_native_text_output,
};

const WM_ACTIVATEAPP: u32 = 0x001c;
const WM_PARENTNOTIFY: u32 = 0x0210;

pub(super) unsafe extern "system" fn host_window_proc(
    hwnd: HWND,
    message: u32,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    if message == WM_ACTIVATEAPP && w_param == 0 {
        super::win16_cursor_clip::forget_after_deactivation();
    }
    // The catch arm runs after Rust has unwound local guards. It must know
    // whether WM_DROPFILES' opaque native owner was already released before
    // deciding whether the original native parameters can be forwarded.
    let mut native_drop_consumed = false;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        dispatch_window_proc(hwnd, message, w_param, l_param, &mut native_drop_consumed)
    }));
    match outcome {
        Ok(result) => result,
        Err(_) => {
            if let Some(state) = worker_context() {
                fail_worker(
                    &state,
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "native Win16 WndProc panicked; native callbacks were canceled",
                    ),
                );
            }
            if native_drop_consumed {
                // The native HDROP no longer exists. In particular, do not
                // pass its former bits to DefWindowProc or a retained WNDPROC.
                return 0;
            }
            canceled_native_result(hwnd, message, w_param, l_param)
        }
    }
}

#[path = "win16_timer_callbacks.rs"]
mod timer_callbacks;
pub(super) use timer_callbacks::host_timer_proc;

fn dispatch_window_proc(
    hwnd: HWND,
    message: u32,
    w_param: WPARAM,
    l_param: LPARAM,
    native_drop_consumed: &mut bool,
) -> LRESULT {
    let is_native_drop = message == WM_DROPFILES
        && !super::win16_guest_notifications::is_carrier_message(hwnd, message, w_param, l_param);
    let Some(state) = worker_context() else {
        if is_native_drop {
            let _owner = NativeDropOwner::raw(w_param as usize, native_drop_consumed);
            return 0;
        }
        return unsafe { DefWindowProcW(hwnd, message, w_param, l_param) };
    };
    let queued_drop_claim = if is_native_drop {
        match claim_queued_drop_callback(&state, hwnd, w_param as usize) {
            Ok(NativeDropCallbackResolution::Unqueued) => None,
            Ok(NativeDropCallbackResolution::ExactLive(claim)) => Some(claim),
            Ok(NativeDropCallbackResolution::StaleLease(claim)) => {
                // The ledger already owns this transferred HDROP. Finish that
                // exact owner and suppress routing after its cookie went stale;
                // never create a second raw guard for the same handle.
                let mut owner = NativeDropOwner::queued(claim, native_drop_consumed);
                owner.finish();
                super::win16_window_position::report_diagnostic(
                    &state,
                    Kind::CompatibilityGap,
                    "rejected queued WM_DROPFILES after its exact HWND cookie generation retired",
                );
                return 0;
            }
            Err(error) => {
                fail_worker(&state, error);
                return 0;
            }
        }
    } else {
        None
    };
    // A claimed modal-pump record moves its original RAII owner out of the
    // PM_NOREMOVE ledger. Unqueued WndProc deliveries start with that same
    // owner abstraction here.
    let mut native_drop_owner = if is_native_drop {
        Some(match queued_drop_claim {
            Some(claim) => NativeDropOwner::queued(claim, native_drop_consumed),
            None => NativeDropOwner::raw(w_param as usize, native_drop_consumed),
        })
    } else {
        None
    };
    let enabled = {
        let state = state.borrow();
        state.callbacks_enabled && !state.aborted
    };
    if !enabled {
        if is_native_drop {
            return 0;
        }
        return canceled_native_result(hwnd, message, w_param, l_param);
    }
    match super::win16_mdi_pending_creation::identify_mdi_child_creation(
        &state, hwnd, message, l_param,
    ) {
        Ok(Some(route)) => {
            if is_native_drop {
                return 0;
            }
            let class = route.data.mdi.class;
            let creation = route.data.mdi.creation;
            return dispatch_guest_callback_with_mdi(
                &state,
                hwnd,
                route.identity,
                Some(class),
                message,
                w_param,
                l_param,
                0,
                Some(creation),
                Win16HostMessage::MdiChildCreation {
                    non_client: message == WM_NCCREATE,
                    data: route.data,
                },
                None,
                None,
                Some(route.callback_mdi_struct),
            );
        }
        Err(error) => {
            fail_worker(&state, error);
            return creation_rejected(message);
        }
        Ok(None) => {}
    }
    if super::win16_mdi_pending_creation::suppresses_unproven_mdi_candidate(&state, hwnd) {
        // Before USER supplies the exact MCS in a creation notification, no
        // guest identity can be claimed from the enclosing ordinary creation.
        if is_native_drop {
            return 0;
        }
        return unsafe { DefWindowProcW(hwnd, message, w_param, l_param) };
    }
    let identified = match worker_window::identify_window(&state, hwnd) {
        Some(identity) => Ok(Some(identity)),
        None => super::win16_window_dialog_creation::identify(&state, hwnd, message, l_param),
    };
    let Some((identity, creation, pending_cookie, creation_id)) = (match identified {
        Ok(identity) => identity,
        Err(error) => {
            fail_worker(&state, error);
            return creation_rejected(message);
        }
    }) else {
        if matches!(message, WM_NCCREATE | WM_CREATE) {
            // A private class must acquire its identity before creation can
            // succeed. USER tears down rejected creation without exposing an
            // untracked HWND that a later cleanup could mistake for another.
            return creation_rejected(message);
        }
        if is_native_drop {
            return 0;
        }
        // A private WndProc can be reached before the worker has registered a
        // token only during teardown. Keep native handling safe and quiet.
        return unsafe { DefWindowProcW(hwnd, message, w_param, l_param) };
    };
    // Native subclasses carry an explicit window owner, not a fabricated
    // guest class. The saved procedure is the fallback for native-only input.
    let native_subclass = super::win16_native_procedures::is_subclassed(&state, identity.window);
    let host_class = if native_subclass { None } else { identity.class };
    if host_class.is_none() && !native_subclass {
        if is_native_drop { return 0; }
        return canceled_native_result(hwnd, message, w_param, l_param);
    }
    if native_subclass && let Some((guest_message, payload)) = super::win16_subclass_send::capture(
        &state, identity.window, hwnd, message, w_param, l_param,
    ) {
        return dispatch_guest_callback(&state, hwnd, identity, None, u32::from(guest_message),
            0, 0, 0, None, payload, None, None);
    }
    if super::win16_guest_notifications::is_carrier_message(hwnd, message, w_param, l_param) {
        if worker_window::current_operation_id().is_none() {
            super::win16_guest_notifications::defer_callback_marker(
                hwnd, message, w_param, l_param,
            );
            return 0;
        }
        return match super::win16_guest_notifications::callback_notification(
            &state, hwnd, message, w_param, l_param,
        ) {
            Ok(Some(notification)) => dispatch_guest_callback(
                &state,
                hwnd,
                identity,
                host_class,
                message,
                w_param,
                l_param,
                0,
                None,
                Win16HostMessage::GuestNotification(notification),
                None,
                None,
            ),
            Ok(None) => 0,
            Err(error) => {
                fail_worker(&state, error);
                0
            }
        };
    }
    if message == WM_DESTROY {
        worker_window::retire_clipboard_viewer(&state, identity.window);
    }
    // Registered dialog notifications contain native pointers. Classify them
    // before the generic private-message path can copy LPARAM into guest data.
    match super::win16_common_dialog_callbacks::classify(&state, identity.window, message, l_param)
    {
        Ok(super::win16_common_dialog_worker::RegisteredCommonDialogMessage::NotFamily) => {}
        Ok(super::win16_common_dialog_worker::RegisteredCommonDialogMessage::NativeOnly) => {
            return untranslated(&state, hwnd, message, w_param, l_param);
        }
        Ok(super::win16_common_dialog_worker::RegisteredCommonDialogMessage::FindReplace(
            notification,
        )) => {
            return dispatch_guest_callback(
                &state,
                hwnd,
                identity,
                host_class,
                message,
                w_param,
                l_param,
                0,
                None,
                Win16HostMessage::FindReplaceNotification(notification),
                None,
                None,
            );
        }
        Err(error) => {
            fail_worker(&state, error);
            return canceled_native_result(hwnd, message, w_param, l_param);
        }
    }
    if let Some(result) = drag_list_dispatch::dispatch(
        &state, hwnd, identity, host_class, message, w_param, l_param,
    ) {
        return result;
    }
    let mut creation_cookie = 0_usize;
    let mut original_nonclient_position: Option<*mut WINDOWPOS> = None;
    let mut original_native_high_flags: Option<u32> = None;
    let decoded_input = if message == WM_NCACTIVATE {
        super::win16_window_input::decode_nonclient_activation(&state, hwnd, w_param, l_param)
    } else {
        super::win16_window_input::decode_window_input(&state, message, w_param, l_param)
    };
    let decoded_input = match decoded_input {
        Ok(input) => input,
        Err(error) => {
            fail_worker(&state, error);
            return canceled_native_result(hwnd, message, w_param, l_param);
        }
    };
    let native_mdi = super::win16_message_loop::capture_mdi_message(
        &state,
        &windows_sys::Win32::UI::WindowsAndMessaging::MSG {
            hwnd,
            message,
            wParam: w_param,
            lParam: l_param,
            ..Default::default()
        },
    );
    let mdi_payload = match native_mdi {
        Ok(Some(queued)) => match queued.l_param {
            runtime::Win16MessageParam::Mdi(payload) => Some(payload),
            _ => {
                fail_worker(
                    &state,
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "MDI callback capture returned a different payload family",
                    ),
                );
                return canceled_native_result(hwnd, message, w_param, l_param);
            }
        },
        Ok(None) => None,
        Err(error) => {
            fail_worker(&state, error);
            return canceled_native_result(hwnd, message, w_param, l_param);
        }
    };
    let translated = if let Some(payload) = mdi_payload {
        Some(Win16HostMessage::MdiQueued(payload))
    } else if let Some(input) = decoded_input {
        Some(Win16HostMessage::WindowInput(input))
    } else {
        match message {
            WM_ACTIVATEAPP => super::win16_window_input::decode_activation_app(w_param, l_param)
                .map(Win16HostMessage::ActivationApp),
            WM_PARENTNOTIFY => match super::win16_window_input::decode_parent_notification(
                &state, w_param, l_param,
            ) {
                Ok(Some(input)) => Some(Win16HostMessage::ParentNotification(input)),
                Ok(None) => None,
                Err(error) => {
                    fail_worker(&state, error);
                    return canceled_native_result(hwnd, message, w_param, l_param);
                }
            },
            _ if super::win16_window_input::control_color_kind(message).is_some() => {
                match super::win16_window_input::decode_control_color(
                    &state,
                    identity.window,
                    message,
                    w_param,
                    l_param,
                ) {
                    Ok(Some(input)) => Some(Win16HostMessage::ControlColor(input)),
                    Ok(None) => None,
                    Err(error) => {
                        fail_worker(&state, error);
                        return canceled_native_result(hwnd, message, w_param, l_param);
                    }
                }
            }
            WM_NCCREATE | WM_CREATE => {
                let Some(host_class) = host_class else {
                    return untranslated(&state, hwnd, message, w_param, l_param);
                };
                let Some(template) = creation else {
                    return untranslated(&state, hwnd, message, w_param, l_param);
                };
                if l_param == 0 {
                    return untranslated(&state, hwnd, message, w_param, l_param);
                }
                // USER's CREATESTRUCTW is valid for this synchronous call. Its
                // lpCreateParams is a host cookie only for CreateWindowEx. A
                // dialog manager owns the CREATESTRUCT passed to class WndProc;
                // its lpCreateParams is never a Win16 FAR and is not the dialog's
                // init parameter. Dialog provenance was already matched against
                // the exact pending template route by identify().
                let native_create = unsafe { &*(l_param as *const CREATESTRUCTW) };
                let dialog_route = creation_id.is_some() && pending_cookie == 0;
                if !dialog_route {
                    creation_cookie = native_create.lpCreateParams as usize;
                    if creation_cookie == 0 || creation_cookie != pending_cookie {
                        return creation_rejected(message);
                    }
                    // Pointer equality above ties this address to the worker's
                    // live Box before its host-only fields are read.
                    let cookie = unsafe { &*(creation_cookie as *const NativeCreateCookie) };
                    if cookie.window != identity.window
                        || Some(cookie.class) != identity.class
                        || Some(cookie.creation) != creation_id
                    {
                        return creation_rejected(message);
                    }
                }
                let data = match creation_input::creation_from_native(
                    &state,
                    host_class,
                    native_create,
                    template,
                    !dialog_route,
                ) {
                    Ok(data) => data,
                    Err(error) => {
                        fail_worker(&state, error);
                        return creation_rejected(message);
                    }
                };
                Some(Win16HostMessage::Creation {
                    non_client: message == WM_NCCREATE,
                    data,
                })
            }
            WM_SETTEXT => match creation_input::copy_native_wide(&state, l_param) {
                Ok(text) => Some(Win16HostMessage::SetText(text)),
                Err(error) => {
                    fail_worker(&state, error);
                    return canceled_native_result(hwnd, message, w_param, l_param);
                }
            },
            WM_SETFONT => {
                let font = if w_param == 0 {
                    None
                } else {
                    let mapped =
                        state
                            .borrow()
                            .active_operations
                            .iter()
                            .rev()
                            .find_map(|operation| {
                                operation
                                    .native_font
                                    .filter(|(_, native)| *native == w_param)
                                    .map(|(token, _)| token)
                            });
                    let Some(font) = mapped else {
                        return untranslated(&state, hwnd, message, w_param, l_param);
                    };
                    Some(font)
                };
                Some(Win16HostMessage::SetFont {
                    font,
                    redraw: l_param as u16 != 0,
                })
            }
            WM_GETTEXT => {
                let (capacity, buffer_is_null) =
                    match super::win16_window_text_context::guest_capacity(
                        &state,
                        identity.window,
                        hwnd,
                        message,
                        w_param,
                        l_param == 0,
                    ) {
                        Ok(contract) => contract,
                        Err(error) => {
                            fail_worker(&state, error);
                            return canceled_native_result(hwnd, message, w_param, l_param);
                        }
                    };
                Some(Win16HostMessage::GetText {
                    capacity,
                    buffer_is_null,
                })
            }
            WM_GETTEXTLENGTH => Some(Win16HostMessage::GetTextLength),
            WM_DROPFILES => {
                let snapshot = if let Some(queued) = native_drop_owner
                    .as_ref()
                    .and_then(NativeDropOwner::queued_delivery)
                {
                    Ok(Win16HostMessage::QueuedDropFiles(queued.clone()))
                } else {
                    let codec = state.borrow().text_codec;
                    snapshot_native_drop_files(w_param as HDROP, codec)
                        .map(Win16HostMessage::DropFiles)
                };
                if let Some(owner) = native_drop_owner.as_mut() {
                    owner.finish();
                }
                match snapshot {
                    Ok(drop) => Some(drop),
                    Err(error) => {
                        if error.kind() == Kind::CompatibilityGap {
                            super::win16_window_position::report_diagnostic(
                                &state,
                                Kind::CompatibilityGap,
                                "native WM_DROPFILES could not be copied for the guest window; the drop was rejected",
                            );
                            // Refuse only this drop when the guest ANSI block or
                            // path cannot be represented; do not strand the USER
                            // worker or forward an HDROP whose owner may be gone.
                            return 0;
                        }
                        fail_worker(&state, error);
                        return 0;
                    }
                }
            }
            // Windows 3.0 specifies no guest parameters for WM_GETDLGCODE. The
            // native VK/MSG arguments remain available only through the live frame.
            WM_GETDLGCODE => Some(Win16HostMessage::GetDlgCode),
            WM_NCPAINT => Some(Win16HostMessage::NonClientPaint),
            WM_NCCALCSIZE if l_param != 0 => match copy_nonclient_input(&state, w_param, l_param) {
                Ok(input) => {
                    original_nonclient_position = input.original_position;
                    original_native_high_flags = input.original_position_high_flags;
                    Some(Win16HostMessage::NonClientCalcSize {
                        w_param: input.w_param,
                        data: input.data,
                    })
                }
                Err(error) => {
                    fail_worker(&state, error);
                    return canceled_native_result(hwnd, message, w_param, l_param);
                }
            },
            WM_WINDOWPOSCHANGING | WM_WINDOWPOSCHANGED if l_param != 0 => {
                match super::win16_window_position::copy_native_input(&state, w_param, l_param) {
                    Ok(Some(input)) => {
                        original_native_high_flags = Some(input.native_high_flags);
                        Some(Win16HostMessage::WindowPosition {
                            changing: message == WM_WINDOWPOSCHANGING,
                            w_param: input.w_param,
                            data: input.data,
                        })
                    }
                    Ok(None) => None,
                    Err(error) => {
                        fail_worker(&state, error);
                        return canceled_native_result(hwnd, message, w_param, l_param);
                    }
                }
            }
            WM_GETMINMAXINFO if l_param != 0 => {
                // USER owns this synchronous structure; only copied coordinates
                // cross to the runtime while the native call remains suspended.
                let native = unsafe { &*(l_param as *const MINMAXINFO) };
                Some(Win16HostMessage::MinMaxInfo(copy_minmax(native)))
            }
            // A WndProc receives WM_TIMER from synchronous SendMessage, where
            // LPARAM is just message data. For a queued WM_TIMER with a non-null
            // TIMERPROC, DispatchMessage invokes that native callback directly and
            // never enters this WndProc. Guest PostMessage timers are posted with
            // native LPARAM zero and use the separate guest timer sidecar.
            WM_TIMER => Some(Win16HostMessage::Scalar {
                kind: Win16ScalarMessage::Timer,
                w_param: w_param as u16,
                l_param: l_param as u32,
            }),
            WM_COMMAND => {
                let (control, control_parent) = if l_param == 0 {
                    (Some(None), None)
                } else {
                    let native_control = l_param as HWND;
                    if unsafe { IsWindow(native_control) } == 0 {
                        (None, None)
                    } else {
                        let control = match worker_window::token_for_native(&state, native_control)
                        {
                            Ok(control) => control,
                            Err(error) => {
                                fail_worker(&state, error);
                                return canceled_native_result(hwnd, message, w_param, l_param);
                            }
                        };
                        let native_parent = unsafe { GetParent(native_control) };
                        let control_parent = if native_parent.is_null() {
                            None
                        } else {
                            match worker_window::token_for_native(&state, native_parent) {
                                Ok(parent) => Some(parent),
                                Err(error) => {
                                    fail_worker(&state, error);
                                    return canceled_native_result(hwnd, message, w_param, l_param);
                                }
                            }
                        };
                        (Some(Some(control)), control_parent)
                    }
                };
                control.map(|control| Win16HostMessage::Command {
                    id: w_param as u16,
                    notify: (w_param >> 16) as u16,
                    control,
                    control_parent,
                })
            }
            WM_CHANGECBCHAIN => {
                let removed = if w_param == 0 {
                    Ok(None)
                } else {
                    worker_window::token_for_native(&state, w_param as HWND).map(Some)
                };
                let next = if l_param == 0 {
                    Ok(None)
                } else {
                    worker_window::token_for_native(&state, l_param as HWND).map(Some)
                };
                match (removed, next) {
                    (Ok(removed), Ok(next)) => {
                        worker_window::update_clipboard_viewer_chain(
                            &state,
                            identity.window,
                            w_param as HWND,
                            l_param as HWND,
                        );
                        Some(Win16HostMessage::ClipboardChainChange { removed, next })
                    }
                    (Err(error), _) | (_, Err(error)) => {
                        fail_worker(&state, error);
                        return canceled_native_result(hwnd, message, w_param, l_param);
                    }
                }
            }
            _ if super::win16_owner_draw_callbacks::is_message(message) => {
                match super::win16_owner_draw_callbacks::copy_input(
                    &state,
                    identity.window,
                    message,
                    w_param,
                    l_param,
                ) {
                    Ok(input) => input,
                    Err(error) => {
                        fail_worker(&state, error);
                        return canceled_native_result(hwnd, message, w_param, l_param);
                    }
                }
            }
            WM_ERASEBKGND | WM_PAINT => {
                let payload = |dc| {
                    if message == WM_PAINT {
                        Win16HostMessage::Paint { dc }
                    } else {
                        Win16HostMessage::EraseBackground { dc }
                    }
                };
                if w_param == 0 {
                    Some(payload(None))
                } else {
                    match worker_window::adopt_callback_dc(&state, identity.window, w_param) {
                        Ok(dc) => Some(payload(dc)),
                        Err(error) => {
                            fail_worker(&state, error);
                            return canceled_native_result(hwnd, message, w_param, l_param);
                        }
                    }
                }
            }
            _ if host_class.is_some() && message >= 0x0400 && message <= u32::from(u16::MAX) => {
                Some(Win16HostMessage::GuestOpaque {
                    message: message as u16,
                    w_param: w_param as u16,
                    l_param: l_param as u32,
                })
            }
            _ => Win16ScalarMessage::from_raw(message as u16)
                .filter(|_| message <= u32::from(u16::MAX))
                .and_then(|kind| super::win16_character_messages::to_guest(&state,
                    message, w_param).map(|guest_w| Win16HostMessage::Scalar {
                        kind, w_param: guest_w, l_param: l_param as u32,
                    })),
        }
    };
    let Some(translated) = translated else {
        return untranslated(&state, hwnd, message, w_param, l_param);
    };
    let (callback_w_param, callback_l_param) = if matches!(
        &translated,
        Win16HostMessage::DropFiles(_) | Win16HostMessage::QueuedDropFiles(_),
    ) {
        // copy_native_drop_files has released HDROP; the guest callback sees
        // only its owned Win16 HGLOBAL payload in Win16HostMessage.
        (0, 0)
    } else {
        (w_param, l_param)
    };
    dispatch_guest_callback(
        &state,
        hwnd,
        identity,
        host_class,
        message,
        callback_w_param,
        callback_l_param,
        creation_cookie,
        creation_id,
        translated,
        original_nonclient_position,
        original_native_high_flags,
    )
}

pub(super) fn snapshot_native_drop_files(
    drop: HDROP,
    codec: GuestTextCodec,
) -> Result<Win16HostDropFiles, RuntimeError> {
    let copied = (|| {
        if drop.is_null() {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "WM_DROPFILES carried a null HDROP",
            ));
        }
        let count = unsafe { DragQueryFileW(drop, u32::MAX, std::ptr::null_mut(), 0) };
        let count = usize::try_from(count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "convert native HDROP file count",
                error,
            )
        })?;
        if count > MAX_WIN16_DROP_PATHS {
            return Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "native HDROP cannot fit one Win16 far-addressable double-NUL block",
            ));
        }
        let mut files = Vec::new();
        files.try_reserve_exact(count).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve native HDROP path snapshot",
                error,
            )
        })?;
        let mut block_size: usize = 8 + if count == 0 { 2 } else { 1 };
        for index in 0..count {
            let index = u32::try_from(index).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "convert native HDROP index",
                    error,
                )
            })?;
            let length = unsafe { DragQueryFileW(drop, index, std::ptr::null_mut(), 0) };
            if length == 0 || length > 32_767 {
                return Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "native HDROP path has an empty or non-Win16-representable length",
                ));
            }
            let capacity = length.checked_add(1).ok_or_else(|| {
                RuntimeError::new(Kind::ResourceExhausted, "native HDROP path size overflow")
            })?;
            let mut wide = Vec::new();
            wide.try_reserve_exact(capacity as usize).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "reserve native HDROP UTF-16 path",
                    error,
                )
            })?;
            wide.resize(capacity as usize, 0);
            let copied = unsafe { DragQueryFileW(drop, index, wide.as_mut_ptr(), capacity) };
            if copied != length || wide.get(length as usize) != Some(&0) {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    "native DragQueryFileW returned a partial path snapshot",
                ));
            }
            wide.truncate(length as usize);
            let encoded = codec.from_wide(&wide)?;
            if encoded.used_default_char == Some(true) {
                return Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "native dropped path is not exactly representable in the guest ANSI code page",
                ));
            }
            if encoded.bytes.is_empty() || encoded.bytes.contains(&0) {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    "native DragQueryFileW produced an empty or embedded-NUL path",
                ));
            }
            let next_size = encoded
                .bytes
                .len()
                .checked_add(1)
                .and_then(|terminated| block_size.checked_add(terminated))
                .ok_or_else(|| {
                    RuntimeError::new(
                        Kind::ResourceExhausted,
                        "native HDROP guest block size overflow",
                    )
                })?;
            if next_size > u16::MAX as usize + 1 {
                return Err(RuntimeError::new(
                    Kind::CompatibilityGap,
                    "native HDROP paths exceed one Win16 far-addressable double-NUL block",
                ));
            }
            block_size = next_size;
            files.push(encoded.bytes);
        }
        let mut point = windows_sys::Win32::Foundation::POINT { x: 0, y: 0 };
        let in_client_area = unsafe { DragQueryPoint(drop, &mut point) } != 0;
        Ok(Win16HostDropFiles {
            paths: files,
            point: Win16HostPoint {
                x: point.x,
                y: point.y,
            },
            in_client_area,
        })
    })();
    copied
}

/// RAII owner for the transferred native HDROP. Drop also runs during panic
/// unwinding so the outer WndProc can distinguish a released handle from a
/// still-live one without forwarding stale pointer bits.
struct NativeDropOwner<'a> {
    raw_owner: Option<NativeDropQueueOwner>,
    queued_owner: Option<NativeDropCallbackClaim>,
    consumed: &'a mut bool,
}

impl<'a> NativeDropOwner<'a> {
    fn raw(handle: usize, consumed: &'a mut bool) -> Self {
        Self {
            raw_owner: Some(NativeDropQueueOwner::new(handle)),
            queued_owner: None,
            consumed,
        }
    }

    fn queued(claim: NativeDropCallbackClaim, consumed: &'a mut bool) -> Self {
        Self {
            raw_owner: None,
            queued_owner: Some(claim),
            consumed,
        }
    }

    fn queued_delivery(&self) -> Option<&Win16HostQueuedDropFiles> {
        self.queued_owner.as_ref().map(|claim| &claim.delivery)
    }

    fn finish(&mut self) {
        let had_owner = self.raw_owner.is_some() || self.queued_owner.is_some();
        if let Some(mut owner) = self.raw_owner.take() {
            owner.finish();
        }
        if let Some(mut claim) = self.queued_owner.take() {
            claim.finish();
        }
        if had_owner {
            *self.consumed = true;
        }
    }
}

impl Drop for NativeDropOwner<'_> {
    fn drop(&mut self) {
        self.finish();
    }
}

pub(super) fn claim_queued_drop_callback(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    hdrop: usize,
) -> Result<NativeDropCallbackResolution, RuntimeError> {
    let window = state
        .borrow()
        .native_drop_files
        .callback_window(hwnd, hdrop)?;
    let Some(window) = window else {
        return Ok(NativeDropCallbackResolution::Unqueued);
    };
    let exact_cookie_live = {
        let state = state.borrow();
        state
            .windows_by_native
            .get(&(hwnd as usize))
            .is_some_and(|identity| {
                identity.window == window && state.windows.get(&window) == Some(&hwnd)
            })
    };
    let exact_cookie_live =
        exact_cookie_live && super::win16_window_identity::resolve(state, window) == Some(hwnd);

    // Reserve before moving the sole HDROP owner out of its ledger, including
    // stale-cookie claims. A stale callback still has a projected runtime
    // lease which must be retired independently from its callback source.
    let retirement_queue = Arc::clone(&state.borrow().native_drop_retirements);
    let reservation = NativeDropRetirementQueue::reserve(&retirement_queue)?;
    let claim = state
        .borrow_mut()
        .native_drop_files
        .claim_callback(hwnd, hdrop, window)?
        .ok_or_else(|| {
            RuntimeError::new(
                Kind::InternalInvariant,
                "native WM_DROPFILES ledger lease disappeared after exact callback lookup",
            )
        })?;
    reservation.publish(runtime::Win16HostDropRetirementReceipt {
        lease: claim.delivery.lease,
        window,
    });
    Ok(if exact_cookie_live {
        NativeDropCallbackResolution::ExactLive(claim)
    } else {
        NativeDropCallbackResolution::StaleLease(claim)
    })
}

fn worker_context() -> Option<Rc<RefCell<WorkerState>>> {
    worker_window::worker_context()
}

fn dispatch_guest_callback(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    identity: NativeWindowIdentity,
    host_class: Option<runtime::Win16HostClass>,
    message: u32,
    w_param: WPARAM,
    l_param: LPARAM,
    creation_cookie: usize,
    creation: Option<Win16CreationId>,
    payload: Win16HostMessage,
    original_nonclient_position: Option<*mut WINDOWPOS>,
    original_native_high_flags: Option<u32>,
) -> LRESULT {
    dispatch_guest_callback_with_mdi(
        state,
        hwnd,
        identity,
        host_class,
        message,
        w_param,
        l_param,
        creation_cookie,
        creation,
        payload,
        original_nonclient_position,
        original_native_high_flags,
        None,
    )
}

fn dispatch_guest_callback_with_mdi(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    identity: NativeWindowIdentity,
    host_class: Option<runtime::Win16HostClass>,
    message: u32,
    w_param: WPARAM,
    l_param: LPARAM,
    creation_cookie: usize,
    creation: Option<Win16CreationId>,
    payload: Win16HostMessage,
    original_nonclient_position: Option<*mut WINDOWPOS>,
    original_native_high_flags: Option<u32>,
    mdi_create_struct: Option<usize>,
) -> LRESULT {
    let guest_owned_drop_files = matches!(
        &payload,
        Win16HostMessage::DropFiles(_) | Win16HostMessage::QueuedDropFiles(_),
    );
    let _callback_dc = CallbackDcGuard::new(state, identity.window, &payload);
    let _common_dialog_storage = match &payload {
        Win16HostMessage::FindReplaceNotification(notification) => {
            super::win16_common_dialog_worker::notification_guard(state, notification.request_id)
        }
        _ => None,
    };
    let _terminal_notification = super::win16_common_dialog_callbacks::terminal_guard(
        state,
        match &payload {
            Win16HostMessage::FindReplaceNotification(notification) => Some(notification),
            _ => None,
        },
    );
    let active = {
        let state = state.borrow();
        if state.callbacks_enabled && !state.aborted {
            state.active_operations.last().cloned()
        } else {
            None
        }
    };
    let Some(active) = active else {
        if guest_owned_drop_files {
            // There is no active operation that can accept this typed guest
            // payload, and the native HDROP has already been released.
            return 0;
        }
        // A message delivered outside an explicit runtime operation cannot
        // safely enter the guest CPU. Keep it on the native default path.
        return untranslated(state, hwnd, message, w_param, l_param);
    };
    let live_callback_reservation = state.borrow_mut().live_callbacks.try_reserve(1);
    if let Err(error) = live_callback_reservation {
        fail_worker(
            state,
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve terminal identity for native Win16 window callback",
                error,
            ),
        );
        if guest_owned_drop_files {
            return 0;
        }
        return canceled_native_result(hwnd, message, w_param, l_param);
    }
    let Some(callback) = worker_window::allocate_callback_id(state) else {
        fail_worker(
            state,
            RuntimeError::new(
                Kind::ResourceExhausted,
                "Win16 native callback identity exhausted",
            ),
        );
        if guest_owned_drop_files {
            return 0;
        }
        return canceled_native_result(hwnd, message, w_param, l_param);
    };
    let native_message_context = native_callback_context(
        state,
        identity.window,
        hwnd,
        active.id,
        message,
        w_param,
        l_param,
        &payload,
    );
    let live = LiveCallback {
        callback,
        operation: active.id,
        source: runtime::Win16NativeCallbackSource::WindowMessage {
            window: identity.window,
            class: host_class,
            message,
        },
        creation,
        identity: Some(identity),
        message: Some(message),
        hwnd,
        w_param: Some(w_param),
        l_param: Some(l_param),
        native_message_context,
        creation_cookie: Some(creation_cookie),
        mdi_create_struct,
    };
    state.borrow_mut().live_callbacks.push(live);
    let creation_data = {
        let borrowed = state.borrow();
        borrowed
            .dialog_creation_data
            .get(&(hwnd as usize))
            .filter(|(id, data)| {
                Some(*id) == creation
                    && Some(data.class) == host_class
                    && borrowed
                        .pending_dialog_routes
                        .iter()
                        .any(|pending| pending.operation == active.id && pending.creation == *id)
            })
            .map(|(_, data)| data.clone())
    };
    let source = runtime::Win16NativeCallbackSource::WindowMessage {
        window: identity.window, class: host_class, message,
    };
    let step = match host_class {
        Some(class) => Win16WindowStep::Callback {
            operation_id: runtime::Win16HostWindowOperationId(active.id),
            callback, creation, creation_data, window: identity.window,
            class, message: payload, source,
        },
        None => Win16WindowStep::NativeSubclassCallback {
            operation_id: runtime::Win16HostWindowOperationId(active.id),
            callback, window: identity.window, message: payload, source,
        },
    };
    if active.response.send(Ok(step)).is_err() {
        remove_live_callback(state, callback);
        if guest_owned_drop_files {
            return 0;
        }
        return canceled_native_result(hwnd, message, w_param, l_param);
    }

    let result = match wait_for_guest_reply(state, &active, callback) {
        Some(callback_reply) => {
            let GuestCallbackReply {
                result: reply,
                native_control_color_result,
            } = callback_reply;
            if super::win16_window_input::control_color_kind(message).is_some() {
                match (&reply.output, native_control_color_result) {
                    (Output::ControlColor(_), Some(native_brush)) => native_brush.native_lresult(),
                    _ => {
                        fail_worker(
                            state,
                            RuntimeError::new(
                                Kind::InternalInvariant,
                                "Win16 WNDPROC control-color reply has no checked native HBRUSH",
                            ),
                        );
                        0
                    }
                }
            } else if native_control_color_result.is_some() {
                fail_worker(
                    state,
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "native HBRUSH sidecar escaped a control-color callback",
                    ),
                );
                0
            } else if message == WM_GETTEXT {
                match write_native_text_output(
                    state,
                    identity.window,
                    hwnd,
                    l_param,
                    w_param,
                    reply.value,
                    &reply.output,
                ) {
                    Some(native_count) => native_count,
                    None => {
                        fail_worker(
                            state,
                            RuntimeError::new(
                                Kind::InternalInvariant,
                                "Win16 WM_GETTEXT output does not match its Unicode native buffer",
                            ),
                        );
                        0
                    }
                }
            } else if message == WM_GETTEXTLENGTH {
                super::win16_window_text_context::record_guest_text_length_result(
                    state,
                    identity.window,
                    hwnd,
                    reply.value as i32 as isize,
                );
                reply.value as i32 as isize
            } else if !write_native_output(
                state,
                message,
                l_param,
                w_param,
                Some((identity.window, hwnd)),
                original_nonclient_position,
                original_native_high_flags,
                &reply,
            ) {
                fail_worker(
                    state,
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 window callback output does not match its native message buffer",
                    ),
                );
                0
            } else if message == WM_NCCALCSIZE {
                // NCCALCSIZE returns UINT16 WVR flags, so the native LRESULT
                // must not sign-extend bit 15.
                (reply.value as u16) as isize
            } else if matches!(message, WM_WINDOWPOSCHANGING | WM_WINDOWPOSCHANGED) {
                // Win16 WNDPROC results are DWORD values. Zero-extend them on
                // 64-bit native targets instead of sign-extending bit 31.
                reply.value as isize
            } else {
                reply.value as i32 as isize
            }
        }
        None if guest_owned_drop_files => 0,
        None => canceled_native_result(hwnd, message, w_param, l_param),
    };
    let rejected_dialog_creation =
        (message == WM_NCCREATE && result == 0) || (message == WM_CREATE && result as i32 == -1);
    if rejected_dialog_creation
        && creation.is_some()
        && state
            .borrow()
            .dialog_creation_data
            .get(&(hwnd as usize))
            .is_some_and(|(pending, _)| Some(*pending) == creation)
    {
        // WM_NCCREATE/WM_CREATE failure can prevent the native dialog manager
        // from delivering WM_NCDESTROY. Retire only the exact creation route
        // that supplied this HWND generation; ordinary CreateWindow cookies
        // and later recycled HWNDs are unaffected.
        super::win16_native_procedures::base_fallback(state, hwnd, WM_NCDESTROY, 0, 0);
        worker_window::remove_window_maps(state, identity.window, hwnd);
    }
    remove_live_callback(state, callback);
    if message == WM_NCDESTROY {
        // A guest subclass may omit forwarding destruction. Release the
        // retained native base once; its binding suppresses a second call.
        super::win16_native_procedures::base_fallback(state, hwnd, message, w_param, l_param);
        worker_window::remove_window_maps(state, identity.window, hwnd);
    }
    result
}

pub(super) fn wait_for_guest_reply(
    state: &Rc<RefCell<WorkerState>>,
    active: &ActiveOperation,
    callback: Win16HostCallback,
) -> Option<GuestCallbackReply> {
    loop {
        let enabled = {
            let state = state.borrow();
            state.callbacks_enabled && !state.aborted
        };
        if !enabled {
            return None;
        }
        let command = worker_window::receive_command(state)?;
        match command {
            WorkerCommand::Resume {
                id,
                reply,
                native_control_color_result,
            } if id == active.id && reply.callback == callback => {
                return Some(GuestCallbackReply {
                    result: reply.result,
                    native_control_color_result,
                });
            }
            WorkerCommand::Resume { .. } => {
                fail_worker(
                    state,
                    RuntimeError::new(
                        Kind::InternalInvariant,
                        "Win16 native callback received a reply for a different suspended frame",
                    ),
                );
                return None;
            }
            other => worker_window::process_command(state, other),
        }
    }
}

pub(super) struct GuestCallbackReply {
    pub result: Win16HostMessageResult,
    pub native_control_color_result: Option<super::HostNativeBrushResult>,
}

pub(super) fn remove_live_callback(state: &Rc<RefCell<WorkerState>>, callback: Win16HostCallback) {
    let mut state = state.borrow_mut();
    if let Some(index) = state
        .live_callbacks
        .iter()
        .rposition(|frame| frame.callback == callback)
    {
        state.live_callbacks.remove(index);
    }
}

/// Keep native-only special values scoped to the callback that supplied them.
/// The payload itself contains only the Win16 contract's owned data.
pub(super) fn native_callback_context(
    state: &Rc<RefCell<WorkerState>>,
    parent: Win16HostWindow,
    parent_hwnd: HWND,
    operation: u64,
    message: u32,
    w_param: WPARAM,
    l_param: LPARAM,
    payload: &Win16HostMessage,
) -> Option<NativeCallbackContext> {
    match (message, payload) {
        (
            windows_sys::Win32::UI::WindowsAndMessaging::WM_COMPAREITEM,
            Win16HostMessage::OwnerDraw(runtime::Win16OwnerDrawMessage::Compare { .. }),
        ) if l_param != 0 => {
            // SAFETY: copy_input has already validated the message family and
            // copied this still-live USER COMPAREITEMSTRUCT before reentry.
            let locale = unsafe {
                (*(l_param as *const windows_sys::Win32::UI::Controls::COMPAREITEMSTRUCT))
                    .dwLocaleId
            };
            Some(NativeCallbackContext::OwnerDrawCompareLocale { locale })
        }
        (_, Win16HostMessage::FindReplaceNotification(notification)) => {
            Some(NativeCallbackContext::FindReplace {
                request_id: notification.request_id,
                native_l_param: l_param,
            })
        }
        (WM_NCACTIVATE, Win16HostMessage::WindowInput(input)) if l_param == -1 => {
            Some(NativeCallbackContext::NonClientActivateNoRepaint { input: *input })
        }
        (WM_NCPAINT, Win16HostMessage::NonClientPaint) => {
            Some(NativeCallbackContext::NonClientPaint {
                native_w_param: w_param,
            })
        }
        (_, Win16HostMessage::DragListNotification(notification)) => {
            drag_list_context::native_context(
                state,
                parent,
                parent_hwnd,
                operation,
                message,
                w_param,
                l_param,
                notification,
            )
        }
        _ => None,
    }
}

pub(super) struct CallbackDcGuard {
    state: Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    dc: Option<runtime::Win16HostDc>,
}

impl CallbackDcGuard {
    pub(super) fn new(
        state: &Rc<RefCell<WorkerState>>,
        window: Win16HostWindow,
        payload: &Win16HostMessage,
    ) -> Self {
        let dc = match payload {
            Win16HostMessage::EraseBackground { dc } | Win16HostMessage::Paint { dc } => *dc,
            Win16HostMessage::ControlColor(input) => input.dc,
            Win16HostMessage::OwnerDraw(input) => input.callback_dc(),
            _ => None,
        };
        Self {
            state: Rc::clone(state),
            window,
            dc,
        }
    }

    pub(super) fn new_dialog(
        state: &Rc<RefCell<WorkerState>>,
        window: Win16HostWindow,
        payload: &runtime::Win16HostDialogMessage,
    ) -> Self {
        let dc = match payload {
            runtime::Win16HostDialogMessage::Message(Win16HostMessage::OwnerDraw(input)) => {
                input.callback_dc()
            }
            runtime::Win16HostDialogMessage::Message(
                Win16HostMessage::EraseBackground { dc } | Win16HostMessage::Paint { dc },
            ) => *dc,
            runtime::Win16HostDialogMessage::Message(Win16HostMessage::ControlColor(input)) => {
                input.dc
            }
            _ => None,
        };
        Self {
            state: Rc::clone(state),
            window,
            dc,
        }
    }
}

impl Drop for CallbackDcGuard {
    fn drop(&mut self) {
        if let Some(dc) = self.dc.take() {
            // USER owns the borrowed HDC. Retire only the opaque alias.
            let _ = worker_window::forget_callback_dc(&self.state, dc, self.window);
        }
    }
}

fn creation_rejected(message: u32) -> LRESULT {
    if message == WM_NCCREATE { 0 } else { -1 }
}

fn canceled_native_result(hwnd: HWND, message: u32, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
    if message == WM_NCCREATE {
        return 0;
    }
    if message == WM_CREATE {
        return -1;
    }
    let context = worker_context();
    if let Some(state) = &context
        && let Some(result) =
            super::win16_native_procedures::base_fallback(state, hwnd, message, w_param, l_param)
    {
        if message == WM_NCDESTROY
            && let Some((identity, _, _, _)) = worker_window::identify_window(state, hwnd)
        {
            worker_window::remove_window_maps(state, identity.window, hwnd);
        }
        return result;
    }
    let is_dialog = context.is_some_and(|state| {
        state
            .borrow()
            .dialog_routes_by_native
            .contains_key(&(hwnd as usize))
    });
    // SAFETY: This uses the native default procedure selected for the exact
    // dialog-root route; unsupported native pointers stay inside USER.
    unsafe {
        if is_dialog {
            DefDlgProcW(hwnd, message, w_param, l_param)
        } else {
            DefWindowProcW(hwnd, message, w_param, l_param)
        }
    }
}

pub(super) fn fail_worker(state: &Rc<RefCell<WorkerState>>, error: RuntimeError) {
    let responders = {
        let mut state = state.borrow_mut();
        state.callbacks_enabled = false;
        state.aborted = true;
        state
            .active_operations
            .iter()
            .map(|active| active.response.clone())
            .collect::<Vec<_>>()
    };
    let shared_error = Arc::new(error);
    for response in responders.into_iter().rev() {
        let error = RuntimeError::with_source(
            shared_error.kind(),
            "Win16 window worker failure propagated to active operation",
            Arc::clone(&shared_error),
        );
        let _ = response.send(Err(error));
    }
}
