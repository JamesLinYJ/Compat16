//! Typed DefWindowProc delivery for suspended native WndProc callbacks.

use std::cell::RefCell;
use std::ffi::c_void;
use std::rc::Rc;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16CreationId, Win16HostCallback,
    Win16HostCreationData, Win16HostMessage, Win16HostMessageOutput as Output,
    Win16HostMessageResult, Win16HostWindow, Win16ScalarMessage,
};
use windows_sys::Win32::Foundation::{HWND, POINT};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CREATESTRUCTW, DefDlgProcW, DefFrameProcW, DefMDIChildProcW, DefWindowProcW, DispatchMessageW,
    GetDlgCtrlID, GetParent, MINMAXINFO, SendMessageW, WM_CHANGECBCHAIN, WM_CLOSE, WM_COMMAND,
    WM_CREATE, WM_DESTROY, WM_DROPFILES, WM_ERASEBKGND, WM_GETDLGCODE, WM_GETMINMAXINFO,
    WM_GETTEXT, WM_GETTEXTLENGTH, WM_INITDIALOG, WM_NCACTIVATE, WM_NCCALCSIZE, WM_NCCREATE,
    WM_NCPAINT, WM_PAINT, WM_SETFONT, WM_SETTEXT, WM_SYSCOMMAND, WM_WINDOWPOSCHANGED,
    WM_WINDOWPOSCHANGING,
};

use super::win16_window_geometry::{copy_minmax, native_minmax};
use super::win16_window_position::NativeWindowPosition;
use super::win16_window_worker::{NativeCallbackContext, NativeWindowIdentity, WorkerState};

#[path = "win16_message_mdi.rs"]
pub(super) mod mdi;

#[path = "win16_window_dialog_default_init.rs"]
mod dialog_init;

/// Apply DefWindowProcW using either a validated live native callback frame or
/// entirely host-owned buffers reconstructed from the typed operation.
pub(super) fn default_message(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    callback: Option<Win16HostCallback>,
    message: Win16HostMessage,
    control_color_return: Option<&super::ControlColorReturnSlot>,
) -> Result<Option<Win16HostMessageResult>, RuntimeError> {
    message_with_invocation(
        state,
        window,
        callback,
        message,
        MessageInvocation::Default,
        control_color_return,
    )
}

/// Apply the MDI frame default procedure with the same owned message payload.
pub(super) fn frame_default_message(
    state: &Rc<RefCell<WorkerState>>,
    frame: Win16HostWindow,
    mdi_client: Option<Win16HostWindow>,
    callback: Option<Win16HostCallback>,
    message: Win16HostMessage,
    control_color_return: Option<&super::ControlColorReturnSlot>,
) -> Result<Option<Win16HostMessageResult>, RuntimeError> {
    let mdi_client = match mdi_client {
        Some(client) => match super::win16_window_identity::resolve_user_window(state, client) {
            Some(hwnd) => hwnd,
            None => return Ok(None),
        },
        None => HWND::default(),
    };
    // The native client identity stays on its USER owner thread. Reuse the
    // message-specific owned buffers and callback copyback of DefWindowProc.
    message_with_invocation(
        state,
        frame,
        callback,
        message,
        MessageInvocation::FrameDefault { mdi_client },
        control_color_return,
    )
}

pub(super) fn mdi_child_default_message(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    callback: Option<Win16HostCallback>,
    message: Win16HostMessage,
    control_color_return: Option<&super::ControlColorReturnSlot>,
) -> Result<Option<Win16HostMessageResult>, RuntimeError> {
    message_with_invocation(
        state,
        window,
        callback,
        message,
        MessageInvocation::MdiChildDefault,
        control_color_return,
    )
}

/// Apply the dialog-class default procedure with the same owned payload
/// marshalling used by DefWindowProc. The live callback pins native-only
/// parameters while guest addresses remain in the runtime output continuation.
pub(super) fn dialog_default_message(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    callback: Option<Win16HostCallback>,
    message: Win16HostMessage,
    control_color_return: Option<&super::ControlColorReturnSlot>,
) -> Result<Option<Win16HostMessageResult>, RuntimeError> {
    message_with_invocation(
        state,
        window,
        callback,
        message,
        MessageInvocation::DialogDefault,
        control_color_return,
    )
}

/// Apply one previously captured native procedure to checked, host-owned
/// message data. GuestOpaque is intentionally unavailable here because its
/// LPARAM contains guest bits, not a native pointer or control argument.
pub(super) fn procedure_message(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    callback: Option<Win16HostCallback>,
    token: runtime::Win16HostProcedure,
    procedure: isize,
    message: Win16HostMessage,
    control_color_return: Option<&super::ControlColorReturnSlot>,
) -> Result<Option<Win16HostMessageResult>, RuntimeError> {
    if matches!(&message, Win16HostMessage::GuestOpaque { .. }) {
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "native Win16 procedure cannot receive opaque guest LPARAM bits",
        ));
    }
    message_with_invocation(
        state,
        window,
        callback,
        message,
        MessageInvocation::Procedure {
            address: procedure,
            token,
        },
        control_color_return,
    )
}

/// Deliver one synchronous guest SendMessage operation with owned typed
/// payloads. Pointer-bearing structures are reconstructed locally and remain
/// alive for the complete native call, including reentrant guest callbacks.
pub(super) fn send_message(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    message: Win16HostMessage,
    control_color_return: Option<&super::ControlColorReturnSlot>,
) -> Result<Option<Win16HostMessageResult>, RuntimeError> {
    if let Win16HostMessage::GuestOpaque { message, w_param, l_param } = &message {
        return super::win16_subclass_send::send(state, window, *message, *w_param, *l_param);
    }
    if !matches!(
        &message,
        Win16HostMessage::ControlColor(_)
            | Win16HostMessage::Control(_)
            | Win16HostMessage::OwnerDraw(_)
            | Win16HostMessage::Mdi(_)
            | Win16HostMessage::Paint { .. }
            | Win16HostMessage::SetText(_)
            | Win16HostMessage::GetText { .. }
            | Win16HostMessage::GetTextLength
            | Win16HostMessage::SetFont { .. }
            | Win16HostMessage::NonClientCalcSize { .. }
            | Win16HostMessage::NonClientPaint
            | Win16HostMessage::WindowPosition { .. }
    ) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "Win16 synchronous SendMessage received an unsupported typed payload",
        ));
    }
    message_with_invocation(
        state,
        window,
        None,
        message,
        MessageInvocation::Send,
        control_color_return,
    )
}

#[derive(Clone, Copy)]
pub(super) enum MessageInvocation {
    Default,
    FrameDefault {
        mdi_client: HWND,
    },
    MdiChildDefault,
    DialogDefault,
    Send,
    /// Dispatch one reconstructed native MSG through USER while preserving
    /// the guest-visible MSG time and point fields.
    Dispatch {
        time: u32,
        point: runtime::Win16HostPoint,
    },
    /// Raw WNDPROC bits from GetWindowLongPtrW. CallWindowProc accepts USER's
    /// internal procedure sentinels too, which are not Rust function pointers.
    Procedure {
        address: isize,
        token: runtime::Win16HostProcedure,
    },
}

fn message_with_invocation(
    state: &Rc<RefCell<WorkerState>>,
    window: Win16HostWindow,
    callback: Option<Win16HostCallback>,
    message: Win16HostMessage,
    invocation: MessageInvocation,
    control_color_return: Option<&super::ControlColorReturnSlot>,
) -> Result<Option<Win16HostMessageResult>, RuntimeError> {
    if let Win16HostMessage::Control(call) = message {
        if callback.is_some() || call.window != window {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "standard-control request carries an unrelated callback or window",
            ));
        }
        return super::win16_standard_controls::invoke(state, call, invocation);
    }
    let live = if let Some(callback) = callback {
        let frame = state
            .borrow()
            .live_callbacks
            .iter()
            .find(|frame| frame.callback == callback)
            .and_then(|frame| {
                Some(LiveFrame {
                    operation: frame.operation,
                    identity: frame.identity?,
                    creation: frame.creation,
                    message: frame.message?,
                    hwnd: frame.hwnd,
                    w_param: frame.w_param?,
                    l_param: frame.l_param?,
                    native_message_context: frame.native_message_context,
                    creation_cookie: frame.creation_cookie,
                    mdi_create_struct: frame.mdi_create_struct,
                })
            })
            .ok_or_else(|| {
                RuntimeError::new(
                    Kind::InvalidInput,
                    "Win16 default processing callback token is no longer active",
                )
            })?;
        if frame.identity.window != window || Some(frame.message) != message_id(&message) {
            return Err(RuntimeError::new(
                Kind::InvalidInput,
                "Win16 default processing callback does not match its window and message",
            ));
        }
        if matches!(
            &message,
            Win16HostMessage::Creation { .. } | Win16HostMessage::MdiChildCreation { .. }
        ) && frame.creation.is_none()
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 creation default processing has no pending creation identity",
            ));
        }
        if !state
            .borrow()
            .active_operations
            .iter()
            .any(|active| active.id == frame.operation)
        {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "Win16 default processing callback has no active operation",
            ));
        }
        Some(frame)
    } else {
        None
    };
    let hwnd = if let Some(live) = live {
        // A guest callback can destroy its window and create another before
        // asking for default processing. HWND bit reuse must not redirect the
        // suspended callback to the new window incarnation.
        if super::win16_window_identity::resolve(state, window) != Some(live.hwnd) {
            return Ok(None);
        }
        live.hwnd
    } else {
        let Some(hwnd) = super::win16_window_identity::resolve_user_window(state, window) else {
            return Ok(None);
        };
        hwnd
    };
    if unsafe { windows_sys::Win32::UI::WindowsAndMessaging::IsWindow(hwnd) } == 0 {
        return Ok(None);
    }
    if matches!(
        &message,
        Win16HostMessage::DropFiles(_) | Win16HostMessage::QueuedDropFiles(_),
    ) {
        // WM_DROPFILES' native HDROP has already been copied and DragFinish'd.
        // DefWindowProc/DefDlgProc define no useful default action here; a
        // custom native procedure cannot receive the expired handle.
        return match invocation {
            MessageInvocation::Default
            | MessageInvocation::FrameDefault { .. }
            | MessageInvocation::MdiChildDefault
            | MessageInvocation::DialogDefault => Ok(Some(zero_message_result())),
            MessageInvocation::Procedure { address, .. }
                if address as usize == DefWindowProcW as *const () as usize
                    || address as usize == DefDlgProcW as *const () as usize =>
            {
                Ok(Some(zero_message_result()))
            }
            MessageInvocation::Send
            | MessageInvocation::Dispatch { .. }
            | MessageInvocation::Procedure { .. } => Err(RuntimeError::new(
                Kind::CompatibilityGap,
                "native WM_DROPFILES procedure dispatch is unavailable after HDROP snapshot retirement",
            )),
        };
    }
    let result = match message {
        Win16HostMessage::MdiChildCreation { non_client, data } => {
            let Some(callback) = callback else {
                return Ok(None);
            };
            let Some(frame) = live else {
                return Ok(None);
            };
            if frame.creation != Some(data.mdi.creation)
                || frame.mdi_create_struct.is_none()
                || frame.identity.class != Some(data.mdi.class)
                || data.creation.class != data.mdi.class
            {
                return Err(RuntimeError::new(
                    Kind::InvalidInput,
                    "MDI creation default processing has a different creation identity",
                ));
            }
            let parameter = super::win16_mdi_pending_creation::apply_live_mdi_create_fields(
                state, callback, window, &data.mdi,
            )?;
            return default_creation(
                state,
                hwnd,
                live,
                non_client,
                data.creation,
                invocation,
                Some(parameter as usize),
            );
        }
        Win16HostMessage::MdiQueued(_) => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "incoming MDI notification bypassed its guest parameter projection",
            ));
        }
        Win16HostMessage::Mdi(message) => {
            let client = match invocation {
                MessageInvocation::FrameDefault { mdi_client } => mdi_client,
                _ => hwnd,
            };
            if !super::win16_message_loop::validate_mdi_owned_target(state, client, &message) {
                return Ok(None);
            }
            let frame = match invocation {
                MessageInvocation::FrameDefault { .. } => hwnd,
                _ if matches!(&message, runtime::Win16HostMdiMessage::ActivateChild { .. }) => unsafe {
                    GetParent(GetParent(client))
                },
                _ => unsafe { GetParent(client) },
            };
            let (requested_frame, requested_window) = match &message {
                runtime::Win16HostMdiMessage::SetMenu {
                    frame_menu,
                    window_menu,
                    ..
                } => (*frame_menu, *window_menu),
                _ => (None, None),
            };
            let result = mdi::with_menu_call_owners(
                state,
                frame,
                requested_frame,
                requested_window,
                || mdi::invoke(state, invocation, hwnd, message),
            )?;
            return Ok(result.map(|result| Win16HostMessageResult {
                value: result.value,
                output: Output::Mdi(result.output),
                dialog_result: None,
            }));
        }
        Win16HostMessage::Control(_) => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "standard-control message bypassed its checked dispatch",
            ));
        }
        Win16HostMessage::DropFiles(_) | Win16HostMessage::QueuedDropFiles(_) => {
            return Err(RuntimeError::new(
                Kind::InternalInvariant,
                "WM_DROPFILES bypassed its no-native-handle default result",
            ));
        }
        Win16HostMessage::OwnerDraw(item) => {
            let locale = live.and_then(|frame| match frame.native_message_context {
                Some(NativeCallbackContext::OwnerDrawCompareLocale { locale }) => Some(locale),
                _ => None,
            });
            return super::win16_owner_draw_callbacks::invoke_owned(
                state,
                item,
                locale,
                |message, w_param, l_param| {
                    invoke_message(invocation, hwnd, message, w_param, l_param)
                },
            );
        }
        Win16HostMessage::FindReplaceNotification(notification) => {
            let source = live.and_then(|frame| match frame.native_message_context {
                Some(NativeCallbackContext::FindReplace {
                    request_id,
                    native_l_param,
                }) if request_id == notification.request_id => Some(native_l_param),
                _ => None,
            });
            let Some(source) = source else {
                return Ok(None);
            };
            invoke_message(
                invocation,
                hwnd,
                u32::from(notification.find_message),
                0,
                source,
            )
        }
        Win16HostMessage::DragListNotification(notification) => {
            let Some(frame) = live else {
                return Ok(None);
            };
            let native_l_param = match frame.native_message_context {
                Some(NativeCallbackContext::DragList {
                    operation,
                    list_box,
                    native_list_hwnd,
                    native_l_param,
                }) if operation == frame.operation
                    && list_box == notification.list_box
                    && native_l_param != 0
                    && frame.message == u32::from(notification.message)
                    && frame.w_param as u16 == notification.control_id
                    && frame.hwnd == hwnd =>
                {
                    (native_list_hwnd, native_l_param)
                }
                _ => return Ok(None),
            };
            let Some(list_hwnd) =
                super::win16_window_identity::resolve_user_window(state, notification.list_box)
            else {
                return Ok(None);
            };
            if list_hwnd as usize != native_l_param.0
                || unsafe { GetParent(list_hwnd) } != hwnd
                || unsafe { GetDlgCtrlID(list_hwnd) as u16 } != notification.control_id
            {
                return Ok(None);
            }
            invoke_message(
                invocation,
                hwnd,
                u32::from(notification.message),
                frame.w_param,
                native_l_param.1,
            )
        }
        Win16HostMessage::WindowInput(input) => {
            let Some((message, w_param, mut l_param)) =
                super::win16_window_input::encode_window_input(state, input)?
            else {
                return Ok(None);
            };
            // Win32's -1 requests defaulting without repaint and cannot be
            // encoded as HWND16. Only a live capability with identical typed
            // input may forward it; independent guest messages use their data.
            if message == WM_NCACTIVATE
                && live.is_some_and(|frame| {
                    matches!(
                        frame.native_message_context,
                        Some(NativeCallbackContext::NonClientActivateNoRepaint { input: original })
                            if original == input
                    )
                })
            {
                l_param = -1;
            }
            // The helper resolves all opaque HWND tokens before returning;
            // no RefCell borrow is held during DefWindowProc/CallWindowProc.
            invoke_message(invocation, hwnd, message, w_param, l_param)
        }
        Win16HostMessage::ActivationApp(input) => {
            let Some((w_param, l_param)) = super::win16_window_input::encode_activation_app(input)
            else {
                return Ok(None);
            };
            invoke_message(invocation, hwnd, 0x001c, w_param, l_param)
        }
        Win16HostMessage::ParentNotification(input) => {
            let Some((w_param, l_param)) =
                super::win16_window_input::encode_parent_notification(state, input)?
            else {
                return Ok(None);
            };
            invoke_message(invocation, hwnd, 0x0210, w_param, l_param)
        }
        Win16HostMessage::ControlColor(input) => {
            return super::win16_window_control_color::invoke(
                state,
                hwnd,
                invocation,
                input,
                control_color_return,
            );
        }
        Win16HostMessage::Scalar {
            kind,
            w_param,
            l_param,
        } => {
            let Some(native_w) = super::win16_character_messages::to_native(state,
                u32::from(kind as u16), w_param)? else { return Ok(None); };
            let native_l = (l_param as i32) as isize;
            let native_message = u32::from(kind as u16);
            // This variant carries only scalar message fields. Messages with
            // buffers and handles use their own marshalling variants.
            if may_destroy_window_tree(native_message, native_w) {
                let snapshot = mdi::snapshot_window_retirements(state, window, hwnd)?;
                let result = invoke_message(invocation, hwnd, native_message, native_w, native_l);
                let retirements = mdi::finish_window_retirements(state, snapshot);
                if !retirements.receipts.is_empty() || !retirements.invalidated_menus.is_empty() {
                    return Ok(Some(Win16HostMessageResult {
                        value: result.value,
                        output: Output::WindowRetirements(retirements),
                        dialog_result: result.dialog_result,
                    }));
                }
                result
            } else {
                invoke_message(invocation, hwnd, native_message, native_w, native_l)
            }
        }
        Win16HostMessage::GuestNotification(notification) => {
            if notification.source.id == 0
                || notification.source.generation == 0
                || notification.source.sequence == 0
                || !matches!(notification.target,
                    runtime::Win16GuestNotificationTarget::Window { window: target, .. }
                        if target == window)
            {
                return Err(RuntimeError::new(
                    Kind::InvalidInput,
                    "owned guest notification default route lost its exact source or window target",
                ));
            }
            if runtime::is_multimedia_notification_message(notification.message) {
                if runtime::multimedia_notification_has_guest_far_lparam(notification.message) {
                    // MMSYSTEM defines these LPARAM values as guest WAVEHDR16
                    // or MIDIHDR16 FARs. The default result is zero; never pass
                    // a guest address to native USER.
                    zero_message_result()
                } else {
                    match invocation {
                        MessageInvocation::Default
                        | MessageInvocation::FrameDefault { .. }
                        | MessageInvocation::MdiChildDefault
                        | MessageInvocation::Send => zero_message_result(),
                        MessageInvocation::Dispatch { .. }
                        | MessageInvocation::DialogDefault
                        | MessageInvocation::Procedure { .. } => invoke_message(
                            invocation,
                            hwnd,
                            u32::from(notification.message),
                            usize::from(notification.w_param),
                            (notification.l_param as i32) as isize,
                        ),
                    }
                }
            } else {
                let pointer_free = Win16ScalarMessage::from_raw(notification.message).is_some()
                    && (!Win16ScalarMessage::is_timer_message(notification.message)
                        || notification.l_param == 0);
                if pointer_free {
                    invoke_message(
                        invocation,
                        hwnd,
                        u32::from(notification.message),
                        usize::from(notification.w_param),
                        (notification.l_param as i32) as isize,
                    )
                } else {
                    // Unknown and pointer-bearing notifications retain their
                    // Win16 numeric LPARAM but have no ABI-safe native default
                    // conversion. The unhandled default result is zero.
                    zero_message_result()
                }
            }
        }
        Win16HostMessage::MultimediaNotification {
            message,
            w_param,
            l_param,
        } => {
            if !runtime::is_multimedia_notification_message(message) {
                return Err(RuntimeError::new(
                    Kind::InvalidInput,
                    "typed Win16 multimedia default message is outside the MM_* range",
                ));
            }
            if runtime::multimedia_notification_has_guest_far_lparam(message) {
                zero_message_result()
            } else {
                match invocation {
                    MessageInvocation::Default
                    | MessageInvocation::FrameDefault { .. }
                    | MessageInvocation::MdiChildDefault
                    | MessageInvocation::Send => zero_message_result(),
                    MessageInvocation::Dispatch { .. }
                    | MessageInvocation::DialogDefault
                    | MessageInvocation::Procedure { .. } => invoke_message(
                        invocation,
                        hwnd,
                        u32::from(message),
                        usize::from(w_param),
                        (l_param as i32) as isize,
                    ),
                }
            }
        }
        Win16HostMessage::GuestOpaque {
            message,
            w_param,
            l_param,
        } => {
            if message < 0x0400 {
                return Err(RuntimeError::new(
                    Kind::InvalidInput,
                    "Win16 opaque message is outside the application-defined range",
                ));
            }
            invoke_message(
                invocation,
                hwnd,
                u32::from(message),
                usize::from(w_param),
                (l_param as i32) as isize,
            )
        }
        Win16HostMessage::Command {
            id,
            notify,
            control,
            ..
        } => {
            let native_control = match control {
                Some(control) => {
                    match super::win16_window_identity::resolve_user_window(state, control) {
                        Some(hwnd) => hwnd,
                        None => return Ok(None),
                    }
                }
                None => std::ptr::null_mut(),
            };
            let native_w_param = usize::from(id) | (usize::from(notify) << 16);
            invoke_message(
                invocation,
                hwnd,
                WM_COMMAND,
                native_w_param,
                native_control as isize,
            )
        }
        Win16HostMessage::ClipboardChainChange { removed, next } => {
            let resolve = |token: Option<Win16HostWindow>| -> Option<HWND> {
                match token {
                    Some(token) => super::win16_window_identity::resolve_user_window(state, token),
                    None => Some(std::ptr::null_mut()),
                }
            };
            let Some(removed) = resolve(removed) else {
                return Ok(None);
            };
            let Some(next) = resolve(next) else {
                return Ok(None);
            };
            invoke_message(
                invocation,
                hwnd,
                WM_CHANGECBCHAIN,
                removed as usize,
                next as isize,
            )
        }
        payload @ (Win16HostMessage::EraseBackground { .. } | Win16HostMessage::Paint { .. }) => {
            let (message, dc) = match payload {
                Win16HostMessage::EraseBackground { dc } => (WM_ERASEBKGND, dc),
                Win16HostMessage::Paint { dc } => (WM_PAINT, dc),
                _ => unreachable!(),
            };
            let dc_use = match dc {
                Some(dc) => Some(state.borrow().dcs.lease_dc(dc)?.ok_or_else(|| {
                    RuntimeError::new(
                        Kind::InvalidInput,
                        "Win16 drawing message HDC token is no longer mapped",
                    )
                })?),
                None => None,
            };
            // The lease pins the HDC without holding either the USER state
            // borrow or the DC table mutex across a reentrant native call.
            let native_dc = dc_use
                .as_ref()
                .map_or(std::ptr::null_mut(), |dc| dc.native());
            invoke_message(invocation, hwnd, message, native_dc as usize, 0)
        }
        Win16HostMessage::Creation { non_client, data } => {
            if let Some(live) = live {
                if Some(data.class) != live.identity.class {
                    return Err(RuntimeError::new(
                        Kind::InvalidInput,
                        "Win16 creation default class differs from its native callback",
                    ));
                }
            }
            let Some(result) =
                default_creation(state, hwnd, live, non_client, data, invocation, None)?
            else {
                return Ok(None);
            };
            result
        }
        Win16HostMessage::SetText(text) => {
            let _text_context = super::win16_window_text_context::enter(
                state,
                window,
                hwnd,
                super::win16_window_text_context::WindowTextCall::SetText,
            )?;
            let text = text
                .as_deref()
                .map(|bytes| super::win16_window_text_context::wide_z_from_guest(state, bytes))
                .transpose()?;
            let w_param = live.map_or(0, |frame| frame.w_param);
            invoke_message(
                invocation,
                hwnd,
                WM_SETTEXT,
                w_param,
                text.as_ref()
                    .map_or(0, |text| text.as_ptr() as usize as isize),
            )
        }
        Win16HostMessage::GetText {
            capacity,
            buffer_is_null,
        } => {
            if may_return_static_icon(invocation) {
                check_text_output_contract(state, hwnd)?;
            }
            if capacity != 0 && buffer_is_null {
                return Err(RuntimeError::new(
                    Kind::GuestFault,
                    "Win16 WM_GETTEXT has a null output pointer for positive capacity",
                ));
            }
            let native_capacity_units = usize::from(capacity);
            let output_size = match (capacity, buffer_is_null) {
                (0, false) => 1,
                _ => usize::from(capacity),
            };
            let mut output = crate::windows::guest_text::GuestTextBuffer::acquire();
            output.try_reserve_exact(output_size).map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "cannot allocate the native Win16 WM_GETTEXT buffer",
                    error,
                )
            })?;
            output.resize(output_size, u16::MAX);
            let w_param = usize::from(capacity);
            let l_param = if buffer_is_null || output.is_empty() {
                0
            } else {
                output.as_mut_ptr() as usize as isize
            };
            let _text_context = super::win16_window_text_context::enter(
                state,
                window,
                hwnd,
                super::win16_window_text_context::WindowTextCall::GetText {
                    guest_capacity_bytes: capacity,
                    buffer_is_null,
                    native_capacity_units,
                },
            )?;
            let native = invoke_message(invocation, hwnd, WM_GETTEXT, w_param, l_param);
            // The Windows 3.1 WM_GETTEXT contract permits CB_ERR (-1) for a
            // non-edit combo box. It has no text output to copy back.
            if native.value == u32::MAX {
                return Ok(Some(Win16HostMessageResult {
                    dialog_result: None,
                    value: native.value,
                    output: Output::None,
                }));
            }
            if capacity == 0 {
                // Zero capacity has no bytes to copy back. The owned one-byte
                // buffer above exists only to preserve a non-NULL LPARAM.
                return Ok(Some(Win16HostMessageResult {
                    dialog_result: None,
                    value: native.value,
                    output: Output::Text(Vec::new()),
                }));
            }
            // Do not turn an untouched native buffer into an empty string.
            if native.value == 0 && output.first() != Some(&0) {
                return Ok(Some(Win16HostMessageResult {
                    dialog_result: None,
                    value: native.value,
                    output: Output::None,
                }));
            }
            let length = usize::try_from(native.value).map_err(|_| {
                RuntimeError::new(
                    Kind::HostFailure,
                    "native WM_GETTEXT returned an invalid character count",
                )
            })?;
            if length >= output.len() {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    "native WM_GETTEXT returned a count outside its supplied buffer",
                ));
            }
            if output[..length].contains(&0) || output[length] != 0 {
                return Err(RuntimeError::new(
                    Kind::HostFailure,
                    "native WM_GETTEXT output does not match its returned character count",
                ));
            }
            let (guest_output, guest_count) =
                super::win16_window_text_context::native_prefix_to_guest(
                    state,
                    &output[..length],
                    usize::from(capacity).saturating_sub(1),
                )?;
            Win16HostMessageResult {
                dialog_result: None,
                value: guest_count as u32,
                output: Output::Text(guest_output),
            }
        }
        Win16HostMessage::GetTextLength => {
            let _text_context = super::win16_window_text_context::enter(
                state,
                window,
                hwnd,
                super::win16_window_text_context::WindowTextCall::GetTextLength,
            )?;
            let native = invoke_message(invocation, hwnd, WM_GETTEXTLENGTH, 0, 0);
            let value = if let Some(guest_result) =
                super::win16_window_text_context::recorded_guest_text_length_result(
                    state, window, hwnd,
                ) {
                guest_result as i32 as u32
            } else {
                super::win16_window_text_context::native_text_length_upper_bound(
                    state,
                    native.value as i32,
                )? as u32
            };
            Win16HostMessageResult {
                dialog_result: None,
                value,
                output: Output::None,
            }
        }
        Win16HostMessage::SetFont { font, redraw } => {
            let native = match font {
                None => 0,
                Some(token) => match state
                    .borrow()
                    .active_operations
                    .last()
                    .and_then(|operation| operation.native_font)
                    .filter(|(mapped, _)| *mapped == token)
                {
                    Some((_, native)) => native,
                    None => return Ok(None),
                },
            };
            // HFONT is a Windows-validated handle; Rust never dereferences it.
            // The Win16 SDK assigns font ownership to the caller, as does USER.
            invoke_message(invocation, hwnd, WM_SETFONT, native, isize::from(redraw))
        }
        Win16HostMessage::NonClientPaint => {
            // A native callback's update HRGN belongs to the suspended USER
            // delivery. Reuse it only with that exact capability. Win16
            // WM_NCPAINT has no region parameter, and this bridge has no
            // evidence-backed full-frame HRGN conversion for independent
            // guest calls, so report the gap instead of claiming a repaint.
            let native_region = live.and_then(|frame| match frame.native_message_context {
                Some(NativeCallbackContext::NonClientPaint { native_w_param }) => {
                    Some(native_w_param)
                }
                _ => None,
            });
            if let Some(native_region) = native_region {
                invoke_message(invocation, hwnd, WM_NCPAINT, native_region, 0)
            } else {
                super::win16_window_position::report_diagnostic(
                    state,
                    Kind::CompatibilityGap,
                    "Win16 WM_NCPAINT has no native update-region source; native repaint was skipped",
                );
                Win16HostMessageResult {
                    dialog_result: None,
                    value: 0,
                    output: Output::None,
                }
            }
        }
        Win16HostMessage::MinMaxInfo(data) => {
            let mut native = native_minmax(data);
            let result = invoke_message(
                invocation,
                hwnd,
                WM_GETMINMAXINFO,
                0,
                (&mut native as *mut MINMAXINFO) as isize,
            );
            Win16HostMessageResult {
                dialog_result: None,
                value: result.value,
                output: Output::MinMaxInfo(copy_minmax(&native)),
            }
        }
        Win16HostMessage::NonClientCalcSize { w_param, data } => {
            let mut native =
                match super::win16_window_callbacks::NativeNonClientCalcSize::from_owned(
                    state, w_param, data,
                ) {
                    Ok(Some(native)) => native,
                    Ok(None) => return Ok(None),
                    // Shape and handle mismatches have no native output; in
                    // particular, never turn an unmappable token into HWND_NULL.
                    Err(error) if error.kind() == Kind::InvalidInput => return Ok(None),
                    Err(error) => return Err(error),
                };
            let native_l_param = native.l_param();
            let result = invoke_message(
                invocation,
                hwnd,
                WM_NCCALCSIZE,
                usize::from(w_param),
                native_l_param,
            );
            // Native execution can reenter the guest and destroy/recreate the
            // target. Preserve the native LRESULT, but suppress buffer output
            // when the original HWND identity has retired.
            if super::win16_window_identity::resolve_user_window(state, window) != Some(hwnd) {
                return Ok(Some(Win16HostMessageResult {
                    dialog_result: None,
                    value: result.value,
                    output: Output::None,
                }));
            }
            let Some(output) = native.owned_output(state)? else {
                return Ok(None);
            };
            Win16HostMessageResult {
                dialog_result: None,
                value: result.value,
                output: Output::NonClientCalcSize(output),
            }
        }
        Win16HostMessage::WindowPosition {
            changing,
            w_param,
            data,
        } => {
            let Some(mut native) = NativeWindowPosition::from_owned(state, data)? else {
                return Ok(None);
            };
            let native_l_param = native.l_param();
            let native_message = if changing {
                WM_WINDOWPOSCHANGING
            } else {
                WM_WINDOWPOSCHANGED
            };
            let result = invoke_message(
                invocation,
                hwnd,
                native_message,
                usize::from(w_param),
                native_l_param,
            );
            // Preserve the native LRESULT, but do not project output into a
            // replacement receiver if reentrant USER work destroyed and
            // recycled the original HWND.
            if super::win16_window_identity::resolve_user_window(state, window) != Some(hwnd) {
                return Ok(Some(Win16HostMessageResult {
                    dialog_result: None,
                    value: result.value,
                    output: Output::None,
                }));
            }
            let output = if changing {
                match native.owned_output(state)? {
                    Some(output) => Output::WindowPosition(output),
                    None => {
                        super::win16_window_position::report_diagnostic(
                            state,
                            Kind::InvalidInput,
                            "native WM_WINDOWPOSCHANGING output contains an unmapped or retired HWND; typed output omitted",
                        );
                        Output::None
                    }
                }
            } else {
                // WM_WINDOWPOSCHANGED is input-only even if the native
                // procedure modified its local structure.
                Output::None
            };
            Win16HostMessageResult {
                dialog_result: None,
                value: result.value,
                output,
            }
        }
        Win16HostMessage::InitDialog { .. } | Win16HostMessage::GetDlgCode => {
            // The Win16 payload intentionally omits native handles and MSG
            // pointers. A matching suspended callback is the sole capability
            // that can supply those host arguments to the native default proc.
            let Some(frame) = live else {
                return Ok(None);
            };
            // DefDlgProc is a nested USER operation. Authorize only this
            // exact live initialization callback to reenter its creation's
            // DLGPROC; merely finding an ancestor operation is insufficient.
            let _dialog_init = if matches!(invocation, MessageInvocation::DialogDefault)
                && frame.message == WM_INITDIALOG
            {
                dialog_init::DefaultInitScope::begin(
                    state, hwnd, window, frame.creation, frame.operation,
                )?
            } else { None };
            invoke_message(
                invocation,
                hwnd,
                frame.message,
                frame.w_param,
                frame.l_param,
            )
        }
    };
    Ok(Some(result))
}

#[derive(Clone, Copy)]
struct LiveFrame {
    operation: u64,
    creation: Option<Win16CreationId>,
    identity: NativeWindowIdentity,
    message: u32,
    hwnd: HWND,
    w_param: usize,
    l_param: isize,
    native_message_context: Option<NativeCallbackContext>,
    creation_cookie: Option<usize>,
    mdi_create_struct: Option<usize>,
}

fn default_creation(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    live: Option<LiveFrame>,
    non_client: bool,
    data: Win16HostCreationData,
    invocation: MessageInvocation,
    mdi_create_parameter: Option<usize>,
) -> Result<Option<Win16HostMessageResult>, RuntimeError> {
    let Some(class) = state.borrow().classes.get(&data.class).cloned() else {
        return Ok(Some(Win16HostMessageResult {
            dialog_result: None,
            value: 0,
            output: Output::None,
        }));
    };
    let parent = match data.parent {
        Some(parent) => match super::win16_window_identity::resolve_user_window(state, parent) {
            Some(hwnd) => hwnd,
            None => return Ok(None),
        },
        None => std::ptr::null_mut(),
    };
    let title = super::win16_window_text_context::wide_z_from_guest(
        state,
        data.title.as_deref().unwrap_or_default(),
    )?;
    let class_name = state
        .borrow()
        .text_codec
        .to_wide_z(&class.name[..class.name.len().saturating_sub(1)])?;
    let menu = if let Some(child_id) = data.child_id {
        usize::from(child_id) as *mut c_void
    } else {
        match data.menu {
            Some(menu) => match state.borrow().menus.get(&menu).copied() {
                Some(native) => native,
                None => return Ok(None),
            },
            None => std::ptr::null_mut(),
        }
    };
    let mut native = CREATESTRUCTW {
        lpCreateParams: mdi_create_parameter
            .or_else(|| live.and_then(|frame| frame.creation_cookie))
            .map_or(std::ptr::null_mut(), |cookie| cookie as *mut c_void),
        hInstance: class.instance,
        hMenu: menu,
        hwndParent: parent,
        cy: i32::from(data.height),
        cx: i32::from(data.width),
        y: i32::from(data.y),
        x: i32::from(data.x),
        style: data.style as i32,
        lpszName: title.as_ptr(),
        lpszClass: class_name.as_ptr(),
        dwExStyle: data.ex_style,
    };
    let message = if non_client { WM_NCCREATE } else { WM_CREATE };
    let w_param = live.map_or(0, |frame| frame.w_param);
    if non_client
        && let MessageInvocation::Procedure { token, .. } = invocation
        && !super::win16_native_procedures::enter_creation(state, hwnd, token)
    {
        return Ok(None);
    }
    Ok(Some(invoke_message(
        invocation,
        hwnd,
        message,
        w_param,
        &mut native as *mut CREATESTRUCTW as isize,
    )))
}

pub(super) fn invoke_message(
    invocation: MessageInvocation,
    hwnd: HWND,
    message: u32,
    w_param: usize,
    l_param: isize,
) -> Win16HostMessageResult {
    let value = invoke_native_message(invocation, hwnd, message, w_param, l_param);
    Win16HostMessageResult {
        dialog_result: None,
        value: value as i32 as u32,
        output: Output::None,
    }
}

/// Preserve pointer-width results until the message-specific ABI projection.
pub(super) fn invoke_native_message(
    invocation: MessageInvocation,
    hwnd: HWND,
    message: u32,
    w_param: usize,
    l_param: isize,
) -> isize {
    // SAFETY: `l_param` is typed scalar data, an owned UTF-16 buffer, or a
    // local host CREATESTRUCTW. Guest addresses never enter this call. A
    // captured procedure value (possibly an internal USER thunk) is passed
    // only to CallWindowProcW, which owns its interpretation.
    unsafe {
        match invocation {
            MessageInvocation::Default => DefWindowProcW(hwnd, message, w_param, l_param),
            MessageInvocation::FrameDefault { mdi_client } => {
                DefFrameProcW(hwnd, mdi_client, message, w_param, l_param)
            }
            MessageInvocation::MdiChildDefault => DefMDIChildProcW(hwnd, message, w_param, l_param),
            MessageInvocation::DialogDefault => DefDlgProcW(hwnd, message, w_param, l_param),
            MessageInvocation::Send => SendMessageW(hwnd, message, w_param, l_param),
            MessageInvocation::Dispatch { time, point } => {
                let native = windows_sys::Win32::UI::WindowsAndMessaging::MSG {
                    hwnd,
                    message,
                    wParam: w_param,
                    lParam: l_param,
                    time,
                    pt: POINT {
                        x: point.x,
                        y: point.y,
                    },
                };
                DispatchMessageW(&native)
            }
            MessageInvocation::Procedure { address, .. } => {
                call_window_proc_w_opaque(address, hwnd, message, w_param, l_param)
            }
        }
    }
}

fn zero_message_result() -> Win16HostMessageResult {
    Win16HostMessageResult {
        dialog_result: None,
        value: 0,
        output: Output::None,
    }
}

/// Check the output layout before either GetWindowText or message delivery.
/// Windows 3.1 SDK Vol. 3, PDF p. 139 specifies two-byte HICON output for
/// SS_ICON; modern WM_GETTEXT documents four bytes, not an ANSI string.
pub(super) fn check_text_output_contract(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
) -> Result<(), RuntimeError> {
    if matches!(
        super::win16_static_controls::native_static_control_kind(state, hwnd),
        Some(super::win16_static_controls::NativeStaticControlKind::Icon),
    ) {
        // A subclass can forward to the native static procedure. Until a
        // typed icon result exists, its output cannot use the text contract.
        return Err(RuntimeError::new(
            Kind::CompatibilityGap,
            "WM_GETTEXT on a native static icon requires HICON handle translation",
        ));
    }
    Ok(())
}

fn may_return_static_icon(invocation: MessageInvocation) -> bool {
    match invocation {
        MessageInvocation::Default
        | MessageInvocation::FrameDefault { .. }
        | MessageInvocation::MdiChildDefault
        | MessageInvocation::DialogDefault => false,
        MessageInvocation::Send | MessageInvocation::Dispatch { .. } => true,
        MessageInvocation::Procedure { address, .. } => {
            address as usize != DefWindowProcW as *const () as usize
        }
    }
}

fn may_destroy_window_tree(message: u32, w_param: usize) -> bool {
    message == WM_CLOSE
        || message == WM_DESTROY
        || (message == WM_SYSCOMMAND && (w_param as u32 & 0xfff0) == 0xf060)
}

// windows-sys types the first CallWindowProcW parameter as WNDPROC. Windows
// also documents opaque USER procedure values that are valid only when passed
// back to CallWindowProcW. Keep that value integer-shaped to avoid fabricating
// an invalid Rust function pointer merely to satisfy the wrapper's signature.
#[link(name = "user32")]
unsafe extern "system" {
    #[link_name = "CallWindowProcW"]
    pub(super) fn call_window_proc_w_opaque(
        previous: isize,
        hwnd: HWND,
        message: u32,
        w_param: usize,
        l_param: isize,
    ) -> isize;
}

fn message_id(message: &Win16HostMessage) -> Option<u32> {
    Some(match message {
        // Typed control operations do not carry native callback provenance.
        Win16HostMessage::Control(_) => return None,
        Win16HostMessage::Mdi(message) => message.native_message_id(),
        Win16HostMessage::MdiQueued(message) => message.native_message_id(),
        Win16HostMessage::MdiChildCreation { non_client, .. } => {
            if *non_client {
                WM_NCCREATE
            } else {
                WM_CREATE
            }
        }
        Win16HostMessage::OwnerDraw(item) => u32::from(item.message_id()),
        Win16HostMessage::FindReplaceNotification(notification) => {
            u32::from(notification.find_message)
        }
        Win16HostMessage::DragListNotification(notification) => u32::from(notification.message),
        Win16HostMessage::WindowInput(input) => u32::from(input.message_id()),
        // The active callback source carries one of Win32's seven native IDs;
        // Win16 combines them into WM_CTLCOLOR only after projection.
        Win16HostMessage::ControlColor(input) => 0x0132 + u32::from(input.kind),
        Win16HostMessage::ActivationApp(_) => 0x001c,
        Win16HostMessage::ParentNotification(_) => 0x0210,
        Win16HostMessage::Scalar { kind, .. } => u32::from(*kind as u16),
        Win16HostMessage::MultimediaNotification { message, .. } => u32::from(*message),
        Win16HostMessage::GuestNotification(notification) => u32::from(notification.message),
        Win16HostMessage::GuestOpaque { message, .. } => u32::from(*message),
        Win16HostMessage::DropFiles(_) | Win16HostMessage::QueuedDropFiles(_) => WM_DROPFILES,
        Win16HostMessage::Command { .. } => WM_COMMAND,
        Win16HostMessage::ClipboardChainChange { .. } => WM_CHANGECBCHAIN,
        Win16HostMessage::EraseBackground { .. } => WM_ERASEBKGND,
        Win16HostMessage::Paint { .. } => WM_PAINT,
        Win16HostMessage::Creation { non_client, .. } => {
            if *non_client {
                WM_NCCREATE
            } else {
                WM_CREATE
            }
        }
        Win16HostMessage::SetText(_) => WM_SETTEXT,
        Win16HostMessage::GetText { .. } => WM_GETTEXT,
        Win16HostMessage::GetTextLength => WM_GETTEXTLENGTH,
        Win16HostMessage::SetFont { .. } => WM_SETFONT,
        Win16HostMessage::NonClientPaint => WM_NCPAINT,
        Win16HostMessage::MinMaxInfo(_) => WM_GETMINMAXINFO,
        Win16HostMessage::NonClientCalcSize { .. } => WM_NCCALCSIZE,
        Win16HostMessage::WindowPosition { changing, .. } => {
            if *changing {
                WM_WINDOWPOSCHANGING
            } else {
                WM_WINDOWPOSCHANGED
            }
        }
        Win16HostMessage::InitDialog { .. } => WM_INITDIALOG,
        Win16HostMessage::GetDlgCode => WM_GETDLGCODE,
    })
}
