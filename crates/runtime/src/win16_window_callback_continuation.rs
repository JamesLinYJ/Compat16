//! Typed continuations retained across one guest USER callback.

use crate::{Win16GuestNotification, Win16HostCallback, Win16HostWindow};

/// A captured native message may be forwarded only with this exact tuple.
#[derive(Clone, Copy)]
pub(in crate::win16_runtime) struct ForwardedWindowMessage {
    pub(in crate::win16_runtime) callback: Win16HostCallback,
    pub(in crate::win16_runtime) native_window: Win16HostWindow,
    pub(in crate::win16_runtime) window: u16,
    pub(in crate::win16_runtime) message: u16,
    pub(in crate::win16_runtime) w_param: u16,
    pub(in crate::win16_runtime) l_param: u32,
    pub(in crate::win16_runtime) guest_notification: Option<Win16GuestNotification>,
}

#[derive(Clone, Copy)]
pub(in crate::win16_runtime) enum WindowCallbackContinuation {
    Host {
        callback: Win16HostCallback,
        native_window: Win16HostWindow,
        window: u16,
        destroyed: bool,
    },
    HostDialog {
        callback: Win16HostCallback,
        native_window: Win16HostWindow,
        window: u16,
        destroyed: bool,
    },
    HostTimer { callback: Win16HostCallback },
    GuestDispatch,
    GuestDialogDispatch { window: u16 },
    GuestTimer,
    GuestProcedureCall { forwarded: Option<ForwardedWindowMessage> },
}
