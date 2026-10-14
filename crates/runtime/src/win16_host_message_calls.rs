//! Typed native USER calls for Win16 messages, input state, timers and focus.
//!
//! The worker owns USER queue/thread semantics and native handles. This
//! protocol carries only checked window tokens, copied scalar data, and
//! guest-bit values kept numeric for a verified guest WndProc or the current
//! task's thread queue.

use crate::{Win16HostClass, Win16HostWindow, Win16MessageParam, Win16ScalarMessage};
use crate::win16_runtime::guest_ranges::GuestOutputRange;

/// A USER operation executed on the dedicated native window thread.
#[derive(Clone, Debug)]
pub enum Win16MessageCall {
    /// HWND_BROADCAST is an explicit target, never an opaque window token.
    /// Only a classified scalar message may reach unrelated native windows.
    SendBroadcast {
        kind: Win16ScalarMessage,
        w_param: u16,
        l_param: u32,
    },
    PostBroadcast {
        kind: Win16ScalarMessage,
        w_param: u16,
        l_param: u32,
    },
    SendMessage {
        window: Win16HostWindow,
        message: u16,
        w_param: u16,
        l_param: Win16MessageParam,
        /// Present only when the runtime has a registered guest WndProc for
        /// this HWND. The host verifies it against the native window identity
        /// before accepting custom guest LPARAM bits.
        guest_class: Option<Win16HostClass>,
    },
    PostMessage {
        window: Win16HostWindow,
        message: u16,
        w_param: u16,
        l_param: Win16MessageParam,
        guest_class: Option<Win16HostClass>,
    },
    /// Post to the current Win16 task's native worker queue. The guest HTASK
    /// is validated by runtime and is never interpreted as a native TID.
    PostThreadMessage {
        message: u16,
        w_param: u16,
        l_param: Win16MessageParam,
        guest_class: Option<Win16HostClass>,
    },
    WaitMessage,
    SetTimer {
        window: Option<Win16HostWindow>,
        timer_id: u16,
        interval_ms: u16,
        /// Opaque generation token returned by the prior SetTimer for this
        /// Win16 (HWND, timer ID), if one is being replaced.
        native_timer_id: Option<u64>,
        /// Install a host-owned TIMERPROC thunk. No guest code address crosses
        /// this boundary; the runtime resolves its callback registration.
        guest_callback: bool,
    },
    KillTimer {
        window: Option<Win16HostWindow>,
        host_timer_id: u64,
    },
    /// None is the documented NULL target that clears this queue's focus;
    /// an unknown nonzero guest HWND must never be translated to None.
    SetFocus { window: Option<Win16HostWindow> },
    GetFocus,
    SetCapture { window: Win16HostWindow },
    GetCapture,
    ReleaseCapture,
    GetMessagePos,
    GetMessageTime,
    /// Scalar queue metadata; no native or guest pointer is dereferenced.
    GetMessageExtraInfo,
    /// Query InSendMessage on the native worker owning the active guest WndProc.
    InSendMessage,
    GetInputState,
    GetQueueStatus { flags: u16 },
    GetKeyboardState,
    SetKeyboardState { state: [u8; 256] },
}

/// Result from one native USER message/input operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16MessageCallResult {
    Boolean(bool),
    Window(Option<Win16HostWindow>),
    Dword(u32),
    Long(i32),
    Timer(Option<u64>),
    KeyboardState { succeeded: bool, state: [u8; 256] },
}

/// Guest-side bookkeeping required to finish an asynchronous Win16 call.
/// This is intentionally separate from the host operation: return width and
/// timer-ID translation belong to the Win16 ABI, not USER's native handle.
#[derive(Debug)]
pub(crate) enum Win16MessageCallContinuation {
    Boolean { return_kind: win16_abi::Win16ReturnKind },
    /// Keep queue waits distinct so guest work cannot complete a BOOL call.
    WaitMessage { return_kind: win16_abi::Win16ReturnKind },
    Window { return_kind: win16_abi::Win16ReturnKind },
    Dword { return_kind: win16_abi::Win16ReturnKind },
    SetTimer {
        guest_window: u16,
        host_window: Option<Win16HostWindow>,
        guest_timer_id: u16,
        callback: Option<u32>,
    },
    KillTimer { guest_window: u16, guest_timer_id: u16 },
    GetKeyboardState {
        output_far: u32,
        output_range: Option<GuestOutputRange>,
    },
    SetKeyboardState,
}
