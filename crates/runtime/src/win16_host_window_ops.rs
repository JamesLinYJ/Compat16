//! Owned values for Win16 USER window-state and geometry calls.
//!
//! These values are the runtime/host boundary. Guest pointers are validated
//! and copied before constructing a call; native HWNDs remain host-owned and
//! cross this boundary only as opaque `Win16HostWindow` tokens.

use crate::{Win16HostClass, Win16HostPoint, Win16HostRect, Win16HostWindow};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16WindowPlacement {
    pub flags: u32,
    pub show_command: u32,
    pub minimum: Win16HostPoint,
    pub maximum: Win16HostPoint,
    pub normal: Win16HostRect,
}

/// Class selector for `FindWindow`. Guest registered classes use their opaque
/// registration token so the host can match the private native class that
/// backs them. Other class names remain ordinary owned bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16WindowSearchClass {
    Name(Vec<u8>),
    Registered(Win16HostClass),
}

/// `SetWindowPos`'s insertion target. The four USER pseudo-handles are kept
/// distinct from a real opaque window token and converted only in the host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16WindowInsertAfter {
    Top,
    Bottom,
    Topmost,
    NotTopmost,
    Window(Win16HostWindow),
}

/// A guest HWND after runtime translation. `Null` preserves the Win16 null
/// handle for native API semantics; `Invalid` prevents an unknown nonzero
/// guest token from being mistaken for native NULL; `Mapped` is an opaque
/// identity resolved only by the host worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16WindowTarget {
    Null,
    Invalid,
    Mapped(Win16HostWindow),
}

/// One synchronous native USER window operation. The host worker executes the
/// call on the window-owning thread and can suspend it for guest callbacks.
#[derive(Clone, Debug)]
pub enum Win16WindowCall {
    WindowData(crate::Win16WindowDataCall),
    SetWindowProperty {
        window: Win16WindowTarget,
        name: crate::Win16HostPropertyName,
        data: u16,
    },
    GetWindowProperty {
        window: Win16WindowTarget,
        name: crate::Win16HostPropertyName,
    },
    RemoveWindowProperty {
        window: Win16WindowTarget,
        name: crate::Win16HostPropertyName,
    },
    EnumWindowProperties { window: Win16WindowTarget },
    IsIconic { window: Win16WindowTarget },
    GetWindowRect { window: Win16WindowTarget },
    GetClientRect { window: Win16WindowTarget },
    EnableWindow { window: Win16WindowTarget, enable: bool },
    IsWindowEnabled { window: Win16WindowTarget },
    BringWindowToTop { window: Win16WindowTarget },
    GetParent { window: Win16WindowTarget },
    IsWindow { window: Win16WindowTarget },
    IsWindowVisible { window: Win16WindowTarget },
    FindWindow {
        class: Option<Win16WindowSearchClass>,
        title: Option<Vec<u8>>,
    },
    DestroyWindow { window: Win16WindowTarget },
    GetClassName { window: Win16WindowTarget, capacity: u16 },
    SetActiveWindow { window: Win16WindowTarget },
    GetActiveWindow,
    GetWindow { window: Win16WindowTarget, command: u16 },
    GetTopWindow { window: Win16WindowTarget },
    ShowOwnedPopups { window: Win16WindowTarget, show: bool },
    IsZoomed { window: Win16WindowTarget },
    GetDlgCtrlId { window: Win16WindowTarget },
    GetDesktopWindow,
    GetCursorPos,
    GetWindowPlacement { window: Win16WindowTarget },
    SetWindowPlacement { window: Win16WindowTarget, placement: Win16WindowPlacement },
    GetLastActivePopup { window: Win16WindowTarget },
    ClientToScreen { window: Win16WindowTarget, point: Win16HostPoint },
    ScreenToClient { window: Win16WindowTarget, point: Win16HostPoint },
    WindowFromPoint { point: Win16HostPoint },
    MoveWindow {
        window: Win16WindowTarget,
        x: i16,
        y: i16,
        width: i16,
        height: i16,
        repaint: bool,
    },
    SetWindowPos {
        window: Win16WindowTarget,
        insert_after: Win16WindowInsertAfter,
        x: i16,
        y: i16,
        width: i16,
        height: i16,
        flags: u16,
    },
}

/// Results copied back from a host USER operation. A missing rectangle or
/// point means the native API reported failure and no guest structure is
/// written. `ClassName.bytes` includes the final NUL when `count` is positive.
#[derive(Clone, Debug)]
pub enum Win16WindowCallResult {
    WindowData(crate::Win16WindowDataResult),
    PropertySet(bool),
    PropertyValue(Option<u16>),
    PropertyEnumeration(i16),
    Boolean(bool),
    Rect(Option<Win16HostRect>),
    Point(Option<Win16HostPoint>),
    Placement(Option<Win16WindowPlacement>),
    Window(Option<Win16HostWindow>),
    ClassName {
        count: i32,
        bytes: Vec<u8>,
        registered_class: Option<Win16HostClass>,
    },
    Integer(i32),
    Destroyed {
        succeeded: bool,
        invalidated_menus: Vec<crate::Win16HostMenu>,
    },
}

/// Runtime-only continuation data for copying successful host outputs into
/// checked guest buffers. This is never included in a host operation.
#[derive(Debug)]
pub(crate) enum Win16WindowCallOutput {
    None,
    WindowRect {
        range: crate::win16_runtime::guest_ranges::GuestOutputRange,
        api: &'static str,
        guest_window: u16,
    },
    Point(crate::win16_runtime::guest_ranges::GuestOutputRange),
    Placement(crate::win16_runtime::guest_ranges::GuestOutputRange),
    ClassName { range: crate::win16_runtime::guest_ranges::GuestOutputRange, capacity: u16 },
}

/// Runtime-only completion policy for an asynchronous native window call.
#[derive(Debug)]
pub(crate) struct Win16WindowCallContinuation {
    pub return_kind: win16_abi::Win16ReturnKind,
    pub output: Win16WindowCallOutput,
    /// The guest token to retire after a successful explicit DestroyWindow.
    pub destroyed_guest_window: Option<u16>,
    /// Host incarnation captured at submission; teardown must not retire a
    /// guest token that was reused during a reentrant host callback.
    pub destroyed_native_window: Option<crate::Win16HostWindow>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16WindowEnumerationScope {
    Desktop,
    Children(Win16WindowTarget),
    TaskQueue(crate::Win16HostTaskQueue),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16WindowEnumerationQuery {
    Snapshot(Win16WindowEnumerationScope),
    IsCurrent(Win16HostWindow),
}
#[derive(Clone, Debug)]
pub enum Win16WindowEnumerationReply {
    Snapshot { success: bool, windows: Vec<Win16HostWindow> },
    IsCurrent(bool),
}
