//! Pointer-free scroll-bar operations for the HWND-owning host worker.

use crate::Win16HostWindow;

#[derive(Clone, Debug)]
pub enum Win16HostScrollBarOperation {
    SetPosition { window: Win16HostWindow, bar: i16, position: i16, redraw: bool },
    GetPosition { window: Win16HostWindow, bar: i16 },
    SetRange { window: Win16HostWindow, bar: i16, minimum: i16, maximum: i16, redraw: bool },
    GetRange { window: Win16HostWindow, bar: i16 },
    Show { window: Win16HostWindow, bar: i16, show: bool },
    Enable { window: Win16HostWindow, bar: i16, flags: u16 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostScrollBarResult {
    Position(i32),
    Range(Option<(i32, i32)>),
    Void,
    Enabled(bool),
    /// The original host window identity retired before execution.
    Unavailable,
}
