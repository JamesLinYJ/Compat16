//! Typed arguments for the Win16 USER scroll-bar calls.

/// USER scroll-bar APIs retain their Win16-sized scalar arguments. The range
/// getters keep FAR output addresses as raw guest values until runtime can
/// capture both writable ranges before starting the native window operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16UserScrollBarRequest {
    SetPosition { window: u16, bar: i16, position: i16, redraw: bool },
    GetPosition { window: u16, bar: i16 },
    SetRange { window: u16, bar: i16, minimum: i16, maximum: i16, redraw: bool },
    GetRange { window: u16, bar: i16, minimum: u32, maximum: u32 },
    Show { window: u16, bar: i16, show: bool },
    Enable { window: u16, bar: i16, flags: u16 },
}
