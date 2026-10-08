//! Portable USER/GDI state and software bitmap operations.
//!
//! This crate deliberately stops at host-facing actions and events. It does not
//! create native windows, call a platform graphics API, or claim that an OS
//! window was successfully shown.
#![forbid(unsafe_code)]

mod gdi;
mod handle;
mod surface;
mod user;

pub use gdi::{DeviceContextHandle, Gdi, GdiError, BitmapHandle};
pub use handle::{HandleError, HandleTable, TypedHandle, WindowHandle};
pub use surface::{
    Color, DibError, RasterOp, Rect, Surface, GraphicsError, MAX_SURFACE_PIXELS,
};
pub use user::{
    HostAction, HostEvent, MessageQueue, MouseButton, UserError, WindowDescription,
    WindowInfo, WindowMessage, WindowSystem, MAX_QUEUED_MESSAGES, WM_CLOSE, WM_KEYDOWN,
    WM_KEYUP, WM_CHAR, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MBUTTONDOWN, WM_MBUTTONUP, WM_MOUSEMOVE,
    WM_PAINT, WM_RBUTTONDOWN, WM_RBUTTONUP,
};
