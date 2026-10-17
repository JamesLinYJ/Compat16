//! Native facts for CTL3D dialog-frame painting.
//!
//! The guest HWND stays in the runtime. This value is the opaque host window
//! token already mapped for that HWND, never a guest address or a host pointer.

/// Style and iconic state read on the window-owning thread.
/// `Ctl3dDlgFramePaint` does not carry a guest `WM_DLGBORDER` writeback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostCtl3dFrameFacts {
    pub style: u32,
    pub iconic: bool,
}
