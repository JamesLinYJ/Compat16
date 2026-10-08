//! Copied nonclient geometry, independent of native and segmented pointers.

use crate::{Win16HostRect, Win16HostWindow, Win16WindowInsertAfter};

/// WINDOWPOS fields copied while the native message's structure is valid.
/// HWND pseudo-handles remain distinct from actual window identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Win16HostWindowPos {
    pub window: Option<Win16HostWindow>,
    pub insert_after: Win16WindowInsertAfter,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub flags: u32,
}

/// WM_NCCALCSIZE has two conditional layouts. The false branch owns just
/// one rectangle; it never implies a readable NCCALCSIZE_PARAMS tail.
/// Windows 3.1 SDK WINDOWS.H:3474-3478 defines the true branch. Keep rectangle
/// indices unchanged across the ABI, including the valid source/destination pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16HostNonClientCalcSize {
    Rect(Win16HostRect),
    ValidRects {
        rects: [Win16HostRect; 3],
        position: Option<Win16HostWindowPos>,
    },
}
