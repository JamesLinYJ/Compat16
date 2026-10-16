//! Owned USER update-region operations on the window callback worker.

use crate::{Win16HostDc, Win16HostGdiObject, Win16HostRect, Win16HostWindow};

/// `None` retains the native API's null HWND/RECT/HRGN meaning. An invalid
/// non-null guest handle must fail during translation rather than become None.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostUpdateOperation {
    UpdateWindow { window: Option<Win16HostWindow> },
    InvalidateRect { window: Option<Win16HostWindow>, rect: Option<Win16HostRect>, erase: bool },
    InvalidateRgn { window: Option<Win16HostWindow>, region: Option<Win16HostGdiObject>, erase: bool },
    ValidateRect { window: Option<Win16HostWindow>, rect: Option<Win16HostRect> },
    ValidateRgn { window: Option<Win16HostWindow>, region: Option<Win16HostGdiObject> },
    GetUpdateRect { window: Option<Win16HostWindow>, rect_is_null: bool, erase: bool },
    GetUpdateRgn { window: Option<Win16HostWindow>, region: Win16HostGdiObject, erase: bool },
    ExcludeUpdateRgn { dc: Win16HostDc, window: Option<Win16HostWindow> },
    RedrawWindow { window: Option<Win16HostWindow>, rect: Option<Win16HostRect>,
        region: Option<Win16HostGdiObject>, flags: u16 },
    LockWindowUpdate { window: Option<Win16HostWindow> },
    ScrollWindow { window: Option<Win16HostWindow>, dx: i16, dy: i16,
        scroll_rect: Option<Win16HostRect>, clip_rect: Option<Win16HostRect> },
    ScrollDC { dc: Win16HostDc, dx: i16, dy: i16,
        scroll_rect: Option<Win16HostRect>, clip_rect: Option<Win16HostRect>,
        update_region: Option<Win16HostGdiObject>, update_rect_is_null: bool },
    ScrollWindowEx { window: Option<Win16HostWindow>, dx: i16, dy: i16,
        scroll_rect: Option<Win16HostRect>, clip_rect: Option<Win16HostRect>,
        update_region: Option<Win16HostGdiObject>, update_rect_is_null: bool, flags: u16 },
}

/// The native BOOL of a guest-void API describes completion only. It never
/// becomes AX. Rectangles are copied native values, with no guest pointers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16HostUpdateResult {
    Void { succeeded: bool },
    Word(u16),
    Rect { value: u16, rect: Option<Win16HostRect> },
}
