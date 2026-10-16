//! Owned Win16 USER update-region and window-redraw requests.

/// USER redraw/update calls decoded with their original Win16 scalar bits.
/// FAR values remain guest `selector:offset` integers until runtime performs
/// the appropriate checked conversion for the selected operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16UserUpdateRequest {
    UpdateWindow { window: u16 },
    InvalidateRect { window: u16, rect: u32, erase: u16 },
    InvalidateRgn { window: u16, region: u16, erase: u16 },
    ValidateRect { window: u16, rect: u32 },
    ValidateRgn { window: u16, region: u16 },
    GetUpdateRect { window: u16, rect: u32, erase: u16 },
    GetUpdateRgn { window: u16, region: u16, erase: u16 },
    ExcludeUpdateRgn { dc: u16, window: u16 },
    RedrawWindow { window: u16, rect: u32, region: u16, flags: u16 },
    LockWindowUpdate { window: u16 },
    ScrollWindow {
        window: u16,
        dx: i16,
        dy: i16,
        scroll_rect: u32,
        clip_rect: u32,
    },
    ScrollDC {
        dc: u16,
        dx: i16,
        dy: i16,
        scroll_rect: u32,
        clip_rect: u32,
        update_region: u16,
        update_rect: u32,
    },
    ScrollWindowEx {
        window: u16,
        dx: i16,
        dy: i16,
        scroll_rect: u32,
        clip_rect: u32,
        update_region: u16,
        update_rect: u32,
        flags: u16,
    },
}
