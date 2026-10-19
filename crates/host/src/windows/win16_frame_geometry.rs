//! Win16 frame metrics around native caption and menu processing.

use super::{win16_window_identity, win16_window_worker::WorkerState};
use runtime::{Win16HostNonClientCalcSize as Calc, Win16HostRect, Win16HostWindow};
use std::{cell::RefCell, rc::Rc};
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AdjustWindowRectEx, GWL_EXSTYLE, GWL_STYLE, GetSystemMetrics, GetWindowLongPtrW, IsIconic,
    SM_CXBORDER, SM_CXDLGFRAME, SM_CXEDGE, SM_CXFRAME, SM_CYBORDER, SM_CYDLGFRAME, SM_CYEDGE,
    SM_CYFRAME, WS_CAPTION, WS_EX_CLIENTEDGE, WS_EX_DLGMODALFRAME, WS_EX_STATICEDGE,
    WS_EX_TOOLWINDOW, WS_EX_WINDOWEDGE, WS_THICKFRAME,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CaptionFrame {
    x: i32,
    y: i32,
    caption: i32,
}

fn eligible(style: u32, ex_style: u32) -> bool {
    style & WS_CAPTION == WS_CAPTION && ex_style & WS_EX_TOOLWINDOW == 0
}

fn caption_padding() -> Option<i32> {
    let mut native: RECT = unsafe { std::mem::zeroed() };
    if unsafe { AdjustWindowRectEx(&mut native, WS_CAPTION, 0, 0) } == 0 {
        return None;
    }
    let padding = native
        .bottom
        .checked_sub(unsafe { GetSystemMetrics(SM_CYBORDER) })?;
    (padding >= 0).then_some(padding)
}

pub(in crate::windows) fn caption_height(native: i32) -> i32 {
    // Native caption/menu drawing keeps its padded origin. Include that
    // space in the guest metric so legacy frame calculations cannot place
    // the client over native menu pixels.
    if native <= 0 {
        return native;
    }
    caption_padding()
        .and_then(|padding| native.checked_add(padding))
        .unwrap_or(native)
}

impl CaptionFrame {
    pub(super) fn query(style: u32, ex_style: u32) -> Option<Self> {
        if !eligible(style, ex_style) {
            return None;
        }
        let mut native: RECT = unsafe { std::mem::zeroed() };
        if unsafe { AdjustWindowRectEx(&mut native, style, 0, ex_style) } == 0 {
            return None;
        }
        // Use the same exposed metrics for all ordinary caption styles.
        // Native USER still owns drawing/hit testing of the caption/menu.
        let (cx, cy) = if ex_style & WS_EX_DLGMODALFRAME != 0 {
            (SM_CXDLGFRAME, SM_CYDLGFRAME)
        } else if style & WS_THICKFRAME != 0 {
            (SM_CXFRAME, SM_CYFRAME)
        } else {
            (SM_CXBORDER, SM_CYBORDER)
        };
        let mut legacy_x = unsafe { GetSystemMetrics(cx) };
        let mut legacy_y = unsafe { GetSystemMetrics(cy) };
        if ex_style & WS_EX_CLIENTEDGE != 0 {
            legacy_x = legacy_x.checked_add(unsafe { GetSystemMetrics(SM_CXEDGE) })?;
            legacy_y = legacy_y.checked_add(unsafe { GetSystemMetrics(SM_CYEDGE) })?;
        }
        if ex_style & WS_EX_STATICEDGE != 0 && ex_style & WS_EX_WINDOWEDGE == 0 {
            legacy_x = legacy_x.checked_add(unsafe { GetSystemMetrics(SM_CXBORDER) })?;
            legacy_y = legacy_y.checked_add(unsafe { GetSystemMetrics(SM_CYBORDER) })?;
        }
        let caption = caption_padding()?;
        let x = native.right.checked_sub(legacy_x)?;
        let y = native.bottom.checked_sub(legacy_y)?;
        // Never move the client over native caption/menu pixels for a style
        // whose extra native edge cannot be described by these metrics.
        let (x, y) = if x >= 0 && y >= 0 && y <= caption {
            (x, y)
        } else {
            (0, 0)
        };
        (x != 0 || y != 0 || caption != 0).then_some(Self { x, y, caption })
    }

    pub(super) fn for_window(
        state: &Rc<RefCell<WorkerState>>,
        window: Win16HostWindow,
        hwnd: HWND,
    ) -> Option<Self> {
        if win16_window_identity::resolve(state, window) != Some(hwnd)
            || unsafe { IsIconic(hwnd) } != 0
        {
            return None;
        }
        let style = unsafe { GetWindowLongPtrW(hwnd, GWL_STYLE) } as u32;
        let ex_style = unsafe { GetWindowLongPtrW(hwnd, GWL_EXSTYLE) } as u32;
        Self::query(style, ex_style)
    }

    pub(super) fn prepare(self, mut data: Calc) -> Option<Calc> {
        // Let native USER measure/wrap the menu using the legacy client width.
        // Only the proposed new rectangle changes; old/valid rectangles and
        // the checked WINDOWPOS retain their original ownership and contents.
        let rect = first_mut(&mut data);
        rect.right = rect.right.checked_add(self.x.checked_mul(2)?)?;
        rect.bottom = rect
            .bottom
            .checked_add(self.y.checked_mul(2)?.checked_sub(self.caption)?)?;
        Some(data)
    }

    pub(super) fn finish(self, mut data: Calc) -> Option<Calc> {
        let rect = first_mut(&mut data);
        rect.left = rect.left.checked_sub(self.x)?;
        rect.right = rect.right.checked_sub(self.x)?;
        let top_padding = self.caption.checked_sub(self.y)?;
        rect.top = rect.top.checked_add(top_padding)?;
        rect.bottom = rect.bottom.checked_add(top_padding)?;
        Some(data)
    }

    pub(super) fn adjust_outer(self, mut rect: RECT) -> Option<RECT> {
        rect.left = rect.left.checked_add(self.x)?;
        rect.right = rect.right.checked_sub(self.x)?;
        rect.top = rect.top.checked_add(self.y.checked_sub(self.caption)?)?;
        rect.bottom = rect.bottom.checked_sub(self.y)?;
        Some(rect)
    }
}

fn first_mut(data: &mut Calc) -> &mut Win16HostRect {
    match data {
        Calc::Rect(rect) => rect,
        Calc::ValidRects { rects, .. } => &mut rects[0],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caption_policy_preserves_small_toolwindow_captions() {
        assert!(eligible(WS_CAPTION, 0));
        assert!(eligible(
            WS_CAPTION,
            windows_sys::Win32::UI::WindowsAndMessaging::WS_EX_WINDOWEDGE
        ));
        assert!(!eligible(0, 0));
        for style in [
            WS_CAPTION | WS_THICKFRAME,
            WS_CAPTION | windows_sys::Win32::UI::WindowsAndMessaging::WS_CHILD,
        ] {
            assert!(eligible(style, 0));
        }
        for ex in [WS_EX_DLGMODALFRAME, WS_EX_CLIENTEDGE, WS_EX_STATICEDGE] {
            assert!(eligible(WS_CAPTION, ex));
        }
        assert!(!eligible(WS_CAPTION, WS_EX_TOOLWINDOW));
        assert_eq!(caption_height(0), 0);
        assert_eq!(caption_height(-1), -1);
    }

    #[test]
    fn legacy_client_and_adjusted_outer_rectangles_are_inverses() {
        let frame = CaptionFrame {
            x: 7,
            y: 7,
            caption: 7,
        };
        let input = Win16HostRect {
            left: 10,
            top: 20,
            right: 164,
            bottom: 260,
        };
        let Calc::Rect(mut expanded) = frame.prepare(Calc::Rect(input)).unwrap() else {
            panic!()
        };
        // Native fixed frame 8 and caption 23, applied to the expanded input.
        expanded.left += 8;
        expanded.right -= 8;
        expanded.top += 31;
        expanded.bottom -= 8;
        let Calc::Rect(client) = frame.finish(Calc::Rect(expanded)).unwrap() else {
            panic!()
        };
        assert_eq!(
            (client.left, client.top, client.right, client.bottom),
            (11, 51, 163, 259)
        );
        let native = RECT {
            left: client.left - 8,
            top: client.top - 31,
            right: client.right + 8,
            bottom: client.bottom + 8,
        };
        let outer = frame.adjust_outer(native).unwrap();
        assert_eq!(
            (outer.left, outer.top, outer.right, outer.bottom),
            (input.left, input.top, input.right, input.bottom)
        );
    }

    #[test]
    fn valid_rectangles_and_window_position_are_not_translated() {
        let rect = Win16HostRect {
            left: 1,
            top: 2,
            right: 100,
            bottom: 90,
        };
        let data = Calc::ValidRects {
            rects: [rect; 3],
            position: None,
        };
        let Calc::ValidRects { rects, position } = (CaptionFrame {
            x: 7,
            y: 7,
            caption: 7,
        })
        .prepare(data)
        .unwrap() else {
            panic!()
        };
        assert_eq!((rects[0].right, rects[0].bottom), (114, 97));
        for old in &rects[1..] {
            assert_eq!((old.left, old.top, old.right, old.bottom), (1, 2, 100, 90));
        }
        assert!(position.is_none());
    }

    #[test]
    fn geometry_overflow_never_wraps_native_coordinates() {
        let rect = Win16HostRect {
            left: 0,
            top: 0,
            right: i32::MAX,
            bottom: 10,
        };
        assert!(
            (CaptionFrame {
                x: 7,
                y: 7,
                caption: 7
            })
            .prepare(Calc::Rect(rect))
            .is_none()
        );
        let rect = Win16HostRect {
            left: i32::MIN,
            top: 0,
            right: 10,
            bottom: 10,
        };
        assert!(
            (CaptionFrame {
                x: 7,
                y: 7,
                caption: 7
            })
            .finish(Calc::Rect(rect))
            .is_none()
        );
    }

    #[test]
    fn caption_and_menu_pixels_stay_above_the_client_for_supported_frames() {
        let native = Win16HostRect {
            left: 8,
            top: 51,
            right: 146,
            bottom: 232,
        };
        for border_delta in [0, 4, 5, 7] {
            let frame = CaptionFrame {
                x: border_delta,
                y: border_delta,
                caption: 7,
            };
            let Calc::Rect(client) = frame.finish(Calc::Rect(native)).unwrap() else {
                panic!()
            };
            assert!(
                client.top >= native.top,
                "client must not cover native menu pixels"
            );
        }
    }
}
