use super::controls::{WINDOW_STYLE, scale};
use super::*;
use windows_sys::Win32::UI::Controls::SetScrollInfo;

impl State {
    pub fn draw_run(&self, item: &windows_sys::Win32::UI::Controls::DRAWITEMSTRUCT) {
        use windows_sys::Win32::UI::Controls::{ODS_DISABLED, ODS_FOCUS, ODS_SELECTED};
        unsafe {
            let saved = SaveDC(item.hDC);
            let brush = CreateSolidBrush(if item.itemState & ODS_DISABLED != 0 {
                0x00a0_a0a0
            } else if item.itemState & ODS_SELECTED != 0 {
                0x009e_5700
            } else {
                0x00d7_7800
            });
            SelectObject(item.hDC, brush);
            SelectObject(item.hDC, GetStockObject(NULL_PEN));
            let rect = item.rcItem;
            RoundRect(
                item.hDC,
                rect.left,
                rect.top,
                rect.right,
                rect.bottom,
                scale(8, self.dpi),
                scale(8, self.dpi),
            );
            SelectObject(item.hDC, self.fonts.regular);
            SetBkMode(item.hDC, TRANSPARENT as i32);
            SetTextColor(item.hDC, 0x00ff_ffff);
            let mut label_rect = rect;
            DrawTextW(
                item.hDC,
                wide("运行").as_ptr(),
                -1,
                &mut label_rect,
                DT_CENTER | DT_VCENTER | DT_SINGLELINE,
            );
            if item.itemState & ODS_FOCUS != 0 {
                let inset = scale(4, self.dpi);
                let focus = RECT {
                    left: rect.left + inset,
                    top: rect.top + inset,
                    right: rect.right - inset,
                    bottom: rect.bottom - inset,
                };
                DrawFocusRect(item.hDC, &focus);
            }
            RestoreDC(item.hDC, saved);
            if !brush.is_null() {
                DeleteObject(brush);
            }
        }
    }

    pub fn layout(&mut self, resize: bool) {
        let content_height = scale(if self.advanced { 826 } else { 648 }, self.dpi);
        if resize {
            let mut rect = RECT {
                left: 0,
                top: 0,
                right: scale(640, self.dpi),
                bottom: content_height,
            };
            let mut monitor = MONITORINFO {
                cbSize: std::mem::size_of::<MONITORINFO>() as u32,
                ..Default::default()
            };
            unsafe {
                AdjustWindowRectExForDpi(
                    &mut rect,
                    WINDOW_STYLE,
                    0,
                    WS_EX_ACCEPTFILES | WS_EX_CONTROLPARENT,
                    self.dpi,
                );
                let mut current = RECT::default();
                GetWindowRect(self.window, &mut current);
                let found = GetMonitorInfoW(
                    MonitorFromWindow(self.window, MONITOR_DEFAULTTONEAREST),
                    &mut monitor,
                ) != 0;
                let height = if found {
                    (rect.bottom - rect.top).min(monitor.rcWork.bottom - monitor.rcWork.top)
                } else {
                    rect.bottom - rect.top
                };
                let width = rect.right
                    - rect.left
                    - if height == rect.bottom - rect.top {
                        GetSystemMetricsForDpi(SM_CXVSCROLL, self.dpi)
                    } else {
                        0
                    };
                let top = if found {
                    current
                        .top
                        .min(monitor.rcWork.bottom - height)
                        .max(monitor.rcWork.top)
                } else {
                    current.top
                };
                SetWindowPos(
                    self.window,
                    null_mut(),
                    current.left,
                    top,
                    width,
                    height,
                    SWP_NOZORDER | SWP_NOACTIVATE,
                );
            }
        }
        let mut client = RECT::default();
        unsafe {
            GetClientRect(self.window, &mut client);
        }
        self.scroll = self
            .scroll
            .clamp(0, (content_height - client.bottom).max(0));
        let info = SCROLLINFO {
            cbSize: std::mem::size_of::<SCROLLINFO>() as u32,
            fMask: SIF_RANGE | SIF_PAGE | SIF_POS,
            nMin: 0,
            nMax: content_height - 1,
            nPage: client.bottom.max(1) as u32,
            nPos: self.scroll,
            ..Default::default()
        };
        unsafe {
            SetScrollInfo(self.window, SB_VERT, &info, 1);
            SendMessageW(
                self.controls.icon,
                STM_SETICON,
                LoadImageW(
                    GetModuleHandleW(null()),
                    101_usize as *const u16,
                    IMAGE_ICON,
                    scale(40, self.dpi),
                    scale(40, self.dpi),
                    LR_SHARED,
                ) as usize,
                0,
            );
        }
        for item in &self.controls.items {
            let [x, y, width, height] = item.rect;
            let y = y + if item.footer && self.advanced { 178 } else { 0 };
            unsafe {
                ShowWindow(
                    item.window,
                    if !item.advanced || self.advanced {
                        SW_SHOW
                    } else {
                        SW_HIDE
                    },
                );
                MoveWindow(
                    item.window,
                    scale(x, self.dpi),
                    scale(y, self.dpi) - self.scroll,
                    scale(width, self.dpi),
                    scale(height, self.dpi),
                    1,
                );
            }
        }
        unsafe {
            InvalidateRect(self.window, null(), 1);
        }
    }

    pub fn scroll(&mut self, command: i32, wheel: i32) {
        let step = scale(36, self.dpi);
        self.scroll += match command {
            SB_LINEUP => -step,
            SB_LINEDOWN => step,
            SB_PAGEUP => -scale(260, self.dpi),
            SB_PAGEDOWN => scale(260, self.dpi),
            SB_TOP => -self.scroll,
            SB_BOTTOM => i32::MAX / 2,
            SB_THUMBTRACK | SB_THUMBPOSITION => {
                let mut info = SCROLLINFO {
                    cbSize: std::mem::size_of::<SCROLLINFO>() as u32,
                    fMask: SIF_TRACKPOS,
                    ..Default::default()
                };
                unsafe {
                    GetScrollInfo(self.window, SB_VERT, &mut info);
                }
                info.nTrackPos - self.scroll
            }
            _ => -wheel * step / 120,
        };
        self.layout(false);
    }
}
