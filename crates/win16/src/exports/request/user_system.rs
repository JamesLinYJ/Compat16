//! Typed USER timing, system-color, and dialog-base query arguments.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Win16UserSystemRequest {
    /// AX retains the spec's `-ret16` slot; Win3.1 declares this setter void.
    SetDoubleClickTime {
        milliseconds: u16,
    },
    GetDoubleClickTime,
    /// AX retains the spec's `-ret16` slot; Win3.1 declares this setter void.
    SetCaretBlinkTime {
        milliseconds: u16,
    },
    GetCaretBlinkTime,
    GetSysColor {
        index: u16,
    },
    SetSysColors {
        indices: Vec<i32>,
        colors: Vec<u32>,
    },
    SwapMouseButton {
        swap: bool,
    },
    GetDialogBaseUnits,
    /// Desktop-wide query for an owned, visible top-level window.
    AnyPopup,

    /// USER.188 stores one guest HWND. Zero clears the system-modal window.
    SetSysModalWindow {
        window: u16,
    },

    /// USER.189 reads the current system-modal guest HWND.
    GetSysModalWindow,

    /// USER.281. The signed index selects a Windows 3.1 COLOR_* brush.
    GetSysColorBrush {
        index: i16,
    },

    /// USER.284. The selector is GFSR_SYSTEMRESOURCES, GDI, or USER.
    GetFreeSystemResources {
        selector: u16,
    },
    /// USER.86. The Windows 3.1 header does not declare this export. The
    /// result is a DWORD: icon width in the low word and height in the high
    /// word, using the same SM_CXICON and SM_CYICON indexes as GetSystemMetrics.
    IconSize,
    /// USER.464. HWND, HWND, UINT, DWORD, and HCURSOR are guest words and a
    /// guest payload. None of them is a host pointer.
    DragObject {
        parent: u16,
        source: u16,
        format: u16,
        data: u32,
        cursor: u16,
    },
    /// USER.465. `point` is a screen POINT passed by value, x in the low word.
    /// `window` stays a guest HWND word.
    DragDetect {
        window: u16,
        x: i16,
        y: i16,
    },
}
