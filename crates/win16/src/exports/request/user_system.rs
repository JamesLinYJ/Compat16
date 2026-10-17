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
}
