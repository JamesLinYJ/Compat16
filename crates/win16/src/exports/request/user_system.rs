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
    GetDialogBaseUnits,
    /// Desktop-wide query for an owned, visible top-level window.
    AnyPopup,
}
