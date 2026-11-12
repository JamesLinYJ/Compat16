//! Window identities carried by focus, activation, cursor, and dialog-control
//! messages.
//!
//! Windows 3.1 SDK message crackers (WINDOWSX.H HANDLE/FORWARD_WM_*)
//! define the guest packing for focus, activation, and cursor messages.
//! WM_ACTIVATE puts its other HWND and minimized WORD in LPARAM, whereas the
//! native ABI puts minimized in WPARAM. WM_NCACTIVATE's helper packs HWND and
//! minimized into LPARAM; ownership of that HWND remains an inference.
//! WM_NEXTDLGCTL uses the low word of LPARAM as its mode flag and may carry
//! a control HWND16 in WPARAM. These owned values keep native handles out of
//! guest bits.

use crate::Win16HostWindow;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16WindowInputMessage {
    Focus { gained: bool, other: Option<Win16HostWindow> },
    Activate { state: u16, minimized: u16, other: Option<Win16HostWindow> },
    /// Win16 SDK `WINDOWSX.H` packs `other` in LOWORD(LPARAM) and `minimized`
    /// in HIWORD(LPARAM); which window that packed handle denotes is not
    /// established by Windows 3.1 Vol. 3 p. 159.
    NonClientActivate { active: u16, minimized: u16, other: Option<Win16HostWindow> },
    SetCursor { target: Option<Win16HostWindow>, hit_test: u16, mouse_message: u16 },
    MouseActivate { parent: Option<Win16HostWindow>, hit_test: u16, mouse_message: u16 },
    /// WM_NEXTDLGCTL (0x0028). Learn documents that LOWORD(lParam) nonzero
    /// means `control` is the window to focus, and LOWORD(lParam) zero means
    /// `direction` selects the next WS_TABSTOP when zero and the previous
    /// one when nonzero. The high word is not that flag.
    NextDialogControl {
        direction: u16,
        control: Option<Win16HostWindow>,
        control_form: bool,
    },
}

impl Win16WindowInputMessage {
    pub const fn accepts(message: u16) -> bool {
        matches!(message, 0x0006 | 0x0007 | 0x0008 | 0x0020 | 0x0021 | 0x0028 | 0x0086)
    }

    /// Guest WPARAM and LPARAM for WM_NEXTDLGCTL.
    ///
    /// Control form publishes the HWND16 and low word 1. Direction form
    /// publishes the original direction word and low word 0, so a guest high
    /// word such as 0x00010000 cannot be read as the control-form flag.
    pub const fn next_dialog_guest_params(
        direction: u16, control: u16, control_form: bool,
    ) -> (u16, u32) {
        if control_form { (control, 1) } else { (direction, 0) }
    }

    pub const fn message_id(self) -> u16 {
        match self {
            Self::Activate { .. } => 0x0006,
            Self::Focus { gained: true, .. } => 0x0007,
            Self::Focus { gained: false, .. } => 0x0008,
            Self::NonClientActivate { .. } => 0x0086,
            Self::SetCursor { .. } => 0x0020,
            Self::MouseActivate { .. } => 0x0021,
            Self::NextDialogControl { .. } => 0x0028,
        }
    }
}
