//! Window identities carried by focus, activation and cursor messages.
//!
//! Windows 3.1 SDK message crackers (WINDOWSX.H HANDLE/FORWARD_WM_*)
//! define the guest packing for focus, activation, and cursor messages.
//! WM_ACTIVATE puts its other HWND and minimized WORD in LPARAM, whereas the
//! native ABI puts minimized in WPARAM. WM_NCACTIVATE's helper packs HWND and
//! minimized into LPARAM; ownership of that HWND remains an inference. These
//! owned values keep native handles out of guest bits.

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
}

impl Win16WindowInputMessage {
    pub const fn accepts(message: u16) -> bool {
        matches!(message, 0x0006 | 0x0007 | 0x0008 | 0x0020 | 0x0021 | 0x0086)
    }

    pub const fn message_id(self) -> u16 {
        match self {
            Self::Activate { .. } => 0x0006,
            Self::Focus { gained: true, .. } => 0x0007,
            Self::Focus { gained: false, .. } => 0x0008,
            Self::NonClientActivate { .. } => 0x0086,
            Self::SetCursor { .. } => 0x0020,
            Self::MouseActivate { .. } => 0x0021,
        }
    }
}
