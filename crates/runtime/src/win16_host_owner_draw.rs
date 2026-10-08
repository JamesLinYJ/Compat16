//! Owned USER owner-draw inputs; native pointers remain in the live callback.

use crate::{Win16HostDc, Win16HostMenu, Win16HostRect, Win16HostWindow};

// Windows 3.1 SDK WINDOWS.H: WM_* and ODT_* identifiers. The four guest
// structure layouts are implemented by win16_abi::owner_draw's codecs.
pub const WM_DRAWITEM: u16 = 0x002b;
pub const WM_MEASUREITEM: u16 = 0x002c;
pub const WM_DELETEITEM: u16 = 0x002d;
pub const WM_COMPAREITEM: u16 = 0x0039;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Win16OwnerDrawTarget {
    Window(Option<Win16HostWindow>),
    Menu(Option<Win16HostMenu>),
}

#[derive(Clone, Debug)]
pub enum Win16OwnerDrawMessage {
    Draw {
        control_id: u16, ctl_type: u16, ctl_id: u16, item_id: u16,
        item_action: u16, item_state: u16,
        target: Win16OwnerDrawTarget, dc: Option<Win16HostDc>,
        rect: Win16HostRect, item_data: u32,
    },
    Measure {
        control_id: u16, ctl_type: u16, ctl_id: u16, item_id: u16,
        width: u16, height: u16, item_data: u32,
    },
    Delete {
        control_id: u16, ctl_type: u16, ctl_id: u16, item_id: u16,
        window: Option<Win16HostWindow>, item_data: u32,
    },
    Compare {
        control_id: u16, ctl_type: u16, ctl_id: u16,
        window: Option<Win16HostWindow>,
        item_id1: u16, item_data1: u32, item_id2: u16, item_data2: u32,
    },
}

impl Win16OwnerDrawMessage {
    pub const fn accepts(message: u16) -> bool {
        matches!(message, WM_DRAWITEM | WM_MEASUREITEM | WM_DELETEITEM | WM_COMPAREITEM)
    }

    pub const fn message_id(&self) -> u16 {
        match self {
            Self::Draw { .. } => WM_DRAWITEM,
            Self::Measure { .. } => WM_MEASUREITEM,
            Self::Delete { .. } => WM_DELETEITEM,
            Self::Compare { .. } => WM_COMPAREITEM,
        }
    }

    pub const fn control_id(&self) -> u16 {
        match self {
            Self::Draw { control_id, .. } | Self::Measure { control_id, .. }
                | Self::Delete { control_id, .. } | Self::Compare { control_id, .. } => *control_id,
        }
    }

    pub const fn callback_dc(&self) -> Option<Win16HostDc> {
        match self { Self::Draw { dc, .. } => *dc, _ => None }
    }
}
