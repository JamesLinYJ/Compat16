//! Checked bidirectional conversion for HWND fields in standard USER messages.
//!
//! Guest message packing follows the Windows 3.1 SDK `WINDOWSX.H` crackers
//! and forwarders: WM_ACTIVATE (372–376), WM_SETFOCUS (390–394),
//! WM_KILLFOCUS (396–400), WM_MOUSEACTIVATE (558–562), and WM_SETCURSOR
//! (710–713). WM_NCACTIVATE (384–388) provides packed HWND/BOOL fields, but
//! Windows 3.1 Vol. 3 p. 159 does not define the packed HWND's ownership.
//! Guest HWND16 values are resolved only through the runtime map; unknown
//! nonzero handles are rejected instead of being forwarded as native bits.

use crate::{RuntimeError, Win16WindowInputMessage};

use super::Win16State;

const WM_ACTIVATE: u16 = 0x0006;
const WM_SETFOCUS: u16 = 0x0007;
const WM_KILLFOCUS: u16 = 0x0008;
const WM_SETCURSOR: u16 = 0x0020;
const WM_MOUSEACTIVATE: u16 = 0x0021;
const WM_NCACTIVATE: u16 = 0x0086;

impl Win16State {
    /// Convert Win16 wParam/lParam fields into owned host window identities.
    /// `None` means that the message is outside this family or that a nonzero
    /// embedded guest HWND has no current mapping. A zero HWND is represented
    /// as `Some(None)` because it is a valid null value in these messages.
    pub(in crate::win16_runtime) fn window_input_from_guest(
        &self,
        message: u16,
        w_param: u16,
        l_param: u32,
    ) -> Option<Win16WindowInputMessage> {
        let host_window = |guest: u16| {
            if guest == 0 {
                Some(None)
            } else {
                self.window_handles.get(&guest).copied().map(Some)
            }
        };

        Some(match message {
            WM_ACTIVATE => Win16WindowInputMessage::Activate {
                state: w_param,
                minimized: (l_param >> 16) as u16,
                other: host_window(l_param as u16)?,
            },
            // WINDOWSX.H establishes the two-WORD packing. Vol. 3 p. 159
            // describes activation but does not define ownership of this
            // packed HWND; receiver selection is handled as a host-side
            // compatibility inference, not as a proven Win16 contract.
            WM_NCACTIVATE => Win16WindowInputMessage::NonClientActivate {
                active: w_param,
                minimized: (l_param >> 16) as u16,
                other: host_window(l_param as u16)?,
            },
            WM_SETFOCUS => Win16WindowInputMessage::Focus {
                gained: true,
                other: host_window(w_param)?,
            },
            WM_KILLFOCUS => Win16WindowInputMessage::Focus {
                gained: false,
                other: host_window(w_param)?,
            },
            WM_SETCURSOR => Win16WindowInputMessage::SetCursor {
                target: host_window(w_param)?,
                hit_test: l_param as u16,
                mouse_message: (l_param >> 16) as u16,
            },
            WM_MOUSEACTIVATE => Win16WindowInputMessage::MouseActivate {
                parent: host_window(w_param)?,
                hit_test: l_param as u16,
                mouse_message: (l_param >> 16) as u16,
            },
            _ => return None,
        })
    }

    /// Restore the Win16 wParam/lParam layout, allocating a guest HWND token
    /// for any host identity that does not yet have one.
    pub(in crate::win16_runtime) fn window_input_to_guest(
        &mut self,
        input: Win16WindowInputMessage,
    ) -> Result<(u16, u16, u32), RuntimeError> {
        let (w_param, l_param) = match input {
            Win16WindowInputMessage::Activate { state, minimized, other } => {
                let other = self.guest_window(other)?;
                (state, u32::from(other) | (u32::from(minimized) << 16))
            }
            Win16WindowInputMessage::NonClientActivate { active, minimized, other } => {
                let other = self.guest_window(other)?;
                (active, u32::from(other) | (u32::from(minimized) << 16))
            }
            Win16WindowInputMessage::Focus { other, .. } => {
                (self.guest_window(other)?, 0)
            }
            Win16WindowInputMessage::SetCursor { target, hit_test, mouse_message } => {
                let target = self.guest_window(target)?;
                (target, u32::from(hit_test) | (u32::from(mouse_message) << 16))
            }
            Win16WindowInputMessage::MouseActivate { parent, hit_test, mouse_message } => {
                let parent = self.guest_window(parent)?;
                (parent, u32::from(hit_test) | (u32::from(mouse_message) << 16))
            }
        };
        Ok((input.message_id(), w_param, l_param))
    }

    fn guest_window(
        &mut self,
        native: Option<crate::Win16HostWindow>,
    ) -> Result<u16, RuntimeError> {
        match native {
            Some(native) => self.map_window_handle(native, false),
            None => Ok(0),
        }
    }
}
