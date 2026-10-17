//! Register image for USER.289 `keybd_event` and USER.299 `mouse_event`.
//!
//! Windows 3.1 `WINDOWS.H` does not publish prototypes for these ordinals.
//! Both catalog rows are register exports with no stack arguments. The image
//! below is the keyboard and mouse driver contract: AX/BX/CX/DX carry the
//! event, and SI:DI carry the opaque extra-info dword.

use super::*;
use crate::Win16RegisterContext;

const KEYEVENTF_EXTENDEDKEY: u32 = 0x0001;
const KEYEVENTF_KEYUP: u32 = 0x0002;
const MOUSEEVENTF_ABSOLUTE: u16 = 0x8000;

pub(super) fn decode(
    export: Win16ExportId,
    context: &Win16RegisterContext,
) -> Win16UserInputRequest {
    let extra_info = u32::from(context.edi as u16) << 16 | u32::from(context.esi as u16);
    match export {
        Win16ExportId::UserKeybdEvent => {
            let mut flags = 0;
            if context.eax & 0x8000 != 0 {
                flags |= KEYEVENTF_KEYUP;
            }
            if context.ebx & 0x0100 != 0 {
                flags |= KEYEVENTF_EXTENDEDKEY;
            }
            Win16UserInputRequest::KeybdEvent {
                virtual_key: context.eax as u8,
                scan: context.ebx as u8,
                flags,
                extra_info,
            }
        }
        Win16ExportId::UserMouseEvent => {
            let flags = context.eax as u16;
            let absolute = flags & MOUSEEVENTF_ABSOLUTE != 0;
            Win16UserInputRequest::MouseEvent {
                flags,
                dx: mouse_delta(context.ebx as u16, absolute),
                dy: mouse_delta(context.ecx as u16, absolute),
                buttons: context.edx as u16,
                extra_info,
            }
        }
        _ => unreachable!("input-event decoder is only used for USER 289 and 299"),
    }
}

fn mouse_delta(raw: u16, absolute: bool) -> i32 {
    if absolute {
        i32::from(raw)
    } else {
        i32::from(raw as i16)
    }
}
