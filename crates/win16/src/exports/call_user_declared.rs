//! Decoder for USER exports that were declaration-only.
//!
//! A null parent and null child-after `FindWindowEx` is `FindWindow`.
//! `GetDesktopHwnd` and `GetForegroundWindow` use the desktop and active
//! window. `SetWindowTextEx` stores the guest ANSI bytes. `MessageBoxEx` and
//! `BiDiMessageBoxEx` use the existing message box. Every other ordinal keeps
//! its decoded slots for the runtime failure or session result.

use super::{
    Win16ApiRequest, Win16ClassName, Win16ExportDescriptor, Win16UserDeclaredCall,
    Win16UserRequest, Win16UserTextRequest, Win16UserWindowRequest, dword_argument,
    read_far_string, read_nullable_far_string, word_argument,
};
use crate::{SelectorTable, Win16Argument, Win16Error};
use guest_core::GuestMemory;

const DECLARED_USER_ORDINALS: &[u16] = &[
    172, 216, 217, 226, 231, 251, 252, 253, 254, 255, 256, 257, 273, 275, 278, 279, 285, 301, 302,
    303, 304, 305, 306, 307, 314, 320, 321, 324, 325, 326, 331, 332, 333, 336, 337, 344, 356, 357,
    362, 364, 374, 389, 390, 391, 394, 395, 397, 398, 400, 408, 409, 427, 441, 448, 449, 450, 455,
    456, 459, 460, 461, 462, 463, 475, 476, 477, 486, 487, 488, 489, 490, 491, 492, 493, 494, 495,
    496, 600, 606, 608, 609, 610, 620, 621, 640, 656, 657, 659, 660, 668, 819, 820, 821, 822, 823,
    827, 901, 902, 903, 904, 905, 906, 907, 908, 909, 910, 911, 912, 913, 914, 915, 916, 917, 918,
    919, 920, 922, 923, 924, 925, 926, 927, 928, 929, 930, 1000, 1001,
];

pub(super) fn decode(
    descriptor: &Win16ExportDescriptor,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Option<Win16ApiRequest>, Win16Error> {
    let ordinal = descriptor.ordinal();
    if DECLARED_USER_ORDINALS.binary_search(&ordinal).is_err() {
        return Ok(None);
    }
    let request = match ordinal {
        278 => Win16ApiRequest::User(Win16UserRequest::Window(
            Win16UserWindowRequest::GetDesktopWindow,
        )),
        608 => Win16ApiRequest::User(Win16UserRequest::Window(
            Win16UserWindowRequest::GetActiveWindow,
        )),
        427 => find_window_ex(ordinal, arguments, selectors, memory)?,
        909 => Win16ApiRequest::User(Win16UserRequest::Window(
            Win16UserWindowRequest::SetWindowText {
                window: word_argument(arguments, 0)?,
                text: read_nullable_far_string(dword_argument(arguments, 1)?, selectors, memory)?,
            },
        )),
        910 | 930 => {
            Win16ApiRequest::User(Win16UserRequest::Text(Win16UserTextRequest::MessageBox {
                owner: word_argument(arguments, 0)?,
                text: read_nullable_far_string(dword_argument(arguments, 1)?, selectors, memory)?,
                caption: read_nullable_far_string(
                    dword_argument(arguments, 2)?,
                    selectors,
                    memory,
                )?,
                style: word_argument(arguments, 3)?,
            }))
        }
        _ => declared(ordinal, arguments)?,
    };
    Ok(Some(request))
}

fn find_window_ex(
    ordinal: u16,
    arguments: &[Win16Argument],
    selectors: &SelectorTable,
    memory: &impl GuestMemory,
) -> Result<Win16ApiRequest, Win16Error> {
    let parent = word_argument(arguments, 0)?;
    let child_after = word_argument(arguments, 1)?;
    if parent != 0 || child_after != 0 {
        return declared(ordinal, arguments);
    }
    let class_far = dword_argument(arguments, 2)?;
    let class_name = if class_far == 0 {
        None
    } else if class_far >> 16 == 0 {
        Some(Win16ClassName::Atom(class_far as u16))
    } else {
        Some(Win16ClassName::Name(read_far_string(
            class_far, selectors, memory,
        )?))
    };
    Ok(Win16ApiRequest::User(Win16UserRequest::Window(
        Win16UserWindowRequest::FindWindow {
            class_name,
            window_name: read_nullable_far_string(
                dword_argument(arguments, 3)?,
                selectors,
                memory,
            )?,
        },
    )))
}

fn declared(ordinal: u16, arguments: &[Win16Argument]) -> Result<Win16ApiRequest, Win16Error> {
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(arguments.len())
        .map_err(|_| Win16Error::OutOfMemory)?;
    for argument in arguments {
        slots.push(match argument {
            Win16Argument::Byte(value) => u32::from(*value),
            Win16Argument::Word(value) => u32::from(*value),
            Win16Argument::Dword(value) => *value,
        });
    }
    Ok(Win16ApiRequest::User(Win16UserRequest::Declared(
        Win16UserDeclaredCall { ordinal, slots },
    )))
}
