//! Win16 SendDlgItemMessage lookup and continuation.
//!
//! The USER worker resolves the dialog item to an opaque native HWND first.
//! Runtime then assigns/reuses its guest alias and enters the same SendMessage
//! marshalling path used for a directly supplied Win16 HWND.

use guest_core::{Registers, memory::Memory};
use win16_abi::Win16ReturnKind;

use super::{
    SendMessagePreparation, Win16State, WindowReturn, prepare_send_message,
};
use crate::{
    RuntimeError, RuntimeHost,
    Win16HostDialogControlOperation as ControlOperation, Win16HostUserServiceOperation,
    Win16WindowOperation,
};

pub(super) fn begin(
    state: &mut Win16State,
    registers: &mut Registers,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
    dialog: u16,
    id: u16,
    message: u16,
    w_param: u16,
    l_param: u32,
    return_to: (u16, u16, u32),
) -> Result<Option<u8>, RuntimeError> {
    let Some(&native_dialog) = state.window_handles.get(&dialog).filter(|_| dialog != 0) else {
        return state.complete_return(
            registers,
            return_to.0,
            return_to.1,
            return_to.2,
            0,
            Win16ReturnKind::Dword,
        );
    };

    state.begin_window_operation(
        registers,
        memory,
        host,
        Win16WindowOperation::UserService(Win16HostUserServiceOperation::DialogControl(
            ControlOperation::GetItem {
                dialog: native_dialog,
                id,
            },
        )),
        WindowReturn::DialogItemMessage {
            dialog,
            native_dialog,
            message,
            w_param,
            l_param,
        },
        return_to,
    )
}

/// Finish the preparation half of SendDlgItemMessage after USER resolves the
/// control. The caller owns the lookup frame and starts any returned native
/// operation only after the exact GetItem source proof has been observed.
pub(in crate::win16_runtime) fn prepare_dialog_item_send_message(
    state: &mut Win16State,
    dialog: u16,
    native_dialog: crate::Win16HostWindow,
    child: Option<crate::Win16HostWindow>,
    message: u16,
    w_param: u16,
    l_param: u32,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<SendMessagePreparation, RuntimeError> {
    if dialog == 0 || state.window_handles.get(&dialog) != Some(&native_dialog) {
        return Ok(SendMessagePreparation::Immediate {
            value: 0,
            return_kind: Win16ReturnKind::Dword,
        });
    }
    let Some(native_child) = child else {
        return Ok(SendMessagePreparation::Immediate {
            value: 0,
            return_kind: Win16ReturnKind::Dword,
        });
    };

    let guest_child = state.map_window_handle(native_child, false)?;
    state.set_window_parent_from_host(guest_child, dialog)?;
    prepare_send_message(state, guest_child, message, w_param, l_param, memory, host)
}
