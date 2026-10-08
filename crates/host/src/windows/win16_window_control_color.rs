//! Synchronous Win16 WM_CTLCOLOR marshalling on the HWND-owning thread.

use std::cell::RefCell;
use std::rc::Rc;

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostControlColor,
    Win16HostMessageOutput, Win16HostMessageResult};
use windows_sys::Win32::Foundation::HWND;

use super::win16_window_default::{MessageInvocation, invoke_native_message};
use super::win16_window_worker::WorkerState;
use super::ControlColorReturnSlot;

pub(super) fn invoke(
    state: &Rc<RefCell<WorkerState>>,
    hwnd: HWND,
    invocation: MessageInvocation,
    input: Win16HostControlColor,
    control_color_return: Option<&ControlColorReturnSlot>,
) -> Result<Option<Win16HostMessageResult>, RuntimeError> {
    if input.kind > 6 {
        return Err(RuntimeError::new(Kind::InvalidInput,
            "Win16 control-color type is outside the seven SDK classes"));
    }
    let return_slot = control_color_return.ok_or_else(|| RuntimeError::new(
        Kind::InternalInvariant,
        "typed Win16 control-color native call has no host-only result slot",
    ))?;
    let child = match input.control {
        Some(child) => match super::win16_window_identity::resolve_user_window(state, child) {
            Some(child) => child,
            None => return Ok(None),
        },
        None => HWND::default(),
    };
    let dc_use = match input.dc {
        Some(dc) => Some(state.borrow().dcs.lease_dc(dc)?.ok_or_else(|| {
            RuntimeError::new(Kind::InvalidInput,
                "Win16 control-color HDC lease is no longer live")
        })?),
        None => None,
    };
    let native_dc = dc_use.as_ref().map_or(0, |dc| dc.native() as usize);
    let native_result = invoke_native_message(
        invocation,
        hwnd,
        0x0132 + u32::from(input.kind),
        native_dc,
        child as isize,
    );
    // The Send/default/CallWindowProc result is pointer-width host data. The
    // coordinator alone converts it to a checked brush identity.
    return_slot.store(native_result)?;
    Ok(Some(Win16HostMessageResult {
        value: 0,
        output: Win16HostMessageOutput::None,
        dialog_result: None,
    }))
}
