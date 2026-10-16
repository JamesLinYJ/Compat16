//! Shared native request preparation for SendMessage and the second stage of
//! SendDlgItemMessage. It may translate or validate guest-owned payloads and
//! report compatibility gaps, but it does not begin or send a native request.

use guest_core::memory::Memory;
use win16_abi::Win16ReturnKind;

use super::{Win16MessageCallContinuation, Win16State, WindowReturn};
use crate::{
    RuntimeError, RuntimeHost, Win16HostStaticIconOperation, Win16MessageCall,
    Win16WindowOperation,
};

/// An immediate Win16 return or a fully translated native operation. Keeping
/// the operation and continuation together lets a compound caller defer its
/// one native begin until its existing source has reached the required phase.
pub(in crate::win16_runtime) enum SendMessagePreparation {
    Immediate {
        value: u32,
        return_kind: Win16ReturnKind,
    },
    Prepared {
        operation: Win16WindowOperation,
        continuation: WindowReturn,
    },
}

pub(in crate::win16_runtime) fn prepare_send_message(
    state: &mut Win16State,
    guest_window: u16,
    message: u16,
    w_param: u16,
    l_param: u32,
    memory: &mut Memory,
    host: &mut impl RuntimeHost,
) -> Result<SendMessagePreparation, RuntimeError> {
    if guest_window == super::HWND_BROADCAST {
        return Ok(match super::broadcast::prepare_broadcast_call(
            message, w_param, l_param, host, true,
        ) {
            Some(call) => SendMessagePreparation::Prepared {
                operation: Win16WindowOperation::MessageCall(call),
                continuation: WindowReturn::MessageCall(Win16MessageCallContinuation::Dword {
                    return_kind: Win16ReturnKind::Dword,
                }),
            },
            None => immediate_zero(),
        });
    }
    if super::super::messages_mdi::is_mdi_message(message) {
        let Some(endpoint) = state.mdi_endpoint_for_guest_window(guest_window) else {
            host.report_diagnostic(&crate::Diagnostic::warning(
                crate::DiagnosticKind::CompatibilityGap,
                format!("Win16 SendMessage MDI message 0x{message:04X} has no verified MDI endpoint"),
            ));
            return Ok(immediate_zero());
        };
        let Some(&window) = state.window_handles.get(&guest_window) else {
            return Ok(immediate_zero());
        };
        let mdi_client = matches!(endpoint, crate::Win16MdiEndpoint::Client)
            .then_some((guest_window, window));
        let Some((payload, output)) = state.translate_mdi_message(
            endpoint, mdi_client, message, w_param, l_param, memory, host,
        )? else {
            return Ok(immediate_zero());
        };
        return Ok(SendMessagePreparation::Prepared {
            operation: Win16WindowOperation::Send { window, message: payload },
            continuation: WindowReturn::Message { output },
        });
    }

    // Preserve the original Win16 control ABI for a guest subclass. Its call
    // to the saved procedure performs the eventual native control conversion.
    if message >= super::WM_USER && state.native_subclass_procedure(guest_window).is_some() {
        let Some(&window) = state.window_handles.get(&guest_window) else { return Ok(immediate_zero()); };
        return Ok(SendMessagePreparation::Prepared {
            operation: Win16WindowOperation::Send {
                window, message: crate::Win16HostMessage::GuestOpaque { message, w_param, l_param },
            },
            continuation: WindowReturn::Message { output: super::super::messages::MessageOutput::None },
        });
    }
    if message >= super::WM_USER
        && !state.window_procedures.contains_key(&guest_window)
        && !state.dialog_procedures.contains_key(&guest_window)
    {
        let identity = state.control_identity(guest_window, None, host)?;
        if let Some(identity) = identity {
            if identity.family != crate::Win16HostControlFamily::Static {
                let payload = state.prepare_control_message(guest_window, message,
                    w_param, l_param, None, identity, memory, host)?;
                let Some((payload, output)) = payload else { return Ok(immediate_zero()); };
                let Some(&window) = state.window_handles.get(&guest_window) else { return Ok(immediate_zero()); };
                return Ok(SendMessagePreparation::Prepared {
                    operation: Win16WindowOperation::Send { window, message: payload },
                    continuation: WindowReturn::Message { output },
                });
            }
        } else {
            host.report_diagnostic(&crate::Diagnostic::warning(crate::DiagnosticKind::CompatibilityGap,
                format!("Win16 SendMessage 0x{message:04X} has no control-family conversion; returned zero")));
            return Ok(immediate_zero());
        }
    }
    if super::super::messages::is_static_icon_message(message)
        && !state.window_procedures.contains_key(&guest_window)
        && !state.dialog_procedures.contains_key(&guest_window)
    {
        let Some(&window) = state.window_handles.get(&guest_window) else {
            return Ok(immediate_zero());
        };
        let operation = if message == super::WM_USER + 1 {
            Win16HostStaticIconOperation::Get
        } else if w_param == 0 {
            Win16HostStaticIconOperation::Set { icon: None }
        } else if let Some(icon) = state.guest_images.icon(w_param) {
            Win16HostStaticIconOperation::Set { icon: Some(icon) }
        } else {
            // HICON16 is a guest token; an unknown value is not a native HICON.
            return Ok(immediate_zero());
        };
        return Ok(SendMessagePreparation::Prepared {
            operation: Win16WindowOperation::StaticIcon {
                window,
                procedure: None,
                operation,
            },
            continuation: WindowReturn::Icon {
                window: guest_window,
                message,
            },
        });
    }

    if super::super::messages::is_window_text_message(message)
        || message == super::super::messages::WM_PAINT
        || crate::Win16OwnerDrawMessage::accepts(message)
        || message == super::super::messages::WM_SETFONT
        || matches!(
            message,
            super::WM_NCCALCSIZE
                | super::WM_CTLCOLOR
                | super::super::messages::WM_NCPAINT
                | super::super::window_payloads::window_position_payloads::WM_WINDOWPOSCHANGING
                | super::super::window_payloads::window_position_payloads::WM_WINDOWPOSCHANGED
        )
    {
        let Some(&window) = state
            .window_handles
            .get(&guest_window)
            .filter(|_| guest_window != 0)
        else {
            return Ok(immediate_zero());
        };
        let Some((payload, output)) = state.translate_window_message(
            guest_window,
            message,
            w_param,
            l_param,
            memory,
            host,
            false,
        )? else {
            return Ok(immediate_zero());
        };
        return Ok(SendMessagePreparation::Prepared {
            operation: Win16WindowOperation::Send {
                window,
                message: payload,
            },
            continuation: WindowReturn::Message { output },
        });
    }

    let Some((target, parameter, guest_class)) =
        state.prepare_message_call(guest_window, message, w_param, l_param, host, true)?
    else {
        return Ok(immediate_zero());
    };
    Ok(SendMessagePreparation::Prepared {
        operation: Win16WindowOperation::MessageCall(Win16MessageCall::SendMessage {
            window: target,
            message,
            w_param,
            l_param: parameter,
            guest_class,
        }),
        continuation: WindowReturn::MessageCall(Win16MessageCallContinuation::Dword {
            return_kind: Win16ReturnKind::Dword,
        }),
    })
}

fn immediate_zero() -> SendMessagePreparation {
    SendMessagePreparation::Immediate {
        value: 0,
        return_kind: Win16ReturnKind::Dword,
    }
}
