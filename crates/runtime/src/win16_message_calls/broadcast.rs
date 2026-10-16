//! Checked HWND_BROADCAST preparation shared by SendMessage and PostMessage.

use crate::{
    Diagnostic, DiagnosticKind, RuntimeHost, Win16MessageCall, Win16ScalarMessage,
};

pub(super) fn prepare_broadcast_call(
    message: u16,
    w_param: u16,
    l_param: u32,
    host: &mut impl RuntimeHost,
    send: bool,
) -> Option<Win16MessageCall> {
    let Some(kind) = Win16ScalarMessage::from_raw(message)
        .filter(|kind| kind.broadcast_parameters_are_scalar(w_param, l_param))
    else {
        let operation = if send { "SendMessage" } else { "PostMessage" };
        host.report_diagnostic(&Diagnostic::warning(
            DiagnosticKind::CompatibilityGap,
            format!(
                "Win16 {operation}(HWND_BROADCAST, 0x{message:04X}) has no pointer-free parameter translation",
            ),
        ));
        return None;
    };
    Some(if send {
        Win16MessageCall::SendBroadcast { kind, w_param, l_param }
    } else {
        Win16MessageCall::PostBroadcast { kind, w_param, l_param }
    })
}
