//! Runtime-side results for the known Win16 CTL3D/CTL3DV2 exports.

use win16_abi::{Win16Ctl3dArgument, Win16Ctl3dModule, Win16Ctl3dRequest};

use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost};

// Windows 3.1 SDK `WINDOWS.H`: a visible dialog frame has all three bits.
const WS_VISIBLE: u32 = 0x1000_0000;
const WS_DLGFRAME: u32 = 0x0040_0000;
const DS_MODALFRAME: u32 = 0x0000_0080;
const DIALOG_FRAME_STYLE: u32 = WS_VISIBLE | WS_DLGFRAME | DS_MODALFRAME;
// Windows 3.1 Programmer's Reference, Vol. 3: WM_NCPAINT is 0x0085 and a
// processed non-client paint returns zero. WM_NCACTIVATE is 0x0086 and a
// processed non-client activation returns TRUE.
const WM_NCACTIVATE: u16 = 0x0086;

impl super::Win16State {
    /// Report the compatibility behavior of the original CTL3D exports.
    ///
    /// The Microsoft WFW 3.1 sample header declares the WORD/BOOL/HBRUSH and
    /// LONG result contracts, but its subclass, owner-draw, and brush behavior
    /// has no connected Win16 callback or GDI implementation here. Returning
    /// a normal zero result keeps unsupported optional CTL3D effects from
    /// becoming execution failures; warnings make the missing effect visible.
    pub(super) fn ctl3d_request(
        &mut self,
        request: Win16Ctl3dRequest,
        host: &mut impl RuntimeHost,
    ) -> Result<u32, RuntimeError> {
        let module = match request.module {
            Win16Ctl3dModule::Ctl3d => "CTL3D",
            Win16Ctl3dModule::Ctl3dV2 => "CTL3DV2",
        };
        let name = request.name.unwrap_or("unknown export");

        match request.ordinal {
            // No CTL3D implementation is active, so the documented capability
            // query is truthfully false rather than a synthetic success.
            5 => Ok(0),
            // Auto-subclassing is never installed by this runtime.
            23 => Ok(0),
            // The SDK header confirms WORD, but neither it nor the local SDK
            // provides a verified GetVer return constant for this DLL build.
            1 => {
                report_ctl3d_gap(host, module, name,
                    "the CTL3D version value is unverified; returning zero");
                Ok(0)
            }
            // SetStyle is deliberately not typed from the available Microsoft
            // header. If another path supplies it, do not claim it was applied.
            19 => {
                report_ctl3d_gap(host, module, name,
                    "the export signature and style semantics are unverified");
                Ok(0)
            }
            // The SDK header publishes the LONG result and is silent on its
            // value. Only a visible, non-iconic dialog frame returns the
            // default frame result. Every other message stays LONG zero.
            20 => self.ctl3d_dialog_frame(request, host, module, name),
            // The compared export declaration uses a void result; the WFW
            // sample header predates this export. Preserve AX/DX via the
            // descriptor instead of inventing a return value.
            22 => {
                report_ctl3d_gap(host, module, name,
                    "CTL3D color/settings refresh has no active CTL3D state");
                Ok(0)
            }
            // Subclassing, color-brush creation, and registration all require
            // CTL3D-specific state or native control drawing not present here.
            2..=4 | 6 | 12..=13 | 16 | 18 | 21 | 24..=27 => {
                report_ctl3d_gap(host, module, name,
                    "the requested CTL3D subclass, color, or registration effect is unavailable");
                Ok(0)
            }
            // Procedures without a verified Windows 3.1 header contract must
            // stay ordinary failed exports; this does not guess a return.
            _ => {
                report_ctl3d_gap(host, module, name,
                    "no verified CTL3D procedure bridge is available");
                Ok(0)
            }
        }
    }

    /// `Ctl3dDlgFramePaint` (CTL3D/CTL3DV2 ordinal 20).
    ///
    /// The Windows 3.1 SDK header publishes the LONG-returning signature and
    /// does not publish the value. The dialog-frame case is a non-iconic
    /// window whose style contains `WS_VISIBLE`, `WS_DLGFRAME`, and
    /// `DS_MODALFRAME`. `WM_NCPAINT` returns zero. `WM_NCACTIVATE` returns
    /// TRUE. Guest handles are resolved through the runtime map; `lParam` is
    /// not a host pointer and is not dereferenced.
    fn ctl3d_dialog_frame(
        &self,
        request: Win16Ctl3dRequest,
        host: &mut impl RuntimeHost,
        module: &'static str,
        name: &'static str,
    ) -> Result<u32, RuntimeError> {
        let Some((window, message)) = dialog_frame_arguments(&request.arguments) else {
            report_ctl3d_gap(host, module, name,
                "CTL3D dialog-frame arguments do not match the LONG painter; returning LONG zero");
            return Ok(0);
        };
        let Some(native) = self.window_handles.get(&window).copied() else {
            return Ok(0);
        };
        let Some(facts) = host.win16_ctl3d_frame(native)? else {
            report_ctl3d_gap(host, module, name,
                "CTL3D dialog-frame style is unavailable; returning LONG zero");
            return Ok(0);
        };
        Ok(ctl3d_dialog_frame_result(facts.style, facts.iconic, message).unwrap_or(0))
    }
}

/// Real default-frame result for the dialog-frame case.
/// `None` is not that case and the caller returns LONG zero.
fn ctl3d_dialog_frame_result(style: u32, iconic: bool, message: u16) -> Option<u32> {
    if iconic || (style & DIALOG_FRAME_STYLE) != DIALOG_FRAME_STYLE {
        return None;
    }
    match message {
        super::messages::WM_NCPAINT => Some(0),
        WM_NCACTIVATE => Some(1),
        _ => None,
    }
}

fn dialog_frame_arguments(arguments: &[Win16Ctl3dArgument]) -> Option<(u16, u16)> {
    match arguments {
        [
            Win16Ctl3dArgument::Word(window),
            Win16Ctl3dArgument::Word(message),
            Win16Ctl3dArgument::Word(_w_param),
            Win16Ctl3dArgument::Dword(_l_param),
        ] => Some((*window, *message)),
        _ => None,
    }
}

fn report_ctl3d_gap(
    host: &mut impl RuntimeHost,
    module: &'static str,
    name: &'static str,
    reason: &'static str,
) {
    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
        format!("{module}.{name}: {reason}")));
}

#[cfg(test)]
#[path = "win16_ctl3d_tests.rs"]
mod tests;
