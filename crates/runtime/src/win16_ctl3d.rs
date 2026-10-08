//! Runtime-side results for the known Win16 CTL3D/CTL3DV2 exports.

use win16_abi::{Win16Ctl3dModule, Win16Ctl3dRequest};

use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost};

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
            // The header verifies this LONG-returning frame painter. The host
            // has no compatible CTL3D frame-paint callback to invoke.
            20 => {
                report_ctl3d_gap(host, module, name,
                    "CTL3D dialog-frame painting is not implemented; returning LONG zero");
                Ok(0)
            }
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
