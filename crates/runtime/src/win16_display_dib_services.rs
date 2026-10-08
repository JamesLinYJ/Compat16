//! Win16 full-screen DIB display service.

use win16_abi::Win16DisplayDibRequest;

use crate::{Diagnostic, DiagnosticKind as Kind, RuntimeError, RuntimeHost};

/// `DISPDIB.H` defines `DISPLAYDIB_NOTSUPPORTED` as 1. The API takes over the
/// VGA display for full-screen output; windowed GDI cannot provide that mode.
pub(crate) const DISPLAY_DIB_NOT_SUPPORTED: u32 = 1;

pub(crate) fn execute(
    _request: Win16DisplayDibRequest,
    host: &mut impl RuntimeHost,
) -> Result<u32, RuntimeError> {
    host.report_diagnostic(&Diagnostic::warning(Kind::CompatibilityGap,
        "Win16 DisplayDib cannot take over the host display in full-screen VGA mode")
        .with_context("Win16 DISPDIB DisplayDib"));
    Ok(DISPLAY_DIB_NOT_SUPPORTED)
}
