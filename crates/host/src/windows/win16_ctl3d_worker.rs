//! Honest no-CTL3D capability result for the native host boundary.

use runtime::{RuntimeError, Win16HostCtl3dCall, Win16HostCtl3dResult};

/// The host does not have a corresponding CTL3D subclasser or owner-draw
/// implementation. Return each routine's ordinary zero failure value and let
/// the runtime report the recoverable warning; never fail the guest call.
pub(super) fn execute(
    call: Win16HostCtl3dCall,
) -> Result<Win16HostCtl3dResult, RuntimeError> {
    let warning = match call.ordinal {
        // These queries accurately describe this adapter's disabled state.
        5 | 23 => None,
        1 => Some("CTL3D version constant is unverified; returning zero"),
        19 => Some("CTL3D SetStyle signature and semantics are unverified"),
        20 => Some("CTL3D dialog-frame painting is unavailable; returning LONG zero"),
        22 => Some("CTL3D color/settings refresh has no active CTL3D state"),
        _ => Some("no native CTL3D subclass, color, or registration operation is available"),
    };
    Ok(Win16HostCtl3dResult { value: 0, warning })
}
