//! Native MCI yield-source registration retirement.

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16HostMciQuiescenceEvidence,
    Win16HostMciYieldRegistration,
};
use windows_sys::Win32::Media::Multimedia::*;

use super::super::{WorkerThreadState, worker_loop::mci_yield_proc};

/// Disable one exact installed thunk and query whether that thunk remains
/// visible. `mciSetYieldProc` success alone does not prove source retirement;
/// the registration is retired only after the query observes our thunk gone.
pub(in crate::windows::win16_mci_owner::worker) fn disable_yield_registration(
    state: &WorkerThreadState,
    owner: Win16HostMciYieldRegistration,
) -> Result<Win16HostMciQuiescenceEvidence, RuntimeError> {
    if let Some(evidence) = state.prior_yield_source_evidence(owner) {
        return Ok(evidence);
    }
    let (native, _) = state.native_id(owner.device)?;
    if state.current_yield_registration(owner.device) != Some(owner.registration) {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "MCI source-disable request references a stale yield registration generation",
        ));
    }
    let reserved = state.reserve_yield_source_evidence(owner)?;
    debug_assert!(reserved);
    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
    let set_result = unsafe { mciSetYieldProc(native, None, 0) };
    let mut data = 0_u32;
    // SAFETY: The pointers in this block are caller-owned host addresses that stay live for the synchronous operation. They are not guest addresses.
    let installed = unsafe { mciGetYieldProc(native, &mut data) }
        .is_some_and(|proc| proc as usize == mci_yield_proc as *const () as usize);
    if !installed {
        state.retire_yield_registration(owner.device, owner.registration)?;
    }
    let evidence = Win16HostMciQuiescenceEvidence::YieldSourceDisabled {
        owner,
        // Preserve the native BOOL bits in the existing u32 evidence DTO.
        set_result: set_result as u32,
        observed_installed: installed,
    };
    if !installed {
        state.record_yield_source_evidence(evidence.clone());
    }
    Ok(evidence)
}
