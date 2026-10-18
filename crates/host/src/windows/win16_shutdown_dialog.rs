//! A legacy exit request opens the native Shell chooser on the USER worker.
//! The Shell owns the choices and confirmation; no session-changing API or
//! shutdown privilege is invoked by this adapter.

use runtime::{
    Win16HostSessionApiFailure as ApiFailure, Win16HostSessionApiPhase as ApiPhase,
    Win16HostSessionResult as SessionResult,
};
use windows_sys::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
};

use crate::windows::com_bindings::generated::{
    CLSCTX_INPROC_SERVER, CoCreateInstance, IShellDispatch, Shell,
};

struct Apartment;

impl Drop for Apartment {
    fn drop(&mut self) {
        // Balanced on this thread for both S_OK and S_FALSE initialization.
        unsafe { CoUninitialize() };
    }
}

pub(super) fn show() -> SessionResult {
    finish(show_native())
}

fn show_native() -> Result<(), ApiFailure> {
    let initialized = unsafe {
        CoInitializeEx(
            std::ptr::null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        )
    };
    if initialized < 0 {
        return Err(failure(ApiPhase::InitializeShellApartment, initialized));
    }
    let _apartment = Apartment;
    // The SDK-generated interface owns/releases its reference before COM is
    // uninitialized. This operation holds no USER worker-state borrow.
    let shell: IShellDispatch = unsafe { CoCreateInstance(&Shell, None, CLSCTX_INPROC_SERVER) }
        .map_err(|error| failure(ApiPhase::CreateShell, error.code().0))?;
    // Shell.ShutdownWindows displays the Windows-owned selection dialog. It
    // does not tell us whether an action was selected or cancelled.
    unsafe { shell.ShutdownWindows() }
        .ok()
        .map_err(|error| failure(ApiPhase::ShowShutdownDialog, error.code().0))
}

fn failure(phase: ApiPhase, status: i32) -> ApiFailure {
    ApiFailure {
        phase,
        error_code: status as u32,
    }
}

fn finish(result: Result<(), ApiFailure>) -> SessionResult {
    SessionResult {
        // Showing a chooser is not acceptance of a session change. In
        // particular, cancelling it must return FALSE to the Win16 caller.
        accepted: false,
        request_attempted: result
            .as_ref()
            .err()
            .is_none_or(|failure| failure.phase == ApiPhase::ShowShutdownDialog),
        operation_failure: result.err(),
        ..SessionResult::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_exit_chooser_completion_does_not_claim_logoff_or_reboot() {
        let result = finish(Ok(()));
        assert!(!result.accepted);
        assert!(result.request_attempted);
        assert!(result.operation_failure.is_none());
        assert!(!result.cleanup.owner_retained);
    }

    #[test]
    fn session_exit_chooser_failure_preserves_phase_without_claiming_success() {
        for phase in [
            ApiPhase::InitializeShellApartment,
            ApiPhase::CreateShell,
            ApiPhase::ShowShutdownDialog,
        ] {
            let error = failure(phase, 0x80004005u32 as i32);
            let result = finish(Err(error));
            assert!(!result.accepted);
            assert_eq!(
                result.request_attempted,
                phase == ApiPhase::ShowShutdownDialog
            );
            assert_eq!(result.operation_failure, Some(error));
            assert!(!result.cleanup.owner_retained);
        }
    }
}
