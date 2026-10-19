//! Native ExitWindows semantics used by the NT WOW USER thunk.

use runtime::{
    Win16HostSessionApiFailure as ApiFailure, Win16HostSessionApiPhase as ApiPhase,
    Win16HostSessionResult as SessionResult,
};
use windows_sys::Win32::System::Shutdown::{EWX_LOGOFF, ExitWindowsEx};

pub(super) fn exit_windows(reserved: u32, code: u16) -> SessionResult {
    exit_windows_with(reserved, code, |flags, reason| {
        // SAFETY: `ExitWindowsEx` uses caller-owned borrows that stay live for this synchronous call. Invalid handles return the API's failure code, and no guest address is passed.
        if unsafe { ExitWindowsEx(flags, reason) } != 0 {
            Ok(())
        } else {
            Err(crate::windows::win32_safe::last_error())
        }
    })
}

fn exit_windows_with(
    _reserved: u32,
    _code: u16,
    call_native: impl FnOnce(u32, u32) -> Result<(), u32>,
) -> SessionResult {
    // NT 3.5 and XP WU32ExitWindows forward the DWORD and WORD to ExitWindows.
    // Both the NT 3.5 and current SDK winuser.h define that API as a macro:
    // ExitWindowsEx(EWX_LOGOFF, 0xFFFFFFFF). It ignores the two old arguments;
    // they must not be reinterpreted as ExitWindowsEx flags or a reboot code.
    let result = call_native(EWX_LOGOFF, u32::MAX);
    SessionResult {
        accepted: result.is_ok(),
        operation_failure: result.err().map(|error_code| ApiFailure {
            phase: ApiPhase::ExitWindowsEx,
            error_code,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_exit_wow_macro_reaches_the_native_contract_for_all_guest_values() {
        for (reserved, code) in [(0, 0), (0x42, 0), (0x43, 0), (u32::MAX, u16::MAX)] {
            let mut observed = None;
            let result = exit_windows_with(reserved, code, |flags, reason| {
                observed = Some((flags, reason));
                Ok(())
            });
            assert_eq!(observed, Some((0, u32::MAX)));
            assert!(result.accepted);
            assert!(result.operation_failure.is_none());
        }
    }

    #[test]
    fn session_exit_native_failure_is_returned_without_claiming_success() {
        let result = exit_windows_with(0, 0, |flags, reason| {
            assert_eq!((flags, reason), (0, u32::MAX));
            Err(5)
        });
        assert!(!result.accepted);
        assert_eq!(
            result.operation_failure,
            Some(ApiFailure {
                phase: ApiPhase::ExitWindowsEx,
                error_code: 5,
            })
        );
    }
}
