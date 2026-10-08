//! Retained ownership for the process shutdown privilege used by USER session APIs.

use std::sync::{Mutex, MutexGuard, OnceLock};

use runtime::{
    Win16HostSessionApiFailure as ApiFailure,
    Win16HostSessionApiPhase as ApiPhase,
    Win16HostSessionCleanupReceipt as CleanupReceipt,
    Win16HostSessionResult as SessionResult,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, LUID, SetLastError, ERROR_BUSY,
    ERROR_NOT_ALL_ASSIGNED,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES,
    SE_PRIVILEGE_ENABLED, SE_SHUTDOWN_NAME, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Shutdown::{
    ExitWindowsEx, EWX_LOGOFF, EWX_REBOOT, SHTDN_REASON_FLAG_PLANNED,
    SHTDN_REASON_MAJOR_OTHER, SHTDN_REASON_MINOR_OTHER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

#[derive(Clone, Copy, Debug, Default)]
struct CleanupOutcome {
    privilege_restore_failure: Option<ApiFailure>,
    token_close_failure: Option<ApiFailure>,
    receipt: CleanupReceipt,
}

impl CleanupOutcome {
    fn pending(&self) -> bool {
        self.receipt.owner_retained
    }

    fn into_session_result(self) -> SessionResult {
        SessionResult {
            privilege_restore_failure: self.privilege_restore_failure,
            token_close_failure: self.token_close_failure,
            cleanup: self.receipt,
            ..SessionResult::default()
        }
    }
}

fn api_failure(phase: ApiPhase, error_code: u32) -> ApiFailure {
    ApiFailure { phase, error_code }
}

struct RetainedToken {
    // Store HANDLE bits, not a raw pointer, so the process-wide mutex owner is Send.
    token_bits: usize,
    previous: TOKEN_PRIVILEGES,
    restore_pending: bool,
}

impl RetainedToken {
    fn new(token: HANDLE) -> Self {
        Self {
            token_bits: token as usize,
            previous: TOKEN_PRIVILEGES::default(),
            restore_pending: false,
        }
    }

    fn token(&self) -> HANDLE {
        self.token_bits as HANDLE
    }

    fn cleanup(&mut self) -> CleanupOutcome {
        if self.restore_pending {
            if let Some(error) = restore_shutdown_privilege(self.token(), &self.previous) {
                // Keep the token open while its previous privilege state is uncertain.
                return CleanupOutcome {
                    privilege_restore_failure: Some(api_failure(
                        ApiPhase::RestoreShutdownPrivilege,
                        error,
                    )),
                    token_close_failure: None,
                    receipt: CleanupReceipt {
                        owner_retained: true,
                        restore_pending: true,
                        token_close_pending: true,
                        previous_privilege_state_saved: self.previous.PrivilegeCount != 0,
                        failure_receipt_unreported: false,
                    },
                };
            }
            self.restore_pending = false;
        }

        if let Some(error) = close_token(self.token()) {
            return CleanupOutcome {
                privilege_restore_failure: None,
                token_close_failure: Some(api_failure(ApiPhase::CloseToken, error)),
                receipt: CleanupReceipt {
                    owner_retained: true,
                    restore_pending: false,
                    token_close_pending: true,
                    previous_privilege_state_saved: self.previous.PrivilegeCount != 0,
                    failure_receipt_unreported: false,
                },
            };
        }

        CleanupOutcome::default()
    }
}

#[derive(Default)]
struct RetainedState {
    active_request: bool,
    owner: Option<RetainedToken>,
    // A Drop-time cleanup failure has no synchronous caller to receive it.
    // Preserve one receipt so the next request reports it before retrying.
    unreported: Option<CleanupOutcome>,
}

static RETAINED_STATE: OnceLock<Mutex<RetainedState>> = OnceLock::new();

fn retained_state() -> &'static Mutex<RetainedState> {
    RETAINED_STATE.get_or_init(|| Mutex::new(RetainedState::default()))
}

fn lock_state() -> MutexGuard<'static, RetainedState> {
    retained_state()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Win32 token privileges are process-wide. One bounded owner slot is enough:
/// a new session request is refused until its prior token has been restored and
/// closed. This prevents an unbounded list of lost cleanup handles.
struct SessionReservation {
    owner: Option<RetainedToken>,
    active: bool,
}

fn reserve_session() -> Result<SessionReservation, SessionResult> {
    let mut state = lock_state();
    if state.active_request {
        return Err(SessionResult {
            operation_failure: Some(api_failure(ApiPhase::SessionReservation, ERROR_BUSY)),
            ..SessionResult::default()
        });
    }

    if let Some(receipt) = state.unreported.take() {
        return Err(receipt.into_session_result());
    }

    if let Some(owner) = state.owner.as_mut() {
        let outcome = owner.cleanup();
        if outcome.pending() {
            return Err(outcome.into_session_result());
        }
        state.owner = None;
    }

    state.active_request = true;
    Ok(SessionReservation {
        owner: None,
        active: true,
    })
}

impl SessionReservation {
    fn adopt_token(&mut self, token: HANDLE) {
        self.owner = Some(RetainedToken::new(token));
    }

    fn record_previous_state(&mut self, previous: TOKEN_PRIVILEGES) {
        if let Some(owner) = self.owner.as_mut() {
            owner.restore_pending = previous.PrivilegeCount != 0;
            owner.previous = previous;
        }
    }

    fn finish(mut self) -> CleanupOutcome {
        let outcome = self.cleanup_owner();
        self.release(outcome, false);
        outcome
    }

    fn cleanup_owner(&mut self) -> CleanupOutcome {
        let Some(owner) = self.owner.as_mut() else {
            return CleanupOutcome::default();
        };
        let outcome = owner.cleanup();
        if !outcome.pending() {
            self.owner = None;
        }
        outcome
    }

    fn release(&mut self, outcome: CleanupOutcome, report_later: bool) {
        let mut state = lock_state();
        if outcome.pending() {
            // The reservation is exclusive, so the single retained slot must be empty.
            debug_assert!(state.owner.is_none());
            state.owner = self.owner.take();
            if report_later {
                let mut receipt = outcome;
                receipt.receipt.failure_receipt_unreported = true;
                state.unreported = Some(receipt);
            }
        }
        state.active_request = false;
        self.active = false;
    }
}

impl Drop for SessionReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let outcome = self.cleanup_owner();
        let report_later = outcome.pending();
        self.release(outcome, report_later);
    }
}

pub(super) fn request_logoff() -> SessionResult {
    let reservation = match reserve_session() {
        Ok(reservation) => reservation,
        Err(attempt) => return attempt,
    };
    let accepted = unsafe { ExitWindowsEx(EWX_LOGOFF, 0) } != 0;
    let operation_failure = (!accepted).then(|| {
        api_failure(ApiPhase::ExitWindowsEx, unsafe { GetLastError() })
    });
    let cleanup = reservation.finish();
    SessionResult {
        accepted,
        operation_failure,
        request_attempted: true,
        ..cleanup.into_session_result()
    }
}

pub(super) fn request_reboot() -> SessionResult {
    let mut reservation = match reserve_session() {
        Ok(reservation) => reservation,
        Err(attempt) => return attempt,
    };

    let mut token: HANDLE = std::ptr::null_mut();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    } == 0
    {
        let operation_failure = Some(api_failure(
            ApiPhase::OpenProcessToken,
            unsafe { GetLastError() },
        ));
        let cleanup = reservation.finish();
        return attempt_without_request(operation_failure, cleanup);
    }
    reservation.adopt_token(token);

    let mut shutdown_luid = LUID::default();
    if unsafe { LookupPrivilegeValueW(std::ptr::null(), SE_SHUTDOWN_NAME, &mut shutdown_luid) } == 0
    {
        let operation_failure = Some(api_failure(
            ApiPhase::LookupPrivilegeValue,
            unsafe { GetLastError() },
        ));
        let cleanup = reservation.finish();
        return attempt_without_request(operation_failure, cleanup);
    }

    let enabled = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: shutdown_luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    let mut previous = TOKEN_PRIVILEGES::default();
    let mut _previous_bytes = 0_u32;
    // AdjustTokenPrivileges reports ERROR_NOT_ALL_ASSIGNED through last-error
    // even when the function's BOOL is nonzero. Clear stale thread state first.
    unsafe { SetLastError(0) };
    let changed = unsafe {
        AdjustTokenPrivileges(
            token,
            0,
            &enabled,
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            &mut previous,
            &mut _previous_bytes,
        )
    };
    let privilege_error = unsafe { GetLastError() };
    reservation.record_previous_state(previous);
    if changed == 0 || privilege_error == ERROR_NOT_ALL_ASSIGNED {
        let cleanup = reservation.finish();
        return attempt_without_request(
            Some(api_failure(ApiPhase::AdjustTokenPrivileges, privilege_error)),
            cleanup,
        );
    }

    // Windows documents Other (Planned) for a planned restart. No force flag
    // is set, and only an already-assigned token privilege is enabled.
    let reason = SHTDN_REASON_MAJOR_OTHER
        | SHTDN_REASON_MINOR_OTHER
        | SHTDN_REASON_FLAG_PLANNED;
    let accepted = unsafe { ExitWindowsEx(EWX_REBOOT, reason) } != 0;
    let operation_failure = (!accepted).then(|| {
        api_failure(ApiPhase::ExitWindowsEx, unsafe { GetLastError() })
    });
    let cleanup = reservation.finish();
    SessionResult {
        accepted,
        operation_failure,
        request_attempted: true,
        ..cleanup.into_session_result()
    }
}

fn attempt_without_request(
    operation_failure: Option<ApiFailure>,
    cleanup: CleanupOutcome,
) -> SessionResult {
    SessionResult {
        operation_failure,
        ..cleanup.into_session_result()
    }
}

fn restore_shutdown_privilege(token: HANDLE, previous: &TOKEN_PRIVILEGES) -> Option<u32> {
    unsafe { SetLastError(0) };
    let restored = unsafe {
        AdjustTokenPrivileges(token, 0, previous, 0, std::ptr::null_mut(), std::ptr::null_mut())
    };
    let error = unsafe { GetLastError() };
    (restored == 0 || error == ERROR_NOT_ALL_ASSIGNED).then_some(error)
}

fn close_token(token: HANDLE) -> Option<u32> {
    (unsafe { CloseHandle(token) } == 0).then(|| unsafe { GetLastError() })
}
