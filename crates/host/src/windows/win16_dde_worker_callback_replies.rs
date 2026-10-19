//! Retain failed native callback replies until the DDE owner can release them.

use std::error::Error;
use std::fmt;
use std::sync::{Arc, MutexGuard};
use std::thread;
use std::time::Duration;

use runtime::{
    DiagnosticKind as Kind, RuntimeError, Win16DdeAbortPhase, Win16DdeCleanupFailure,
    Win16DdeCleanupStatus, Win16DdeNativeReplyReceipt,
};
use windows_sys::Win32::System::DataExchange::DdeFreeDataHandle;

use super::WorkerContext;

#[derive(Default)]
pub(super) struct CallbackReplyOwners {
    entries: Vec<FailedCallbackReply>,
    reserved_slots: usize,
}

struct FailedCallbackReply {
    identity: super::FailedCallbackReplyIdentity,
    native_instance: Option<u32>,
    handle: usize,
    first_failure: Arc<RuntimeError>,
    shutdown_retry_recorded: bool,
    owner_slot_was_reserved: bool,
}

pub(super) struct CallbackReplyReleaseReport {
    pub(super) replies: Vec<Win16DdeNativeReplyReceipt>,
    pub(super) failures: Vec<Win16DdeCleanupFailure>,
    pub(super) all_released_or_transferred: bool,
}

fn lock_owners(context: &WorkerContext) -> (MutexGuard<'_, CallbackReplyOwners>, bool) {
    match context.callback_reply_cleanup.lock() {
        Ok(owners) => (owners, false),
        Err(poisoned) => (poisoned.into_inner(), true),
    }
}

pub(in crate::windows::win16_dde) fn reserve_callback_reply_cleanup_slot(
    context: &WorkerContext,
) -> Result<(), RuntimeError> {
    let (mut owners, poisoned) = lock_owners(context);
    if poisoned {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "DDE callback reply cleanup ledger was poisoned before native handle creation",
        ));
    }
    let reserved = owners.reserved_slots.checked_add(1).ok_or_else(|| {
        RuntimeError::new(
            Kind::ResourceExhausted,
            "DDE callback reply cleanup reservations are exhausted",
        )
    })?;
    owners.entries.try_reserve(reserved).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve ownership for a native DDE callback reply handle",
            error,
        )
    })?;
    owners.reserved_slots = reserved;
    Ok(())
}

pub(in crate::windows::win16_dde) fn release_callback_reply_cleanup_slot(
    context: &WorkerContext,
) -> Result<(), RuntimeError> {
    let (mut owners, poisoned) = lock_owners(context);
    if owners.reserved_slots == 0 {
        return Err(RuntimeError::new(
            Kind::InternalInvariant,
            "DDE callback reply cleanup reservation was released more than once",
        ));
    }
    owners.reserved_slots -= 1;
    if poisoned {
        Err(RuntimeError::new(
            Kind::InternalInvariant,
            "DDE callback reply cleanup ledger was poisoned while releasing a reservation",
        ))
    } else {
        Ok(())
    }
}

pub(in crate::windows::win16_dde) fn retain_failed_callback_reply(
    context: &WorkerContext,
    identity: super::FailedCallbackReplyIdentity,
    native_instance: Option<u32>,
    handle: usize,
    first_failure: RuntimeError,
) -> Result<(), RuntimeError> {
    let (mut owners, poisoned) = lock_owners(context);
    let missing_reservation = owners.reserved_slots == 0;
    if missing_reservation {
        owners.entries.try_reserve(1).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve emergency ownership for a failed DDE callback reply",
                error,
            )
        })?;
    } else {
        owners.reserved_slots -= 1;
    }
    owners.entries.push(FailedCallbackReply {
        identity,
        native_instance,
        handle,
        first_failure: Arc::new(first_failure),
        shutdown_retry_recorded: false,
        owner_slot_was_reserved: !missing_reservation,
    });
    if missing_reservation {
        Err(RuntimeError::new(
            Kind::InternalInvariant,
            "failed DDE callback reply was retained without a reserved owner slot",
        ))
    } else if poisoned {
        Err(RuntimeError::new(
            Kind::InternalInvariant,
            "DDE callback reply owner was retained after cleanup ledger poisoning",
        ))
    } else {
        Ok(())
    }
}

pub(super) fn release_failed_callback_replies(
    context: &WorkerContext,
) -> CallbackReplyReleaseReport {
    let mut replies = Vec::new();
    let mut cleanup_failures = Vec::new();
    let mut ledger_poison_reported = false;
    let mut ledger_poisoned = false;
    loop {
        let (mut owners, poisoned) = lock_owners(context);
        if poisoned && !ledger_poison_reported {
            ledger_poison_reported = true;
            ledger_poisoned = true;
            cleanup_failures.push(Win16DdeCleanupFailure {
                phase: Win16DdeAbortPhase::ReleaseCallbackReply,
                frame: None,
                operation: None,
                instance: None,
                status: Win16DdeCleanupStatus::Unresolved,
                cause: Arc::new(RuntimeError::new(
                    Kind::InternalInvariant,
                    "DDE callback reply cleanup ledger was poisoned during native release",
                )),
            });
        }
        let mut index = 0;
        while index < owners.entries.len() {
            let owner = &owners.entries[index];
            // SAFETY: DdeFreeDataHandle releases a data handle this instance owns.
            if unsafe { DdeFreeDataHandle(owner.handle as _) } != 0 {
                let owner = owners.entries.remove(index);
                let status = if owner.owner_slot_was_reserved {
                    Win16DdeCleanupStatus::RetriedAndReleased
                } else {
                    Win16DdeCleanupStatus::Unresolved
                };
                let failure = Some(Arc::clone(&owner.first_failure));
                replies.push(Win16DdeNativeReplyReceipt {
                    frame: owner.identity.frame,
                    operation: owner.identity.operation,
                    instance: owner.identity.instance,
                    role: owner.identity.role,
                    status,
                    failure: failure.clone(),
                });
                cleanup_failures.push(Win16DdeCleanupFailure {
                    phase: Win16DdeAbortPhase::ReleaseCallbackReply,
                    frame: Some(owner.identity.frame),
                    operation: owner.identity.operation,
                    instance: Some(owner.identity.instance),
                    status,
                    cause: Arc::clone(&owner.first_failure),
                });
                ledger_poisoned |= status == Win16DdeCleanupStatus::Unresolved;
            } else {
                let owner = &mut owners.entries[index];
                if !owner.shutdown_retry_recorded {
                    let prior = shared_failure(
                        Arc::clone(&owner.first_failure),
                        "earlier DDE callback reply cleanup failure",
                    );
                    let retry = callback_reply_free_error(owner.native_instance);
                    owner.first_failure = Arc::new(super::super::errors::combine_cleanup_errors(
                        prior,
                        retry,
                        "DDE callback reply and shutdown retry release both failed",
                    ));
                    owner.shutdown_retry_recorded = true;
                }
                index += 1;
            }
        }
        let still_owned = !owners.entries.is_empty();
        let unconsumed_reservations = owners.reserved_slots;
        drop(owners);
        if !still_owned {
            if unconsumed_reservations != 0 {
                cleanup_failures.push(Win16DdeCleanupFailure {
                    phase: Win16DdeAbortPhase::ReleaseCallbackReply,
                    frame: None,
                    operation: None,
                    instance: None,
                    status: Win16DdeCleanupStatus::Unresolved,
                    cause: Arc::new(RuntimeError::new(
                        Kind::InternalInvariant,
                        "DDE callback reply owner slots remained reserved at worker shutdown",
                    )),
                });
                ledger_poisoned = true;
            }
            return CallbackReplyReleaseReport {
                all_released_or_transferred: unconsumed_reservations == 0
                    && !ledger_poisoned
                    && replies.iter().all(|reply| {
                        matches!(
                            reply.status,
                            Win16DdeCleanupStatus::Released
                                | Win16DdeCleanupStatus::RetriedAndReleased
                        )
                    }),
                replies,
                failures: cleanup_failures,
            };
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn shared_failure(failure: Arc<RuntimeError>, context: &'static str) -> RuntimeError {
    RuntimeError::with_source(failure.kind(), context, failure)
}

fn callback_reply_free_error(native_instance: Option<u32>) -> RuntimeError {
    let Some(native_instance) = native_instance else {
        return RuntimeError::new(
            Kind::InternalInvariant,
            "retained DDE callback reply lost the native instance needed to read DMLERR",
        );
    };
    let error = crate::windows::win32_safe::dde_last_error(native_instance) as u16;
    RuntimeError::with_source(
        Kind::HostFailure,
        "DdeFreeDataHandle could not release a retained DDE callback reply",
        CallbackReplyFreeFailure {
            native_instance,
            dde_error: error,
        },
    )
}

#[derive(Debug)]
struct CallbackReplyFreeFailure {
    native_instance: u32,
    dde_error: u16,
}

impl fmt::Display for CallbackReplyFreeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "DdeFreeDataHandle failed for DDEML instance {:#010x} (DMLERR={:#06x})",
            self.native_instance, self.dde_error,
        )
    }
}

impl Error for CallbackReplyFreeFailure {}
