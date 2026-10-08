//! Reservation and cleanup for guest bitmap snapshots crossing a USER send.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use runtime::{DiagnosticKind as Kind, RuntimeError, Win16HostGdiObject};

use super::super::win16_gdi_bitmap_lease::Win16BitmapLease;
use super::{ToolbarBitmapOwner, ToolbarBitmapRetention, ToolbarBitmapSidecar};

/// Reserve slots before a USER Begin command snapshots native bitmap owners.
pub(in crate::windows) fn reserve_unconsumed_leases(
    storage: &Arc<Mutex<ToolbarBitmapRetention>>,
    count: usize,
) -> Result<(), RuntimeError> {
    let mut retained = storage
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    retained.reserve_slots(count)
}

/// Release untouched snapshots or keep failed owners in the post-join pool.
pub(in crate::windows) fn release_unconsumed_leases(
    worker_id: u64,
    operation: u64,
    storage: &Arc<Mutex<ToolbarBitmapRetention>>,
    leases: BTreeMap<Win16HostGdiObject, Option<Win16BitmapLease>>,
) -> Result<(), RuntimeError> {
    let mut failure = None;
    for (_, lease) in leases {
        let Some(mut lease) = lease else {
            let result = storage
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .cancel_slots(1);
            if let Err(error) = result {
                super::remember(&mut failure, error);
            }
            continue;
        };
        match lease.try_release() {
            Ok(()) => {
                let result = storage
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .cancel_slots(1);
                if let Err(error) = result {
                    super::remember(&mut failure, error);
                }
            }
            Err(primary) => match retain_unconsumed_lease(worker_id, operation, storage, lease) {
                Ok(()) => super::remember(&mut failure, primary),
                Err((retention, owner)) => {
                    let cause = primary.with_cleanup(
                        "toolbar bitmap release failed and owner retention failed",
                        retention,
                    );
                    super::remember(
                        &mut failure,
                        RuntimeError::with_source(
                            cause.kind(),
                            "retain failed toolbar bitmap owner",
                            UnretainedGuestBitmapFailure {
                                cause,
                                _owner: owner,
                            },
                        ),
                    );
                }
            },
        }
    }
    failure.map_or(Ok(()), Err)
}

fn retain_unconsumed_lease(
    worker_id: u64,
    operation: u64,
    storage: &Arc<Mutex<ToolbarBitmapRetention>>,
    owner: Win16BitmapLease,
) -> Result<(), (RuntimeError, Win16BitmapLease)> {
    let mut retained = storage
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if retained.reserved_slots == 0 || retained.sidecars.len() == retained.sidecars.capacity() {
        return Err((
            RuntimeError::new(
                Kind::InternalInvariant,
                "unconsumed guest bitmap has no reserved retention slot",
            ),
            owner,
        ));
    }
    retained.sidecars.push(ToolbarBitmapSidecar {
        worker_retirement_id: worker_id,
        operation,
        window: None,
        hwnd: None,
        expected_parent: 0,
        control_id: 0,
        subclass_id: 0,
        installed: false,
        owner: ToolbarBitmapOwner::Guest(owner),
    });
    retained.reserved_slots -= 1;
    Ok(())
}

#[derive(Debug)]
struct UnretainedGuestBitmapFailure {
    cause: RuntimeError,
    // Keep the copied native bitmap alive until this failure is released.
    _owner: Win16BitmapLease,
}

impl std::fmt::Display for UnretainedGuestBitmapFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.cause, formatter)
    }
}

impl std::error::Error for UnretainedGuestBitmapFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
