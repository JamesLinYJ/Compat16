//! Checked cloning, owner projection, and retained receipt construction.

use super::Win16State;
use crate::{
    DiagnosticKind as Kind, RuntimeError, Win16HostMciQuiescenceEvidence,
    Win16HostMciQuiescenceFailure, Win16HostMciQuiescenceReceipt,
    Win16HostMciQuiescenceStatus, Win16HostMciQuiesceRequest,
    Win16HostMciRetainedOwner,
};

pub(super) fn apply_confirmed_mci_retirements(
    state: &mut Win16State,
    receipt: &Win16HostMciQuiescenceReceipt,
) {
    for evidence in &receipt.confirmed {
        match evidence {
            Win16HostMciQuiescenceEvidence::YieldSourceDisabled {
                owner,
                set_result: _,
                observed_installed,
            } if !observed_installed => {
                if state.mci.yield_procedures.get(&owner.device).is_some_and(|entry| {
                    entry.registration == owner.registration
                }) {
                    state.mci.yield_procedures.remove(&owner.device);
                }
                if !state.mci.retired_yield_sources.contains(owner) {
                    state.mci.retired_yield_sources.push(*owner);
                }
            }
            Win16HostMciQuiescenceEvidence::DeviceClosed {
                device,
                native_result: 0,
            } => {
                state.mci.orphan_devices.retain(|orphan| orphan != device);
                state
                    .mci
                    .retired_yield_sources
                    .retain(|owner| {
                        owner.device != *device
                            || !receipt.confirmed.iter().any(|evidence| matches!(evidence,
                                Win16HostMciQuiescenceEvidence::YieldSourceDisabled {
                                    owner: disabled,
                                    observed_installed: false,
                                    ..
                                } if disabled == owner
                            ))
                    });
                state.retire_mci_host_device(*device);
            }
            _ => {}
        }
    }
    if receipt.status == Win16HostMciQuiescenceStatus::Quiesced
        && all_requested_owners_confirmed(receipt)
    {
        state.mci.completed_yields.clear();
        state.mci.completed_operations.clear();
    }
}

pub(super) fn try_clone_request(
    request: &Win16HostMciQuiesceRequest,
) -> Result<Win16HostMciQuiesceRequest, RuntimeError> {
    let mut copy = Win16HostMciQuiesceRequest::default();
    copy.devices.try_reserve_exact(request.devices.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "copy MCI quiescence device owners", error)
    })?;
    copy.registrations.try_reserve_exact(request.registrations.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "copy MCI quiescence registration owners", error)
    })?;
    copy.pending_begins
        .try_reserve_exact(request.pending_begins.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "copy MCI pending Begin operation identities",
                error,
            )
        })?;
    copy.active_yields.try_reserve_exact(request.active_yields.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "copy MCI quiescence active frames", error)
    })?;
    copy.returned_yields
        .try_reserve_exact(request.returned_yields.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "copy MCI quiescence returned-yield proofs",
                error,
            )
        })?;
    copy.completed_operations
        .try_reserve_exact(request.completed_operations.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "copy MCI quiescence completed-operation proofs",
                error,
            )
        })?;
    copy.resolved_causes
        .try_reserve_exact(request.resolved_causes.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "copy MCI quiescence typed cause history",
                error,
            )
        })?;
    copy.devices.extend_from_slice(&request.devices);
    copy.registrations.extend_from_slice(&request.registrations);
    copy.pending_begins.extend_from_slice(&request.pending_begins);
    copy.active_yields.extend_from_slice(&request.active_yields);
    copy.returned_yields.extend_from_slice(&request.returned_yields);
    copy.completed_operations
        .extend_from_slice(&request.completed_operations);
    copy.resolved_causes
        .extend(request.resolved_causes.iter().cloned());
    Ok(copy)
}

pub(super) fn owners_in_request(
    request: &Win16HostMciQuiesceRequest,
) -> Result<Vec<Win16HostMciRetainedOwner>, RuntimeError> {
    let mut retained = Vec::new();
    retained.try_reserve_exact(
        request.devices.len()
            .saturating_add(request.registrations.len())
            .saturating_add(request.pending_begins.len())
            .saturating_add(request.active_yields.len())
            .saturating_add(request.active_yields.len())
            .saturating_add(request.returned_yields.len())
            .saturating_add(request.completed_operations.len())
            .saturating_add(usize::from(!request.pending_begins.is_empty())),
    ).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted,
        "reserve exact MCI quiescence retained-owner list",
        error,
    ))?;
    retained.extend(request.devices.iter().copied().map(Win16HostMciRetainedOwner::Device));
    retained.extend(request.registrations.iter().copied().map(Win16HostMciRetainedOwner::Registration));
    retained.extend(request.pending_begins.iter().copied().map(Win16HostMciRetainedOwner::PendingBegin));
    if !request.pending_begins.is_empty() {
        retained.push(Win16HostMciRetainedOwner::OwnerThread);
    }
    retained.extend(request.active_yields.iter().copied().map(Win16HostMciRetainedOwner::ActiveYield));
    for operation in request.active_yields.iter().map(|owner| owner.operation) {
        if !retained.contains(&Win16HostMciRetainedOwner::Operation(operation)) {
            retained.push(Win16HostMciRetainedOwner::Operation(operation));
        }
    }
    retained.extend(request.returned_yields.iter().copied().map(Win16HostMciRetainedOwner::YieldReturn));
    retained.extend(request.completed_operations.iter().copied().map(Win16HostMciRetainedOwner::CompletedOperation));
    Ok(retained)
}

pub(super) fn missing_owners(
    receipt: &Win16HostMciQuiescenceReceipt,
) -> Result<Vec<Win16HostMciRetainedOwner>, RuntimeError> {
    let mut retained = Vec::new();
    retained.try_reserve_exact(
        receipt.request.devices.len()
            .saturating_add(receipt.request.registrations.len())
            .saturating_add(receipt.request.pending_begins.len())
            .saturating_add(receipt.request.active_yields.len())
            .saturating_add(receipt.request.active_yields.len())
            .saturating_add(receipt.request.returned_yields.len())
            .saturating_add(receipt.request.completed_operations.len())
            .saturating_add(2),
    ).map_err(|error| RuntimeError::with_source(
        Kind::ResourceExhausted,
        "reserve missing exact MCI quiescence owner list",
        error,
    ))?;
    for device in &receipt.request.devices {
        if !receipt.confirmed.iter().any(|evidence| matches!(evidence,
            Win16HostMciQuiescenceEvidence::DeviceClosed { device: closed, native_result: 0 } if closed == device
        )) {
            retained.push(Win16HostMciRetainedOwner::Device(*device));
        }
    }
    retained.extend(
        receipt
            .request
            .pending_begins
            .iter()
            .copied()
            .map(Win16HostMciRetainedOwner::PendingBegin),
    );
    if !receipt.request.pending_begins.is_empty() {
        retained.push(Win16HostMciRetainedOwner::OwnerThread);
    }
    for registration in &receipt.request.registrations {
        if !receipt.confirmed.iter().any(|evidence| matches!(evidence,
            Win16HostMciQuiescenceEvidence::YieldSourceDisabled { owner, observed_installed: false, .. }
                if owner == registration
        )) {
            retained.push(Win16HostMciRetainedOwner::Registration(*registration));
        }
    }
    for active in &receipt.request.active_yields {
        if !receipt.confirmed.iter().any(|evidence| matches!(evidence,
            Win16HostMciQuiescenceEvidence::ActiveYieldReturned { owner, .. } if owner == active
        )) {
            retained.push(Win16HostMciRetainedOwner::ActiveYield(*active));
        }
        if !receipt.confirmed.iter().any(|evidence| matches!(evidence,
            Win16HostMciQuiescenceEvidence::OperationCompleted { operation, .. }
                if operation == &active.operation
        )) && !retained.contains(&Win16HostMciRetainedOwner::Operation(active.operation)) {
            retained.push(Win16HostMciRetainedOwner::Operation(active.operation));
        }
    }
    for returned in &receipt.request.returned_yields {
        if !receipt.confirmed.iter().any(|evidence| matches!(evidence,
            Win16HostMciQuiescenceEvidence::ActiveYieldReturned { owner, guest_return }
                if owner == &returned.owner && guest_return == &returned.guest_return
        )) {
            retained.push(Win16HostMciRetainedOwner::YieldReturn(*returned));
        }
    }
    for completed in &receipt.request.completed_operations {
        if !receipt.confirmed.iter().any(|evidence| matches!(evidence,
            Win16HostMciQuiescenceEvidence::OperationCompleted { operation, native_return_value }
                if operation == &completed.operation && native_return_value == &completed.native_return_value
        )) {
            retained.push(Win16HostMciRetainedOwner::CompletedOperation(*completed));
        }
    }
    if !receipt.confirmed.iter().any(|evidence| matches!(evidence,
        Win16HostMciQuiescenceEvidence::NotificationLedgerDrained {
            pending_routes: 0,
            queued_events: 0,
            callback_failures: 0,
            wake_failures: 0,
        }
    )) {
        retained.push(Win16HostMciRetainedOwner::NotificationSink);
    }
    Ok(retained)
}

pub(super) fn all_requested_owners_confirmed(receipt: &Win16HostMciQuiescenceReceipt) -> bool {
    let exact_device_closes = receipt.request.devices.iter().all(|device| {
        receipt.confirmed.iter().any(|evidence| matches!(
            evidence,
            Win16HostMciQuiescenceEvidence::DeviceClosed {
                device: closed,
                native_result: 0,
            } if closed == device
        ))
    });
    let exact_source_disables = receipt.request.registrations.iter().all(|registration| {
        receipt.confirmed.iter().any(|evidence| matches!(
            evidence,
            Win16HostMciQuiescenceEvidence::YieldSourceDisabled {
                owner,
                observed_installed: false,
                ..
            } if owner == registration
        ))
    });
    let exact_active_yields = receipt.request.active_yields.iter().all(|active| {
        let returned = receipt.request.returned_yields.iter().find(|returned| {
            returned.owner == *active
        });
        let completion = receipt.request.completed_operations.iter().find(|completed| {
            completed.operation == active.operation
        });
        returned.is_some_and(|returned| {
            receipt.confirmed.iter().any(|evidence| matches!(
                evidence,
                Win16HostMciQuiescenceEvidence::ActiveYieldReturned {
                    owner,
                    guest_return,
                } if owner == active && *guest_return == returned.guest_return
            ))
        }) && completion.is_some_and(|completion| {
            receipt.confirmed.iter().any(|evidence| matches!(
                evidence,
                Win16HostMciQuiescenceEvidence::OperationCompleted {
                    operation,
                    native_return_value,
                } if *operation == completion.operation
                    && *native_return_value == completion.native_return_value
            ))
        })
    });
    let exact_returned_yields = receipt.request.returned_yields.iter().all(|returned| {
        receipt.confirmed.iter().any(|evidence| matches!(
            evidence,
            Win16HostMciQuiescenceEvidence::ActiveYieldReturned {
                owner,
                guest_return,
            } if owner == &returned.owner && guest_return == &returned.guest_return
        ))
    });
    let exact_completed_operations = receipt.request.completed_operations.iter().all(|completed| {
        receipt.confirmed.iter().any(|evidence| matches!(
            evidence,
            Win16HostMciQuiescenceEvidence::OperationCompleted {
                operation,
                native_return_value,
            } if operation == &completed.operation
                && native_return_value == &completed.native_return_value
        ))
    });
    receipt.request.pending_begins.is_empty()
        && exact_device_closes
        && exact_source_disables
        && exact_active_yields
        && exact_returned_yields
        && exact_completed_operations
        && receipt.confirmed.iter().any(|evidence| matches!(
            evidence,
            Win16HostMciQuiescenceEvidence::NotificationLedgerDrained {
                pending_routes: 0,
                queued_events: 0,
                callback_failures: 0,
                wake_failures: 0,
            }
        ))
}

pub(super) fn retained_receipt(
    request: Win16HostMciQuiesceRequest,
    error: RuntimeError,
) -> Result<Win16HostMciQuiescenceReceipt, RuntimeError> {
    let retained = owners_in_request(&request)?;
    let mut causes = Vec::new();
    causes.try_reserve_exact(1).map_err(|reserve_error| RuntimeError::with_source(
        Kind::ResourceExhausted,
        "reserve host-failure MCI quiescence cause",
        reserve_error,
    ))?;
    causes.push(std::sync::Arc::new(error));
    let mut resolved_causes = Vec::new();
    resolved_causes
        .try_reserve_exact(request.resolved_causes.len())
        .map_err(|reserve_error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve resolved typed causes in retained MCI quiescence receipt",
                reserve_error,
            )
        })?;
    resolved_causes.extend(request.resolved_causes.iter().cloned());
    Ok(Win16HostMciQuiescenceReceipt {
        request,
        status: Win16HostMciQuiescenceStatus::Retained,
        confirmed: Vec::new(),
        retained,
        causes,
        resolved_causes,
    })
}

pub(super) fn quiescence_failure(receipt: Win16HostMciQuiescenceReceipt) -> RuntimeError {
    let kind = receipt.causes.first().map_or(Kind::CompatibilityGap, |cause| cause.kind());
    RuntimeError::with_source(
        kind,
        "Win16 MCI quiescence retains exact native owner identities and retryable phases",
        Win16HostMciQuiescenceFailure { receipt },
    )
}
