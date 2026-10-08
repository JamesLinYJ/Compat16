use super::*;

#[path = "win16_mci_worker_quiesce_close.rs"]
mod close;
pub(super) use close::close_all_devices;

pub(super) fn quiesce_requested(
    state: &WorkerThreadState,
    request: Win16HostMciQuiesceRequest,
) -> Result<Win16HostMciQuiescenceReceipt, RuntimeError> {
    state.producer_admission_closed.set(true);
    state
        .notifications
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .close_source_admission();
    let owned_request = try_clone_quiesce_request(&request)?;
    let mut receipt = Win16HostMciQuiescenceReceipt {
        request: owned_request,
        status: Win16HostMciQuiescenceStatus::Quiesced,
        confirmed: Vec::new(),
        retained: Vec::new(),
        causes: Vec::new(),
        resolved_causes: Vec::new(),
    };
    if !request.pending_begins.is_empty() {
        let owner_capacity = request
            .devices
            .len()
            .saturating_add(request.registrations.len())
            .saturating_add(request.pending_begins.len().saturating_mul(2))
            .saturating_add(request.active_yields.len().saturating_mul(2))
            .saturating_add(request.returned_yields.len())
            .saturating_add(request.completed_operations.len())
            .saturating_add(2);
        receipt.retained.try_reserve_exact(owner_capacity).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve retained owners for pending MCI Begin reconciliation",
                error,
            )
        })?;
        receipt.causes.try_reserve_exact(request.pending_begins.len()).map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "reserve pending MCI Begin reconciliation causes",
                error,
            )
        })?;
        receipt
            .resolved_causes
            .try_reserve_exact(request.resolved_causes.len())
            .map_err(|error| {
                RuntimeError::with_source(
                    Kind::ResourceExhausted,
                    "retain prior MCI causes while Begin result is pending",
                    error,
                )
            })?;
        receipt
            .resolved_causes
            .extend(request.resolved_causes.iter().cloned());
        receipt
            .retained
            .extend(request.devices.iter().copied().map(Win16HostMciRetainedOwner::Device));
        receipt.retained.extend(
            request
                .registrations
                .iter()
                .copied()
                .map(Win16HostMciRetainedOwner::Registration),
        );
        receipt.retained.extend(
            request
                .pending_begins
                .iter()
                .copied()
                .map(Win16HostMciRetainedOwner::PendingBegin),
        );
        receipt.retained.extend(
            request
                .pending_begins
                .iter()
                .copied()
                .map(Win16HostMciRetainedOwner::Operation),
        );
        receipt.retained.extend(
            request
                .active_yields
                .iter()
                .copied()
                .map(Win16HostMciRetainedOwner::ActiveYield),
        );
        receipt.retained.extend(
            request
                .returned_yields
                .iter()
                .copied()
                .map(Win16HostMciRetainedOwner::YieldReturn),
        );
        receipt.retained.extend(
            request
                .completed_operations
                .iter()
                .copied()
                .map(Win16HostMciRetainedOwner::CompletedOperation),
        );
        for owner in &request.active_yields {
            if !receipt
                .retained
                .contains(&Win16HostMciRetainedOwner::Operation(owner.operation))
            {
                receipt
                    .retained
                    .push(Win16HostMciRetainedOwner::Operation(owner.operation));
            }
        }
        receipt.retained.push(Win16HostMciRetainedOwner::OwnerThread);
        receipt.retained.push(Win16HostMciRetainedOwner::NotificationSink);
        receipt.causes.extend(request.pending_begins.iter().map(|operation| {
            Arc::new(RuntimeError::new(
                Kind::CompatibilityGap,
                format!(
                    "MCI operation {} remains owned by runtime Begin-result reconciliation; no YIELDPROC frame is inferred and no device is closed",
                    operation.0
                ),
            ))
        }));
        receipt.status = Win16HostMciQuiescenceStatus::Retained;
        return Ok(receipt);
    }
    let (host_devices, unmapped_owner_count) = {
        let devices = state.devices.lock().unwrap_or_else(PoisonError::into_inner);
        let host_devices = devices.snapshot()?;
        let unmapped_registrations = devices
            .yield_registrations
            .keys()
            .filter(|device| !devices.by_identity.contains_key(device))
            .count();
        (
            host_devices,
            devices
                .orphan_aliases
                .len()
                .saturating_add(devices.orphan_native_ids.len())
                .saturating_add(unmapped_registrations),
        )
    };
    let notification_snapshot = state
        .notifications
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .quiescence_snapshot();
    let notification_ledger_drained = notification_snapshot.4;
    let mut returned_yield_tombstones = Vec::new();
    returned_yield_tombstones
        .try_reserve_exact(state.returned_yields.borrow().len())
        .map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "snapshot exact returned MCI yield ACK tombstones before quiescence",
            error,
        ))?;
    returned_yield_tombstones.extend_from_slice(state.returned_yields.borrow().as_slice());
    let mut completed_operation_tombstones = Vec::new();
    completed_operation_tombstones
        .try_reserve_exact(state.completed_operations.borrow().len())
        .map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "snapshot exact MCI completion tombstones before quiescence",
            error,
        ))?;
    completed_operation_tombstones
        .extend_from_slice(state.completed_operations.borrow().as_slice());
    let active_invocation_count = ACTIVE_YIELDS.with(|active| {
        active
            .borrow()
            .iter()
            .filter(|invocation| invocation.active_yield.is_some())
            .count()
    });
    let mut live_active_yields = Vec::new();
    live_active_yields
        .try_reserve_exact(active_invocation_count)
        .map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "snapshot exact live native MCI yield owners before quiescence",
            error,
        ))?;
    ACTIVE_YIELDS.with(|active| {
        live_active_yields.extend(
            active
                .borrow()
                .iter()
                .filter_map(|invocation| invocation.active_yield),
        );
    });
    let unrequested_live_yields = live_active_yields
        .iter()
        .filter(|owner| !request.active_yields.contains(owner))
        .count();
    let unrequested_live_device_count = host_devices
        .iter()
        .filter(|(device, _)| !request.devices.contains(device))
        .count();
    let mut unrequested_live_devices = Vec::new();
    unrequested_live_devices
        .try_reserve_exact(unrequested_live_device_count)
        .map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve exact host-discovered MCI device blockers before quiescence",
            error,
        ))?;
    unrequested_live_devices.extend(
        host_devices
            .iter()
            .map(|(device, _)| *device)
            .filter(|device| !request.devices.contains(device)),
    );
    let mut unrequested_registrations = Vec::new();
    unrequested_registrations
        .try_reserve_exact(host_devices.len())
        .map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve host-discovered MCI registration blockers before quiescence",
            error,
        ))?;
    for (device, _) in &host_devices {
        if let Some(registration) = state.current_yield_registration(*device) {
            let owner = Win16HostMciYieldRegistration {
                device: *device,
                registration,
            };
            if !request.registrations.contains(&owner)
                && !unrequested_registrations.contains(&owner)
            {
                unrequested_registrations.push(owner);
            }
        }
    }
    let relevant_returned_count = returned_yield_tombstones
        .iter()
        .filter(|returned| request.returned_yields.contains(*returned))
        .count();
    let relevant_completion_count = completed_operation_tombstones
        .iter()
        .filter(|completed| request.completed_operations.contains(*completed))
        .count();
    let evidence_capacity = request
        .registrations
        .len()
        .saturating_add(request.devices.len())
        .saturating_add(request.active_yields.len())
        .saturating_add(relevant_returned_count)
        .saturating_add(relevant_completion_count)
        .saturating_add(usize::from(notification_ledger_drained));
    let retained_capacity = evidence_capacity
        .saturating_add(request.active_yields.len())
        .saturating_add(request.returned_yields.len().saturating_mul(2))
        .saturating_add(request.completed_operations.len())
        .saturating_add(unrequested_live_yields.saturating_mul(2))
        .saturating_add(unrequested_registrations.len())
        .saturating_add(unrequested_live_devices.len())
        .saturating_add(usize::from(unmapped_owner_count != 0))
        .saturating_add(usize::from(!notification_ledger_drained));
    receipt.confirmed.try_reserve_exact(evidence_capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve MCI native quiescence evidence before disabling sources",
            error,
        )
    })?;
    receipt.retained.try_reserve_exact(retained_capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve exact MCI native owner identities before quiescence",
            error,
        )
    })?;
    receipt.causes.try_reserve_exact(retained_capacity).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve MCI native quiescence failure causes before side effects",
            error,
        )
    })?;
    receipt.resolved_causes.try_reserve_exact(
        request
            .registrations
            .len()
            .saturating_add(request.resolved_causes.len()),
    ).map_err(|error| {
        RuntimeError::with_source(
            Kind::ResourceExhausted,
            "reserve resolved MCI source-disable and prior retry causes before side effects",
            error,
        )
    })?;
    receipt
        .resolved_causes
        .extend(request.resolved_causes.iter().cloned());
    let request_is_empty = request.devices.is_empty()
        && request.registrations.is_empty()
        && request.pending_begins.is_empty()
        && request.active_yields.is_empty()
        && request.returned_yields.is_empty()
        && request.completed_operations.is_empty();
    if request_is_empty
        && host_devices.is_empty()
        && unmapped_owner_count == 0
        && live_active_yields.is_empty()
        && notification_ledger_drained
    {
        receipt.status = Win16HostMciQuiescenceStatus::NotStarted;
        return Ok(receipt);
    }
    if notification_ledger_drained {
        receipt
            .confirmed
            .push(Win16HostMciQuiescenceEvidence::NotificationLedgerDrained {
                pending_routes: notification_snapshot.0,
                queued_events: notification_snapshot.1,
                callback_failures: notification_snapshot.2,
                wake_failures: notification_snapshot.3,
            });
    } else {
        receipt
            .retained
            .push(Win16HostMciRetainedOwner::NotificationSink);
        let kind = if notification_snapshot.2 != 0 || notification_snapshot.3 != 0 {
            Kind::HostFailure
        } else {
            Kind::CompatibilityGap
        };
        receipt.causes.push(Arc::new(RuntimeError::new(
            kind,
            format!(
                "MCI notification ledger retains {} route(s), {} event(s), {} callback failure(s), and {} wake failure(s)",
                notification_snapshot.0,
                notification_snapshot.1,
                notification_snapshot.2,
                notification_snapshot.3
            ),
        )));
    }
    for owner in &live_active_yields {
        if request.active_yields.contains(owner)
            || receipt
                .retained
                .contains(&Win16HostMciRetainedOwner::ActiveYield(*owner))
        {
            continue;
        }
        receipt
            .retained
            .push(Win16HostMciRetainedOwner::ActiveYield(*owner));
        if !receipt
            .retained
            .contains(&Win16HostMciRetainedOwner::Operation(owner.operation))
        {
            receipt
                .retained
                .push(Win16HostMciRetainedOwner::Operation(owner.operation));
        }
        receipt.causes.push(Arc::new(RuntimeError::new(
            Kind::InternalInvariant,
            format!(
                "native MCI owner has unrequested active operation {} frame {} on device token {} generation {}",
                owner.operation.0, owner.frame.0, owner.device.token, owner.device.generation
            ),
        )));
    }
    for owner in &unrequested_registrations {
        receipt
            .retained
            .push(Win16HostMciRetainedOwner::Registration(*owner));
        receipt.causes.push(Arc::new(RuntimeError::new(
            Kind::InternalInvariant,
            format!(
                "MCI device token {} generation {} retains unrequested yield registration {}",
                owner.device.token, owner.device.generation, owner.registration.0
            ),
        )));
    }
    for device in &unrequested_live_devices {
        receipt
            .retained
            .push(Win16HostMciRetainedOwner::Device(*device));
        receipt.causes.push(Arc::new(RuntimeError::new(
            Kind::InternalInvariant,
            format!(
                "native MCI device token {} generation {} is live but absent from the exact quiescence request",
                device.token, device.generation
            ),
        )));
    }
    if unmapped_owner_count != 0 {
        receipt
            .retained
            .push(Win16HostMciRetainedOwner::OwnerThread);
        receipt.causes.push(Arc::new(RuntimeError::new(
            Kind::InternalInvariant,
            format!(
                "native MCI worker registry retains {unmapped_owner_count} owner record(s) without an exact live device identity"
            ),
        )));
    }
    for returned in returned_yield_tombstones
        .iter()
        .copied()
        .filter(|returned| request.returned_yields.contains(returned))
    {
        receipt
            .confirmed
            .push(Win16HostMciQuiescenceEvidence::ActiveYieldReturned {
                owner: returned.owner,
                guest_return: returned.guest_return,
            });
    }
    for completed in completed_operation_tombstones
        .iter()
        .copied()
        .filter(|completed| request.completed_operations.contains(completed))
    {
        receipt
            .confirmed
            .push(Win16HostMciQuiescenceEvidence::OperationCompleted {
                operation: completed.operation,
                native_return_value: completed.native_return_value,
            });
    }

    for returned in &request.returned_yields {
        if !returned_yield_tombstones.contains(returned) {
            receipt
                .retained
                .push(Win16HostMciRetainedOwner::YieldReturn(*returned));
            receipt.causes.push(Arc::new(RuntimeError::new(
                Kind::InternalInvariant,
                format!(
                    "MCI request claims returned operation {} frame {} without the worker native ACK tombstone",
                    returned.owner.operation.0, returned.owner.frame.0
                ),
            )));
        }
    }

    for returned in &request.returned_yields {
        let completion_confirmed = request.completed_operations.iter().any(|completed| {
            completed.operation == returned.owner.operation
                && completed_operation_tombstones.contains(completed)
        });
        if !completion_confirmed
            && !receipt
                .retained
                .contains(&Win16HostMciRetainedOwner::Operation(
                    returned.owner.operation,
                ))
        {
            receipt
                .retained
                .push(Win16HostMciRetainedOwner::Operation(
                    returned.owner.operation,
                ));
            receipt.causes.push(Arc::new(RuntimeError::new(
                Kind::CompatibilityGap,
                format!(
                    "MCI operation {} has an acknowledged yield but no exact native operation-completion receipt",
                    returned.owner.operation.0
                ),
            )));
        }
    }
    for completed in &request.completed_operations {
        if !completed_operation_tombstones.contains(completed) {
            receipt
                .retained
                .push(Win16HostMciRetainedOwner::CompletedOperation(*completed));
            receipt.causes.push(Arc::new(RuntimeError::new(
                Kind::InternalInvariant,
                format!(
                    "MCI request claims operation {} completed without the worker native result tombstone",
                    completed.operation.0
                ),
            )));
        }
    }

    state.reserve_yield_source_evidence_batch(&request.registrations)?;
    for owner in &request.registrations {
        match native::disable_yield_registration(state, *owner) {
            Ok(evidence @ Win16HostMciQuiescenceEvidence::YieldSourceDisabled {
                set_result,
                observed_installed,
                ..
            }) => {
                if !observed_installed {
                    if set_result == 0 {
                        receipt.resolved_causes.push(Arc::new(RuntimeError::new(
                            Kind::HostFailure,
                            format!(
                                "mciSetYieldProc returned FALSE for registration {} although mciGetYieldProc confirmed the runtime thunk is absent",
                                owner.registration.0
                            ),
                        )));
                    }
                    receipt.confirmed.push(evidence);
                } else {
                    receipt.retained.push(Win16HostMciRetainedOwner::Registration(*owner));
                    receipt.causes.push(Arc::new(RuntimeError::new(
                        Kind::HostFailure,
                        format!(
                            "mciSetYieldProc result {set_result} left registration {} installed",
                            owner.registration.0
                        ),
                    )));
                }
            }
            Ok(_) => {
                receipt.retained.push(Win16HostMciRetainedOwner::Registration(*owner));
                receipt.causes.push(Arc::new(RuntimeError::new(
                    Kind::InternalInvariant,
                    "native MCI source-disable operation returned evidence for a different phase",
                )));
            }
            Err(error) => {
                receipt.retained.push(Win16HostMciRetainedOwner::Registration(*owner));
                receipt.causes.push(Arc::new(error));
            }
        }
    }

    for owner in &request.active_yields {
        let return_confirmed = request.returned_yields.iter().any(|expected| {
            expected.owner == *owner && returned_yield_tombstones.contains(expected)
        });
        if !return_confirmed {
            receipt.retained.push(Win16HostMciRetainedOwner::ActiveYield(*owner));
            receipt.causes.push(Arc::new(RuntimeError::new(
                Kind::CompatibilityGap,
                format!(
                    "MCI operation {} frame {} lacks the exact guest-WORD/native-ACK pair required to retire its YIELDPROC owner; no cancellation WORD is documented",
                    owner.operation.0, owner.frame.0
                ),
            )));
        }
        let completion_confirmed = request.completed_operations.iter().any(|expected| {
            expected.operation == owner.operation
                && completed_operation_tombstones.contains(expected)
        });
        if !completion_confirmed
            && !receipt
                .retained
                .contains(&Win16HostMciRetainedOwner::Operation(owner.operation))
        {
            receipt
                .retained
                .push(Win16HostMciRetainedOwner::Operation(owner.operation));
            receipt.causes.push(Arc::new(RuntimeError::new(
                Kind::CompatibilityGap,
                format!(
                    "MCI operation {} lacks the exact runtime result/native completion pair required before device retirement",
                    owner.operation.0
                ),
            )));
        }
    }

    let completion_proofs_missing = request.completed_operations.iter().any(|expected| {
        !completed_operation_tombstones.contains(expected)
    });
    for device in &request.devices {
        let active = live_active_yields
            .iter()
            .any(|yield_owner| yield_owner.device == *device)
            || request.active_yields.iter().any(|yield_owner| {
                yield_owner.device == *device
                    && (!request.returned_yields.iter().any(|expected| {
                        expected.owner == *yield_owner
                            && returned_yield_tombstones.contains(expected)
                    })
                        || !request.completed_operations.iter().any(|expected| {
                            expected.operation == yield_owner.operation
                                && completed_operation_tombstones.contains(expected)
                        }))
            })
            || request.returned_yields.iter().any(|returned| {
                returned.owner.device == *device
                    && (!returned_yield_tombstones.contains(returned)
                        || !request.completed_operations.iter().any(|completed| {
                            completed.operation == returned.owner.operation
                                && completed_operation_tombstones.contains(completed)
                        }))
            })
            || completion_proofs_missing
            || unmapped_owner_count != 0;
        let source_retained = request.registrations.iter().any(|registration| {
            registration.device == *device
                && receipt.retained.iter().any(|retained| {
                    matches!(retained, Win16HostMciRetainedOwner::Registration(current) if current == registration)
                })
        }) || unrequested_registrations
            .iter()
            .any(|registration| registration.device == *device)
            || !notification_ledger_drained;
        if active || source_retained {
            receipt.retained.push(Win16HostMciRetainedOwner::Device(*device));
            continue;
        }
        let (resolved, retired) = {
            let devices = state.devices.lock().unwrap_or_else(PoisonError::into_inner);
            (devices.resolve(*device), devices.is_retired(*device))
        };
        let Some((native_id, _)) = resolved else {
            if retired {
                receipt.confirmed.push(Win16HostMciQuiescenceEvidence::DeviceClosed {
                    device: *device,
                    native_result: 0,
                });
            } else {
                receipt.retained.push(Win16HostMciRetainedOwner::Device(*device));
                receipt.causes.push(Arc::new(RuntimeError::new(
                    Kind::InvalidInput,
                    format!(
                        "MCI quiescence references unknown device token {} generation {}",
                        device.token, device.generation
                    ),
                )));
            }
            continue;
        };
        let native_result = native::close_native_device(native_id, state.sink);
        receipt.confirmed.push(Win16HostMciQuiescenceEvidence::DeviceClosed {
            device: *device,
            native_result,
        });
        if native_result == 0 {
            if let Err(error) = state.retire_device(*device) {
                // Native close already happened; report retained bookkeeping evidence instead
                // of returning Err, which the client may safely retry only before side effects.
                receipt.retained.push(Win16HostMciRetainedOwner::Device(*device));
                receipt.causes.push(Arc::new(error));
            }
        } else {
            receipt.retained.push(Win16HostMciRetainedOwner::Device(*device));
            receipt.causes.push(Arc::new(RuntimeError::new(
                Kind::HostFailure,
                format!(
                    "MCI_CLOSE for device token {} generation {} returned native result {native_result}",
                    device.token, device.generation
                ),
            )));
        }
    }

    if !receipt.retained.is_empty() {
        receipt.status = Win16HostMciQuiescenceStatus::Retained;
    }
    Ok(receipt)
}

fn try_clone_quiesce_request(
    request: &Win16HostMciQuiesceRequest,
) -> Result<Win16HostMciQuiesceRequest, RuntimeError> {
    let mut copy = Win16HostMciQuiesceRequest::default();
    copy.devices.try_reserve_exact(request.devices.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "copy MCI quiescence device identities", error)
    })?;
    copy.registrations.try_reserve_exact(request.registrations.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "copy MCI quiescence registration identities", error)
    })?;
    copy.pending_begins
        .try_reserve_exact(request.pending_begins.len())
        .map_err(|error| {
            RuntimeError::with_source(
                Kind::ResourceExhausted,
                "copy pending MCI Begin owner identities",
                error,
            )
        })?;
    copy.active_yields.try_reserve_exact(request.active_yields.len()).map_err(|error| {
        RuntimeError::with_source(Kind::ResourceExhausted, "copy MCI active yield identities", error)
    })?;
    copy.returned_yields
        .try_reserve_exact(request.returned_yields.len())
        .map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "copy MCI returned-yield ACK proofs",
            error,
        ))?;
    copy.completed_operations
        .try_reserve_exact(request.completed_operations.len())
        .map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "copy MCI completed-operation proofs",
            error,
        ))?;
    copy.resolved_causes
        .try_reserve_exact(request.resolved_causes.len())
        .map_err(|error| RuntimeError::with_source(
            Kind::ResourceExhausted,
            "copy cumulative MCI typed causes",
            error,
        ))?;
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
